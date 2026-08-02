#!/usr/bin/env python3
"""Codex hook that routes shared work through authoritative Overseer evidence."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import sqlite3
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


OVERSEER_API = "http://127.0.0.1:8766"
OVERSEER_HEALTH = f"{OVERSEER_API}/health"
OVERSEER_PROJECT = "/home/god/.local/share/overseer/project"
OVERSEER_STORE = f"{OVERSEER_PROJECT}/state/overseer.sqlite3"
OVERSEER_TOKEN_FILE = f"{OVERSEER_PROJECT}/state/api-token"
DEFAULT_FINDINGS = Path.home() / ".codex/state/overseer-evidence-findings.json"

RESOURCE_RE = re.compile(
    r"\b(overseer|protected\s+gateway|gateway|proxy|proxies|port|ports|listener|listeners|"
    r"service|systemd|daemon|mcp|api\s*key|quota|usage\s*limit|cooldown|rate\s*limit|"
    r"install|update|upgrade|patch|package|apt|firewall|iptables|nftables|firewalld|"
    r"security|intrusion|block\s+ip|allow\s+tcp|deny\s+tcp|usb|serial|com\s*port|"
    r"storage|power|vm|vms|virtual\s+machine|emulator|emulators|device|devices|"
    r"checkout|claim|lock|lease|shared\s+resource|local\s+resource)\b",
    re.IGNORECASE,
)
LOCAL_PROJECT_RE = re.compile(
    r"/home/god/Documents/Codex Workspace|/home/god/|local|this\s+computer|this\s+machine",
    re.IGNORECASE,
)
WORK_DONE_RE = re.compile(
    r"\b(implemented|added|created|built|changed|updated|fixed|repaired|completed|"
    r"installed|upgraded|patched|restarted|started|stopped|enabled|disabled|"
    r"opened|allowed|blocked|claimed|checked\s+out|reserved|deployed|pushed)\b",
    re.IGNORECASE,
)
NON_RECORD_EVIDENCE_RE = re.compile(
    r"(service-status\s+(?:ok|healthy)|runtime-status\s+(?:ok|healthy)|"
    r"usage-continuation\s+(?:queued|approved)|Quark remote testing evidence)",
    re.IGNORECASE,
)
STRUCTURED_EVIDENCE_RE = re.compile(r"^\s*Overseer evidence:\s*(\{.*\})\s*$", re.MULTILINE)
RECORD_REFERENCE_RE = re.compile(
    r"\b(?:crew\.[a-z0-9_.-]+|admin\.[a-z0-9_.-]+|claim\.[a-z0-9_.-]+|"
    r"backup-provision\.[a-z0-9_.-]+|root-auth\.[a-z0-9_.-]+)\b",
    re.IGNORECASE,
)
HOOK_PROMPT_RE = re.compile(r"<hook_prompt\b[^>]*>.*?</hook_prompt>", re.IGNORECASE | re.DOTALL)

RECORD_TYPES: dict[str, tuple[str, frozenset[str]]] = {
    "crew_message": (
        "crew_messages",
        frozenset({"id", "owner_domain", "status", "review_status", "related_plan_id", "related_resource_id", "requested_by", "decided_by"}),
    ),
    "admin_plan": (
        "admin_change_plans",
        frozenset({"id", "kind", "owner_domain", "target", "risk_level", "approval_level", "approved", "approved_by", "canceled", "archived"}),
    ),
    "claim": (
        "claims",
        frozenset({"id", "resource_id", "claim_type", "owner_thread", "owner_role", "status", "risk_level"}),
    ),
    "usage_continuation": (
        "usage_continuation_requests",
        frozenset({"id", "limit_id", "resource_id", "owner_thread", "requested_units", "risk_level", "requested_by"}),
    ),
    "backup_provisioning_plan": (
        "backup_provisioning_plans",
        frozenset({"id", "plan_id", "kind", "status", "approved_by", "plan_digest", "evidence_digest", "root_authorization_refs"}),
    ),
    "storage_root_authorization": (
        "storage_root_authorizations",
        frozenset({"id", "authorization_ref", "project_id", "root_id", "status", "root_identity", "approval_id", "target_digest"}),
    ),
}

REQUIRED_EXPECTED_FIELDS: dict[str, frozenset[str]] = {
    "crew_message": frozenset({"owner_domain", "status", "review_status", "requested_by"}),
    "admin_plan": frozenset({"kind", "target", "approval_level", "approved", "canceled"}),
    "claim": frozenset({"resource_id", "claim_type", "owner_thread", "status"}),
    "usage_continuation": frozenset({"limit_id", "resource_id", "requested_units", "requested_by"}),
    "backup_provisioning_plan": frozenset({"plan_id", "status", "plan_digest", "evidence_digest", "root_authorization_refs"}),
    "storage_root_authorization": frozenset({"authorization_ref", "project_id", "root_id", "status", "root_identity", "approval_id"}),
}


def read_payload() -> dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def strip_hook_prompts(text: str) -> str:
    return HOOK_PROMPT_RE.sub("", text)


def prompt_text(payload: dict[str, Any]) -> str:
    for key in ("prompt", "user_prompt", "message"):
        value = payload.get(key)
        if isinstance(value, str):
            return strip_hook_prompts(value)
    return strip_hook_prompts(json.dumps(payload, sort_keys=True))


def text_from_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            item["text"] for item in content
            if isinstance(item, dict) and isinstance(item.get("text"), str)
        )
    return ""


def entry_role_and_text(entry: dict[str, Any]) -> tuple[str | None, str]:
    payload = entry.get("payload") or {}
    if entry.get("type") == "response_item":
        item_type = payload.get("type")
        if item_type == "message":
            return payload.get("role"), text_from_content(payload.get("content"))
        if item_type in {"function_call", "function_call_output", "tool_call", "tool_result"}:
            return "tool", json.dumps(payload, sort_keys=True)
        return None, json.dumps(payload, sort_keys=True)
    if entry.get("type") == "event_msg":
        msg_type = payload.get("type")
        if msg_type == "user_message":
            return "user", str(payload.get("message") or "")
        if msg_type == "agent_message":
            return "assistant", str(payload.get("message") or "")
    return None, ""


def latest_turn(path: Path) -> list[tuple[str | None, str]]:
    entries: list[tuple[str | None, str]] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(raw, dict):
                entries.append(entry_role_and_text(raw))
    last_user = max((index for index, (role, _text) in enumerate(entries) if role == "user"), default=-1)
    return entries[last_user:] if last_user >= 0 else entries


def overseer_ready() -> bool:
    try:
        with urllib.request.urlopen(OVERSEER_HEALTH, timeout=2) as response:
            return 200 <= response.status < 300
    except OSError:
        return False


def needs_overseer(text: str, cwd: str = "") -> bool:
    if not RESOURCE_RE.search(text):
        return False
    if LOCAL_PROJECT_RE.search(text) or LOCAL_PROJECT_RE.search(cwd):
        return True
    return bool(re.search(r"\b(run|serve|deploy|restart|install|update|firewall|usb|serial|vm|emulator|gateway|proxy|mcp)\b", text, re.IGNORECASE))


def route_message(ready: bool) -> str:
    status = "reachable" if ready else "not reachable"
    example = '{"record_type":"crew_message","record_id":"crew.kira.example","expected":{"owner_domain":"kira","status":"acknowledged","review_status":"approved","requested_by":"Roadex"}}'
    return "\n".join([
        "Overseer local coordination required for shared-resource work on this computer.",
        "Use the `overseer-local-coordination` skill before changing or reserving shared resources.",
        f"Overseer API health is {status} at {OVERSEER_HEALTH}.",
        f"Use store `{OVERSEER_STORE}` and token file `{OVERSEER_TOKEN_FILE}`; never print the token.",
        f"Record evidence must be authoritative and exact. Final format: `Overseer evidence: {example}`.",
    ])


def emit_continue_message(message: str) -> None:
    print(json.dumps({"continue": True, "suppressOutput": True, "systemMessage": message}))


def parse_claims(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    claims: list[dict[str, Any]] = []
    errors: list[str] = []
    for match in STRUCTURED_EVIDENCE_RE.finditer(text):
        try:
            value = json.loads(match.group(1))
        except json.JSONDecodeError:
            errors.append("malformed JSON evidence")
            continue
        if not isinstance(value, dict):
            errors.append("evidence must be a JSON object")
            continue
        claims.append(value)
    return claims, errors


def _canonical_record(store_path: Path, record_type: str, record_id: str) -> tuple[dict[str, Any] | None, str | None]:
    spec = RECORD_TYPES.get(record_type)
    if spec is None:
        return None, f"unsupported record_type {record_type!r}"
    table, _allowed = spec
    try:
        connection = sqlite3.connect(f"file:{store_path}?mode=ro", uri=True, timeout=2)
        try:
            row = connection.execute(f"SELECT * FROM {table} WHERE id = ?", (record_id,)).fetchone()
            if row is None:
                return None, None
            columns = [item[0] for item in connection.execute(f"SELECT * FROM {table} LIMIT 0").description]
        finally:
            connection.close()
    except (OSError, sqlite3.Error) as exc:
        return None, f"authoritative store unavailable: {type(exc).__name__}"
    raw = dict(zip(columns, row, strict=True))
    payload = raw.pop("payload", "{}")
    try:
        decoded = json.loads(payload)
    except (TypeError, json.JSONDecodeError):
        return None, "authoritative record payload is invalid"
    if not isinstance(decoded, dict):
        return None, "authoritative record payload is invalid"
    return {**raw, **decoded}, None


def verify_claim(claim: dict[str, Any], store_path: Path) -> dict[str, Any]:
    record_type = claim.get("record_type")
    record_id = claim.get("record_id")
    expected = claim.get("expected")
    if not isinstance(record_type, str) or not isinstance(record_id, str) or not isinstance(expected, dict) or not expected:
        return {"accepted": False, "failure_class": "malformed", "reason": "record_type, record_id, and non-empty expected object are required"}
    spec = RECORD_TYPES.get(record_type)
    if spec is None:
        return {"accepted": False, "failure_class": "malformed", "record_type": record_type, "record_id": record_id, "reason": "unsupported record_type"}
    unknown = sorted(set(expected) - spec[1])
    if unknown:
        return {"accepted": False, "failure_class": "malformed", "record_type": record_type, "record_id": record_id, "reason": f"unsupported expected fields: {', '.join(unknown)}"}
    missing = sorted(REQUIRED_EXPECTED_FIELDS[record_type] - set(expected))
    if missing:
        return {"accepted": False, "failure_class": "malformed", "record_type": record_type, "record_id": record_id, "reason": f"required exact fields missing: {', '.join(missing)}"}
    actual, error = _canonical_record(store_path, record_type, record_id)
    if error:
        return {"accepted": False, "failure_class": "unavailable", "record_type": record_type, "record_id": record_id, "reason": error}
    if actual is None:
        return {"accepted": False, "failure_class": "not_found", "record_type": record_type, "record_id": record_id, "reason": "record does not exist in authoritative Overseer store"}
    mismatches = [field for field, expected_value in expected.items() if actual.get(field) != expected_value]
    if mismatches:
        return {"accepted": False, "failure_class": "field_mismatch", "record_type": record_type, "record_id": record_id, "mismatches": mismatches, "reason": f"authoritative fields differ: {', '.join(mismatches)}"}
    return {"accepted": True, "record_type": record_type, "record_id": record_id}


def _finding_fingerprint(result: dict[str, Any], claim: dict[str, Any]) -> str:
    safe = {
        "hook": "overseer_project_guard",
        "record_type": result.get("record_type") or claim.get("record_type"),
        "record_id": result.get("record_id") or claim.get("record_id"),
        "expected": claim.get("expected") if isinstance(claim.get("expected"), dict) else {},
        "failure_class": result.get("failure_class"),
    }
    return hashlib.sha256(json.dumps(safe, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _attempt_id(transcript: Path, assistant_text: str) -> str:
    material = f"{transcript.resolve()}\0{hashlib.sha256(assistant_text.encode()).hexdigest()}"
    return hashlib.sha256(material.encode()).hexdigest()


def escalate_to_odo(fingerprint: str, result: dict[str, Any], count: int, store_path: Path) -> str:
    message_id = f"crew.odo.hook-evidence.{fingerprint[:20]}"
    connection = sqlite3.connect(store_path, timeout=3)
    try:
        if connection.execute("SELECT 1 FROM crew_messages WHERE id = ?", (message_id,)).fetchone():
            return message_id
    finally:
        connection.close()
    source_root = Path(os.environ.get("OVERSEER_SOURCE_ROOT", f"{OVERSEER_PROJECT}/src"))
    sys.path.insert(0, str(source_root))
    from overseer.cli import record_crew_message_status

    record_crew_message_status(
        store_path,
        "odo",
        "Repeated unverified Overseer hook evidence",
        (
            f"Risk assessment requested after {count} distinct hook attempts claimed the same unverified "
            f"{result.get('record_type', 'record')} identifier. Failure class: {result.get('failure_class')}. "
            "The hook denied completion. No transcript, credentials, or authoritative field values were retained."
        ),
        priority="high",
        requested_by="overseer_project_guard",
        message_id=message_id,
        related_resource_id="security.codex-hooks",
    )
    return message_id


def record_failure(result: dict[str, Any], claim: dict[str, Any], transcript: Path, assistant_text: str, store_path: Path, findings_path: Path) -> dict[str, Any]:
    fingerprint = _finding_fingerprint(result, claim)
    attempt = _attempt_id(transcript, assistant_text)
    findings_path.parent.mkdir(parents=True, exist_ok=True)
    if not findings_path.exists():
        findings_path.touch(mode=0o600)
    else:
        findings_path.chmod(0o600)
    with findings_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        handle.seek(0)
        try:
            state = json.load(handle)
        except (json.JSONDecodeError, ValueError):
            state = {"version": 1, "findings": {}}
        findings = state.setdefault("findings", {})
        item = findings.setdefault(fingerprint, {
            "failure_class": result.get("failure_class"),
            "record_type": result.get("record_type") or claim.get("record_type"),
            "record_id": result.get("record_id") or claim.get("record_id"),
            "first_seen_at": datetime.now(UTC).isoformat(),
            "occurrence_count": 0,
            "attempts": [],
            "odo_message_id": None,
        })
        if attempt not in item["attempts"]:
            item["attempts"].append(attempt)
            item["attempts"] = item["attempts"][-20:]
            item["occurrence_count"] += 1
            item["last_seen_at"] = datetime.now(UTC).isoformat()
        if item["occurrence_count"] >= 2 and not item.get("odo_message_id"):
            try:
                item["odo_message_id"] = escalate_to_odo(fingerprint, result, item["occurrence_count"], store_path)
            except Exception as exc:  # Keep the validation fail-closed even when escalation is unavailable.
                item["escalation_error"] = type(exc).__name__
        handle.seek(0)
        handle.truncate()
        json.dump(state, handle, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    return {"fingerprint": fingerprint, "occurrence_count": item["occurrence_count"], "odo_message_id": item.get("odo_message_id")}


def preflight(payload: dict[str, Any]) -> int:
    text = prompt_text(payload)
    cwd = str(payload.get("cwd") or "")
    if needs_overseer(text, cwd):
        emit_continue_message(route_message(overseer_ready()))
    return 0


def stop_check(payload: dict[str, Any]) -> int:
    transcript_value = payload.get("transcript_path")
    if not transcript_value:
        return 0
    transcript = Path(str(transcript_value))
    if not transcript.exists():
        return 0
    entries = latest_turn(transcript)
    user_text = strip_hook_prompts("\n".join(text for role, text in entries if role == "user" and text))
    assistant_text = strip_hook_prompts("\n".join(text for role, text in entries if role == "assistant" and text))
    cwd = str(payload.get("cwd") or "")
    if not needs_overseer(user_text, cwd) or not WORK_DONE_RE.search(assistant_text):
        return 0

    claims, parse_errors = parse_claims(assistant_text)
    store_path = Path(os.environ.get("OVERSEER_STORE", OVERSEER_STORE))
    findings_path = Path(os.environ.get("OVERSEER_EVIDENCE_FINDINGS", str(DEFAULT_FINDINGS)))
    failures: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for claim in claims:
        result = verify_claim(claim, store_path)
        if not result["accepted"]:
            failures.append((result, claim))
    if parse_errors:
        failures.append(({"accepted": False, "failure_class": "malformed", "reason": parse_errors[0]}, {}))

    if failures:
        result, claim = failures[0]
        finding = record_failure(result, claim, transcript, assistant_text, store_path, findings_path)
        escalation = f" Odo risk record: {finding['odo_message_id']}." if finding.get("odo_message_id") else ""
        print(
            "overseer_project_guard: blocked final response; claimed Overseer evidence was denied: "
            f"{result['reason']}. Acquire the real record and report its exact authoritative fields."
            f"{escalation}",
            file=sys.stderr,
        )
        return 2

    if claims:
        return 0

    references = RECORD_REFERENCE_RE.findall(assistant_text)
    if references or "Overseer evidence:" in assistant_text:
        record_id = references[0] if references else None
        result = {"accepted": False, "failure_class": "malformed", "record_id": record_id, "reason": "record evidence was not supplied as a typed JSON claim"}
        claim = {"record_id": record_id}
        finding = record_failure(result, claim, transcript, assistant_text, store_path, findings_path)
        escalation = f" Odo risk record: {finding['odo_message_id']}." if finding.get("odo_message_id") else ""
        print(
            "overseer_project_guard: blocked final response; record-like evidence cannot be accepted from prose or tool output. "
            "Acquire the real record and use `Overseer evidence: {\"record_type\":...,\"record_id\":...,\"expected\":{...}}`."
            f"{escalation}",
            file=sys.stderr,
        )
        return 2

    if NON_RECORD_EVIDENCE_RE.search(assistant_text):
        return 0
    print(
        "overseer_project_guard: blocked final response; shared local resource work needs authoritative Overseer evidence.",
        file=sys.stderr,
    )
    return 2


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--from-stdin", action="store_true")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--stop-check", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    payload = read_payload() if args.from_stdin or args.dry_run else {}
    return stop_check(payload) if args.stop_check else preflight(payload)


if __name__ == "__main__":
    raise SystemExit(main())
