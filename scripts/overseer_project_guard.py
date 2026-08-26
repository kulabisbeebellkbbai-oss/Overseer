#!/usr/bin/env python3
"""Codex hook that routes shared work through authoritative Overseer evidence."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse


DEFAULT_OVERSEER_API = "http://127.0.0.1:8766"
DEFAULT_OVERSEER_TOKEN_FILE = "/home/god/.local/share/overseer/project/state/api-token"
DEFAULT_FINDINGS = Path.home() / ".codex/state/overseer-evidence-findings.json"
MAX_TOKEN_BYTES = 4096
MAX_API_RESPONSE_BYTES = 1024 * 1024

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

RECORD_TYPES: dict[str, frozenset[str]] = {
    "crew_message": frozenset({"id", "owner_domain", "status", "review_status", "related_plan_id", "related_resource_id", "requested_by", "decided_by"}),
    "admin_plan": frozenset({"id", "kind", "owner_domain", "target", "risk_level", "approval_level", "approved", "approved_by", "canceled", "archived"}),
    "claim": frozenset({"id", "resource_id", "claim_type", "owner_thread", "owner_role", "status", "risk_level"}),
    "usage_continuation": frozenset({"id", "limit_id", "resource_id", "owner_thread", "requested_units", "risk_level", "requested_by"}),
    "backup_provisioning_plan": frozenset({"id", "plan_id", "kind", "status", "approved_by", "plan_digest", "evidence_digest", "root_authorization_refs"}),
    "storage_root_authorization": frozenset({"id", "authorization_ref", "project_id", "root_id", "status", "root_identity", "approval_id", "target_digest"}),
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
    last_message_source: str | None = None
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(raw, dict):
                entry = entry_role_and_text(raw)
                source = str(raw.get("type") or "")
                role, text = entry
                if (
                    role in {"user", "assistant"}
                    and bool(text)
                    and bool(entries)
                    and entries[-1] == entry
                    and {source, last_message_source} == {"response_item", "event_msg"}
                ):
                    last_message_source = source
                    continue
                entries.append(entry)
                last_message_source = source if role in {"user", "assistant"} else None
    last_user = max((index for index, (role, _text) in enumerate(entries) if role == "user"), default=-1)
    return entries[last_user:] if last_user >= 0 else entries


class OverseerApiError(RuntimeError):
    """A redacted failure to use the local Overseer authority API."""


def overseer_api_url(api_url: str | None = None) -> str:
    selected = (api_url or os.environ.get("OVERSEER_API_URL") or DEFAULT_OVERSEER_API).rstrip("/")
    parsed = urlparse(selected)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise OverseerApiError("Overseer API URL must be an uncredentialed loopback HTTP origin")
    return selected


def overseer_token_file(token_file: str | None = None) -> Path:
    return Path(token_file or os.environ.get("OVERSEER_TOKEN_FILE") or DEFAULT_OVERSEER_TOKEN_FILE).expanduser()


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _validate_token_metadata(metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise OverseerApiError("ordinary API token is not a regular file")
    if metadata.st_nlink != 1:
        raise OverseerApiError("ordinary API token file must not be hard-linked")
    if metadata.st_uid != os.geteuid():
        raise OverseerApiError("ordinary API token file has an unexpected owner")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise OverseerApiError("ordinary API token file must have mode 0600")
    if metadata.st_size > MAX_TOKEN_BYTES:
        raise OverseerApiError("ordinary API token file is too large")


def read_api_token(token_file: str | None = None) -> str:
    path = overseer_token_file(token_file)
    try:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode):
            raise OverseerApiError("ordinary API token file must not be a symlink")
        _validate_token_metadata(before)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            _validate_token_metadata(opened)
            if not _same_file(before, opened):
                raise OverseerApiError("ordinary API token file changed while opening")
            raw = os.read(descriptor, MAX_TOKEN_BYTES + 1)
            if len(raw) > MAX_TOKEN_BYTES:
                raise OverseerApiError("ordinary API token file is too large")
            after = os.fstat(descriptor)
            _validate_token_metadata(after)
            if not _same_file(opened, after) or after.st_size != before.st_size:
                raise OverseerApiError("ordinary API token file changed while reading")
            lexical_after = os.lstat(path)
            _validate_token_metadata(lexical_after)
            if not _same_file(before, lexical_after):
                raise OverseerApiError("ordinary API token file changed while reading")
        finally:
            os.close(descriptor)
    except OverseerApiError:
        raise
    except OSError as error:
        raise OverseerApiError("ordinary API token file could not be safely read") from error
    try:
        token = raw.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise OverseerApiError("ordinary API token file is not valid UTF-8") from error
    if not token or any(character.isspace() or ord(character) < 0x20 for character in token):
        raise OverseerApiError("ordinary API token is not canonical")
    return token


def overseer_ready(api_url: str | None = None) -> bool:
    try:
        with urllib.request.urlopen(f"{overseer_api_url(api_url)}/health", timeout=2) as response:
            return 200 <= response.status < 300
    except (OSError, OverseerApiError):
        return False


def needs_overseer(text: str, cwd: str = "") -> bool:
    if not RESOURCE_RE.search(text):
        return False
    if LOCAL_PROJECT_RE.search(text) or LOCAL_PROJECT_RE.search(cwd):
        return True
    return bool(re.search(r"\b(run|serve|deploy|restart|install|update|firewall|usb|serial|vm|emulator|gateway|proxy|mcp)\b", text, re.IGNORECASE))


def route_message(ready: bool) -> str:
    status = "reachable" if ready else "not reachable"
    try:
        health_endpoint = f"{overseer_api_url()}/health"
    except OverseerApiError:
        health_endpoint = "invalid loopback API configuration"
    example = '{"record_type":"crew_message","record_id":"crew.kira.example","expected":{"owner_domain":"kira","status":"acknowledged","review_status":"approved","requested_by":"Roadex"}}'
    return "\n".join([
        "Overseer local coordination required for shared-resource work on this computer.",
        "Use the `overseer-local-coordination` skill before changing or reserving shared resources.",
        f"Overseer API health is {status} at {health_endpoint}.",
        f"Use the authenticated API and token file `{overseer_token_file()}`; never print the token.",
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


def _fetch_authoritative_record(
    record_type: str,
    record_id: str,
    *,
    api_url: str | None = None,
    token_file: str | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    if record_type not in RECORD_TYPES:
        return None, f"unsupported record_type {record_type!r}"
    try:
        token = read_api_token(token_file)
        request = urllib.request.Request(
            f"{overseer_api_url(api_url)}/evidence/records/{quote(record_type, safe='')}/{quote(record_id, safe='')}",
            headers={"Authorization": f"Bearer {token}"},
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            raw = response.read(MAX_API_RESPONSE_BYTES + 1)
            if len(raw) > MAX_API_RESPONSE_BYTES:
                raise OverseerApiError("authoritative API response is too large")
            payload = json.loads(raw)
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read())
        except (OSError, TypeError, json.JSONDecodeError):
            payload = {}
        if exc.code == 404 and payload.get("error") == "record_not_found":
            return None, None
        return None, f"authoritative API unavailable: HTTP {exc.code}"
    except (OSError, TypeError, ValueError, OverseerApiError, json.JSONDecodeError) as exc:
        return None, f"authoritative API unavailable: {type(exc).__name__}"
    if not isinstance(payload, dict) or payload.get("record_type") != record_type or payload.get("record_id") != record_id:
        return None, "authoritative API response is invalid"
    fields = payload.get("fields")
    if not isinstance(fields, dict):
        return None, "authoritative API response is invalid"
    if set(fields) - RECORD_TYPES[record_type]:
        return None, "authoritative API response contains unsupported fields"
    return fields, None


def verify_claim(
    claim: dict[str, Any],
    *,
    api_url: str | None = None,
    token_file: str | None = None,
) -> dict[str, Any]:
    record_type = claim.get("record_type")
    record_id = claim.get("record_id")
    expected = claim.get("expected")
    if not isinstance(record_type, str) or not isinstance(record_id, str) or not isinstance(expected, dict) or not expected:
        return {"accepted": False, "failure_class": "malformed", "reason": "record_type, record_id, and non-empty expected object are required"}
    spec = RECORD_TYPES.get(record_type)
    if spec is None:
        return {"accepted": False, "failure_class": "malformed", "record_type": record_type, "record_id": record_id, "reason": "unsupported record_type"}
    unknown = sorted(set(expected) - spec)
    if unknown:
        return {"accepted": False, "failure_class": "malformed", "record_type": record_type, "record_id": record_id, "reason": f"unsupported expected fields: {', '.join(unknown)}"}
    missing = sorted(REQUIRED_EXPECTED_FIELDS[record_type] - set(expected))
    if missing:
        return {"accepted": False, "failure_class": "malformed", "record_type": record_type, "record_id": record_id, "reason": f"required exact fields missing: {', '.join(missing)}"}
    actual, error = _fetch_authoritative_record(
        record_type, record_id, api_url=api_url, token_file=token_file
    )
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


def escalate_to_odo(
    fingerprint: str,
    result: dict[str, Any],
    count: int,
    *,
    api_url: str | None = None,
    token_file: str | None = None,
) -> str:
    message_id = f"crew.odo.hook-evidence.{fingerprint[:20]}"
    token = read_api_token(token_file)
    body = json.dumps(
        {
            "message_id": message_id,
            "owner_domain": "odo",
            "subject": "Repeated unverified Overseer hook evidence",
            "message": (
                f"Risk assessment requested after {count} distinct hook attempts claimed the same unverified "
                f"{result.get('record_type', 'record')} identifier. Failure class: {result.get('failure_class')}. "
                "The hook denied completion. No transcript, credentials, or authoritative field values were retained."
            ),
            "priority": "high",
            "requested_by": "overseer_project_guard",
            "related_resource_id": "security.codex-hooks",
        },
        sort_keys=True,
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{overseer_api_url(api_url)}/crew/messages",
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=3) as response:
        if not 200 <= response.status < 300:
            raise OSError(f"crew escalation returned HTTP {response.status}")
        if len(response.read(MAX_API_RESPONSE_BYTES + 1)) > MAX_API_RESPONSE_BYTES:
            raise OverseerApiError("crew escalation API response is too large")
    return message_id


def record_failure(
    result: dict[str, Any],
    claim: dict[str, Any],
    transcript: Path,
    assistant_text: str,
    findings_path: Path,
    *,
    api_url: str | None = None,
    token_file: str | None = None,
) -> dict[str, Any]:
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
                item["odo_message_id"] = escalate_to_odo(
                    fingerprint,
                    result,
                    item["occurrence_count"],
                    api_url=api_url,
                    token_file=token_file,
                )
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
    api_url = os.environ.get("OVERSEER_API_URL") or DEFAULT_OVERSEER_API
    token_file = str(overseer_token_file())
    findings_path = Path(os.environ.get("OVERSEER_EVIDENCE_FINDINGS", str(DEFAULT_FINDINGS)))
    failures: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for claim in claims:
        result = verify_claim(claim, api_url=api_url, token_file=token_file)
        if not result["accepted"]:
            failures.append((result, claim))
    if parse_errors:
        failures.append(({"accepted": False, "failure_class": "malformed", "reason": parse_errors[0]}, {}))

    if failures:
        result, claim = failures[0]
        finding = record_failure(
            result,
            claim,
            transcript,
            assistant_text,
            findings_path,
            api_url=api_url,
            token_file=token_file,
        )
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
        finding = record_failure(
            result,
            claim,
            transcript,
            assistant_text,
            findings_path,
            api_url=api_url,
            token_file=token_file,
        )
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
