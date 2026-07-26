#!/usr/bin/env python3
"""Stop hook that lets Quark coordinate remote testing before final delivery."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


DEFAULT_PROJECT_ROOT = Path("/home/god/.local/share/overseer/project")
DEFAULT_SOURCE_ROOT = DEFAULT_PROJECT_ROOT / "src"
DEFAULT_STORE = DEFAULT_PROJECT_ROOT / "state" / "overseer.sqlite3"
HOOK_PROMPT_RE = re.compile(r"<hook_prompt\b[^>]*>.*?</hook_prompt>", re.IGNORECASE | re.DOTALL)
WORK_DONE_RE = re.compile(r"\b(implemented|added|created|built|changed|updated|fixed|repaired|completed|wired|exposed|served|deployed)\b", re.IGNORECASE)
REMOTE_TEST_RE = re.compile(
    r"\b(ui|dashboard|browser|page|panel|auth|unlock|protected\s+gateway|gateway|route|endpoint|api|"
    r"regression|performance|latency|http\s+status|workflow|control)\b",
    re.IGNORECASE,
)
QUARK_EVIDENCE_RE = re.compile(
    r"(Quark remote testing evidence|Tank/MSI|remote-testing|overseer\.full_ui_regression|"
    r"overseer\.performance_regression|protected_gateway\.request_sequence|job-\d{8}T\d{6}Z)",
    re.IGNORECASE,
)


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


def text_from_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(item.get("text") or "") for item in content if isinstance(item, dict))
    return ""


def entry_role_and_text(entry: dict[str, Any]) -> tuple[str | None, str]:
    payload = entry.get("payload") or {}
    if entry.get("type") == "response_item":
        if payload.get("type") == "message":
            return payload.get("role"), text_from_content(payload.get("content"))
        if payload.get("type") in {"function_call", "function_call_output", "tool_call", "tool_result"}:
            return "tool", json.dumps(payload, sort_keys=True)
    if entry.get("type") == "event_msg":
        if payload.get("type") == "user_message":
            return "user", str(payload.get("message") or "")
        if payload.get("type") == "agent_message":
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
    last_user = -1
    for index, (role, _text) in enumerate(entries):
        if role == "user":
            last_user = index
    return entries[last_user:] if last_user >= 0 else entries


def project_name(cwd: str) -> str:
    name = Path(cwd or ".").name.strip() or "Codex"
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip("-") or "Codex"


def stable_suffix(session_id: str, cwd: str) -> str:
    digest = hashlib.sha256(f"{session_id}|{cwd}".encode("utf-8")).hexdigest()
    return digest[:12]


def project_gateway_path(name: str) -> str:
    if name.lower() == "overseer":
        return "/Overseer"
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "", name) or name
    return f"/{cleaned}"


def job_type_for(text: str, name: str) -> str:
    if re.search(r"\b(performance|latency|load|timing|slow|speed)\b", text, re.IGNORECASE):
        return "overseer.performance_regression" if name.lower() == "overseer" else "protected_gateway.request_sequence"
    if name.lower() == "overseer" and re.search(r"\b(ui|dashboard|browser|page|panel|auth|unlock|regression|workflow|control)\b", text, re.IGNORECASE):
        return "overseer.full_ui_regression"
    return "protected_gateway.request_sequence"


def needs_quark_testing(user_text: str, assistant_text: str, cwd: str) -> bool:
    combined = strip_hook_prompts("\n".join([user_text, assistant_text]))
    if QUARK_EVIDENCE_RE.search(combined):
        return False
    if not WORK_DONE_RE.search(assistant_text):
        return False
    if not REMOTE_TEST_RE.search(combined):
        return False
    if re.search(r"\b(no remote test|skip remote testing|local-only|not needed)\b", combined, re.IGNORECASE):
        return False
    return bool(cwd)


def import_overseer(project_root: Path, source_root: Path) -> None:
    for path in (str(source_root), str(project_root / "src")):
        if path not in sys.path:
            sys.path.insert(0, path)


def ensure_quark_job(project_root: Path, store_path: Path, session_id: str, cwd: str, assistant_text: str, dry_run: bool = False) -> dict[str, object]:
    import_overseer(project_root, Path(os.environ.get("OVERSEER_SOURCE_ROOT", str(DEFAULT_SOURCE_ROOT))))
    from overseer.core import OwnerDomain, RiskLevel
    from overseer.remote_testing import (
        collect_remote_test_results_status,
        enqueue_remote_test_job_status,
        remote_testing_status,
        request_remote_testing_lease_status,
    )
    from overseer.cli import record_crew_message_status
    from overseer.store import SQLiteStore

    name = project_name(cwd)
    suffix = stable_suffix(session_id or "session", cwd)
    lease_id = f"lease.codex-stop.{name.lower()}.{suffix}"
    gateway_path = project_gateway_path(name)
    job_type = job_type_for(assistant_text, name)
    status = remote_testing_status(project_root)
    existing_lease = next((item for item in status["leases"] if item.get("lease_id") == lease_id), None)
    if existing_lease and existing_lease.get("last_job_id"):
        results = collect_remote_test_results_status(project_root, lease_id=lease_id)
        if results["result_count"]:
            return {"action": "collected", "lease_id": lease_id, "job_type": job_type, "results": results["results"]}
        pending = [job for job in status["pending_jobs"] + status["claimed_jobs"] if job.get("lease_id") == lease_id]
        if pending:
            return {"action": "waiting", "lease_id": lease_id, "job_type": job_type, "pending": pending}
    if dry_run:
        return {"action": "would_queue", "lease_id": lease_id, "job_type": job_type, "gateway_path": gateway_path}
    request_remote_testing_lease_status(
        project_root,
        lease_id,
        name,
        "Quark coordinated final-answer regression check before Codex response delivery",
        requested_by="quark",
        job_types=(job_type,),
        priority="normal",
    )
    params: dict[str, object] = {"scheduled_by": "quark-stop-hook", "validation_stage": "final-answer-coordination"}
    if job_type == "protected_gateway.request_sequence":
        params["requests"] = [{"label": "health", "method": "GET", "path": "/health"}]
    job = enqueue_remote_test_job_status(
        project_root,
        lease_id,
        job_type,
        requested_by="quark",
        project=name,
        params=params,
        base_url=os.environ.get("OVERSEER_REMOTE_TEST_BASE_URL", "https://roadex.home.arpa:9443"),
        ui_path=f"{gateway_path}/ui",
        gateway_path=gateway_path,
        token_source="state/api-token",
        mutates=False,
    )
    crew_id = f"crew.quark.remote-testing-final.{name.lower()}.{suffix}"
    if store_path.exists():
        store = SQLiteStore(store_path)
        try:
            try:
                store.load_crew_message(crew_id)
                exists = True
            except KeyError:
                exists = False
        finally:
            store.close()
        if not exists:
            record_crew_message_status(
                store_path,
                OwnerDomain.QUARK.value,
                "Coordinate final-answer remote testing",
                f"Queued {job_type} for {name} before final response delivery; collect redacted result and continue the thread.",
                RiskLevel.MEDIUM.value,
                requested_by=name,
                message_id=crew_id,
                related_resource_id="remote-testing.tank-msi",
            )
    return {"action": "queued", "lease_id": lease_id, "job_type": job_type, "job": job["job"], "crew_message_id": crew_id}


def system_message(result: dict[str, object]) -> str:
    action = result.get("action")
    if action == "collected":
        return (
            "Quark remote testing evidence collected before final delivery. "
            f"Lease `{result.get('lease_id')}` results: {json.dumps(result.get('results'), sort_keys=True)}. "
            "Update the final answer with the redacted result summary and continue."
        )
    if action == "waiting":
        return (
            "Quark remote testing is still pending before final delivery. "
            f"Lease `{result.get('lease_id')}`, job type `{result.get('job_type')}`, pending: "
            f"{json.dumps(result.get('pending'), sort_keys=True)}. Continue by collecting results when available."
        )
    return (
        "Quark scheduled coordinated remote testing before final delivery. "
        f"Lease `{result.get('lease_id')}`, job type `{result.get('job_type')}`, "
        f"job `{(result.get('job') or {}).get('job_id') if isinstance(result.get('job'), dict) else ''}`. "
        "Continue this thread by collecting the redacted Tank/MSI result and include Quark remote testing evidence."
    )


def stop_check(payload: dict[str, Any], dry_run: bool = False) -> int:
    transcript = payload.get("transcript_path")
    if not transcript:
        return 0
    path = Path(str(transcript))
    if not path.exists():
        return 0
    entries = latest_turn(path)
    user_text = strip_hook_prompts("\n".join(text for role, text in entries if role == "user" and text))
    assistant_text = strip_hook_prompts("\n".join(text for role, text in entries if role == "assistant" and text))
    cwd = str(payload.get("cwd") or "")
    if not needs_quark_testing(user_text, assistant_text, cwd):
        return 0
    project_root = Path(os.environ.get("OVERSEER_PROJECT_ROOT", str(DEFAULT_PROJECT_ROOT))).expanduser()
    store_path = Path(os.environ.get("OVERSEER_STORE", str(DEFAULT_STORE))).expanduser()
    try:
        result = ensure_quark_job(project_root, store_path, str(payload.get("session_id") or ""), cwd, assistant_text, dry_run=dry_run)
    except Exception as error:
        print(f"quark_remote_testing_stop_hook: unable to coordinate remote test: {error}", file=sys.stderr)
        return 0
    if dry_run:
        print(json.dumps(result, sort_keys=True))
        return 0
    print(system_message(result), file=sys.stderr)
    return 2


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--from-stdin", action="store_true")
    parser.add_argument("--stop-check", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    payload = read_payload() if args.from_stdin or args.dry_run else {}
    if args.stop_check or args.dry_run:
        return stop_check(payload, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
