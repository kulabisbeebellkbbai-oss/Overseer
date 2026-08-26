#!/usr/bin/env python3
"""Stop hook that lets Quark fulfill explicit remote testing requests."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


DEFAULT_API_URL = "http://127.0.0.1:8766"
DEFAULT_TOKEN_FILE = Path("/home/god/.local/share/overseer/project/state/api-token")
MAX_TOKEN_BYTES = 4096
MAX_API_RESPONSE_BYTES = 1024 * 1024
HOOK_PROMPT_RE = re.compile(r"<hook_prompt\b[^>]*>.*?</hook_prompt>", re.IGNORECASE | re.DOTALL)
EXPLICIT_REMOTE_TEST_RE = re.compile(
    r"("
    r"\b(run|queue|schedule|perform|execute|request|have|use)\b.{0,80}\b(test|tests|testing|regression|smoke|performance|browser|ui|mobile|emulator|avd|android|ios)\b|"
    r"\b(test|tests|testing|regression|smoke|performance|mobile|emulator|avd|android|ios)\b.{0,80}\b(tank|quark|msi|remote|protected\s+gateway|gateway|emulator)\b|"
    r"\b(tank|quark|msi|remote[-\s]?testing|emulator|avd)\b.{0,80}\b(test|tests|testing|regression|smoke|performance|mobile|android|ios)\b|"
    r"\boverseer\.(full_ui_regression|performance_regression)\b|"
    r"\bprotected_gateway\.request_sequence\b"
    r")",
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


def has_explicit_remote_testing_request(user_text: str) -> bool:
    cleaned = strip_hook_prompts(user_text)
    if re.search(r"\b(no remote test|skip remote testing|local-only|not needed)\b", cleaned, re.IGNORECASE):
        return False
    return bool(EXPLICIT_REMOTE_TEST_RE.search(cleaned))


def has_quark_hook_continuation(raw_user_text: str) -> bool:
    return "Quark scheduled coordinated remote testing" in raw_user_text or "Quark remote testing is still pending" in raw_user_text


def needs_quark_testing(user_text: str, assistant_text: str, cwd: str) -> bool:
    if not cwd:
        return False
    if QUARK_EVIDENCE_RE.search(strip_hook_prompts(assistant_text)):
        return False
    return has_explicit_remote_testing_request(user_text)


class OverseerApiError(RuntimeError):
    """A redacted failure to use the local Overseer authority API."""


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _validate_token_metadata(metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise OverseerApiError("API token is not a regular file")
    if metadata.st_nlink != 1:
        raise OverseerApiError("API token file must not be hard-linked")
    if metadata.st_uid != os.geteuid():
        raise OverseerApiError("API token file has an unexpected owner")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise OverseerApiError("API token file must have mode 0600")
    if metadata.st_size > MAX_TOKEN_BYTES:
        raise OverseerApiError("API token file is too large")


def _read_api_token(path: Path) -> str:
    try:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode):
            raise OverseerApiError("API token file must not be a symlink")
        _validate_token_metadata(before)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            _validate_token_metadata(opened)
            if not _same_file(before, opened):
                raise OverseerApiError("API token file changed while opening")
            raw = os.read(descriptor, MAX_TOKEN_BYTES + 1)
            if len(raw) > MAX_TOKEN_BYTES:
                raise OverseerApiError("API token file is too large")
            after = os.fstat(descriptor)
            _validate_token_metadata(after)
            if not _same_file(opened, after) or after.st_size != before.st_size:
                raise OverseerApiError("API token file changed while reading")
            lexical_after = os.lstat(path)
            _validate_token_metadata(lexical_after)
            if not _same_file(before, lexical_after):
                raise OverseerApiError("API token file changed while reading")
        finally:
            os.close(descriptor)
    except OverseerApiError:
        raise
    except OSError as error:
        raise OverseerApiError("API token file could not be safely read") from error
    try:
        token = raw.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise OverseerApiError("API token file is not valid UTF-8") from error
    if not token or any(character.isspace() or ord(character) < 0x20 for character in token):
        raise OverseerApiError("API token is not canonical")
    return token


def _api_base_url() -> str:
    selected = os.environ.get("OVERSEER_API_URL", DEFAULT_API_URL).rstrip("/")
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


def _api_request(path: str, payload: dict[str, object] | None = None) -> dict[str, Any]:
    method = "POST" if payload is not None else "GET"
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    token_path = Path(os.environ.get("OVERSEER_TOKEN_FILE", str(DEFAULT_TOKEN_FILE))).expanduser()
    request = Request(f"{_api_base_url()}{path}", data=body, method=method)
    request.add_header("Accept", "application/json")
    request.add_header("Authorization", f"Bearer {_read_api_token(token_path)}")
    if body is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urlopen(request, timeout=5) as response:
            raw = response.read(MAX_API_RESPONSE_BYTES + 1)
    except HTTPError as error:
        raise OverseerApiError(f"Overseer API rejected {method} {path} with HTTP {error.code}") from error
    except (OSError, URLError) as error:
        raise OverseerApiError(f"Overseer API request failed for {method} {path}") from error
    if len(raw) > MAX_API_RESPONSE_BYTES:
        raise OverseerApiError("Overseer API response is too large")
    try:
        decoded = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OverseerApiError("Overseer API returned invalid JSON") from error
    if not isinstance(decoded, dict):
        raise OverseerApiError("Overseer API returned a non-object response")
    return decoded


def ensure_quark_job(
    session_id: str,
    cwd: str,
    trigger_text: str,
    dry_run: bool = False,
    allow_queue: bool = True,
) -> dict[str, object]:
    name = project_name(cwd)
    suffix = stable_suffix(session_id or "session", cwd)
    lease_id = f"lease.codex-stop.{name.lower()}.{suffix}"
    gateway_path = project_gateway_path(name)
    job_type = job_type_for(trigger_text, name)
    status = _api_request("/usage/remote-testing")
    existing_lease = next((item for item in status["leases"] if item.get("lease_id") == lease_id), None)
    if existing_lease and existing_lease.get("last_job_id"):
        results = _api_request("/usage/remote-testing/results", {"lease_id": lease_id})
        if results["result_count"]:
            return {"action": "collected", "lease_id": lease_id, "job_type": job_type, "results": results["results"]}
        pending = [job for job in status["pending_jobs"] + status["claimed_jobs"] if job.get("lease_id") == lease_id]
        if pending:
            return {"action": "waiting", "lease_id": lease_id, "job_type": job_type, "pending": pending}
    if not allow_queue:
        return {"action": "noop", "lease_id": lease_id, "job_type": job_type, "reason": "no existing requested test job"}
    if dry_run:
        return {"action": "would_queue", "lease_id": lease_id, "job_type": job_type, "gateway_path": gateway_path}
    _api_request(
        "/usage/remote-testing/leases",
        {
            "lease_id": lease_id,
            "project": name,
            "purpose": "Quark coordinated explicitly requested remote testing",
            "requested_by": "quark",
            "job_types": [job_type],
            "priority": "normal",
        },
    )
    params: dict[str, object] = {"scheduled_by": "quark-stop-hook", "validation_stage": "requested-remote-testing"}
    if job_type == "protected_gateway.request_sequence":
        params["requests"] = [{"label": "health", "method": "GET", "path": "/health"}]
    job = _api_request(
        "/usage/remote-testing/jobs",
        {
            "lease_id": lease_id,
            "job_type": job_type,
            "requested_by": "quark",
            "project": name,
            "params": params,
            "base_url": os.environ.get("OVERSEER_REMOTE_TEST_BASE_URL", "https://roadex.home.arpa:9443"),
            "ui_path": f"{gateway_path}/ui",
            "gateway_path": gateway_path,
            "token_source": "state/api-token",
            "mutates": False,
        },
    )
    crew_id = f"crew.quark.remote-testing-final.{name.lower()}.{suffix}"
    _api_request(
        "/crew/messages",
        {
            "message_id": crew_id,
            "owner_domain": "quark",
            "subject": "Coordinate requested remote testing",
            "message": (
                f"Queued {job_type} for {name} after explicit thread request; "
                "collect redacted result and continue the thread."
            ),
            "priority": "medium",
            "requested_by": name,
            "related_resource_id": "remote-testing.tank-msi",
        },
    )
    return {"action": "queued", "lease_id": lease_id, "job_type": job_type, "job": job["job"], "crew_message_id": crew_id}


def system_message(result: dict[str, object]) -> str:
    action = result.get("action")
    if action == "collected":
        return (
            "Quark remote testing evidence collected for requested test. "
            f"Lease `{result.get('lease_id')}` results: {json.dumps(result.get('results'), sort_keys=True)}. "
            "Update the final answer with the redacted result summary and continue."
        )
    if action == "waiting":
        return (
            "Quark remote testing is still pending for requested test. "
            f"Lease `{result.get('lease_id')}`, job type `{result.get('job_type')}`, pending: "
            f"{json.dumps(result.get('pending'), sort_keys=True)}. Continue by collecting results when available."
        )
    if action == "noop":
        return "Quark remote testing listener found no requested test job to collect."
    return (
        "Quark scheduled requested coordinated remote testing. "
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
    raw_user_text = "\n".join(text for role, text in entries if role == "user" and text)
    user_text = strip_hook_prompts(raw_user_text)
    assistant_text = strip_hook_prompts("\n".join(text for role, text in entries if role == "assistant" and text))
    cwd = str(payload.get("cwd") or "")
    explicit_request = needs_quark_testing(user_text, assistant_text, cwd)
    hook_continuation = has_quark_hook_continuation(raw_user_text)
    if not explicit_request and not hook_continuation:
        return 0
    try:
        result = ensure_quark_job(
            str(payload.get("session_id") or ""),
            cwd,
            "\n".join([user_text, assistant_text]),
            dry_run=dry_run,
            allow_queue=explicit_request,
        )
    except Exception as error:
        print(
            "quark_remote_testing_stop_hook: unable to coordinate requested remote test through Overseer: "
            f"{type(error).__name__}",
            file=sys.stderr,
        )
        return 2
    if dry_run:
        print(json.dumps(result, sort_keys=True))
        return 0
    if result.get("action") == "noop":
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
