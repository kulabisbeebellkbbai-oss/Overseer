"""One-shot, human-authorized attestation of one legacy Psychlo round binding."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import secrets
import shlex
from datetime import timezone
from typing import Any, Mapping

from .admin import AdminChangeKind, plan_psychlo_legacy_round_reconciliation
from .core import ApprovalLevel, OwnerDomain, RiskLevel
from .psychlo_contracts import canonical_digest
from .psychlo_store import PsychloBridgeStore
from .store import SQLiteStore


SCHEMA = "psychlo.legacy-round-binding-attestation.v1"
SOURCE_COMMIT_RE = {40, 64}
_JOURNAL_SCHEMA = "psychlo.original-invocation-journal.v1"
_UNIT_NAME = "overseer-api.service"
_BINDING_FIELDS = ("conversationId", "sessionId", "rolloutPathDigest", "rolloutDev", "rolloutIno")
_LEGACY_PREPARE_ENV = (
    "OVERSEER_PSYCHLO_BRIDGE_DATABASE",
    "OVERSEER_PSYCHLO_PROJECT_BINDINGS_FILE",
    "OVERSEER_STORE_DATABASE",
)


class LegacyBindingAttestationError(ValueError):
    """Raised when one-shot legacy binding evidence cannot be admitted."""


def admin_plan_digest(plan: Any) -> str:
    value = asdict(plan) if is_dataclass(plan) else dict(plan)
    return canonical_digest(_json_safe(value))


def attestation_manifest_digest(manifest: Mapping[str, Any]) -> str:
    """Digest the evidence manifest while avoiding the plan-digest cycle."""
    value = json.loads(json.dumps(manifest))
    approval = value.get("approval")
    if isinstance(approval, dict):
        approval.pop("planDigest", None)
    return canonical_digest(value)


def attest_legacy_round_binding(bridge: Any, round_id: str, manifest_path: str | Path) -> dict[str, Any]:
    """Admit one immutable legacy binding after all evidence is revalidated."""
    if not isinstance(round_id, str) or not round_id.strip():
        raise LegacyBindingAttestationError("round ID is required")
    manifest, manifest_digest = _load_manifest(Path(manifest_path), round_id)
    approval_store = getattr(bridge, "approval_store", None)
    if approval_store is None:
        raise LegacyBindingAttestationError("primary approval store is required")
    request_record = bridge.store.get_round(round_id)
    if request_record is None:
        raise LegacyBindingAttestationError("round is missing")
    request, receipt, _, capability, state, result, _ = request_record
    timing = bridge.store.round_timing(round_id)
    _require_round_and_receipt(request, receipt, round_id, manifest, timing.get("startedAt") if isinstance(timing, Mapping) else None)
    if state != "started" or result is not None:
        raise LegacyBindingAttestationError("only one started result-less round can be attested")
    if not isinstance(capability, str) or not capability:
        raise LegacyBindingAttestationError("round callback capability is missing")
    _verify_human_plan(approval_store, manifest, round_id, manifest_digest)
    _verify_source_lineage(bridge, manifest)
    binding_file = manifest["bindingFile"]
    binding_bytes, binding_meta = _secure_read(Path(binding_file["path"]), binding_file, private=True)
    config = _parse_binding_config(binding_bytes)
    lead = request["projectLeadId"]
    lead_map = binding_file["leadToConversation"]
    if set(config) != set(lead_map) or any(config[key] != lead_map[key] for key in config) or lead not in config:
        raise LegacyBindingAttestationError("binding file lead mapping is not exact")
    dispatcher = bridge.dispatcher
    dispatcher_bindings = getattr(dispatcher, "bindings", None)
    if dispatcher_bindings is not None and _binding_map(dispatcher_bindings) != lead_map:
        raise LegacyBindingAttestationError("dispatcher configuration digest parity failed")
    binding_loader = getattr(dispatcher, "binding_provenance", None)
    scanner = getattr(dispatcher, "scan_rollout", None)
    if not callable(binding_loader) or not callable(scanner):
        raise LegacyBindingAttestationError("dispatcher provenance and full rollout scanner are required")
    binding = _require_binding_provenance(binding_loader(lead), lead_map[lead])
    prompt = bridge._round_prompt(request, capability)
    scan = _require_scan(scanner(lead, prompt))
    if scan["found"] or scan["binding"] != binding:
        raise LegacyBindingAttestationError("exact prompt delivery proof exists or rollout identity changed")
    invocation = _verify_journal_evidence(bridge, manifest, manifest["startedAt"])
    primary_path = getattr(getattr(bridge, "approval_store", None), "path", None)
    effective_systemd_query = getattr(bridge, "systemd_query", None)
    if not callable(effective_systemd_query):
        effective_systemd_query = None
    systemd_files = _verify_systemd_evidence(manifest["systemd"], binding_file["path"], str(bridge.store.filename), str(primary_path) if primary_path is not None else None, effective_query=effective_systemd_query)
    _require_evidence_before_invocation(binding_meta, invocation["startedAt"])
    for metadata in systemd_files:
        _require_evidence_before_invocation(metadata, invocation["startedAt"])
    # Revalidate all mutable external evidence immediately before the single
    # SQLite transaction.  A changed config, conversation identity, or rollout
    # invalidates the migration rather than being repaired.
    binding_again = _require_binding_provenance(binding_loader(lead), lead_map[lead])
    scan_again = _require_scan(scanner(lead, prompt))
    if binding_again != binding or scan_again["found"] or scan_again["binding"] != binding:
        raise LegacyBindingAttestationError("legacy binding evidence changed during attestation")
    systemd_files_again = _verify_systemd_evidence(manifest["systemd"], binding_file["path"], str(bridge.store.filename), str(primary_path) if primary_path is not None else None, effective_query=effective_systemd_query)
    if systemd_files_again != systemd_files:
        raise LegacyBindingAttestationError("systemd evidence changed during attestation")
    _verify_evidence_stable(binding_file, manifest["systemd"], binding_meta, systemd_files, manifest["journalEvidence"], invocation["journalMetadata"])
    existing = bridge.store.round_binding_attestation(round_id)
    if existing is not None:
        expected = {"schemaVersion": SCHEMA, "manifestDigest": manifest_digest, "manifest": manifest, "binding": binding}
        if existing.get("manifestDigest") != manifest_digest or existing.get("attestation") != expected:
            raise LegacyBindingAttestationError("existing attestation identity does not match")
        # A successful retry returns the exact previously committed outcome;
        # it never attempts the conditional migration again.
        return {"accepted": True, "roundId": round_id, "binding": binding, "attestation": existing}
    return bridge.store.migrate_legacy_round_binding(
        round_id,
        request,
        receipt,
        capability,
        binding,
        {"schemaVersion": SCHEMA, "manifestDigest": manifest_digest, "manifest": manifest, "binding": binding},
        now=bridge.clock(),
    )


def _load_manifest(path: Path, round_id: str) -> tuple[dict[str, Any], str]:
    expected = {"schemaVersion", "attestationId", "roundId", "requestDigest", "startedAt", "bindingFile", "systemd", "invocationId", "bootId", "journalEvidence", "approval", "attestationSourceCommit", "sourceTreeDigest"}
    value, _ = _secure_read(path, None, private=True)
    try:
        manifest = json.loads(value.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LegacyBindingAttestationError("attestation manifest is invalid") from error
    if not isinstance(manifest, dict) or set(manifest) != expected or manifest.get("schemaVersion") != SCHEMA or manifest.get("roundId") != round_id:
        raise LegacyBindingAttestationError("attestation manifest identity is invalid")
    digest = attestation_manifest_digest(manifest)
    if not isinstance(manifest.get("attestationSourceCommit"), str) or len(manifest["attestationSourceCommit"]) not in SOURCE_COMMIT_RE or any(char not in "0123456789abcdef" for char in manifest["attestationSourceCommit"].lower()):
        raise LegacyBindingAttestationError("attestationSourceCommit is invalid")
    if not isinstance(manifest.get("sourceTreeDigest"), str) or len(manifest["sourceTreeDigest"]) not in SOURCE_COMMIT_RE:
        raise LegacyBindingAttestationError("source tree digest is invalid")
    if not isinstance(manifest.get("invocationId"), str) or not manifest["invocationId"].strip() or not isinstance(manifest.get("bootId"), str) or not manifest["bootId"].strip():
        raise LegacyBindingAttestationError("invocation identity is invalid")
    if not isinstance(manifest.get("requestDigest"), str) or len(manifest["requestDigest"]) != 64:
        raise LegacyBindingAttestationError("attestation request digest is invalid")
    return manifest, digest


def _secure_read(path: Path, expected: Mapping[str, Any] | None, *, private: bool) -> tuple[bytes, dict[str, Any]]:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise LegacyBindingAttestationError("attested path must be absolute")
    parent_fd = _open_parent(path.parent)
    try:
        parent_before = os.fstat(parent_fd)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except OSError as error:
        os.close(parent_fd)
        raise LegacyBindingAttestationError("attested file cannot be opened safely") from error
    try:
        before = _file_metadata(fd, path)
        if not stat.S_ISREG(before["mode"]) or before["size"] > 256 * 1024:
            raise LegacyBindingAttestationError("attested file is not a bounded regular file")
        if private and (before["uid"] != os.getuid() or before["mode_bits"] & 0o077):
            raise LegacyBindingAttestationError("attestation file is not owner-only")
        if not _mode_is_safe(before, private=private):
            raise LegacyBindingAttestationError("attested file is writable by an unsafe group or other")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        content = b"".join(chunks)
        after = _file_metadata(fd, path)
        parent_after = os.fstat(parent_fd)
        if (parent_before.st_dev, parent_before.st_ino, parent_before.st_mode, parent_before.st_uid) != (parent_after.st_dev, parent_after.st_ino, parent_after.st_mode, parent_after.st_uid) or before != after or hashlib.sha256(content).hexdigest() != (expected or {}).get("digest", hashlib.sha256(content).hexdigest()):
            raise LegacyBindingAttestationError("attested file changed or digest does not match")
        if expected is not None:
            for key in ("path", "dev", "ino", "size", "btime", "mtime", "ctime"):
                if expected.get(key) != before[key]:
                    raise LegacyBindingAttestationError("attested file metadata does not match")
        return content, before
    finally:
        os.close(fd)
        os.close(parent_fd)


def _open_parent(path: Path) -> int:
    if not path.is_absolute():
        raise LegacyBindingAttestationError("attested parent must be absolute")
    flags = getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW
    current = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            nxt = os.open(component, flags, dir_fd=current)
            metadata = os.fstat(nxt)
            writable_parent = metadata.st_mode & 0o002 or ((metadata.st_mode & 0o020) and not _private_group_is_safe(metadata.st_gid))
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid not in {os.getuid(), 0} or writable_parent:
                os.close(nxt)
                raise LegacyBindingAttestationError("attested parent provenance is unsafe")
            os.close(current)
            current = nxt
        return current
    except Exception:
        os.close(current)
        raise


def _file_metadata(fd: int, path: Path) -> dict[str, Any]:
    value = os.fstat(fd)
    return {"path": str(path), "mode": value.st_mode, "mode_bits": stat.S_IMODE(value.st_mode), "uid": value.st_uid, "gid": value.st_gid, "dev": value.st_dev, "ino": value.st_ino, "size": value.st_size, "btime": int(getattr(value, "st_birthtime_ns", 0) or 0), "mtime": value.st_mtime_ns, "ctime": value.st_ctime_ns}


def _private_group_is_safe(gid: int) -> bool:
    """Return true only for the euid's private primary group."""
    try:
        if gid != os.getgid():
            return False
        owner = pwd.getpwuid(os.getuid()).pw_name
        group = grp.getgrgid(gid)
        if any(name != owner for name in group.gr_mem):
            return False
        return all(entry.pw_name == owner or entry.pw_gid != gid for entry in pwd.getpwall())
    except (KeyError, OSError):
        return False


def _mode_is_safe(metadata: Mapping[str, Any], *, private: bool) -> bool:
    bits = int(metadata["mode_bits"])
    if bits & 0o002:
        return False
    if bits & 0o020 and not _private_group_is_safe(int(metadata.get("gid", os.getgid()))):
        return False
    if private and bits & 0o077:
        return False
    return True


def _parse_binding_config(content: bytes) -> dict[str, str]:
    try:
        value = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LegacyBindingAttestationError("binding configuration is invalid") from error
    if not isinstance(value, dict):
        raise LegacyBindingAttestationError("binding configuration is invalid")
    result = _binding_map(value)
    if not result:
        raise LegacyBindingAttestationError("binding configuration is empty")
    return result


def _binding_map(value: Mapping[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for lead, record in value.items():
        if not isinstance(lead, str) or not isinstance(record, Mapping) or not isinstance(record.get("conversationId"), str) or not record["conversationId"].strip():
            raise LegacyBindingAttestationError("binding configuration mapping is invalid")
        result[lead] = record["conversationId"]
    return result


def _require_rollout_binding(value: Any, conversation_id: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_BINDING_FIELDS) or value.get("conversationId") != conversation_id:
        raise LegacyBindingAttestationError("rollout provenance is invalid")
    if any(not isinstance(value[field], str) or not value[field].strip() for field in _BINDING_FIELDS[:3]) or not re.fullmatch(r"[0-9a-f]{64}", value["rolloutPathDigest"]) or isinstance(value["rolloutDev"], bool) or isinstance(value["rolloutIno"], bool) or not isinstance(value["rolloutDev"], int) or not isinstance(value["rolloutIno"], int) or value["rolloutDev"] <= 0 or value["rolloutIno"] <= 0:
        raise LegacyBindingAttestationError("rollout provenance is invalid")
    return dict(value)


def _require_binding_provenance(value: Any, conversation_id: str) -> dict[str, Any]:
    """Validate the dispatcher provenance envelope before identity parsing.

    ``CodexProjectDispatcher.rollout_provenance`` returns a deliberately
    typed lookup envelope.  A missing, true, or non-boolean ``found`` value is
    not equivalent to an absent rollout and must fail closed.  Strip the
    envelope marker only after validating that it is exactly the supported
    negative state; the five identity fields remain closed-world validated by
    ``_require_rollout_binding``.
    """
    if not isinstance(value, Mapping) or "found" not in value or value.get("found") is not False:
        raise LegacyBindingAttestationError("rollout provenance lookup is invalid")
    identity = dict(value)
    identity.pop("found", None)
    return _require_rollout_binding(identity, conversation_id)


def _require_scan(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"found", "conversationId", "sessionId", "rolloutPathDigest", "rolloutDev", "rolloutIno"}:
        raise LegacyBindingAttestationError("rollout scan evidence is invalid")
    binding = _require_rollout_binding({key: value[key] for key in _BINDING_FIELDS}, str(value["conversationId"]))
    if not isinstance(value["found"], bool):
        raise LegacyBindingAttestationError("rollout scan evidence is invalid")
    return {"found": value["found"], "binding": binding}


def _require_round_and_receipt(request: Mapping[str, Any], receipt: Mapping[str, Any], round_id: str, manifest: Mapping[str, Any], started_at: str | None) -> None:
    digest = hashlib.sha256(json.dumps(dict(request), ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    if request.get("roundId") != round_id or digest != manifest["requestDigest"] or receipt.get("status") != "accepted":
        raise LegacyBindingAttestationError("manifest does not bind the exact round request")
    if receipt != {**dict(request), "sourceId": request.get("projectLeadId"), "provenanceId": receipt.get("provenanceId"), "status": "accepted"}:
        raise LegacyBindingAttestationError("stored round receipt is invalid")
    if receipt.get("provenanceId") is None:
        raise LegacyBindingAttestationError("stored round receipt is invalid")
    if not isinstance(started_at, str) or manifest["startedAt"] != started_at:
        raise LegacyBindingAttestationError("manifest started timestamp is invalid")


def _parse_time(value: Any, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as error:
        raise LegacyBindingAttestationError(f"{label} is invalid") from error
    if parsed.tzinfo is None:
        raise LegacyBindingAttestationError(f"{label} must include timezone")
    return parsed


def _validate_journal_export(export: Any, invocation_id: str, boot_id: str, started_at: str) -> tuple[dict[str, Any], dict[str, Any], datetime, datetime]:
    """Apply the closed journal record/order/span contract before staging."""
    if not isinstance(export, Mapping) or set(export) != {"format", "invocationId", "bootId", "userUnit", "records"} or export.get("format") != _JOURNAL_SCHEMA or export.get("invocationId") != invocation_id or export.get("bootId") != boot_id or export.get("userUnit") != _UNIT_NAME:
        raise LegacyBindingAttestationError("journal evidence identity is invalid")
    records = export["records"]
    if not isinstance(records, list) or len(records) < 2 or any(not isinstance(item, Mapping) for item in records):
        raise LegacyBindingAttestationError("journal evidence records are invalid")
    expected = {"cursor", "realtime", "monotonic", "pid", "unit", "messageDigest", "invocationId", "bootId", "userUnit"}
    for entry in records:
        if set(entry) != expected or entry["invocationId"] != invocation_id or entry["bootId"] != boot_id or entry["userUnit"] != _UNIT_NAME or entry["unit"] != _UNIT_NAME or not isinstance(entry["cursor"], str) or not entry["cursor"].strip() or isinstance(entry["monotonic"], bool) or not isinstance(entry["monotonic"], int) or entry["monotonic"] < 0 or isinstance(entry["pid"], bool) or not isinstance(entry["pid"], int) or entry["pid"] <= 0 or not isinstance(entry["messageDigest"], str) or not re.fullmatch(r"[0-9a-f]{64}", entry["messageDigest"]):
            raise LegacyBindingAttestationError("journal entry identity is invalid")
        _parse_time(entry["realtime"], "journal realtime")
    ordered = sorted(records, key=lambda item: (item["monotonic"], item["realtime"], item["cursor"]))
    if ordered != records or len({item["cursor"] for item in ordered}) != len(ordered):
        raise LegacyBindingAttestationError("journal records are not in immutable order")
    started, ended = ordered[0], ordered[-1]
    if started["monotonic"] >= ended["monotonic"]:
        raise LegacyBindingAttestationError("journal invocation span is invalid")
    start_time = _parse_time(started["realtime"], "journal started realtime")
    end_time = _parse_time(ended["realtime"], "journal ended realtime")
    round_time = _parse_time(started_at, "round startedAt")
    if not start_time <= round_time <= end_time:
        raise LegacyBindingAttestationError("journal invocation does not span dispatch")
    return dict(started), dict(ended), start_time, end_time


def _verify_journal_evidence(bridge: Any, manifest: Mapping[str, Any], started_at: str) -> dict[str, Any]:
    evidence = manifest["journalEvidence"]
    evidence_fields = {"path", "digest", "dev", "ino", "size", "btime", "mtime", "ctime", "format", "started", "ended"}
    producer_metadata_fields = {"mode", "mode_bits", "uid", "gid"}
    if not isinstance(evidence, Mapping) or (set(evidence) != evidence_fields and set(evidence) != evidence_fields | producer_metadata_fields) or evidence["format"] != _JOURNAL_SCHEMA:
        raise LegacyBindingAttestationError("journal evidence is invalid")
    journal_bytes, journal_metadata = _secure_read(Path(evidence["path"]), evidence, private=True)
    try:
        export = json.loads(journal_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LegacyBindingAttestationError("journal evidence export is invalid") from error
    started, ended, start_time, end_time = _validate_journal_export(export, str(manifest["invocationId"]), str(manifest["bootId"]), started_at)
    if dict(manifest["journalEvidence"]["started"]) != dict(started) or dict(manifest["journalEvidence"]["ended"]) != dict(ended):
        raise LegacyBindingAttestationError("manifest journal boundaries are not authoritative")
    runner = getattr(bridge, "journal_runner", None)
    if not callable(runner):
        runner = _direct_journal_query
    authoritative = runner(manifest["invocationId"], manifest["bootId"], _UNIT_NAME)
    if authoritative != export:
        raise LegacyBindingAttestationError("direct journal query does not match retained evidence")
    return {"startedAt": start_time, "endedAt": end_time, "startedMonotonic": started["monotonic"], "endedMonotonic": ended["monotonic"], "journalMetadata": journal_metadata}


def _direct_journal_query(invocation_id: str, boot_id: str, unit: str) -> dict[str, Any]:
    """Read a root-managed, JSON journal export with a minimal environment."""
    completed = subprocess.run(
        ("/usr/bin/journalctl", "--user", "--output=json", "--no-pager", "--quiet", "_SYSTEMD_INVOCATION_ID=" + invocation_id, "_BOOT_ID=" + boot_id, "_SYSTEMD_USER_UNIT=" + unit),
        check=False, capture_output=True, text=True, stdin=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C", "LANG": "C"},
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise LegacyBindingAttestationError("direct journal query failed")
    records = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
    records_out = []
    for record in records:
        if not isinstance(record, Mapping):
            continue
        raw_realtime = record.get("__REALTIME_TIMESTAMP")
        raw_monotonic = record.get("__MONOTONIC_TIMESTAMP")
        try:
            realtime = datetime.fromtimestamp(int(raw_realtime) / 1_000_000, tz=timezone.utc).isoformat()
            monotonic = int(raw_monotonic)
            record_pid = int(record.get("_PID"))
        except (TypeError, ValueError, OverflowError):
            raise LegacyBindingAttestationError("journal query record has invalid time or PID") from None
        message = record.get("MESSAGE", "")
        if not isinstance(message, str):
            message = json.dumps(message, sort_keys=True, separators=(",", ":"))
        records_out.append({"cursor": record.get("__CURSOR"), "realtime": realtime, "monotonic": monotonic, "pid": record_pid, "unit": record.get("_SYSTEMD_USER_UNIT") or record.get("_SYSTEMD_UNIT"), "messageDigest": hashlib.sha256(message.encode("utf-8")).hexdigest(), "invocationId": record.get("_SYSTEMD_INVOCATION_ID"), "bootId": record.get("_BOOT_ID"), "userUnit": record.get("_SYSTEMD_USER_UNIT")})
    if len(records_out) < 2:
        raise LegacyBindingAttestationError("journal query export does not carry enough authoritative records")
    return {"format": _JOURNAL_SCHEMA, "invocationId": invocation_id, "bootId": boot_id, "userUnit": unit, "records": records_out}


def _effective_systemd_query(unit: str = _UNIT_NAME) -> dict[str, Any]:
    """Read the effective loaded user unit, not merely its static files."""
    uid = os.getuid()
    runtime_dir = Path(f"/run/user/{uid}")
    try:
        runtime_info = runtime_dir.stat()
        if not stat.S_ISDIR(runtime_info.st_mode) or runtime_info.st_uid != uid or runtime_info.st_mode & 0o077:
            raise OSError("unsafe user runtime directory")
        bus_path = runtime_dir / "bus"
        bus_info = bus_path.lstat()
        # The per-user D-Bus socket is conventionally mode 0666; its trusted
        # owner and the private runtime directory are the identity boundary.
        if not stat.S_ISSOCK(bus_info.st_mode) or bus_info.st_uid != uid:
            raise OSError("unsafe user bus socket")
    except OSError as error:
        raise LegacyBindingAttestationError("user systemd runtime is not safe") from error
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C", "LANG": "C", "XDG_RUNTIME_DIR": str(runtime_dir), "DBUS_SESSION_BUS_ADDRESS": f"unix:path={bus_path}"}
    properties = ("FragmentPath", "DropInPaths", "ExecStart", "Environment", "WorkingDirectory")
    completed = subprocess.run(
        ("/usr/bin/systemctl", "--user", "show", unit, "--no-pager", "--no-legend", *("--property=" + name for name in properties)),
        check=False, capture_output=True, text=True, stdin=subprocess.DEVNULL, env=env,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise LegacyBindingAttestationError("effective systemd configuration cannot be queried")
    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        if "=" not in line:
            raise LegacyBindingAttestationError("effective systemd configuration is invalid")
        key, raw = line.split("=", 1)
        if key not in properties or key in values:
            raise LegacyBindingAttestationError("effective systemd configuration is invalid")
        values[key] = raw
    if set(values) != set(properties):
        raise LegacyBindingAttestationError("effective systemd configuration is incomplete")
    try:
        exec_value = values["ExecStart"].strip()
        if exec_value.startswith("{ "):
            match = re.search(r"(?:^|; )argv\[\]=(.*?)(?: ; ignore_errors=|; ignore_errors=)", exec_value)
            if match is None:
                raise ValueError
            exec_argv = shlex.split(match.group(1).strip())
        else:
            exec_argv = shlex.split(exec_value)
        dropins = shlex.split(values["DropInPaths"]) if values["DropInPaths"].strip() else []
        environment_tokens = shlex.split(values["Environment"]) if values["Environment"].strip() else []
        environment: dict[str, str] = {}
        for token in environment_tokens:
            if "=" not in token:
                raise ValueError
            key, env_value = token.split("=", 1)
            if not key or key in environment:
                raise ValueError
            environment[key] = env_value
    except (ValueError, OSError) as error:
        raise LegacyBindingAttestationError("effective systemd configuration is invalid") from error
    return {"fragmentPath": values["FragmentPath"], "dropInPaths": dropins, "execStart": exec_argv, "environment": environment, "workingDirectory": values["WorkingDirectory"]}


def _verify_systemd_evidence(value: Mapping[str, Any], binding_path: str, bridge_db_path: str, primary_db_path: str | None = None, *, effective_query: Any = None) -> list[dict[str, Any]]:
    if set(value) != {"unit", "dropIn"}:
        raise LegacyBindingAttestationError("systemd evidence is invalid")
    contents: dict[str, str] = {}
    metadata: list[dict[str, Any]] = []
    for name, item in value.items():
        if not isinstance(item, Mapping) or set(item) != {"path", "digest", "dev", "ino", "size", "btime", "mtime", "ctime", "identity"} or not isinstance(item["identity"], str) or not item["identity"].strip():
            raise LegacyBindingAttestationError("systemd evidence is invalid")
        if name == "unit" and item["identity"] != _UNIT_NAME:
            raise LegacyBindingAttestationError("systemd unit identity is not overseer-api.service")
        if name == "dropIn" and not item["identity"].startswith(_UNIT_NAME + ".d/"):
            raise LegacyBindingAttestationError("systemd drop-in identity is unrelated")
        if name == "unit" and Path(item["path"]).name != _UNIT_NAME:
            raise LegacyBindingAttestationError("systemd FragmentPath is not overseer-api.service")
        if name == "dropIn" and Path(item["path"]).parent.name != _UNIT_NAME + ".d":
            raise LegacyBindingAttestationError("systemd DropInPaths directory is unrelated")
        content, info = _secure_read(Path(item["path"]), item, private=False)
        contents[item["identity"]] = content.decode("utf-8", errors="strict")
        metadata.append(info)
    unit = contents.get(_UNIT_NAME)
    if unit is None:
        raise LegacyBindingAttestationError("systemd unit identity is not overseer-api.service")
    unit_exec = [line.split("=", 1)[1].strip() for line in unit.splitlines() if line.startswith("ExecStart=")]
    working_directory = [line.split("=", 1)[1].strip() for line in unit.splitlines() if line.startswith("WorkingDirectory=")]
    if len(unit_exec) != 1:
        raise LegacyBindingAttestationError("systemd ExecStart is not the reviewed overseer-api source")
    try:
        argv = shlex.split(unit_exec[0])
    except ValueError as error:
        raise LegacyBindingAttestationError("systemd ExecStart is not the reviewed overseer-api source") from error
    if len(argv) < 4 or not Path(argv[0]).is_absolute() or argv[1:4] != ["-m", "overseer.cli", "serve-api"]:
        raise LegacyBindingAttestationError("systemd ExecStart is not the reviewed overseer-api source")
    _trusted_executable(Path(argv[0]))
    if primary_db_path is not None:
        store_indices = [index for index, token in enumerate(argv) if token == "--store"]
        if len(store_indices) != 1 or store_indices[0] + 1 >= len(argv):
            raise LegacyBindingAttestationError("systemd ExecStart primary store path is missing or conflicting")
        reviewed_store = _require_existing_store(Path(primary_db_path))
        command_store = _require_existing_store(Path(argv[store_indices[0] + 1]))
        if (reviewed_store["dev"], reviewed_store["ino"]) != (command_store["dev"], command_store["ino"]):
            raise LegacyBindingAttestationError("systemd ExecStart primary store identity is conflicting")
    assignments: dict[str, list[str]] = {}
    for identity, text in contents.items():
        if identity != _UNIT_NAME and any(line.startswith("ExecStart=") for line in text.splitlines()):
            raise LegacyBindingAttestationError("systemd drop-in contains an unreviewed ExecStart override")
        for line in text.splitlines():
            if line.startswith("Environment="):
                try:
                    tokens = shlex.split(line[len("Environment="):])
                except ValueError as error:
                    raise LegacyBindingAttestationError("systemd Environment assignment is invalid") from error
                for assignment in tokens:
                    if "=" not in assignment:
                        raise LegacyBindingAttestationError("systemd Environment assignment is invalid")
                    key, assigned = assignment.split("=", 1)
                    assignments.setdefault(key, []).append(assigned)
    expected_bind = str(Path(binding_path))
    expected_db = str(Path(bridge_db_path))
    # systemd expands %h in the installed drop-in; the manifest must contain
    # the absolute expansion so a conflicting assignment cannot hide behind it.
    for key, expected in (("OVERSEER_PSYCHLO_PROJECT_BINDINGS_FILE", expected_bind), ("OVERSEER_PSYCHLO_BRIDGE_DATABASE", expected_db)):
        values = assignments.get(key, [])
        if len(values) != 1 or values[0].replace("%h", str(Path.home())) != expected:
            raise LegacyBindingAttestationError("systemd Psychlo path assignment is missing or conflicting")
    if primary_db_path is not None:
        _require_existing_store(Path(primary_db_path))
    source_root = Path(__file__).resolve().parents[2]
    if len(working_directory) != 1 or Path(working_directory[0]).resolve(strict=True) != source_root.resolve(strict=True):
        raise LegacyBindingAttestationError("systemd WorkingDirectory is not the reviewed source root")
    python_paths = assignments.get("PYTHONPATH", [])
    if len(python_paths) != 1 or Path(python_paths[0].replace("%h", str(Path.home()))).resolve(strict=True) != (source_root / "src").resolve(strict=True):
        raise LegacyBindingAttestationError("systemd PYTHONPATH is not the reviewed source root")
    dropin_dir = Path(next(item["path"] for name, item in value.items() if name == "dropIn")).parent
    try:
        entries = list(dropin_dir.iterdir())
    except OSError as error:
        raise LegacyBindingAttestationError("systemd DropInPaths cannot be enumerated") from error
    reviewed_dropin = Path(value["dropIn"]["path"]).resolve(strict=True)
    for entry in entries:
        if entry.suffix != ".conf":
            continue
        try:
            entry_metadata = os.lstat(entry)
        except OSError as error:
            raise LegacyBindingAttestationError("systemd DropInPaths changed during evidence collection") from error
        if stat.S_ISLNK(entry_metadata.st_mode) or not stat.S_ISREG(entry_metadata.st_mode) or entry_metadata.st_uid not in {os.getuid(), 0} or entry_metadata.st_mode & 0o022 or entry.resolve(strict=True) != reviewed_dropin:
            raise LegacyBindingAttestationError("systemd DropInPaths contain an unreviewed override")
    effective = effective_query(_UNIT_NAME) if callable(effective_query) else _effective_systemd_query(_UNIT_NAME)
    if not isinstance(effective, Mapping) or set(effective) != {"fragmentPath", "dropInPaths", "execStart", "environment", "workingDirectory"}:
        raise LegacyBindingAttestationError("effective systemd configuration is invalid")
    if Path(str(effective["fragmentPath"])).resolve(strict=True) != Path(value["unit"]["path"]).resolve(strict=True):
        raise LegacyBindingAttestationError("effective systemd FragmentPath conflicts with reviewed unit")
    effective_dropins = [str(Path(path).resolve(strict=True)) for path in effective["dropInPaths"]]
    if effective_dropins != [str(reviewed_dropin)]:
        raise LegacyBindingAttestationError("effective systemd DropInPaths contain an unreviewed override")
    if list(effective["execStart"]) != argv:
        raise LegacyBindingAttestationError("effective systemd ExecStart conflicts with reviewed unit")
    if Path(str(effective["workingDirectory"])).resolve(strict=True) != source_root.resolve(strict=True):
        raise LegacyBindingAttestationError("effective systemd WorkingDirectory is not the reviewed source root")
    effective_environment = effective["environment"]
    if not isinstance(effective_environment, Mapping):
        raise LegacyBindingAttestationError("effective systemd Environment is invalid")
    expected_environment: dict[str, str] = {}
    runtime_credentials = f"/run/user/{os.getuid()}/credentials/{_UNIT_NAME}"
    for key, values in assignments.items():
        if len(values) != 1:
            raise LegacyBindingAttestationError("systemd Environment assignment is conflicting")
        expected_environment[key] = values[0].replace("%h", str(Path.home())).replace("%d", runtime_credentials)
    if set(effective_environment) != set(expected_environment) or any(effective_environment.get(key) != expected for key, expected in expected_environment.items()):
        raise LegacyBindingAttestationError("effective systemd Environment conflicts with reviewed files")
    return metadata


def _require_evidence_before_invocation(metadata: Mapping[str, Any], invocation_start: datetime) -> None:
    for field in ("btime", "ctime", "mtime"):
        value = int(metadata.get(field, 0))
        if value and datetime.fromtimestamp(value / 1_000_000_000, tz=invocation_start.tzinfo) >= invocation_start:
            raise LegacyBindingAttestationError("attested binding or unit file is newer than the original invocation")


def _verify_evidence_stable(binding_file: Mapping[str, Any], systemd: Mapping[str, Any], binding_meta: Mapping[str, Any], systemd_meta: list[Mapping[str, Any]], journal: Mapping[str, Any], journal_meta: Mapping[str, Any]) -> None:
    current_binding, current_binding_meta = _secure_read(Path(binding_file["path"]), binding_file, private=True)
    if current_binding_meta != binding_meta or hashlib.sha256(current_binding).hexdigest() != binding_file["digest"]:
        raise LegacyBindingAttestationError("binding file changed during attestation")
    current_systemd: list[Mapping[str, Any]] = []
    for item in systemd.values():
        _, current = _secure_read(Path(item["path"]), item, private=False)
        current_systemd.append(current)
    if current_systemd != list(systemd_meta):
        raise LegacyBindingAttestationError("systemd evidence changed during attestation")
    _, current_journal_meta = _secure_read(Path(journal["path"]), journal, private=True)
    if current_journal_meta != journal_meta:
        raise LegacyBindingAttestationError("journal evidence changed during attestation")


def _verify_source_lineage(bridge_or_root: Any, manifest: Mapping[str, Any] | str, tree_digest: str | None = None) -> None:
    """Verify reviewed source commit ancestry and exact source-tree identity."""
    if isinstance(manifest, str):
        root = Path(bridge_or_root)
        commit = manifest
        expected_tree = tree_digest
    else:
        root = Path(__file__).resolve().parents[2]
        commit = str(manifest["attestationSourceCommit"])
        expected_tree = str(manifest["sourceTreeDigest"])
    if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", commit) or not isinstance(expected_tree, str) or not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", expected_tree):
        raise LegacyBindingAttestationError("source lineage is invalid")
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_NOGLOBAL": "1", "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C", "LANG": "C"}
    verified = subprocess.run(("/usr/bin/git", "-C", str(root), "rev-parse", "--verify", commit + "^{commit}"), check=False, capture_output=True, text=True, stdin=subprocess.DEVNULL, env=env)
    if verified.returncode or verified.stdout.strip().lower() != commit.lower():
        raise LegacyBindingAttestationError("source commit does not exist")
    head = subprocess.run(("/usr/bin/git", "-C", str(root), "rev-parse", "--verify", "HEAD"), check=False, capture_output=True, text=True, stdin=subprocess.DEVNULL, env=env)
    if head.returncode or head.stdout.strip().lower() != commit.lower():
        raise LegacyBindingAttestationError("attestation source commit is not current HEAD")
    tree = subprocess.run(("/usr/bin/git", "-C", str(root), "rev-parse", "--verify", commit + "^{tree}"), check=False, capture_output=True, text=True, stdin=subprocess.DEVNULL, env=env)
    if tree.returncode or tree.stdout.strip().lower() != expected_tree.lower():
        raise LegacyBindingAttestationError("source tree digest does not match source commit")
    status = subprocess.run(("/usr/bin/git", "-C", str(root), "status", "--porcelain", "--untracked-files=all", "--", "src", "pyproject.toml"), check=False, capture_output=True, text=True, stdin=subprocess.DEVNULL, env=env)
    if status.returncode or status.stdout.strip():
        raise LegacyBindingAttestationError("attestation source tree is dirty")


def _verify_human_plan(store: Any, manifest: Mapping[str, Any], round_id: str, manifest_digest: str) -> None:
    approval = manifest["approval"]
    if set(approval) != {"planId", "planDigest"}:
        raise LegacyBindingAttestationError("approval evidence is invalid")
    try:
        plan = store.load_admin_change_plan(str(approval["planId"]))
    except (KeyError, ValueError) as error:
        raise LegacyBindingAttestationError("approved human authority is missing") from error
    if AdminChangeKind(plan.kind) != AdminChangeKind.PSYCHLO_LEGACY_ROUND_RECONCILIATION or plan.target != round_id or plan.approval_level != ApprovalLevel.HUMAN or plan.risk_level != RiskLevel.HIGH or plan.owner_domain != OwnerDomain.SISKO or not plan.approved or not isinstance(plan.approved_by, str) or not plan.approved_by.strip() or not isinstance(plan.approved_at, str) or not plan.approved_at.strip() or plan.canceled or admin_plan_digest(plan) != approval["planDigest"]:
        raise LegacyBindingAttestationError("approved human plan is not exact")
    metadata = plan.adapter_metadata.get("legacy_round_reconciliation") if isinstance(plan.adapter_metadata, Mapping) else None
    if metadata != {"manifestDigest": manifest_digest, "roundId": round_id, "sourceCommit": manifest["attestationSourceCommit"]}:
        raise LegacyBindingAttestationError("approval plan does not bind the complete attestation manifest")


def _json_safe(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if hasattr(value, "value"):
        return value.value
    return value


def _required_legacy_environment(environment: Mapping[str, str] | None = None) -> dict[str, str]:
    """Load the closed, authoritative environment used by the typed flow."""
    source = dict(environment or os.environ)
    values: dict[str, str] = {}
    for key in _LEGACY_PREPARE_ENV:
        value = source.get(key)
        if not isinstance(value, str) or not value.strip() or not Path(value).is_absolute():
            raise LegacyBindingAttestationError(f"{key} must be an explicit absolute path")
        values[key] = value
    if Path(values["OVERSEER_STORE_DATABASE"]).resolve() == Path(values["OVERSEER_PSYCHLO_BRIDGE_DATABASE"]).resolve():
        raise LegacyBindingAttestationError("authoritative primary store must not be the Psychlo bridge database")
    _require_existing_store(Path(values["OVERSEER_STORE_DATABASE"]))
    values["OVERSEER_STORE_DATABASE"] = str(Path(values["OVERSEER_STORE_DATABASE"]).resolve(strict=True))
    return values


def _trusted_resolve(path: Path) -> Path:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise LegacyBindingAttestationError("trusted path is invalid")
    try:
        resolved = path.resolve(strict=True)
        lexical_prefixes = [Path("/")]
        current = Path("/")
        for component in path.parts[1:]:
            current = current / component
            lexical_prefixes.append(current)
        canonical_prefixes = [Path("/")]
        current = Path("/")
        for component in resolved.parts[1:]:
            current = current / component
            canonical_prefixes.append(current)
        for prefix in lexical_prefixes + canonical_prefixes:
            metadata = os.lstat(prefix)
            if stat.S_ISLNK(metadata.st_mode) and metadata.st_uid not in {os.getuid(), 0}:
                raise LegacyBindingAttestationError("trusted path symlink owner is unsafe")
        _open_parent(resolved.parent)
        return resolved
    except LegacyBindingAttestationError:
        raise
    except OSError as error:
        raise LegacyBindingAttestationError("trusted path cannot be resolved safely") from error


def _require_existing_store(path: Path, *, private: bool = True) -> dict[str, Any]:
    """Validate an existing owner-only primary SQLite file without creating it."""
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise LegacyBindingAttestationError("authoritative primary store path is invalid")
    declared_path = path
    canonical = _trusted_resolve(declared_path)
    parent_fd = _open_parent(canonical.parent)
    try:
        try:
            fd = os.open(canonical.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        except OSError as error:
            raise LegacyBindingAttestationError("authoritative primary store must already exist") from error
        try:
            metadata = _file_metadata(fd, canonical)
            if not stat.S_ISREG(metadata["mode"]) or metadata["uid"] not in {os.getuid(), 0} or not _mode_is_safe(metadata, private=private):
                raise LegacyBindingAttestationError("authoritative primary store identity is unsafe")
            declared_identity = os.stat(declared_path, follow_symlinks=True)
            if (declared_identity.st_dev, declared_identity.st_ino) != (metadata["dev"], metadata["ino"]):
                raise LegacyBindingAttestationError("authoritative primary store identity changed")
            return metadata
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _trusted_executable(path: Path) -> None:
    resolved = _trusted_resolve(path)
    metadata = _require_existing_store(resolved, private=False)
    if metadata["mode_bits"] & 0o111 == 0:
        raise LegacyBindingAttestationError("reviewed service executable is not executable")


def _atomic_create_private(path: Path, content: bytes) -> dict[str, Any]:
    """Create one owner-only file without following symlinks or overwriting."""
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise LegacyBindingAttestationError("attestation output path must be absolute")
    parent_fd = _open_parent(path.parent)
    sync_fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    temporary_name = f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    fd = -1
    try:
        fd = os.open(temporary_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        os.fchmod(fd, 0o600)
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise LegacyBindingAttestationError("attestation output write failed")
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        # link() is atomic and, unlike replace(), refuses an existing target.
        os.link(temporary_name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
        os.unlink(temporary_name, dir_fd=parent_fd)
        os.fsync(sync_fd)
    except FileExistsError as error:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except OSError:
            pass
        raise LegacyBindingAttestationError("attestation output already exists") from error
    except OSError as error:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except OSError:
            pass
        raise LegacyBindingAttestationError("attestation output could not be created safely") from error
    finally:
        os.close(sync_fd)
        os.close(parent_fd)
    _, metadata = _secure_read(path, None, private=True)
    metadata["digest"] = hashlib.sha256(content).hexdigest()
    return metadata


def _atomic_update_manifest(path: Path, manifest: Mapping[str, Any]) -> None:
    """Replace an existing owner-only manifest after a stable identity check."""
    current_bytes, current_meta = _secure_read(path, None, private=True)
    try:
        current = json.loads(current_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LegacyBindingAttestationError("attestation manifest is invalid") from error
    if not isinstance(current, dict) or set(current) != set(manifest):
        raise LegacyBindingAttestationError("attestation manifest changed unexpectedly")
    parent_fd = _open_parent(path.parent)
    sync_fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    temporary_name = f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    fd = -1
    try:
        fd = os.open(temporary_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        payload = json.dumps(dict(manifest), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise LegacyBindingAttestationError("attestation manifest write failed")
            view = view[written:]
        os.fchmod(fd, 0o600)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary_name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(sync_fd)
    except OSError as error:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except OSError:
            pass
        raise LegacyBindingAttestationError("attestation manifest could not be updated safely") from error
    finally:
        os.close(sync_fd)
        os.close(parent_fd)
    _, metadata = _secure_read(path, None, private=True)
    if metadata["uid"] != current_meta["uid"] or metadata["mode_bits"] != current_meta["mode_bits"]:
        raise LegacyBindingAttestationError("attestation manifest ownership changed")


def _create_or_resume_private(path: Path, content: bytes) -> tuple[dict[str, Any], bool]:
    """Resume only an exact prior artifact; altered existing bytes fail closed."""
    if path.exists() or path.is_symlink():
        existing, metadata = _secure_read(path, None, private=True)
        if existing != content:
            raise LegacyBindingAttestationError("existing attestation artifact does not match exact replay")
        metadata["digest"] = hashlib.sha256(existing).hexdigest()
        return metadata, False
    return _atomic_create_private(path, content), True


def _fsync_directory(path: Path) -> None:
    fd = _open_parent(path)
    try:
        sync_fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            os.fsync(sync_fd)
        finally:
            os.close(sync_fd)
    finally:
        os.close(fd)


def _file_evidence(path: Path, *, private: bool) -> tuple[dict[str, Any], bytes]:
    content, metadata = _secure_read(path, None, private=private)
    evidence = {key: metadata[key] for key in ("path", "dev", "ino", "size", "btime", "mtime", "ctime")}
    evidence["digest"] = hashlib.sha256(content).hexdigest()
    return evidence, content


def _source_identity(root: Path) -> tuple[str, str]:
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_NOGLOBAL": "1", "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C", "LANG": "C"}
    commit = subprocess.run(("/usr/bin/git", "-C", str(root), "rev-parse", "--verify", "HEAD"), check=False, capture_output=True, text=True, stdin=subprocess.DEVNULL, env=env)
    tree = subprocess.run(("/usr/bin/git", "-C", str(root), "rev-parse", "--verify", "HEAD^{tree}"), check=False, capture_output=True, text=True, stdin=subprocess.DEVNULL, env=env)
    if commit.returncode or tree.returncode or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit.stdout.strip()) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", tree.stdout.strip()):
        raise LegacyBindingAttestationError("current source identity is unavailable")
    _verify_source_lineage(root, commit.stdout.strip(), tree.stdout.strip())
    return commit.stdout.strip(), tree.stdout.strip()


def prepare_legacy_round_attestation(
    round_id: str, plan_id: str, manifest_path: str | Path, journal_path: str | Path,
    invocation_id: str, boot_id: str, unit_path: str | Path, drop_in_path: str | Path,
    source_root: str | Path, environment: Mapping[str, str] | None = None, reason: str = "approve one immutable legacy Arcade binding attestation",
) -> dict[str, Any]:
    """Derive and persist one unapproved, exact legacy-round attestation plan."""
    env = _required_legacy_environment(environment)
    if not all(isinstance(value, str) and value.strip() for value in (round_id, plan_id, invocation_id, boot_id, reason)):
        raise LegacyBindingAttestationError("legacy attestation identity is required")
    bridge = PsychloBridgeStore(env["OVERSEER_PSYCHLO_BRIDGE_DATABASE"])
    primary = SQLiteStore(env["OVERSEER_STORE_DATABASE"])
    created_journal = False
    created_manifest = False
    try:
        record = bridge.get_round(round_id)
        if record is None:
            raise LegacyBindingAttestationError("round is missing")
        request, receipt, _, capability, state, result, _ = record
        timing = bridge.round_timing(round_id)
        if state != "started" or result is not None or not isinstance(capability, str) or not capability or not isinstance(timing, Mapping) or not isinstance(timing.get("startedAt"), str):
            raise LegacyBindingAttestationError("only one started result-less round can be prepared")
        _require_round_and_receipt(request, receipt, round_id, {"requestDigest": hashlib.sha256(json.dumps(dict(request), ensure_ascii=False, separators=(",", ":")).encode()).hexdigest(), "startedAt": timing["startedAt"]}, timing["startedAt"])
        binding_path = Path(env["OVERSEER_PSYCHLO_PROJECT_BINDINGS_FILE"])
        binding_meta, binding_bytes = _file_evidence(binding_path, private=True)
        lead_map = _parse_binding_config(binding_bytes)
        source_commit, source_tree = _source_identity(Path(source_root))
        invocation_export = _direct_journal_query(invocation_id, boot_id, _UNIT_NAME)
        journal_started, journal_ended, _, _ = _validate_journal_export(invocation_export, invocation_id, boot_id, str(timing["startedAt"]))
        journal_bytes = json.dumps(invocation_export, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        journal_meta, created_journal = _create_or_resume_private(Path(journal_path), journal_bytes)
        unit_meta, _ = _file_evidence(Path(unit_path), private=False)
        dropin_meta, _ = _file_evidence(Path(drop_in_path), private=False)
        journal_evidence = {**journal_meta, "format": _JOURNAL_SCHEMA, "started": journal_started, "ended": journal_ended}
        manifest = {
            "schemaVersion": SCHEMA, "attestationId": f"attestation-{round_id}", "roundId": round_id,
            "requestDigest": hashlib.sha256(json.dumps(dict(request), ensure_ascii=False, separators=(",", ":")).encode()).hexdigest(),
            "startedAt": timing["startedAt"], "bindingFile": {**binding_meta, "leadToConversation": lead_map},
            "systemd": {"unit": {**unit_meta, "identity": _UNIT_NAME}, "dropIn": {**dropin_meta, "identity": f"{_UNIT_NAME}.d/{Path(drop_in_path).name}"}},
            "invocationId": invocation_id, "bootId": boot_id, "journalEvidence": journal_evidence,
            "approval": {"planId": plan_id, "planDigest": ""}, "attestationSourceCommit": source_commit, "sourceTreeDigest": source_tree,
        }
        _verify_systemd_evidence(manifest["systemd"], str(binding_path), env["OVERSEER_PSYCHLO_BRIDGE_DATABASE"], env["OVERSEER_STORE_DATABASE"])
        manifest_digest = attestation_manifest_digest(manifest)
        plan = plan_psychlo_legacy_round_reconciliation(plan_id, round_id, manifest_digest, source_commit, reason)
        # An exact plan/artifact set is a deterministic crash-recovery resume;
        # every other pre-existing record is a conflict and fails closed.
        try:
            existing_plan = primary.load_admin_change_plan(plan_id)
        except KeyError:
            existing_plan = None
        else:
            if existing_plan.kind != plan.kind or existing_plan.target != plan.target or existing_plan.adapter_metadata != plan.adapter_metadata or existing_plan.reason != plan.reason or existing_plan.canceled or admin_plan_digest(existing_plan) != admin_plan_digest(plan):
                raise LegacyBindingAttestationError("legacy attestation plan already exists with conflicting identity")
        manifest_bytes = json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        manifest_meta, created_manifest = _create_or_resume_private(Path(manifest_path), manifest_bytes)
        if existing_plan is None:
            primary.save_admin_change_plan(plan)
            _fsync_directory(Path(primary.path).parent)
        return {"prepared": True, "planId": plan_id, "roundId": round_id, "manifestPath": str(manifest_path), "journalPath": str(journal_path), "manifestDigest": manifest_digest, "manifestMetadata": manifest_meta}
    except Exception as error:
        # Validation failures clean up only this invocation's artifacts.  A
        # non-validation exception may represent a crash after a durable
        # create/save; retain artifacts so the next invocation can validate
        # and resume the exact byte/digest identity.
        if not isinstance(error, LegacyBindingAttestationError):
            raise
        for path, created in ((Path(manifest_path), created_manifest), (Path(journal_path), created_journal)):
            try:
                if created and path.exists() and path.is_file() and not path.is_symlink():
                    path.unlink()
            except OSError:
                pass
        raise
    finally:
        primary.close()
        bridge.close()


def finalize_legacy_round_attestation(plan_id: str, manifest_path: str | Path, environment: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Bind an exact approved plan digest into an existing prepared manifest."""
    env = _required_legacy_environment(environment)
    primary = SQLiteStore(env["OVERSEER_STORE_DATABASE"])
    try:
        path = Path(manifest_path)
        raw, _ = _secure_read(path, None, private=True)
        try:
            manifest = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise LegacyBindingAttestationError("attestation manifest is invalid") from error
        if not isinstance(manifest, dict) or set(manifest) != {"schemaVersion", "attestationId", "roundId", "requestDigest", "startedAt", "bindingFile", "systemd", "invocationId", "bootId", "journalEvidence", "approval", "attestationSourceCommit", "sourceTreeDigest"} or manifest.get("schemaVersion") != SCHEMA:
            raise LegacyBindingAttestationError("attestation manifest identity is invalid")
        approval = manifest.get("approval")
        if not isinstance(approval, dict) or set(approval) != {"planId", "planDigest"} or approval.get("planId") != plan_id or not isinstance(approval.get("planDigest"), str):
            raise LegacyBindingAttestationError("manifest approval identity is invalid")
        already_finalized = bool(approval["planDigest"])
        digest = attestation_manifest_digest(manifest)
        plan = primary.load_admin_change_plan(plan_id)
        if AdminChangeKind(plan.kind) != AdminChangeKind.PSYCHLO_LEGACY_ROUND_RECONCILIATION or plan.target != manifest["roundId"] or plan.approved is not True or not isinstance(plan.approved_by, str) or not plan.approved_by.strip() or not isinstance(plan.approved_at, str) or not plan.approved_at.strip() or plan.canceled or plan.approval_level != ApprovalLevel.HUMAN or plan.risk_level != RiskLevel.HIGH or plan.owner_domain != OwnerDomain.SISKO:
            raise LegacyBindingAttestationError("exact approved human plan is required")
        metadata = plan.adapter_metadata.get("legacy_round_reconciliation") if isinstance(plan.adapter_metadata, Mapping) else None
        if metadata != {"manifestDigest": digest, "roundId": manifest["roundId"], "sourceCommit": manifest["attestationSourceCommit"]}:
            raise LegacyBindingAttestationError("approved plan does not bind this manifest")
        expected_plan_digest = admin_plan_digest(plan)
        if already_finalized:
            if approval["planDigest"] != expected_plan_digest:
                raise LegacyBindingAttestationError("finalized manifest plan digest is not exact")
            return {"finalized": True, "replay": True, "planId": plan_id, "roundId": manifest["roundId"], "manifestPath": str(path), "manifestDigest": digest, "planDigest": expected_plan_digest}
        finalized = json.loads(json.dumps(manifest))
        finalized["approval"]["planDigest"] = expected_plan_digest
        _atomic_update_manifest(path, finalized)
        retained, _ = _secure_read(path, None, private=True)
        after = json.loads(retained.decode("utf-8"))
        if attestation_manifest_digest(after) != digest or after["approval"]["planDigest"] != expected_plan_digest or any(after[key] != manifest[key] for key in manifest if key != "approval"):
            raise LegacyBindingAttestationError("finalized manifest changed outside planDigest")
        return {"finalized": True, "replay": False, "planId": plan_id, "roundId": manifest["roundId"], "manifestPath": str(path), "manifestDigest": digest, "planDigest": expected_plan_digest}
    except KeyError as error:
        raise LegacyBindingAttestationError("approved human plan is missing") from error
    finally:
        primary.close()
