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
from datetime import timezone
from typing import Any, Mapping

from .admin import AdminChangeKind
from .core import ApprovalLevel, OwnerDomain, RiskLevel
from .psychlo_contracts import canonical_digest


SCHEMA = "psychlo.legacy-round-binding-attestation.v1"
SOURCE_COMMIT_RE = {40, 64}
_JOURNAL_SCHEMA = "psychlo.original-invocation-journal.v1"
_UNIT_NAME = "overseer-api.service"
_BINDING_FIELDS = ("conversationId", "sessionId", "rolloutPathDigest", "rolloutDev", "rolloutIno")


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
    binding = _require_rollout_binding(binding_loader(lead), lead_map[lead])
    prompt = bridge._round_prompt(request, capability)
    scan = _require_scan(scanner(lead, prompt))
    if scan["found"] or scan["binding"] != binding:
        raise LegacyBindingAttestationError("exact prompt delivery proof exists or rollout identity changed")
    invocation = _verify_journal_evidence(bridge, manifest, manifest["startedAt"])
    systemd_files = _verify_systemd_evidence(manifest["systemd"], binding_file["path"], str(bridge.store.filename))
    _require_evidence_before_invocation(binding_meta, invocation["startedAt"])
    for metadata in systemd_files:
        _require_evidence_before_invocation(metadata, invocation["startedAt"])
    # Revalidate all mutable external evidence immediately before the single
    # SQLite transaction.  A changed config, conversation identity, or rollout
    # invalidates the migration rather than being repaired.
    binding_again = _require_rollout_binding(binding_loader(lead), lead_map[lead])
    scan_again = _require_scan(scanner(lead, prompt))
    if binding_again != binding or scan_again["found"] or scan_again["binding"] != binding:
        raise LegacyBindingAttestationError("legacy binding evidence changed during attestation")
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
    if any(not isinstance(value[field], str) or not value[field].strip() for field in _BINDING_FIELDS[:3]) or not isinstance(value["rolloutDev"], int) or not isinstance(value["rolloutIno"], int) or value["rolloutDev"] < 0 or value["rolloutIno"] < 0:
        raise LegacyBindingAttestationError("rollout provenance is invalid")
    if not isinstance(value["rolloutPathDigest"], str) or len(value["rolloutPathDigest"]) != 64:
        raise LegacyBindingAttestationError("rollout provenance is invalid")
    return dict(value)


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


def _verify_journal_evidence(bridge: Any, manifest: Mapping[str, Any], started_at: str) -> dict[str, Any]:
    evidence = manifest["journalEvidence"]
    if not isinstance(evidence, Mapping) or set(evidence) != {"path", "digest", "dev", "ino", "size", "btime", "mtime", "ctime", "format", "started", "ended"} or evidence["format"] != _JOURNAL_SCHEMA:
        raise LegacyBindingAttestationError("journal evidence is invalid")
    journal_bytes, journal_metadata = _secure_read(Path(evidence["path"]), evidence, private=True)
    try:
        export = json.loads(journal_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LegacyBindingAttestationError("journal evidence export is invalid") from error
    if not isinstance(export, Mapping) or set(export) != {"format", "invocationId", "bootId", "userUnit", "records"} or export["format"] != _JOURNAL_SCHEMA or export["invocationId"] != manifest["invocationId"] or export["bootId"] != manifest["bootId"] or export["userUnit"] != _UNIT_NAME:
        raise LegacyBindingAttestationError("journal evidence identity is invalid")
    records = export["records"]
    if not isinstance(records, list) or len(records) < 2 or any(not isinstance(item, Mapping) for item in records):
        raise LegacyBindingAttestationError("journal evidence records are invalid")
    expected = {"cursor", "realtime", "monotonic", "pid", "unit", "messageDigest", "invocationId", "bootId", "userUnit"}
    for entry in records:
        if set(entry) != expected or entry["invocationId"] != manifest["invocationId"] or entry["bootId"] != manifest["bootId"] or entry["userUnit"] != _UNIT_NAME or not isinstance(entry["cursor"], str) or not entry["cursor"].strip() or not isinstance(entry["monotonic"], int) or entry["monotonic"] < 0 or not isinstance(entry["pid"], int) or entry["pid"] <= 0 or not isinstance(entry["messageDigest"], str) or not re.fullmatch(r"[0-9a-f]{64}", entry["messageDigest"]):
            raise LegacyBindingAttestationError("journal entry identity is invalid")
        _parse_time(entry["realtime"], "journal realtime")
    ordered = sorted(records, key=lambda item: (item["monotonic"], item["realtime"], item["cursor"]))
    if ordered != records or len({item["cursor"] for item in ordered}) != len(ordered):
        raise LegacyBindingAttestationError("journal records are not in immutable order")
    started = ordered[0]
    ended = ordered[-1]
    if started["monotonic"] >= ended["monotonic"]:
        raise LegacyBindingAttestationError("journal invocation span is invalid")
    if dict(manifest["journalEvidence"]["started"]) != dict(started) or dict(manifest["journalEvidence"]["ended"]) != dict(ended):
        raise LegacyBindingAttestationError("manifest journal boundaries are not authoritative")
    start_time = _parse_time(started["realtime"], "journal started realtime")
    end_time = _parse_time(ended["realtime"], "journal ended realtime")
    round_time = _parse_time(started_at, "round startedAt")
    if not start_time <= round_time <= end_time:
        raise LegacyBindingAttestationError("journal invocation does not span dispatch")
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
        records_out.append({"cursor": record.get("__CURSOR"), "realtime": realtime, "monotonic": monotonic, "pid": record_pid, "unit": record.get("_SYSTEMD_UNIT") or record.get("_SYSTEMD_USER_UNIT"), "messageDigest": hashlib.sha256(message.encode("utf-8")).hexdigest(), "invocationId": record.get("_SYSTEMD_INVOCATION_ID"), "bootId": record.get("_BOOT_ID"), "userUnit": record.get("_SYSTEMD_USER_UNIT")})
    if len(records_out) < 2:
        raise LegacyBindingAttestationError("journal query export does not carry enough authoritative records")
    return {"format": _JOURNAL_SCHEMA, "invocationId": invocation_id, "bootId": boot_id, "userUnit": unit, "records": records_out}


def _verify_systemd_evidence(value: Mapping[str, Any], binding_path: str, bridge_db_path: str) -> list[dict[str, Any]]:
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
        content, info = _secure_read(Path(item["path"]), item, private=False)
        contents[item["identity"]] = content.decode("utf-8", errors="strict")
        metadata.append(info)
    unit = contents.get(_UNIT_NAME)
    if unit is None:
        raise LegacyBindingAttestationError("systemd unit identity is not overseer-api.service")
    unit_exec = [line.split("=", 1)[1].strip() for line in unit.splitlines() if line.startswith("ExecStart=")]
    if len(unit_exec) != 1 or "-m overseer.cli serve-api" not in unit_exec[0]:
        raise LegacyBindingAttestationError("systemd ExecStart is not the reviewed overseer-api source")
    assignments: dict[str, list[str]] = {}
    for text in contents.values():
        for line in text.splitlines():
            if line.startswith("Environment="):
                assignment = line[len("Environment="):]
                if "=" in assignment:
                    key, assigned = assignment.split("=", 1)
                    assignments.setdefault(key, []).append(assigned.strip().strip('"'))
    expected_bind = str(Path(binding_path))
    expected_db = str(Path(bridge_db_path))
    # systemd expands %h in the installed drop-in; the manifest must contain
    # the absolute expansion so a conflicting assignment cannot hide behind it.
    for key, expected in (("OVERSEER_PSYCHLO_PROJECT_BINDINGS_FILE", expected_bind), ("OVERSEER_PSYCHLO_BRIDGE_DATABASE", expected_db)):
        values = assignments.get(key, [])
        if len(values) != 1 or values[0].replace("%h", str(Path.home())) != expected:
            raise LegacyBindingAttestationError("systemd Psychlo path assignment is missing or conflicting")
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
