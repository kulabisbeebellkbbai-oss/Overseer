"""One-shot, human-authorized attestation of one legacy Psychlo round binding."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Mapping

from .admin import AdminChangeKind
from .audit import ApprovalStatus
from .core import ApprovalLevel, RiskLevel
from .psychlo_contracts import canonical_digest


SCHEMA = "psychlo.legacy-round-binding-attestation.v1"
SOURCE_COMMIT_RE = {40, 64}
_BINDING_FIELDS = ("conversationId", "sessionId", "rolloutPathDigest", "rolloutDev", "rolloutIno")


class LegacyBindingAttestationError(ValueError):
    """Raised when one-shot legacy binding evidence cannot be admitted."""


def approval_record_digest(approval: Any) -> str:
    value = {
        "id": approval.id,
        "subjectId": approval.subject_id,
        "approvalLevel": getattr(approval.approval_level, "value", approval.approval_level),
        "requesterThread": approval.requester_thread,
        "ownerDomain": getattr(approval.owner_domain, "value", approval.owner_domain),
        "reason": approval.reason,
        "status": getattr(approval.status, "value", approval.status),
        "evidenceRequired": list(approval.evidence_required),
        "decidedBy": approval.decided_by,
        "decidedAt": approval.decided_at,
    }
    return canonical_digest(value)


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
    binding_file = manifest["bindingFile"]
    binding_bytes, _ = _secure_read(Path(binding_file["path"]), binding_file, private=True)
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
    _verify_invocation_span(manifest["originalInvocation"], manifest["startedAt"])
    _verify_systemd_evidence(manifest["systemd"])
    # Revalidate all mutable external evidence immediately before the single
    # SQLite transaction.  A changed config, conversation identity, or rollout
    # invalidates the migration rather than being repaired.
    binding_again = _require_rollout_binding(binding_loader(lead), lead_map[lead])
    scan_again = _require_scan(scanner(lead, prompt))
    if binding_again != binding or scan_again["found"] or scan_again["binding"] != binding:
        raise LegacyBindingAttestationError("legacy binding evidence changed during attestation")
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
    expected = {"schemaVersion", "attestationId", "roundId", "requestDigest", "startedAt", "bindingFile", "systemd", "originalInvocation", "approval", "sourceCommit"}
    value, _ = _secure_read(path, None, private=True)
    try:
        manifest = json.loads(value.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LegacyBindingAttestationError("attestation manifest is invalid") from error
    if not isinstance(manifest, dict) or set(manifest) != expected or manifest.get("schemaVersion") != SCHEMA or manifest.get("roundId") != round_id:
        raise LegacyBindingAttestationError("attestation manifest identity is invalid")
    digest = attestation_manifest_digest(manifest)
    if not isinstance(manifest.get("sourceCommit"), str) or len(manifest["sourceCommit"]) not in SOURCE_COMMIT_RE or any(char not in "0123456789abcdef" for char in manifest["sourceCommit"].lower()):
        raise LegacyBindingAttestationError("attestation source commit is invalid")
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
        if not private and before["mode_bits"] & 0o022:
            raise LegacyBindingAttestationError("attested system file is writable by group or other")
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
            writable_parent = metadata.st_mode & 0o022 and not (metadata.st_mode & stat.S_ISVTX)
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
    return {"path": str(path), "mode": value.st_mode, "mode_bits": stat.S_IMODE(value.st_mode), "uid": value.st_uid, "dev": value.st_dev, "ino": value.st_ino, "size": value.st_size, "btime": int(getattr(value, "st_birthtime_ns", 0) or 0), "mtime": value.st_mtime_ns, "ctime": value.st_ctime_ns}


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


def _verify_invocation_span(value: Mapping[str, Any], started_at: str) -> None:
    if set(value) != {"startedAt", "endedAt"}:
        raise LegacyBindingAttestationError("original API invocation evidence is invalid")
    try:
        invocation_start = datetime.fromisoformat(str(value["startedAt"]).replace("Z", "+00:00")); invocation_end = datetime.fromisoformat(str(value["endedAt"]).replace("Z", "+00:00")); round_start = datetime.fromisoformat(str(started_at).replace("Z", "+00:00"))
    except ValueError as error:
        raise LegacyBindingAttestationError("original API invocation evidence is invalid") from error
    if invocation_start.tzinfo is None or invocation_end.tzinfo is None or round_start.tzinfo is None or not invocation_start <= round_start <= invocation_end:
        raise LegacyBindingAttestationError("original API invocation does not span dispatch")


def _verify_systemd_evidence(value: Mapping[str, Any]) -> None:
    if set(value) != {"unit", "dropIn"}:
        raise LegacyBindingAttestationError("systemd evidence is invalid")
    for item in value.values():
        if not isinstance(item, Mapping) or set(item) != {"path", "digest", "dev", "ino", "size", "btime", "mtime", "ctime", "identity"} or not isinstance(item["identity"], str) or not item["identity"].strip():
            raise LegacyBindingAttestationError("systemd evidence is invalid")
        _secure_read(Path(item["path"]), item, private=False)


def _verify_human_plan(store: Any, manifest: Mapping[str, Any], round_id: str, manifest_digest: str) -> None:
    approval = manifest["approval"]
    if set(approval) != {"recordId", "recordDigest", "planId", "planDigest"}:
        raise LegacyBindingAttestationError("approval evidence is invalid")
    try:
        record = store.load_approval(str(approval["recordId"]))
        plan = store.load_admin_change_plan(str(approval["planId"]))
    except (KeyError, ValueError) as error:
        raise LegacyBindingAttestationError("approved human authority is missing") from error
    if record.subject_id != approval["planId"] or record.status != ApprovalStatus.APPROVED or record.approval_level != ApprovalLevel.HUMAN or approval_record_digest(record) != approval["recordDigest"]:
        raise LegacyBindingAttestationError("approval record is not exact and approved")
    if AdminChangeKind(plan.kind) != AdminChangeKind.PSYCHLO_LEGACY_ROUND_RECONCILIATION or plan.target != round_id or plan.approval_level != ApprovalLevel.HUMAN or plan.risk_level != RiskLevel.HIGH or not plan.approved or plan.canceled or admin_plan_digest(plan) != approval["planDigest"]:
        raise LegacyBindingAttestationError("legacy reconciliation plan is not approved and exact")
    metadata = plan.adapter_metadata.get("legacy_round_reconciliation") if isinstance(plan.adapter_metadata, Mapping) else None
    if metadata != {"manifestDigest": manifest_digest, "roundId": round_id, "sourceCommit": manifest["sourceCommit"]}:
        raise LegacyBindingAttestationError("approval plan does not bind the complete attestation manifest")


def _json_safe(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if hasattr(value, "value"):
        return value.value
    return value
