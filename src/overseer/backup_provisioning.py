"""Approval-gated DonutHole encrypted-backup provisioning contract.

The module is source-only by default. Host mutation is possible only through an
explicitly injected adapter implementing the exact dedicated operations below.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Callable, Mapping, Protocol

from .crew import CrewMessageStatus, CrewReviewStatus
from .core import OwnerDomain
from .store import SQLiteStore

PLAN_KIND = "donuthole_encrypted_backup_provisioning_v1"
SYSTEM_USER = "donuthole-backup"
SOURCE_PATH = "/home/god/Documents/Codex Workspace/DonutHole"
ADAPTER_SOURCE_PATH = "/home/god/Documents/Codex Workspace/TheUnderdark"
BACKUP_PATH = "/var/lib/codex-development-backups/donuthole"
KEY_DIRECTORY = "/etc/codex-development-backups/keys"
KEY_PATH = f"{KEY_DIRECTORY}/donuthole.gpg-passphrase"
CONFIG_PATH = "/etc/codex-development-backups/donuthole.json"
UNIT_NAME = "theunderdark-donuthole.service"
USER_UNIT_NAME = "theunderdark-mcp.service"
UNIT_PATH = f"/etc/systemd/system/{UNIT_NAME}"
GPG_PATH = "/usr/bin/gpg"
EXECUTABLE_PATH = "/opt/theunderdark/.venv/bin/theunderdark-production"
STATE_PATH = f"{BACKUP_PATH}/state"
ARTIFACT_PATH = f"{BACKUP_PATH}/artifacts"
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8799
OVERSEER_BASE_URL = "http://127.0.0.1:8766"
RETENTION_COUNT = 3
REQUIRED_EVIDENCE = {
    "kira": OwnerDomain.KIRA,
    "obrien": OwnerDomain.OBRIEN,
    "security": OwnerDomain.ODO_IDS,
    "sisko": OwnerDomain.SISKO,
}
OPAQUE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


class ProvisioningStatus(StrEnum):
    STAGED = "staged"
    APPROVED = "approved"
    EXECUTED = "executed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass(frozen=True)
class ProvisioningStep:
    operation: str
    arguments: Mapping[str, object]


@dataclass(frozen=True)
class DonutHoleBackupProvisioningPlan:
    plan_id: str
    gpg_sha256: str
    adapter_commit: str
    runtime_digest: str
    capability_digest: str
    root_authorization_refs: Mapping[str, str]
    root_registrations: tuple[Mapping[str, object], ...]
    overseer_token_source_file: str
    overseer_token_file: str
    cursor_key_file: str
    evidence_ids: Mapping[str, str]
    steps: tuple[ProvisioningStep, ...]
    rollback_steps: tuple[ProvisioningStep, ...]
    plan_digest: str
    config_digest: str
    unit_digest: str
    status: ProvisioningStatus = ProvisioningStatus.STAGED
    kind: str = PLAN_KIND
    system_user: str = SYSTEM_USER
    source_path: str = SOURCE_PATH
    source_access: str = "read_only_acl"
    backup_path: str = BACKUP_PATH
    backup_mode: int = 0o700
    key_directory: str = KEY_DIRECTORY
    key_path: str = KEY_PATH
    config_path: str = CONFIG_PATH
    key_mode: int = 0o600
    gpg_path: str = GPG_PATH
    retention_count: int = RETENTION_COUNT
    unit_path: str = UNIT_PATH
    read_only_paths: tuple[str, ...] = (SOURCE_PATH, CONFIG_PATH, KEY_PATH)
    read_write_paths: tuple[str, ...] = (ARTIFACT_PATH, STATE_PATH)
    approved_by: str | None = None
    approved_at: str | None = None
    executed_at: str | None = None
    evidence_digest: str | None = None


class ProvisioningAdapter(Protocol):
    def execute(self, step: ProvisioningStep) -> Mapping[str, object]: ...


class DedicatedProvisioningAdapter:
    """Dispatch only named syscalls with exact argument maps; never a shell."""

    def __init__(self, operations: Mapping[str, Callable[[Mapping[str, object]], Mapping[str, object]]]):
        self._operations = dict(operations)

    def execute(self, step: ProvisioningStep) -> Mapping[str, object]:
        operation = self._operations.get(step.operation)
        if operation is None:
            raise ValueError("provisioning operation is not allowlisted")
        result = operation(dict(step.arguments))
        if not isinstance(result, Mapping):
            raise ValueError("provisioning operation result is invalid")
        return dict(result)


class AllowlistedHostProvisioningAdapter:
    """Privilege-gated host adapter for the exact immutable plan, with no shell API.

    Concrete syscall handlers are injected by the privileged launcher so this
    library cannot silently acquire authority. Every step must byte-for-byte
    match a forward or rollback step in the approved plan.
    """

    def __init__(self, plan: DonutHoleBackupProvisioningPlan, handlers: Mapping[str, Callable[[Mapping[str, object]], Mapping[str, object]]], *, privileged: bool = False):
        if not privileged:
            raise PermissionError("explicit privileged provisioning authorization is required")
        self._allowed = tuple((*plan.steps, *plan.rollback_steps)); self._handlers = dict(handlers)

    def execute(self, step: ProvisioningStep) -> Mapping[str, object]:
        if step not in self._allowed or step.operation not in self._handlers:
            raise ValueError("host provisioning step is not an exact allowlisted plan operation")
        result = self._handlers[step.operation](dict(step.arguments))
        if not isinstance(result, Mapping): raise ValueError("host provisioning result is invalid")
        return dict(result)


def build_plan(plan_id: str, gpg_sha256: str, adapter_commit: str, runtime_digest: str, capability_digest: str, root_authorization_refs: Mapping[str, str], root_registrations: tuple[Mapping[str, object], ...], overseer_token_source_file: str, overseer_token_file: str, cursor_key_file: str, evidence_ids: Mapping[str, str]) -> DonutHoleBackupProvisioningPlan:
    private_paths = (overseer_token_file, cursor_key_file)
    refs_valid = bool(root_authorization_refs) and all(_digest(key) and isinstance(value, str) and OPAQUE_ID.fullmatch(value) for key, value in root_authorization_refs.items())
    paths_valid = all(isinstance(path, str) and path.startswith(KEY_DIRECTORY + "/") and ".." not in path.split("/") for path in private_paths) and len(set(private_paths)) == 2
    registrations_valid = bool(root_registrations) and all(_valid_root_registration(item) for item in root_registrations)
    if not OPAQUE_ID.fullmatch(plan_id) or not _digest(gpg_sha256) or not re.fullmatch(r"[0-9a-f]{40}", adapter_commit) or not _digest(runtime_digest) or not _digest(capability_digest) or not refs_valid or not registrations_valid or not isinstance(overseer_token_source_file, str) or not overseer_token_source_file.startswith("/") or overseer_token_source_file in private_paths or not paths_valid or set(evidence_ids) != set(REQUIRED_EVIDENCE):
        raise ValueError("exact plan, published source, capability, GPG identity, and evidence roles are required")
    if any(not isinstance(value, str) or not OPAQUE_ID.fullmatch(value) for value in evidence_ids.values()):
        raise ValueError("evidence IDs must be opaque identifiers")
    unit = {
        "user": SYSTEM_USER,
        "exec_start": (EXECUTABLE_PATH, "serve", "--config", CONFIG_PATH),
        "read_only_paths": (SOURCE_PATH, CONFIG_PATH, KEY_PATH, overseer_token_file, cursor_key_file),
        "read_write_paths": (ARTIFACT_PATH, STATE_PATH),
        "umask": "0077",
        "private_tmp": True,
        "private_state": True,
        "protect_system": "strict",
        "protect_home": "read-only",
        "no_new_privileges": True,
        "restrict_address_families": ("AF_UNIX", "AF_INET"),
    }
    config = {
        "host": LISTEN_HOST, "port": LISTEN_PORT, "state_dir": STATE_PATH,
        "journal_path": f"{STATE_PATH}/journal.sqlite3", "admission_path": f"{STATE_PATH}/admission.sqlite3",
        "pagination_path": f"{STATE_PATH}/pagination.sqlite3", "registry_path": f"{STATE_PATH}/registry.sqlite3",
        "overseer_authorization_endpoint": f"{OVERSEER_BASE_URL}/storage/authorizations/verify",
        "overseer_root_endpoint": f"{OVERSEER_BASE_URL}/storage/roots/verify",
        "overseer_token_file": overseer_token_file,
        "cursor_key_file": cursor_key_file,
        "root_authorization_refs": dict(root_authorization_refs),
        "limits": {"max_storage_bytes": 1073741824, "max_concurrent_operations": 1, "max_requests_per_window": 12, "rate_window_seconds": 3600, "lease_seconds": 300},
        "backup_bindings": [{"project_id": "project.donuthole", "root_id": "backup-root", "policy_revision": "1", "source_root": SOURCE_PATH, "artifact_dir": ARTIFACT_PATH, "passphrase_file": KEY_PATH, "gpg_executable": GPG_PATH}],
    }
    config_digest = _object_digest(config); unit_digest = _object_digest(unit)
    steps = (
        ProvisioningStep("verify_published_adapter_source", {"path": ADAPTER_SOURCE_PATH, "commit": adapter_commit, "capability_digest": capability_digest}),
        ProvisioningStep("install_runtime", {"source": ADAPTER_SOURCE_PATH, "commit": adapter_commit, "runtime_digest": runtime_digest, "destination": "/opt/theunderdark", "owner": "root", "immutable": True}),
        ProvisioningStep("verify_endpoint_migration_ready", {"host": LISTEN_HOST, "port": LISTEN_PORT, "forbid_simultaneous_user_and_system_service": True}),
        ProvisioningStep("ensure_system_user", {"name": SYSTEM_USER, "home": "/nonexistent", "shell": "/usr/sbin/nologin"}),
        ProvisioningStep("ensure_directory", {"path": BACKUP_PATH, "mode": 0o700, "owner": SYSTEM_USER}),
        ProvisioningStep("ensure_directory", {"path": ARTIFACT_PATH, "mode": 0o700, "owner": SYSTEM_USER}),
        ProvisioningStep("ensure_directory", {"path": STATE_PATH, "mode": 0o700, "owner": SYSTEM_USER}),
        ProvisioningStep("ensure_directory", {"path": KEY_DIRECTORY, "mode": 0o700, "owner": SYSTEM_USER}),
        ProvisioningStep("generate_secret_file", {"path": KEY_PATH, "mode": 0o600, "owner": SYSTEM_USER, "bytes": 48, "return_value": False}),
        ProvisioningStep("install_overseer_api_token", {"source_path": overseer_token_source_file, "destination_path": overseer_token_file, "mode": 0o600, "owner": SYSTEM_USER, "return_value": False}),
        ProvisioningStep("generate_cursor_key", {"path": cursor_key_file, "mode": 0o600, "owner": SYSTEM_USER, "bytes": 32, "return_value": False}),
        ProvisioningStep("ensure_read_only_acl", {"path": SOURCE_PATH, "principal": SYSTEM_USER, "permissions": "r-X"}),
        ProvisioningStep("install_private_config", {"path": CONFIG_PATH, "mode": 0o600, "owner": SYSTEM_USER, "config": config, "config_digest": config_digest}),
        ProvisioningStep("register_authorized_roots", {"tool": "underdark_root_register", "authorization_endpoint": f"{OVERSEER_BASE_URL}/storage/roots/verify", "registrations": tuple(dict(item) for item in root_registrations), "token_file": overseer_token_file}),
        ProvisioningStep("stop_disable_user_service", {"unit": USER_UNIT_NAME, "scope": "user"}),
        ProvisioningStep("install_systemd_unit", {"path": UNIT_PATH, "unit": UNIT_NAME, "properties": unit, "unit_digest": unit_digest}),
        ProvisioningStep("start_enable_system_service", {"unit": UNIT_NAME, "scope": "system"}),
        ProvisioningStep("verify_mcp_service", {"url": f"http://{LISTEN_HOST}:{LISTEN_PORT}/mcp", "capability_digest": capability_digest, "required_tools": ("underdark_backup_create", "underdark_backup_verify_restore")}),
        ProvisioningStep("update_codex_url_if_changed", {"url": f"http://{LISTEN_HOST}:{LISTEN_PORT}/mcp", "only_if_changed": True}),
        ProvisioningStep("verify_gpg_identity", {"path": GPG_PATH, "sha256": gpg_sha256}),
        ProvisioningStep("verify_backup_policy", {"retention": RETENTION_COUNT, "plaintext_archive": False, "restore_required": True}),
    )
    rollback = (
        ProvisioningStep("stop_disable_system_service", {"unit": UNIT_NAME, "scope": "system"}),
        ProvisioningStep("remove_systemd_unit", {"path": UNIT_PATH, "unit": UNIT_NAME}),
        ProvisioningStep("restore_enable_user_service", {"unit": USER_UNIT_NAME, "scope": "user", "only_if_previously_enabled": True}),
        ProvisioningStep("remove_private_config", {"path": CONFIG_PATH}),
        ProvisioningStep("remove_read_only_acl", {"path": SOURCE_PATH, "principal": SYSTEM_USER}),
        ProvisioningStep("remove_cursor_key_if_unreferenced", {"path": cursor_key_file}),
        ProvisioningStep("remove_overseer_api_token", {"path": overseer_token_file}),
        ProvisioningStep("remove_secret_file_if_no_backups", {"path": KEY_PATH, "artifact_dir": ARTIFACT_PATH}),
        ProvisioningStep("remove_directory_if_empty", {"path": KEY_DIRECTORY}),
        ProvisioningStep("remove_directory_if_empty", {"path": STATE_PATH}),
        ProvisioningStep("remove_directory_if_empty", {"path": ARTIFACT_PATH}),
        ProvisioningStep("remove_directory_if_empty", {"path": BACKUP_PATH}),
        ProvisioningStep("remove_system_user_if_unused", {"name": SYSTEM_USER}),
        ProvisioningStep("remove_runtime_if_unreferenced", {"path": "/opt/theunderdark", "runtime_digest": runtime_digest}),
    )
    plan = DonutHoleBackupProvisioningPlan(plan_id, gpg_sha256, adapter_commit, runtime_digest, capability_digest, dict(root_authorization_refs), tuple(dict(item) for item in root_registrations), overseer_token_source_file, overseer_token_file, cursor_key_file, dict(evidence_ids), steps, rollback, "", config_digest, unit_digest, read_only_paths=(SOURCE_PATH, CONFIG_PATH, KEY_PATH, overseer_token_file, cursor_key_file))
    return replace(plan, plan_digest=_plan_digest(plan))


def stage_plan(store_path: str, plan: DonutHoleBackupProvisioningPlan) -> Mapping[str, object]:
    _validate_plan(plan)
    with SQLiteStore(store_path) as store:
        _initialize(store)
        for role, domain in REQUIRED_EVIDENCE.items():
            message = store.load_crew_message(plan.evidence_ids[role])
            if message.owner_domain != domain or message.status != CrewMessageStatus.ACKNOWLEDGED or message.review_status != CrewReviewStatus.APPROVED or message.decided_by != domain.value or not message.decided_at:
                raise ValueError(f"terminal approved {role} evidence is required")
        payload = _dump(plan)
        existing = store._connection.execute("SELECT payload FROM backup_provisioning_plans WHERE id=?", (plan.plan_id,)).fetchone()
        if existing and str(existing["payload"]) != payload:
            raise ValueError("provisioning plan ID is immutable")
        store._connection.execute("INSERT OR IGNORE INTO backup_provisioning_plans VALUES (?,?)", (plan.plan_id, payload)); store._commit()
    return _public(plan, mutation=True)


def list_plans(store_path: str) -> Mapping[str, object]:
    with SQLiteStore(store_path) as store:
        _initialize(store)
        plans = [_load(str(row["payload"])) for row in store._connection.execute("SELECT payload FROM backup_provisioning_plans ORDER BY id")]
    return {"ok": True, "items": [_public(plan, mutation=False) for plan in plans], "mutation_performed": False, "host_mutation_performed": False}


def approve_plan(store_path: str, plan_id: str, approved_by: str, approved_at: str | None = None) -> Mapping[str, object]:
    now = approved_at or datetime.now(UTC).isoformat(); _time(now)
    with SQLiteStore(store_path) as store:
        plan = _stored(store, plan_id)
        evidence_actors = set(REQUIRED_EVIDENCE) | {domain.value for domain in REQUIRED_EVIDENCE.values()}
        if plan.status != ProvisioningStatus.STAGED or not approved_by.strip() or approved_by in evidence_actors:
            raise ValueError("independent human approval is required")
        approved = replace(plan, status=ProvisioningStatus.APPROVED, approved_by=approved_by, approved_at=now)
        store._connection.execute("UPDATE backup_provisioning_plans SET payload=? WHERE id=?", (_dump(approved), plan_id)); store._commit()
    return _public(approved, mutation=True)


def execute_plan(store_path: str, plan_id: str, adapter: ProvisioningAdapter | None = None, executed_at: str | None = None) -> Mapping[str, object]:
    if adapter is None:
        raise ValueError("an explicit dedicated provisioning adapter is required")
    now = executed_at or datetime.now(UTC).isoformat(); _time(now)
    with SQLiteStore(store_path) as store:
        plan = _stored(store, plan_id); _validate_plan(plan)
        if plan.status != ProvisioningStatus.APPROVED or not plan.approved_by or not plan.approved_at:
            raise ValueError("the exact provisioning plan requires independent human approval")
        evidence = []
        try:
            for expected in plan.steps:
                result = adapter.execute(expected)
                evidence.append({"operation": expected.operation, "ok": result.get("ok") is True})
                if result.get("ok") is not True:
                    raise ValueError("provisioning step failed")
        except Exception:
            rollback_evidence = []
            for rollback in reversed(plan.rollback_steps):
                try:
                    result = adapter.execute(rollback)
                    rollback_evidence.append({"operation": rollback.operation, "ok": result.get("ok") is True})
                except Exception:
                    rollback_evidence.append({"operation": rollback.operation, "ok": False})
            rolled_back = all(item["ok"] for item in rollback_evidence)
            digest = "sha256:" + hashlib.sha256(json.dumps({"execute": evidence, "rollback": rollback_evidence}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            failed = replace(plan, status=ProvisioningStatus.ROLLED_BACK if rolled_back else ProvisioningStatus.FAILED, executed_at=now, evidence_digest=digest)
            store._connection.execute("UPDATE backup_provisioning_plans SET payload=? WHERE id=?", (_dump(failed), plan_id)); store._commit()
            raise
        evidence_digest = "sha256:" + hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        complete = replace(plan, status=ProvisioningStatus.EXECUTED, executed_at=now, evidence_digest=evidence_digest)
        store._connection.execute("UPDATE backup_provisioning_plans SET payload=? WHERE id=?", (_dump(complete), plan_id)); store._commit()
    return _public(complete, mutation=True, host_mutation=True)


def stage_plan_api(store_path: str, payload: Mapping[str, object]) -> Mapping[str, object]:
    required = {"plan_id", "gpg_sha256", "adapter_commit", "runtime_digest", "capability_digest", "root_authorization_refs", "root_registrations", "overseer_token_source_file", "overseer_token_file", "cursor_key_file", "evidence_ids"}
    if set(payload) != required or not isinstance(payload.get("root_authorization_refs"), Mapping) or not isinstance(payload.get("root_registrations"), list) or not isinstance(payload.get("evidence_ids"), Mapping):
        raise ValueError("exact backup provisioning stage fields are required")
    plan = build_plan(str(payload["plan_id"]), str(payload["gpg_sha256"]), str(payload["adapter_commit"]), str(payload["runtime_digest"]), str(payload["capability_digest"]), payload["root_authorization_refs"], tuple(payload["root_registrations"]), str(payload["overseer_token_source_file"]), str(payload["overseer_token_file"]), str(payload["cursor_key_file"]), payload["evidence_ids"])
    return stage_plan(store_path, plan)


def approve_plan_api(store_path: str, payload: Mapping[str, object]) -> Mapping[str, object]:
    if set(payload) != {"plan_id", "approved_by"}: raise ValueError("exact backup provisioning approval fields are required")
    return approve_plan(store_path, str(payload["plan_id"]), str(payload["approved_by"]))


def execute_plan_api(store_path: str, payload: Mapping[str, object], adapter_factory: Callable[[DonutHoleBackupProvisioningPlan], ProvisioningAdapter] | None = None) -> Mapping[str, object]:
    if set(payload) != {"plan_id", "privileged_confirmation"} or payload.get("privileged_confirmation") != "execute-exact-donuthole-backup-provisioning-plan":
        raise ValueError("exact privileged provisioning confirmation is required")
    if adapter_factory is None: raise ValueError("privileged host adapter is not configured")
    with SQLiteStore(store_path) as store: plan = _stored(store, str(payload["plan_id"]))
    return execute_plan(store_path, plan.plan_id, adapter_factory(plan))


def _validate_plan(plan: DonutHoleBackupProvisioningPlan) -> None:
    rebuilt = build_plan(plan.plan_id, plan.gpg_sha256, plan.adapter_commit, plan.runtime_digest, plan.capability_digest, plan.root_authorization_refs, plan.root_registrations, plan.overseer_token_source_file, plan.overseer_token_file, plan.cursor_key_file, plan.evidence_ids)
    if plan.kind != PLAN_KIND or plan.plan_digest != rebuilt.plan_digest or _plan_digest(plan) != plan.plan_digest:
        raise ValueError("provisioning plan contract or digest does not match")


def _plan_digest(plan: DonutHoleBackupProvisioningPlan) -> str:
    payload = asdict(plan); payload.pop("plan_digest"); payload.pop("status"); payload.pop("approved_by"); payload.pop("approved_at"); payload.pop("executed_at"); payload.pop("evidence_digest")
    return "sha256:" + hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _initialize(store: SQLiteStore) -> None:
    store._connection.execute("CREATE TABLE IF NOT EXISTS backup_provisioning_plans(id TEXT PRIMARY KEY,payload TEXT NOT NULL)"); store._commit()


def _stored(store: SQLiteStore, plan_id: str) -> DonutHoleBackupProvisioningPlan:
    _initialize(store); row = store._connection.execute("SELECT payload FROM backup_provisioning_plans WHERE id=?", (plan_id,)).fetchone()
    if not row: raise KeyError(plan_id)
    return _load(str(row["payload"]))


def _dump(plan: DonutHoleBackupProvisioningPlan) -> str:
    return json.dumps(asdict(plan), sort_keys=True, separators=(",", ":"))


def _load(payload: str) -> DonutHoleBackupProvisioningPlan:
    data = json.loads(payload); data["status"] = ProvisioningStatus(data["status"]); data["steps"] = tuple(ProvisioningStep(item["operation"], item["arguments"]) for item in data["steps"]); data["rollback_steps"] = tuple(ProvisioningStep(item["operation"], item["arguments"]) for item in data["rollback_steps"]); data["read_only_paths"] = tuple(data["read_only_paths"]); data["read_write_paths"] = tuple(data["read_write_paths"])
    return DonutHoleBackupProvisioningPlan(**data)


def _public(plan: DonutHoleBackupProvisioningPlan, *, mutation: bool, host_mutation: bool = False) -> Mapping[str, object]:
    return {"ok": True, "plan_id": plan.plan_id, "kind": plan.kind, "plan_digest": plan.plan_digest, "status": plan.status.value, "approval_required": plan.status == ProvisioningStatus.STAGED, "approved_by": plan.approved_by, "evidence_ids": dict(plan.evidence_ids), "evidence_digest": plan.evidence_digest, "rollback_operations": [step.operation for step in plan.rollback_steps], "redactions_applied": True, "mutation_performed": mutation, "host_mutation_performed": host_mutation}


def _digest(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def _object_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _valid_root_registration(value: object) -> bool:
    required = {"project_id", "root_id", "policy_revision", "host_path", "alias", "max_bytes", "authorization_ref"}
    if not isinstance(value, Mapping) or set(value) != required: return False
    opaque = (value["project_id"], value["root_id"], value["policy_revision"], value["alias"], value["authorization_ref"])
    return all(isinstance(item, str) and OPAQUE_ID.fullmatch(item) for item in opaque) and isinstance(value["host_path"], str) and value["host_path"].startswith("/") and isinstance(value["max_bytes"], int) and not isinstance(value["max_bytes"], bool) and value["max_bytes"] > 0


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None: raise ValueError("timezone is required")
    return parsed.astimezone(UTC)


__all__ = ["DonutHoleBackupProvisioningPlan", "DedicatedProvisioningAdapter", "AllowlistedHostProvisioningAdapter", "ProvisioningStep", "ProvisioningStatus", "build_plan", "stage_plan", "list_plans", "approve_plan", "execute_plan", "stage_plan_api", "approve_plan_api", "execute_plan_api"]
