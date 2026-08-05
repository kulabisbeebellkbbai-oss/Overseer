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
from .storage_control import current_root_identity, resolve_current_root_authorization

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
    DENIED = "denied"
    REVISION_REQUESTED = "revision_requested"
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
    provisioning_contract_version: str
    runtime_artifact_identity: str
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
    failed_operation: str | None = None
    error_code: str | None = None
    decision_source: str = "Roadex"
    decision_reason: str | None = None
    decided_by: str | None = None
    decided_at: str | None = None


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
    from .backup_contract import PROVISIONING_CONTRACT_VERSION, runtime_artifact_identity
    from .backup_host_operations import EXPECTED_BACKUP_TOOL_SCHEMAS, capability_digest as reviewed_capability_digest

    provisioning_contract_version = PROVISIONING_CONTRACT_VERSION
    planned_runtime_identity = runtime_artifact_identity(adapter_commit, EXPECTED_BACKUP_TOOL_SCHEMAS)
    reviewed_capability = reviewed_capability_digest(adapter_commit, EXPECTED_BACKUP_TOOL_SCHEMAS, provisioning_contract_version)
    # Retained only to keep the existing stage-request call shape. The reviewed
    # contract, never caller input, owns the persisted capability digest.
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
        ProvisioningStep("verify_published_adapter_source", {"path": ADAPTER_SOURCE_PATH, "commit": adapter_commit, "capability_digest": reviewed_capability, "provisioning_contract_version": provisioning_contract_version, "runtime_artifact_identity": planned_runtime_identity}),
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
        ProvisioningStep("verify_mcp_service", {"url": f"http://{LISTEN_HOST}:{LISTEN_PORT}/mcp", "capability_digest": reviewed_capability, "provisioning_contract_version": provisioning_contract_version, "runtime_artifact_identity": planned_runtime_identity, "required_tools": ("underdark_backup_create", "underdark_backup_verify_restore")}),
        ProvisioningStep("verify_codex_url", {"url": f"http://{LISTEN_HOST}:{LISTEN_PORT}/mcp"}),
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
        ProvisioningStep("remove_system_user_if_unused", {"name": SYSTEM_USER, "retained_path": BACKUP_PATH}),
        ProvisioningStep("remove_runtime_if_unreferenced", {"path": "/opt/theunderdark", "runtime_digest": runtime_digest}),
    )
    plan = DonutHoleBackupProvisioningPlan(plan_id, gpg_sha256, adapter_commit, runtime_digest, reviewed_capability, provisioning_contract_version, planned_runtime_identity, dict(root_authorization_refs), tuple(dict(item) for item in root_registrations), overseer_token_source_file, overseer_token_file, cursor_key_file, dict(evidence_ids), steps, rollback, "", config_digest, unit_digest, read_only_paths=(SOURCE_PATH, CONFIG_PATH, KEY_PATH, overseer_token_file, cursor_key_file))
    return replace(plan, plan_digest=_plan_digest(plan))


def stage_plan(store_path: str, plan: DonutHoleBackupProvisioningPlan) -> Mapping[str, object]:
    with SQLiteStore(store_path) as store:
        with store.agent_transaction():
            _stage_plan_locked(store, plan)
    return _public(plan, mutation=True)


def _stage_plan_locked(
    store: SQLiteStore,
    plan: DonutHoleBackupProvisioningPlan,
    *,
    validated: bool = False,
) -> None:
    if not validated:
        _validate_plan(plan)
    _initialize(store)
    for role, domain in REQUIRED_EVIDENCE.items():
        try:
            message = store.load_crew_message(plan.evidence_ids[role])
        except KeyError:
            continue
        if message.owner_domain != domain or message.related_plan_id != plan.plan_id:
            raise ValueError(f"correctly owned {role} evidence is required")
    store.save_backup_provisioning_plan_payload(plan.plan_id, _dump(plan))


def list_plans(store_path: str) -> Mapping[str, object]:
    with SQLiteStore(store_path) as store:
        _initialize(store)
        plans = [_load(str(row["payload"])) for row in store._connection.execute("SELECT payload FROM backup_provisioning_plans ORDER BY id")]
    return {"ok": True, "items": [_public(plan, mutation=False) for plan in plans], "mutation_performed": False, "host_mutation_performed": False}


def list_roadex_human_decisions(store_path: str) -> Mapping[str, object]:
    """Return final human decisions originating in the Roadex workflow."""
    with SQLiteStore(store_path) as store:
        _initialize(store)
        store._connection.execute("BEGIN")
        try:
            plans = [_load(str(row["payload"])) for row in store._connection.execute("SELECT payload FROM backup_provisioning_plans ORDER BY rowid DESC")]
            items = []
            seen_kinds: set[str] = set()
            for plan in plans:
                if plan.decision_source != "Roadex":
                    continue
                if plan.kind in seen_kinds:
                    continue
                seen_kinds.add(plan.kind)
                if plan.status != ProvisioningStatus.STAGED:
                    continue
                blocker_codes: list[str] = []
                failures: list[str] = []
                try:
                    _require_approval_readiness(store, plan)
                except Exception as exc:
                    code, explanation = _approval_blocker(exc)
                    blocker_codes.append(code)
                    failures.append(explanation)
                items.append({
                "id": f"roadex-human-decision.{plan.plan_id}",
                "source": "Roadex",
                "owner": "Sisko",
                "human_approval_required": True,
                "plan_id": plan.plan_id,
                "plan_digest": plan.plan_digest,
                "kind": plan.kind,
                "title": "Provision the DonutHole encrypted backup service",
                "decision": "Approve or reject the exact immutable TheUnderdark provisioning plan for DonutHole.",
                "explanation": "Approval installs a sandboxed system service, registers only the authorized DonutHole backup root, creates private encryption material, and verifies the service and restore policy before reporting completion.",
                "impact": [
                    f"Install the verified runtime under {ADAPTER_SOURCE_PATH} into /opt/theunderdark.",
                    f"Create locked service identity {SYSTEM_USER} with read-only source access.",
                    f"Store encrypted artifacts under {BACKUP_PATH} and listen only on {LISTEN_HOST}:{LISTEN_PORT}.",
                    "Replace the user service with the sandboxed system service after readiness checks.",
                ],
                "risks": [
                    "TheUnderdark may be briefly unavailable during service migration.",
                    "Privileged files, an ACL, credentials, and a system service are created.",
                    "Any failed verification triggers the declared dependency-safe rollback.",
                ],
                "rollback": [step.operation for step in plan.rollback_steps],
                "status": plan.status.value,
                "ready": not failures,
                "blocker_codes": blocker_codes,
                "blockers": failures,
                "decision_reason": plan.decision_reason,
                "decided_by": plan.decided_by or plan.approved_by,
                "decided_at": plan.decided_at or plan.approved_at,
                "evidence_digest": plan.evidence_digest,
                })
        finally:
            store._connection.rollback()
    return {"ok": True, "source": "Roadex", "items": items, "pending_count": sum(item["human_approval_required"] for item in items), "mutation_performed": False, "host_mutation_performed": False}


def decide_roadex_human_plan(
    store_path: str,
    plan_id: str,
    decision: str,
    decided_by: str,
    reason: str,
    adapter_factory: Callable[[DonutHoleBackupProvisioningPlan], ProvisioningAdapter] | None = None,
) -> Mapping[str, object]:
    if decision not in {"approve", "deny", "request_revision"}:
        raise ValueError("decision must be approve, deny, or request_revision")
    if decision in {"deny", "request_revision"} and not reason.strip():
        raise ValueError("a reason is required for denial or revision")
    with SQLiteStore(store_path) as store:
        with store.agent_transaction():
            plan = _stored(store, plan_id)
            if plan.decision_source != "Roadex" or plan.status != ProvisioningStatus.STAGED:
                raise ValueError("an exact staged Roadex human decision is required")
            decided_by = _validate_independent_human(store, plan, decided_by)
            _require_approval_readiness(store, plan)
            if decision != "approve":
                status = ProvisioningStatus.DENIED if decision == "deny" else ProvisioningStatus.REVISION_REQUESTED
                decided = replace(plan, status=status, decision_reason=reason.strip(), decided_by=decided_by.strip(), decided_at=datetime.now(UTC).isoformat())
                store._connection.execute("UPDATE backup_provisioning_plans SET payload=? WHERE id=?", (_dump(decided), plan_id))
                return {"ok": True, "decision": decision, "action_status": status.value, "plan": _public(decided, mutation=True), "mutation_performed": True, "host_mutation_performed": False}
    if adapter_factory is None:
        raise ValueError("privileged host adapter is not configured")
    adapter = adapter_factory(plan)
    approved = approve_plan(store_path, plan_id, decided_by.strip())
    try:
        executed = execute_plan(store_path, plan_id, adapter)
        return {"ok": True, "decision": decision, "action_status": executed["status"], "plan": executed, "approval": approved, "mutation_performed": True, "host_mutation_performed": True}
    except Exception as exc:
        current = next(item for item in list_plans(store_path)["items"] if item["plan_id"] == plan_id)
        return {"ok": False, "decision": decision, "action_status": current["status"], "plan": current, "error": type(exc).__name__, "mutation_performed": True, "host_mutation_performed": current["status"] in {"failed", "rolled_back"}}


def decide_roadex_human_plan_api(store_path: str, payload: Mapping[str, object], adapter_factory=None) -> Mapping[str, object]:
    if set(payload) != {"plan_id", "decision", "decided_by", "reason"}:
        raise ValueError("exact Roadex human decision fields are required")
    return decide_roadex_human_plan(store_path, str(payload["plan_id"]), str(payload["decision"]), str(payload["decided_by"]), str(payload["reason"]), adapter_factory)


def approve_plan(store_path: str, plan_id: str, approved_by: str, approved_at: str | None = None) -> Mapping[str, object]:
    now = approved_at or datetime.now(UTC).isoformat(); _time(now)
    with SQLiteStore(store_path) as store:
        with store.agent_transaction():
            plan = _stored(store, plan_id)
            _require_approval_readiness(store, plan)
            approved_by = _validate_independent_human(store, plan, approved_by)
            approved = replace(plan, status=ProvisioningStatus.APPROVED, approved_by=approved_by, approved_at=now)
            store._connection.execute("UPDATE backup_provisioning_plans SET payload=? WHERE id=?", (_dump(approved), plan_id))
    return _public(approved, mutation=True)


def execute_plan(
    store_path: str,
    plan_id: str,
    adapter: ProvisioningAdapter | None = None,
    executed_at: str | None = None,
    acceptance_runner=None,
) -> Mapping[str, object]:
    if adapter is None:
        raise ValueError("an explicit dedicated provisioning adapter is required")
    now = executed_at or datetime.now(UTC).isoformat(); _time(now)
    execution_id = None
    with SQLiteStore(store_path) as store:
        typed_execution = _typed_execution_enabled_for_plan_locked(store, plan_id)
        if typed_execution:
            from .backup_execution import _InvocationResult, _start_execution_with_invocation, _continue_execution_with_invocation, derive_backup_execution_view
            _require_typed_execution_bundle(store, _stored(store, plan_id))
            try:
                execution_id = store.load_backup_execution_header_for_plan(plan_id).execution_id
            except KeyError:
                execution_id = None
            try:
                if execution_id is None:
                    invocation = _start_execution_with_invocation(store_path, plan_id, adapter, acceptance_runner, now=now)
                else:
                    invocation = _continue_execution_with_invocation(store_path, execution_id, adapter, acceptance_runner, now=now)
            except ValueError as error:
                # A concurrent caller may observe the winner's durable step
                # claim.  It did not claim or execute anything itself.
                if str(error) != "EXECUTION_IN_PROGRESS":
                    raise
                with SQLiteStore(store_path) as current_store:
                    header = current_store.load_backup_execution_header_for_plan(plan_id)
                    current_checkpoints = current_store.load_backup_execution_checkpoints(header.execution_id)
                    if not current_checkpoints or current_checkpoints[-1].event.value != "step_started":
                        raise
                    current_header = current_store.load_backup_execution_header(current_checkpoints[0].execution_id)
                    current_plan = _stored(current_store, plan_id)
                    current_view = derive_backup_execution_view(current_header, current_checkpoints)
                    invocation = _InvocationResult(
                        view=current_view,
                        entry_checkpoints=current_checkpoints,
                        entry_plan=current_plan,
                        exit_checkpoints=current_checkpoints,
                        exit_plan=current_plan,
                        invocation_checkpoints=(),
                        mutation_performed=False,
                    )
            plan = invocation.exit_plan
            checkpoints = invocation.exit_checkpoints
            header = store.load_backup_execution_header(invocation.view.execution_id)
            prefix = invocation.entry_checkpoints
            if checkpoints[:len(prefix)] != prefix:
                raise ValueError("execution checkpoint prefix identity changed")
            delta = invocation.invocation_checkpoints
            return _typed_execution_public(plan, invocation.view, checkpoints, header=header, invocation_checkpoints=delta, mutation=invocation.mutation_performed)
    with SQLiteStore(store_path) as store:
        plan = _stored(store, plan_id); _validate_plan(plan)
        _require_terminal_evidence(store, plan)
        if plan.status != ProvisioningStatus.APPROVED or not plan.approved_by or not plan.approved_at:
            raise ValueError("the exact provisioning plan requires independent human approval")
        evidence = []
        failed_operation = None
        error_code = None
        try:
            for expected in plan.steps:
                try:
                    result = adapter.execute(expected)
                except Exception as exc:
                    failed_operation = expected.operation
                    error_code = _redacted_error_code(exc)
                    raise
                evidence.append({"operation": expected.operation, "ok": result.get("ok") is True})
                if result.get("ok") is not True:
                    failed_operation = expected.operation
                    error_code = "OPERATION_REPORTED_FAILURE"
                    raise ValueError("provisioning step failed")
        except Exception:
            rollback_evidence = []
            # rollback_steps are declared in dependency-safe execution order:
            # revoke service access and ACLs before deleting the service user,
            # then remove the unreferenced runtime last.
            for rollback in plan.rollback_steps:
                try:
                    result = adapter.execute(rollback)
                    rollback_evidence.append({"operation": rollback.operation, "ok": result.get("ok") is True})
                except Exception:
                    rollback_evidence.append({"operation": rollback.operation, "ok": False})
            rolled_back = all(item["ok"] for item in rollback_evidence)
            digest = "sha256:" + hashlib.sha256(json.dumps({"execute": evidence, "rollback": rollback_evidence}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            failed = replace(plan, status=ProvisioningStatus.ROLLED_BACK if rolled_back else ProvisioningStatus.FAILED, executed_at=now, evidence_digest=digest, failed_operation=failed_operation, error_code=error_code)
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
    _validate_plan(plan)
    with SQLiteStore(store_path) as store:
        with store.agent_transaction():
            if _typed_bundle_feature_enabled_locked(store):
                raise ValueError("TYPED_BUNDLE_REQUIRED")
            _stage_plan_locked(store, plan, validated=True)
    return _public(plan, mutation=True)


def approve_plan_api(store_path: str, payload: Mapping[str, object]) -> Mapping[str, object]:
    if set(payload) != {"plan_id", "approved_by"}: raise ValueError("exact backup provisioning approval fields are required")
    return approve_plan(store_path, str(payload["plan_id"]), str(payload["approved_by"]))


def execute_plan_api(store_path: str, payload: Mapping[str, object], adapter_factory: Callable[[DonutHoleBackupProvisioningPlan], ProvisioningAdapter] | None = None) -> Mapping[str, object]:
    if set(payload) != {"plan_id", "privileged_confirmation"} or payload.get("privileged_confirmation") != "execute-exact-donuthole-backup-provisioning-plan":
        raise ValueError("exact privileged provisioning confirmation is required")
    if adapter_factory is None: raise ValueError("privileged host adapter is not configured")
    with SQLiteStore(store_path) as store: plan = _stored(store, str(payload["plan_id"]))
    return execute_plan(store_path, plan.plan_id, adapter_factory(plan))


def review_plan(store_path: str, plan_id: str, reviewer: str) -> Mapping[str, object]:
    """Deterministically review the immutable staged target without mutation."""
    if reviewer not in {"kira", "obrien", "sisko", "security"}: raise ValueError("unsupported backup provisioning reviewer")
    with SQLiteStore(store_path) as store: plan = _stored(store, plan_id)
    failures: list[str] = []
    try: _validate_plan(plan)
    except ValueError: failures.append("immutable plan kind or digest does not match")
    if plan.status != ProvisioningStatus.STAGED: failures.append("plan is not at the staged review gate")
    names = [step.operation for step in plan.steps]
    required = {"verify_published_adapter_source", "install_runtime", "install_overseer_api_token", "generate_cursor_key", "install_private_config", "register_authorized_roots", "stop_disable_user_service", "install_systemd_unit", "start_enable_system_service", "verify_mcp_service", "verify_gpg_identity", "verify_backup_policy"}
    if not required <= set(names): failures.append("required exact provisioning steps are missing")
    if reviewer == "kira" and not failures:
        try:
            registration = plan.root_registrations[0]
            authorization_ref = str(registration["authorization_ref"])
            identity=current_root_identity(str(registration["host_path"]))
            with SQLiteStore(store_path) as store: resource = store.load_resource("storage.donuthole")
            target_digests=[digest for digest,reference in plan.root_authorization_refs.items() if reference==authorization_ref]
            if len(target_digests)!=1:
                failures.append("materialized root authorization does not match the exact registration")
            else:
                current=resolve_current_root_authorization(store_path,str(registration["project_id"]),str(registration["root_id"]),str(registration["policy_revision"]),identity,str(registration["alias"]),"active",int(registration["max_bytes"]),target_digests[0])
                if current["authorization_ref"]!=authorization_ref:
                    failures.append("plan does not use the current exact root authorization")
            if resource.id != "storage.donuthole" or resource.owner_domain != OwnerDomain.KIRA:
                failures.append("typed DonutHole storage resource is not registered to Kira")
        except (IndexError, KeyError, TypeError, ValueError):
            failures.append("materialized DonutHole root authorization or storage resource is missing")
    if reviewer == "security" and not failures:
        ordered = ("install_overseer_api_token", "generate_cursor_key", "install_private_config", "register_authorized_roots", "stop_disable_user_service", "install_systemd_unit", "start_enable_system_service", "verify_mcp_service")
        if [names.index(name) for name in ordered] != sorted(names.index(name) for name in ordered): failures.append("credential, registration, migration, or verification ordering is invalid")
        unit = next(step for step in plan.steps if step.operation == "install_systemd_unit").arguments["properties"]
        expected_ro = (plan.source_path, plan.config_path, plan.key_path, plan.overseer_token_file, plan.cursor_key_file)
        if tuple(unit.get("read_only_paths", ())) != expected_ro or tuple(unit.get("read_write_paths", ())) != plan.read_write_paths or unit.get("umask") != "0077" or unit.get("protect_system") != "strict" or unit.get("protect_home") != "read-only" or unit.get("private_tmp") is not True or unit.get("no_new_privileges") is not True or tuple(unit.get("restrict_address_families", ())) != ("AF_UNIX", "AF_INET"):
            failures.append("systemd loopback, filesystem, or sandbox boundary is invalid")
        registration = next(step for step in plan.steps if step.operation == "register_authorized_roots")
        if registration.arguments.get("tool") != "underdark_root_register" or not plan.root_registrations: failures.append("exact authorized root registration is missing")
        rollback_names = [step.operation for step in plan.rollback_steps]
        if not {"stop_disable_system_service", "restore_enable_user_service", "remove_secret_file_if_no_backups", "remove_overseer_api_token", "remove_cursor_key_if_unreferenced"} <= set(rollback_names): failures.append("required rollback protections are missing")
    return {"ok": not failures, "plan_id": plan.plan_id, "kind": plan.kind, "plan_digest": plan.plan_digest, "status": plan.status.value, "reviewer": reviewer, "failures": failures, "independent_human_approval_required": True, "mutation_performed": False, "host_mutation_performed": False}


def _validate_plan(plan: DonutHoleBackupProvisioningPlan) -> None:
    from .backup_contract import PROVISIONING_CONTRACT_VERSION, runtime_artifact_identity
    from .backup_host_operations import EXPECTED_BACKUP_TOOL_SCHEMAS, capability_digest as reviewed_capability_digest

    if plan.provisioning_contract_version != PROVISIONING_CONTRACT_VERSION:
        raise ValueError("provisioning contract version does not match the reviewed contract")
    expected_runtime_identity = runtime_artifact_identity(plan.adapter_commit, EXPECTED_BACKUP_TOOL_SCHEMAS)
    if plan.runtime_artifact_identity != expected_runtime_identity:
        raise ValueError("runtime artifact identity does not match the reviewed contract")
    expected_capability_digest = reviewed_capability_digest(plan.adapter_commit, EXPECTED_BACKUP_TOOL_SCHEMAS, plan.provisioning_contract_version)
    if plan.capability_digest != expected_capability_digest:
        raise ValueError("capability digest does not match the reviewed contract")
    rebuilt = build_plan(plan.plan_id, plan.gpg_sha256, plan.adapter_commit, plan.runtime_digest, plan.capability_digest, plan.root_authorization_refs, plan.root_registrations, plan.overseer_token_source_file, plan.overseer_token_file, plan.cursor_key_file, plan.evidence_ids)
    if plan.kind != PLAN_KIND or plan.plan_digest != rebuilt.plan_digest or _plan_digest(plan) != plan.plan_digest:
        raise ValueError("provisioning plan contract or digest does not match")


def _plan_digest(plan: DonutHoleBackupProvisioningPlan) -> str:
    payload = asdict(plan); payload.pop("plan_digest"); payload.pop("status"); payload.pop("approved_by"); payload.pop("approved_at"); payload.pop("executed_at"); payload.pop("evidence_digest"); payload.pop("failed_operation"); payload.pop("error_code"); payload.pop("decision_source"); payload.pop("decision_reason"); payload.pop("decided_by"); payload.pop("decided_at")
    return "sha256:" + hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _initialize(store: SQLiteStore) -> None:
    store.ensure_backup_provisioning_plan_store()
    store._commit_agent_mutation()


def _stored(store: SQLiteStore, plan_id: str) -> DonutHoleBackupProvisioningPlan:
    _initialize(store); row = store._connection.execute("SELECT payload FROM backup_provisioning_plans WHERE id=?", (plan_id,)).fetchone()
    if not row: raise KeyError(plan_id)
    return _load(str(row["payload"]))


def _require_terminal_evidence(store: SQLiteStore, plan: DonutHoleBackupProvisioningPlan) -> None:
    for role, domain in REQUIRED_EVIDENCE.items():
        message = store.load_crew_message(plan.evidence_ids[role])
        if message.owner_domain != domain or message.related_plan_id != plan.plan_id or message.status != CrewMessageStatus.ACKNOWLEDGED or message.review_status != CrewReviewStatus.APPROVED or message.decided_by != domain.value or not message.decided_at:
            raise ValueError(f"terminal approved {role} evidence is required")


def _typed_bundle_feature_enabled_locked(store: SQLiteStore) -> bool:
    """Fail closed once any dedicated typed provisioning artifact exists."""
    checks = (
        "SELECT 1 FROM provisioning_preflight_reports LIMIT 1",
        "SELECT 1 FROM provisioning_bundles LIMIT 1",
        "SELECT 1 FROM provisioning_review_outbox LIMIT 1",
        "SELECT 1 FROM roadex_approval_bindings "
        "WHERE approval_ref LIKE 'approval.donuthole.%' LIMIT 1",
    )
    return any(store._connection.execute(sql).fetchone() is not None for sql in checks)


def _typed_execution_enabled_for_plan_locked(store: SQLiteStore, plan_id: str) -> bool:
    """Select typed execution from durable authority and persist scoped fallback."""
    if store.load_backup_provisioning_plan_execution_mode(plan_id) == "typed":
        return True
    checks = (
        ("SELECT 1 FROM provisioning_bundles WHERE plan_id=? LIMIT 1", (plan_id,)),
        ("SELECT 1 FROM backup_provisioning_execution_headers WHERE plan_id=? LIMIT 1", (plan_id,)),
        ("SELECT 1 FROM provisioning_preflight_reports WHERE plan_id=? LIMIT 1", (plan_id,)),
        ("SELECT 1 FROM provisioning_review_outbox WHERE plan_id=? LIMIT 1", (plan_id,)),
        (
            "SELECT 1 FROM roadex_approval_bindings "
            "WHERE source_kind=? AND source_id=? AND approval_ref=? LIMIT 1",
            ("roadex-human-decision", plan_id, f"approval.donuthole.{plan_id}"),
        ),
    )
    if any(store._connection.execute(sql, parameters).fetchone() is not None for sql, parameters in checks):
        store.mark_backup_provisioning_plan_typed(plan_id)
        return True
    return False


def _require_bundle_preflight_and_reviews(
    store: SQLiteStore,
    plan: DonutHoleBackupProvisioningPlan,
) -> None:
    """Prove the exact persisted typed approval set without mutation."""
    from . import provisioning_bundle

    try:
        bundle = provisioning_bundle.load_provisioning_bundle(store, plan.plan_id)
    except KeyError as error:
        raise ValueError("SUCCESSOR_REQUIRED") from error
    except ValueError as error:
        raise ValueError("TYPED_BUNDLE_REQUIRED") from error
    if (
        bundle.plan.plan_digest != plan.plan_digest
        or dump_staged_plan_payload(bundle.plan) != dump_staged_plan_payload(plan)
    ):
        raise ValueError("TYPED_BUNDLE_REQUIRED")
    try:
        provisioning_bundle._recheck_locked_authority_and_chain(store, bundle)
    except provisioning_bundle.ProvisioningBundleError as error:
        raise ValueError("SUCCESSOR_REQUIRED") from error
    except ValueError as error:
        raise ValueError("PREFLIGHT_NOT_CURRENT") from error
    try:
        draft = provisioning_bundle.binding_draft_for_bundle(bundle)
        binding = store.load_roadex_approval_binding(draft.approval_ref)
    except KeyError as error:
        raise ValueError("SUCCESSOR_REQUIRED") from error
    try:
        report = provisioning_bundle._load_exact_preflight_report(store, bundle)
    except (KeyError, ValueError) as error:
        raise ValueError("PREFLIGHT_NOT_CURRENT") from error
    if not report.passed or report != bundle.preflight:
        raise ValueError("PREFLIGHT_NOT_CURRENT")
    try:
        provisioning_bundle.verify_exact_persisted_bundle_set(
            store, bundle, binding,
        )
    except (KeyError, ValueError) as error:
        raise ValueError("TYPED_BUNDLE_REQUIRED") from error
    try:
        provisioning_bundle.verify_exact_completed_review_outbox_set(
            store, bundle,
        )
    except (KeyError, ValueError) as error:
        raise ValueError("REVIEW_EVIDENCE_NOT_CURRENT") from error
    try:
        _require_terminal_evidence(store, plan)
    except (KeyError, ValueError) as error:
        raise ValueError("REVIEW_EVIDENCE_NOT_CURRENT") from error


def _require_typed_execution_bundle(
    store: SQLiteStore,
    plan: DonutHoleBackupProvisioningPlan,
) -> None:
    """Require the exact typed execution records before entering the coordinator."""
    from . import provisioning_bundle

    try:
        bundle = provisioning_bundle.load_provisioning_bundle(store, plan.plan_id)
    except KeyError as error:
        raise ValueError("SUCCESSOR_REQUIRED") from error
    except ValueError as error:
        raise ValueError("TYPED_BUNDLE_REQUIRED") from error
    if bundle.plan.plan_digest != plan.plan_digest:
        raise ValueError("TYPED_BUNDLE_REQUIRED")
    try:
        provisioning_bundle._load_exact_preflight_report(store, bundle)
        provisioning_bundle._load_exact_outbox(store, bundle)
        provisioning_bundle.verify_exact_completed_review_outbox_set(store, bundle)
        _require_terminal_evidence(store, plan)
    except (KeyError, ValueError) as error:
        raise ValueError("TYPED_BUNDLE_REQUIRED") from error


def _require_approval_readiness(
    store: SQLiteStore,
    plan: DonutHoleBackupProvisioningPlan,
) -> None:
    if _typed_bundle_feature_enabled_locked(store):
        _require_bundle_preflight_and_reviews(store, plan)
    else:
        _require_terminal_evidence(store, plan)


def _validate_independent_human(
    store: SQLiteStore,
    plan: DonutHoleBackupProvisioningPlan,
    identity: str,
) -> str:
    """Validate one canonical actor before any decision mutation."""
    canonical = _canonical_identity(identity)
    if (
        not isinstance(identity, str)
        or not canonical
        or canonical != identity
        or OPAQUE_ID.fullmatch(canonical) is None
        or plan.status != ProvisioningStatus.STAGED
    ):
        raise ValueError("independent human identity is required")
    evidence_actors = {
        _canonical_identity(actor) for actor in REQUIRED_EVIDENCE
    } | {
        _canonical_identity(domain.value) for domain in REQUIRED_EVIDENCE.values()
    }
    evidence_requesters = {
        _canonical_identity(store.load_crew_message(message_id).requested_by)
        for message_id in plan.evidence_ids.values()
    }
    if canonical in evidence_actors or canonical in evidence_requesters:
        raise ValueError("independent human identity is required")
    return canonical


def _canonical_identity(identity: object) -> str:
    return identity.strip().lower() if isinstance(identity, str) else ""


_APPROVAL_BLOCKER_EXPLANATIONS = {
    "TYPED_BUNDLE_REQUIRED": (
        "An exact immutable typed provisioning bundle is required."
    ),
    "PREFLIGHT_NOT_CURRENT": (
        "The exact persisted provisioning preflight must be current and passing."
    ),
    "SUCCESSOR_REQUIRED": (
        "This staged plan requires a new typed successor; legacy evidence does not transfer."
    ),
    "REVIEW_EVIDENCE_NOT_CURRENT": (
        "All four exact provisioning reviews must be approved with current VERIFIED completion receipts."
    ),
}


def _approval_blocker(error: Exception) -> tuple[str, str]:
    raw = str(error)
    if raw in _APPROVAL_BLOCKER_EXPLANATIONS:
        return raw, _APPROVAL_BLOCKER_EXPLANATIONS[raw]
    code = "REVIEW_EVIDENCE_NOT_CURRENT"
    return code, _APPROVAL_BLOCKER_EXPLANATIONS[code]


def _dump(plan: DonutHoleBackupProvisioningPlan) -> str:
    return json.dumps(asdict(plan), sort_keys=True, separators=(",", ":"))


def _load(payload: str) -> DonutHoleBackupProvisioningPlan:
    data = json.loads(payload)
    if "provisioning_contract_version" not in data:
        raise ValueError("provisioning contract version is required for exact plan decoding")
    if "runtime_artifact_identity" not in data:
        raise ValueError("runtime artifact identity is required for exact plan decoding")
    data.setdefault("failed_operation", None); data.setdefault("error_code", None); data["status"] = ProvisioningStatus(data["status"]); data["steps"] = tuple(ProvisioningStep(item["operation"], item["arguments"]) for item in data["steps"]); data["rollback_steps"] = tuple(ProvisioningStep(item["operation"], item["arguments"]) for item in data["rollback_steps"]); data["read_only_paths"] = tuple(data["read_only_paths"]); data["read_write_paths"] = tuple(data["read_write_paths"])
    plan = DonutHoleBackupProvisioningPlan(**data)
    _validate_plan(plan)
    return plan


def dump_staged_plan_payload(plan: DonutHoleBackupProvisioningPlan) -> str:
    """Encode an exact immutable source payload for the atomic bundle boundary."""
    _validate_plan(plan)
    payload = _dump(plan)
    if _dump(_load(payload)) != payload:
        raise ValueError("provisioning plan payload is not exact after serialization")
    return payload


def save_staged_plan_source(store: SQLiteStore, plan: DonutHoleBackupProvisioningPlan) -> None:
    """Save an initial source while preserving a caller-owned transaction."""
    if (
        plan.status != ProvisioningStatus.STAGED
        or plan.approved_by is not None
        or plan.approved_at is not None
        or plan.decided_by is not None
        or plan.decided_at is not None
        or plan.decision_reason is not None
        or plan.executed_at is not None
        or plan.evidence_digest is not None
        or plan.failed_operation is not None
        or plan.error_code is not None
    ):
        raise ValueError("atomic bundle source must be an exact staged plan")
    store.save_backup_provisioning_plan_payload(plan.plan_id, dump_staged_plan_payload(plan))


def _public(plan: DonutHoleBackupProvisioningPlan, *, mutation: bool, host_mutation: bool = False) -> Mapping[str, object]:
    return {"ok": True, "plan_id": plan.plan_id, "kind": plan.kind, "plan_digest": plan.plan_digest, "status": plan.status.value, "approval_required": plan.status == ProvisioningStatus.STAGED, "approved_by": plan.approved_by, "evidence_ids": dict(plan.evidence_ids), "evidence_digest": plan.evidence_digest, "failed_operation": plan.failed_operation, "error_code": plan.error_code, "rollback_operations": [step.operation for step in plan.rollback_steps], "redactions_applied": True, "mutation_performed": mutation, "host_mutation_performed": host_mutation}


def _typed_execution_public(plan: DonutHoleBackupProvisioningPlan, view, checkpoints: tuple[object, ...], *, header, invocation_checkpoints: tuple[object, ...] | None = None, mutation: bool = True) -> Mapping[str, object]:
    from .backup_execution import CheckpointEvent, StepDisposition
    from .backup_execution import _bound_step
    non_synthetic = len(plan.steps)
    synthetic_operations = ("verify_runtime_attestation", "run_behavior_acceptance", "finalize_execution")
    current = checkpoints if invocation_checkpoints is None else invocation_checkpoints
    read_only = {
        "verify_published_adapter_source", "verify_endpoint_migration_ready", "verify_mcp_service",
        "verify_codex_url", "verify_gpg_identity", "verify_backup_policy",
    }
    host_mutation = False
    host_mutation_uncertain = False
    failed_operation = None
    for item in checkpoints:
        event = getattr(item, "event", None)
        if event in {CheckpointEvent.STEP_FAILED, CheckpointEvent.ROLLBACK_FAILED, CheckpointEvent.EXECUTION_ABORTED}:
            identity, is_rollback = _bound_step(header, item)
            operation = identity.rollback if is_rollback else identity.forward
            if operation is None:
                raise ValueError("failed checkpoint lacks an approved operation identity")
            failed_operation = operation.operation
    for index, item in enumerate(current):
        event = getattr(item, "event", None)
        evidence = getattr(item, "step_evidence", None)
        ordinal = getattr(item, "plan_step_ordinal", non_synthetic)
        later = current[index + 1:]
        if event is CheckpointEvent.STEP_FAILED and evidence is not None:
            operation = plan.steps[ordinal].operation if ordinal < non_synthetic else synthetic_operations[ordinal - non_synthetic] if ordinal - non_synthetic < len(synthetic_operations) else None
            if ordinal < non_synthetic and operation not in read_only:
                host_mutation_uncertain = True
        elif event is CheckpointEvent.STEP_STARTED and ordinal < non_synthetic:
            operation = plan.steps[ordinal].operation
            outcome_events = {CheckpointEvent.STEP_COMPLETED, CheckpointEvent.STEP_FAILED}
            if operation not in read_only and not any(getattr(next_item, "plan_step_ordinal", None) == ordinal and getattr(next_item, "event", None) in outcome_events for next_item in later):
                host_mutation_uncertain = True
        elif event is CheckpointEvent.STEP_COMPLETED and ordinal < non_synthetic and evidence is not None and evidence.disposition is StepDisposition.CHANGED:
            if plan.steps[ordinal].operation not in read_only:
                host_mutation = True
        elif event is CheckpointEvent.ROLLBACK_STARTED:
            if not any(getattr(next_item, "plan_step_ordinal", None) == ordinal and getattr(next_item, "event", None) in {CheckpointEvent.ROLLBACK_COMPLETED, CheckpointEvent.ROLLBACK_FAILED} for next_item in later):
                host_mutation_uncertain = True
        elif event is CheckpointEvent.ROLLBACK_FAILED:
            host_mutation_uncertain = True
        elif event is CheckpointEvent.ROLLBACK_COMPLETED and evidence is not None and evidence.disposition is StepDisposition.CHANGED:
            host_mutation = True
    if view.terminal_success:
        status = "executed"
    elif view.rollback_status == "completed":
        status = "rolled_back"
    elif view.rollback_status == "failed" or view.failure_code:
        status = "failed"
    else:
        status = "in_progress"
    result = dict(_public(plan, mutation=mutation, host_mutation=host_mutation))
    result.update({
        "execution_id": view.execution_id,
        "execution_status": view.status,
        "rollback_status": view.rollback_status,
        "status": status,
        "failure_code": view.failure_code,
        "error_code": view.failure_code,
        "evidence_digest": view.evidence_digest,
        "host_mutation_uncertain": host_mutation_uncertain,
    })
    if failed_operation is not None:
        result["failed_operation"] = failed_operation
    return result


def _redacted_error_code(error: Exception) -> str:
    code = getattr(error, "code", None)
    return code if isinstance(code, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code) else "OPERATION_FAILED"


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


__all__ = ["DonutHoleBackupProvisioningPlan", "DedicatedProvisioningAdapter", "AllowlistedHostProvisioningAdapter", "ProvisioningStep", "ProvisioningStatus", "build_plan", "stage_plan", "list_plans", "approve_plan", "execute_plan", "stage_plan_api", "approve_plan_api", "execute_plan_api", "review_plan", "dump_staged_plan_payload", "save_staged_plan_source"]
