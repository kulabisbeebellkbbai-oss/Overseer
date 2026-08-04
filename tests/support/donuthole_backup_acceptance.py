"""Disposable Capability A composition across the reviewed repository boundary."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any, Mapping


_REQUIRED_ENVIRONMENT = ("THEUNDERDARK_PYTHON", "THEUNDERDARK_SOURCE")


def _gpg_available() -> bool:
    executable = Path("/usr/bin/gpg")
    return executable.is_file() and os.access(executable, os.X_OK)


def _sealed_authority_status(authority_path: Path, expected_bytes: bytes) -> bool:
    """Confirm that root-owned fixture authority remains regular, sealed, and exact."""
    try:
        metadata = authority_path.lstat()
        return (
            stat.S_ISREG(metadata.st_mode)
            and stat.S_IMODE(metadata.st_mode) == 0o400
            and authority_path.read_bytes() == expected_bytes
        )
    except OSError:
        return False


class SynchronousMCPBridge:
    """Run one real in-process MCP call to completion without storage substitutes."""

    def __init__(self, mcp: object) -> None:
        self._mcp = mcp
        self._discovered_tools: tuple[str, ...] | None = None

    @property
    def discovered_tools(self) -> tuple[str, ...]:
        if self._discovered_tools is None:
            raise RuntimeError("MCP tools are discovered during the first call_tool invocation")
        return self._discovered_tools

    def call_tool(self, name: str, arguments: Mapping[str, object]) -> Mapping[str, object]:
        async def invoke() -> Mapping[str, object]:
            from mcp.shared.memory import create_connected_server_and_client_session

            async with create_connected_server_and_client_session(self._mcp) as client:
                if self._discovered_tools is None:
                    listed = await client.list_tools()
                    tools = listed.tools
                    self._discovered_tools = tuple(sorted(tool.name for tool in tools))
                response = await client.call_tool(name, dict(arguments))
            structured = getattr(response, "structuredContent", None)
            if isinstance(structured, Mapping):
                return dict(structured)
            content = getattr(response, "content", ())
            if len(content) != 1 or not isinstance(getattr(content[0], "text", None), str):
                raise RuntimeError("production MCP response did not contain one JSON envelope")
            decoded = json.loads(content[0].text)
            if not isinstance(decoded, dict):
                raise RuntimeError("production MCP response envelope was not an object")
            return decoded

        return asyncio.run(invoke())


def run_acceptance_scenario(
    contract_path: Path,
    scenario_name: str,
    workspace: Path,
    *,
    include_backup_restore: bool = False,
    retain_previous_runtime: bool = False,
    tamper_installed_runtime: bool = False,
) -> dict[str, object]:
    """Launch disposable composition with explicit external interpreter/source paths."""

    if include_backup_restore and not _gpg_available():
        import pytest

        pytest.skip("encrypted backup acceptance requires gpg")
    missing = [name for name in _REQUIRED_ENVIRONMENT if not os.environ.get(name)]
    if missing:
        raise RuntimeError("cross-repository acceptance requires " + ", ".join(missing))
    contract_path = contract_path.resolve(strict=True)
    workspace = workspace.resolve()
    source = Path(os.environ["THEUNDERDARK_SOURCE"]).resolve(strict=True)
    interpreter = Path(os.environ["THEUNDERDARK_PYTHON"])
    if not interpreter.is_absolute() or not interpreter.is_file():
        raise RuntimeError("THEUNDERDARK_PYTHON must be an explicit executable path")
    builder = source / "tests" / "test_backup_production_integration.py"
    if not builder.is_file():
        raise RuntimeError("TheUnderdark disposable composition builder is unavailable")
    completed = subprocess.run(
        [
            str(interpreter),
            str(Path(__file__).resolve()),
            "--child",
            *( ["--include-backup-restore"] if include_backup_restore else [] ),
            *( ["--retain-previous-runtime"] if retain_previous_runtime else [] ),
            *( ["--tamper-installed-runtime"] if tamper_installed_runtime else [] ),
            str(contract_path),
            scenario_name,
            str(workspace),
            str(builder),
        ],
        check=False,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PYTHONPATH": os.pathsep.join((
                str(source / "src"),
                str(source),
                str(Path(__file__).resolve().parents[2] / "src"),
                os.environ.get("PYTHONPATH", ""),
            )),
        },
    )
    if completed.returncode:
        raise RuntimeError("disposable acceptance subprocess failed: " + completed.stderr.strip())
    result = json.loads(completed.stdout)
    if not isinstance(result, dict):
        raise RuntimeError("disposable acceptance subprocess returned an invalid result")
    return result


def _fixture_execution_request(
    *,
    payload: Mapping[str, object],
    action: str,
    parameters: Mapping[str, object],
):
    """Build the bounded adapter record from the fixture-owned request fields."""
    from overseer.storage_adapter import StorageExecutionRequest

    return StorageExecutionRequest(
        request_id=str(payload["request_id"]),
        adapter_id="storage-adapter.theunderdark",
        adapter_revision=1,
        project_id=str(payload["project_id"]),
        resource_id="storage.donuthole",
        root_id=str(payload["root_id"]),
        action=action,
        parameters=dict(parameters),
        policy_revision=str(payload["policy_revision"]),
        claim_id=f"claim.{payload['request_id']}",
        approval_id=f"approval.{payload['request_id']}",
        authorization_ref=str(payload["authorization_ref"]),
        idempotency_key=str(payload["idempotency_key"]),
        requested_by=str(payload["project_id"]),
        reason=str(payload["reason"]),
        acceptance_criteria=("disposable encrypted restore verified",),
        limits={"max_bytes": 1_073_741_824, "max_items": 16},
        expires_at="2099-01-01T00:00:00+00:00",
    ).with_digest()


class _DisposableVerificationTransport:
    """Test-only transport to the real, local Overseer verification function."""

    def __init__(self, store_path: Path) -> None:
        self._store_path = store_path
        self.request_digests: list[str] = []

    def post(self, _url: str, *, headers: Mapping[str, str], json: Mapping[str, object], timeout: float) -> Mapping[str, object]:
        from overseer.storage_adapter import verify_storage_authorization_status

        if headers.get("content-type") != "application/json" or timeout != 5.0:
            raise AssertionError("the real verifier did not use its bounded transport contract")
        digest = json.get("request_digest")
        if not isinstance(digest, str):
            raise AssertionError("the verifier omitted the canonical request digest")
        self.request_digests.append(digest)
        return verify_storage_authorization_status(
            str(self._store_path),
            json,
            verified_at="2026-08-04T00:00:00+00:00",
        )


def _configure_disposable_backup_execution(
    service: object,
    workspace: Path,
    request: object,
    root: Path,
    *,
    journal_name: str,
) -> _DisposableVerificationTransport:
    """Attach real encrypted execution to an otherwise sealed disposable service."""
    from overseer.audit import ApprovalRequest, ApprovalStatus
    from overseer.core import ApprovalLevel, Claim, ClaimStatus, ClaimType, OwnerDomain, RiskLevel
    from overseer.storage_adapter import StorageAuthorizationRecord, canonical_adapter_request_digest
    from overseer.store import SQLiteStore
    from theunderdark.backup_executor import EncryptedBackupExecutor
    from theunderdark.journal import SQLiteOperationJournal
    from theunderdark.overseer_verifier import OverseerAuthorizationVerifier

    artifact_dir = workspace / "encrypted-artifacts"
    artifact_dir.mkdir(mode=0o700, exist_ok=True)
    artifact_dir.chmod(0o700)
    passphrase_file = workspace / "backup-passphrase"
    passphrase_file.write_text("disposable encrypted backup passphrase", encoding="utf-8")
    passphrase_file.chmod(0o600)
    executor = EncryptedBackupExecutor(
        source_root=root,
        artifact_dir=artifact_dir,
        passphrase_file=passphrase_file,
    )
    store_path = workspace / f"{journal_name}-authorization.sqlite3"
    tool_digest = canonical_adapter_request_digest(request)
    approval = ApprovalRequest(
        request.approval_id,
        request.request_id,
        ApprovalLevel.HUMAN,
        request.requested_by,
        OwnerDomain.OBRIEN,
        "disposable encrypted backup acceptance",
        status=ApprovalStatus.APPROVED,
    )
    claim = Claim(
        request.claim_id,
        request.resource_id,
        ClaimType.LEASE,
        request.requested_by,
        OwnerDomain.OBRIEN,
        "disposable encrypted backup acceptance",
        request.action,
        RiskLevel.HIGH,
        status=ClaimStatus.ACTIVE,
        expires_at="2099-01-02T00:00:00+00:00",
    )
    authorization = StorageAuthorizationRecord(
        request.authorization_ref,
        request.request_id,
        request.request_digest,
        request.project_id,
        request.root_id,
        request.action,
        request.policy_revision,
        request.claim_id,
        request.approval_id,
        tool_digest,
        dict(request.limits),
        "2026-08-04T00:00:00+00:00",
        "2099-01-01T00:00:00+00:00",
    )
    with SQLiteStore(store_path) as store:
        store.save_storage_execution_request(request)
        store.save_claim(claim)
        store.save_approval(approval)
        store.save_storage_authorization(authorization)
    transport = _DisposableVerificationTransport(store_path)
    service.journal = SQLiteOperationJournal((workspace / f"{journal_name}-journal.sqlite3").resolve())
    service.verifier = OverseerAuthorizationVerifier(
        endpoint="http://127.0.0.1:8766/storage/authorizations/verify",
        token_provider=lambda: "disposable-test-token",
        http_client=transport,
    )
    service.backup_executor_provider = lambda project_id, root_id, policy_revision: (
        executor
        if (project_id, root_id, policy_revision) == (request.project_id, request.root_id, request.policy_revision)
        else (_ for _ in ()).throw(PermissionError("no exact disposable backup binding"))
    )
    return transport


def _load_builder(path: Path):
    spec = importlib.util.spec_from_file_location("theunderdark_disposable_composition", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load TheUnderdark disposable composition builder")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build_real_service


def _seed_active_upgrade_state(
    workspace: Path,
    registration: Mapping[str, object],
    root: Path,
    previous_identity: str,
) -> str:
    """Create the pre-existing registered root and a terminal journal record."""
    from theunderdark.journal import AuthorizationSnapshot, OperationState, SQLiteOperationJournal
    from theunderdark.root_registry import ControlPlaneApproval, SQLiteRootRegistry

    class DisposableRootVerifier:
        def verify(self, action: str, payload: Mapping[str, object], target_digest: str) -> object:
            return ControlPlaneApproval(
                "disposable-active-upgrade-approval",
                action,
                str(payload["project_id"]),
                str(payload["root_id"]),
                str(payload["policy_revision"]),
                target_digest,
                "approved",
                "2099-01-01T00:00:00+00:00",
            )

    state = workspace / "state"
    state.mkdir(mode=0o700, exist_ok=True)
    registry = SQLiteRootRegistry((state / "roots.sqlite3").resolve(), verifier=DisposableRootVerifier())
    try:
        arguments = {
            "project_id": str(registration["project_id"]),
            "root_id": str(registration["root_id"]),
            "policy_revision": str(registration["policy_revision"]),
            "host_path": root,
            "alias": str(registration["alias"]),
            "max_bytes": int(registration["max_bytes"]),
        }
        registry.register(**arguments)
        changes_before_retry = registry._connection.total_changes
        registry.register(**arguments)
        if registry._connection.total_changes != changes_before_retry:
            raise AssertionError("exact active root registration was not a verified no-op")
    finally:
        registry.close()

    journal = SQLiteOperationJournal((state / "journal.sqlite3").resolve())
    try:
        request_id = "request.active-upgrade-preexisting"
        authorization = AuthorizationSnapshot(
            "authorization.active-upgrade-preexisting",
            request_id,
            str(registration["project_id"]),
            str(registration["root_id"]),
            "backup.create",
            previous_identity,
            str(registration["policy_revision"]),
            "claim.active-upgrade-preexisting",
            "approval.active-upgrade-preexisting",
            "2026-08-04T00:00:00+00:00",
            "2099-01-01T00:00:00+00:00",
            {},
        )
        journal.store_authorization(authorization)
        operation, created = journal.reserve(
            project_id=authorization.project_id,
            request_id=request_id,
            idempotency_key="active-upgrade-preexisting",
            request_digest=previous_identity,
            authorization_ref=authorization.authorization_ref,
            action=authorization.action,
            now="2026-08-04T00:00:00+00:00",
        )
        if not created:
            raise AssertionError("active-upgrade journal seed was not newly reserved")
        operation = journal.transition(
            operation.operation_id,
            OperationState.AUTHORIZED,
            summary="disposable active-upgrade authority retained",
            now="2026-08-04T00:00:01+00:00",
        )
        operation = journal.transition(
            operation.operation_id,
            OperationState.EXECUTING,
            summary="disposable active-upgrade journal retained",
            now="2026-08-04T00:00:02+00:00",
        )
        operation = journal.transition(
            operation.operation_id,
            OperationState.SUCCEEDED,
            host_state_changed=False,
            result={"retained": True},
            summary="disposable active-upgrade journal terminal",
            now="2026-08-04T00:00:03+00:00",
        )
        if operation.state != OperationState.SUCCEEDED:
            raise AssertionError("active-upgrade journal seed did not reach a terminal state")
    finally:
        journal.close()
    return "verified_no_op"


def _write_runtime_artifact(path: Path, artifact_bytes: bytes) -> None:
    path.write_bytes(artifact_bytes)
    path.chmod(0o400)


def _read_runtime_artifact(path: Path) -> str:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o400:
        raise AssertionError("disposable runtime artifact is not immutable")
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _seed_runtime_artifacts(
    workspace: Path,
    *,
    previous_bytes: bytes,
    previous_identity: str,
    planned_bytes: bytes,
    planned_identity: str,
    retain_previous_runtime: bool,
    tamper_installed_runtime: bool,
) -> dict[str, str]:
    """Install the deterministic planned candidate without a process lifecycle."""
    if previous_identity == planned_identity:
        raise AssertionError("active-upgrade runtime identities are invalid")
    artifact_dir = workspace / "runtime-artifacts"
    artifact_dir.mkdir(mode=0o700, exist_ok=True)
    artifact_dir.chmod(0o700)
    previous_path = artifact_dir / "previous.json"
    planned_path = artifact_dir / "planned.json"
    installed_path = artifact_dir / "installed.json"
    _write_runtime_artifact(previous_path, previous_bytes)
    _write_runtime_artifact(planned_path, planned_bytes)
    _write_runtime_artifact(installed_path, previous_bytes if retain_previous_runtime else planned_bytes)
    if tamper_installed_runtime:
        installed_path.chmod(0o600)
        installed_path.write_bytes(installed_path.read_bytes() + b"!")
        installed_path.chmod(0o400)
    identities = {
        "previous": _read_runtime_artifact(previous_path),
        "planned": _read_runtime_artifact(planned_path),
        "installed": _read_runtime_artifact(installed_path),
    }
    if identities["previous"] != previous_identity or identities["planned"] != planned_identity:
        raise AssertionError("runtime artifact identities diverged from the fixture")
    return identities


def _child_run(
    contract_path: Path,
    scenario_name: str,
    workspace: Path,
    builder_path: Path,
    *,
    include_backup_restore: bool,
    retain_previous_runtime: bool,
    tamper_installed_runtime: bool,
) -> dict[str, object]:
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    scenarios = {item["name"]: item for item in contract["scenarios"]}
    if scenario_name not in {"clean_install", "active_service_upgrade"} or scenario_name not in scenarios:
        raise ValueError("unsupported Capability A acceptance scenario")
    scenario = scenarios[scenario_name]
    if not isinstance(scenario, Mapping):
        raise ValueError("acceptance scenario must be an object")
    workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
    root = workspace / "disposable-root"
    nested = root / "nested"
    nested.mkdir(parents=True)
    for name in ("alpha.txt", "bravo.txt", "charlie.txt"):
        (root / name).write_text(name + "\n", encoding="utf-8")
    (nested / "delta.txt").write_text("delta\n", encoding="utf-8")
    registration = contract["root_registration"]
    authority_path = workspace / "authority.json"
    authority = {
        "project_id": registration["project_id"],
        "root_id": registration["root_id"],
        "policy_revision": registration["policy_revision"],
        "alias": registration["alias"],
        "max_bytes": registration["max_bytes"],
        "root_path": str(root.resolve()),
    }
    authority_bytes = json.dumps(authority, sort_keys=True, separators=(",", ":")).encode()
    authority_path.write_bytes(authority_bytes)
    authority_path.chmod(0o400)
    if not _sealed_authority_status(authority_path, authority_bytes):
        raise AssertionError("disposable authority was not sealed before composition")
    authority_digest = "sha256:" + hashlib.sha256(authority_bytes).hexdigest()
    registration_disposition = None
    runtime_identity = None
    if scenario_name == "active_service_upgrade":
        from overseer.backup_contract import previous_runtime_artifact_bytes, runtime_artifact_bytes

        runtime = contract["runtime_identity"]
        if not isinstance(runtime, Mapping) or scenario.get("previous_runtime_identity") != runtime.get("previous_identity") or scenario.get("planned_runtime_identity") != runtime.get("planned_identity"):
            raise AssertionError("active-upgrade scenario does not match the reviewed runtime identity")
        registration_disposition = _seed_active_upgrade_state(
            workspace,
            registration,
            root,
            str(scenario["previous_runtime_identity"]),
        )
        runtime_identity = _seed_runtime_artifacts(
            workspace,
            previous_bytes=previous_runtime_artifact_bytes(str(runtime["commit"]), contract["mcp_tools"]),
            previous_identity=str(scenario["previous_runtime_identity"]),
            planned_bytes=runtime_artifact_bytes(str(runtime["commit"]), contract["mcp_tools"]),
            planned_identity=str(scenario["planned_runtime_identity"]),
            retain_previous_runtime=retain_previous_runtime,
            tamper_installed_runtime=tamper_installed_runtime,
        )
    service = _load_builder(builder_path)(workspace, authority_path)
    from theunderdark.production_app import create_production_mcp
    from overseer.storage_adapter import (
        MCPBoundedStorageAdapterClient,
        StorageResultStatus,
        canonical_adapter_request_digest,
    )

    bridge = SynchronousMCPBridge(create_production_mcp(service))
    adapter = MCPBoundedStorageAdapterClient(bridge.call_tool, adapter_revision=1)
    health = adapter.health()
    project_envelope = adapter.project_get(registration["project_id"])
    root_envelope = adapter.root_get(registration["project_id"], registration["root_id"])
    first = adapter.directory_list(registration["project_id"], registration["root_id"], "", registration["policy_revision"], limit=2)
    second = adapter.directory_list(registration["project_id"], registration["root_id"], "", registration["policy_revision"], cursor=first["result"]["next_cursor"], limit=2)
    nested_envelope = adapter.directory_list(registration["project_id"], registration["root_id"], "nested", registration["policy_revision"], limit=2)
    first_result = first["result"]
    second_result = second["result"]
    entries = [entry["name"] for entry in first_result["entries"] + second_result["entries"]]
    if first_result["snapshot_identity"] != second_result["snapshot_identity"]:
        raise AssertionError("pagination did not retain a stable snapshot identity")
    if first_result["total_count"] != second_result["total_count"] or len(entries) != len(set(entries)):
        raise AssertionError("pagination did not preserve a complete duplicate-free traversal")
    common_result = {
        "initialized": {"health": health, "tools": bridge.discovered_tools},
        "project": {"name": "DonutHole", "project_id": registration["project_id"], "roots": project_envelope["result"]["roots"]},
        "root": {**root_envelope["result"], "relative_path": ""},
        "root_listing": {"relative_path": "", "entries": [entry["name"] for entry in first_result["entries"]]},
        "nested_listing": {"relative_path": "nested", "entries": [entry["name"] for entry in nested_envelope["result"]["entries"]]},
        "pagination": {
            "entries": entries,
            "next_cursor": second_result["next_cursor"],
            "page_size": 2,
            "snapshot_identity": first_result["snapshot_identity"],
            "total_count": first_result["total_count"],
        },
        "authority": {"digest": authority_digest, "unchanged": _sealed_authority_status(authority_path, authority_bytes)},
    }
    if not common_result["authority"]["unchanged"]:
        raise AssertionError("authority changed after disposable composition")
    if scenario_name == "active_service_upgrade":
        assert runtime_identity is not None and registration_disposition is not None
        matches_plan = runtime_identity["installed"] == runtime_identity["planned"]
        return {
            **common_result,
            "registration_disposition": registration_disposition,
            "runtime_identity": {**runtime_identity, "matches_plan": matches_plan},
            "terminal_status": "acceptance_passed" if matches_plan else "acceptance_failed",
            **({} if matches_plan else {"evidence": {"code": "runtime_identity_mismatch", "redacted": True}}),
        }
    if not include_backup_restore:
        return common_result
    requests = contract["acceptance_requests"]
    create_payload = requests["backup_create"]["parameters"]
    create_request = _fixture_execution_request(
        payload=create_payload,
        action="backup.create",
        parameters={
            "source_root_id": create_payload["source_root_id"],
            "retention_count": create_payload["retention_count"],
            "encryption_profile": create_payload["encryption_profile"],
        },
    )
    create_transport = _configure_disposable_backup_execution(
        service,
        workspace,
        create_request,
        root,
        journal_name="backup-create",
    )
    create_receipt = adapter.submit(create_request)
    create_result = adapter.get_operation(create_request.project_id, create_receipt.operation_id)
    if create_result.status != StorageResultStatus.COMPLETED:
        raise AssertionError("disposable backup did not reach verified completion")
    expected_create_digest = canonical_adapter_request_digest(create_request)
    if (
        create_transport.request_digests != [expected_create_digest]
        or create_receipt.request_digest != expected_create_digest
        or create_result.request_digest != expected_create_digest
    ):
        raise AssertionError("backup verification did not receive the canonical adapter request digest")
    create_envelope = bridge.call_tool(
        "underdark_operation_get",
        {"project_id": create_request.project_id, "operation_id": create_receipt.operation_id},
    )
    create_details = create_envelope.get("result")
    if not isinstance(create_details, Mapping) or create_envelope.get("request_digest") != expected_create_digest:
        raise AssertionError("backup operation did not expose a bounded result")
    artifact_id = create_details.get("artifact_id")
    artifact_digest = create_details.get("artifact_digest")
    manifest_digest = create_details.get("manifest_digest")
    if not all(isinstance(value, str) and value.startswith("sha256:") for value in (artifact_digest, manifest_digest)) or not isinstance(artifact_id, str):
        raise AssertionError("backup operation did not return canonical artifact identities")
    verify_template = requests["backup_verify_restore"]["parameters"]
    verify_parameters = {
        "artifact_id": artifact_id,
        "expected_artifact_digest": artifact_digest,
        "expected_manifest_digest": manifest_digest,
    }
    verify_request = _fixture_execution_request(
        payload=verify_template,
        action="backup.verify_restore",
        parameters=verify_parameters,
    )
    verify_transport = _configure_disposable_backup_execution(
        service,
        workspace,
        verify_request,
        root,
        journal_name="backup-verify",
    )
    verify_receipt = adapter.submit(verify_request)
    verify_result = adapter.get_operation(verify_request.project_id, verify_receipt.operation_id)
    if verify_result.status != StorageResultStatus.COMPLETED:
        raise AssertionError("disposable restore verification did not reach verified completion")
    expected_verify_digest = canonical_adapter_request_digest(verify_request)
    if (
        verify_transport.request_digests != [expected_verify_digest]
        or verify_receipt.request_digest != expected_verify_digest
        or verify_result.request_digest != expected_verify_digest
    ):
        raise AssertionError("restore verification did not receive the canonical adapter request digest")
    verify_envelope = bridge.call_tool(
        "underdark_operation_get",
        {"project_id": verify_request.project_id, "operation_id": verify_receipt.operation_id},
    )
    verify_details = verify_envelope.get("result")
    if (
        not isinstance(verify_details, Mapping)
        or verify_envelope.get("request_digest") != expected_verify_digest
        or verify_details.get("manifest_digest") != manifest_digest
    ):
        raise AssertionError("restored content did not match the source backup manifest")
    authority_unchanged = _sealed_authority_status(authority_path, authority_bytes)
    if not authority_unchanged:
        raise AssertionError("authority changed after disposable restore verification")
    return {
        **common_result,
        "backup": {
            "status": "completed",
            "request_digest": create_result.request_digest,
            "artifact_identity": artifact_id,
            "source_content_digest": manifest_digest,
        },
        "restore": {
            "status": "verified",
            "request_digest": verify_result.request_digest,
            "restored_content_digest": verify_details["manifest_digest"],
        },
    }


def _main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--include-backup-restore", action="store_true")
    parser.add_argument("--retain-previous-runtime", action="store_true")
    parser.add_argument("--tamper-installed-runtime", action="store_true")
    parser.add_argument("contract_path", type=Path)
    parser.add_argument("scenario_name")
    parser.add_argument("workspace", type=Path)
    parser.add_argument("builder_path", type=Path)
    arguments = parser.parse_args()
    if not arguments.child:
        raise SystemExit("this support module is invoked by run_acceptance_scenario")
    print(json.dumps(_child_run(
        arguments.contract_path,
        arguments.scenario_name,
        arguments.workspace,
        arguments.builder_path,
        include_backup_restore=arguments.include_backup_restore,
        retain_previous_runtime=arguments.retain_previous_runtime,
        tamper_installed_runtime=arguments.tamper_installed_runtime,
    ), sort_keys=True))


if __name__ == "__main__":
    _main()
