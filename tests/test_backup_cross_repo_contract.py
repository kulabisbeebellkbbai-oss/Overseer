import ast
import copy
import hashlib
import json
import subprocess
import textwrap
from pathlib import Path

import pytest

from overseer.backup_contract import (
    PROVISIONING_CONTRACT_VERSION,
    canonical_contract_bytes,
    load_provisioning_contract,
    runtime_artifact_identity,
)
from overseer.backup_host_operations import EXPECTED_BACKUP_TOOL_SCHEMAS
from overseer.storage_adapter import BACKUP_ACTION_PARAMETERS, StorageExecutionRequest, canonical_adapter_request_digest


THEUNDERDARK = Path(__file__).resolve().parents[2] / "TheUnderdark"
FIXTURE = Path(__file__).parent / "fixtures/contracts/donuthole_backup_provisioning_v1.json"
COMMON = {"project_id", "root_id", "request_id", "idempotency_key", "authorization_ref", "policy_revision", "reason"}


def test_provisioning_contract_fixture_is_canonical_complete_and_matches_current_mcp_schemas():
    contract = load_provisioning_contract(FIXTURE)

    assert contract.version == PROVISIONING_CONTRACT_VERSION == "1"
    assert set(contract.raw) == {
        "version",
        "canonical_plan_input",
        "crew_requirements",
        "root_registration",
        "runtime_identity",
        "mcp_tools",
        "acceptance_requests",
        "scenarios",
    }
    assert FIXTURE.read_bytes() == canonical_contract_bytes(contract.raw)
    assert contract.raw["mcp_tools"] == EXPECTED_BACKUP_TOOL_SCHEMAS
    assert [scenario["name"] for scenario in contract.raw["scenarios"]] == [
        "clean_install",
        "active_service_upgrade",
    ]


def test_provisioning_contract_rejects_noncanonical_bytes_and_invalid_nested_types(tmp_path):
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    invalid = copy.deepcopy(raw)
    invalid["acceptance_requests"]["backup_create"]["parameters"]["retention_count"] = True
    invalid_path = tmp_path / "invalid.json"
    invalid_path.write_bytes(canonical_contract_bytes(invalid))

    with pytest.raises(ValueError, match="retention_count"):
        load_provisioning_contract(invalid_path)

    noncanonical_path = tmp_path / "noncanonical.json"
    noncanonical_path.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    with pytest.raises(ValueError, match="canonical JSON"):
        load_provisioning_contract(noncanonical_path)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda raw: raw["acceptance_requests"]["backup_create"]["parameters"].__setitem__("policy_revision", "2"),
            "backup_create policy revision does not match root registration",
        ),
        (
            lambda raw: raw["acceptance_requests"]["backup_verify_restore"]["parameters"].__setitem__("policy_revision", "2"),
            "backup_verify_restore policy revision does not match root registration",
        ),
        (
            lambda raw: raw["acceptance_requests"]["backup_create"]["parameters"].__setitem__("source_root_id", "different-root"),
            "backup_create source root does not match root registration",
        ),
    ],
)
def test_provisioning_contract_rejects_backup_request_registration_mismatches(tmp_path, mutation, message):
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    mutation(raw)
    path = tmp_path / "mismatched-contract.json"
    path.write_bytes(canonical_contract_bytes(raw))

    with pytest.raises(ValueError, match=message):
        load_provisioning_contract(path)


def test_provisioning_contract_rejects_active_upgrade_without_a_distinct_previous_runtime(tmp_path):
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    planned = raw["runtime_identity"]["planned_identity"]
    raw["runtime_identity"]["previous_identity"] = planned
    raw["scenarios"][1]["previous_runtime_identity"] = planned
    path = tmp_path / "same-runtime-contract.json"
    path.write_bytes(canonical_contract_bytes(raw))

    with pytest.raises(ValueError, match="previous identity must differ"):
        load_provisioning_contract(path)


def test_runtime_artifact_identity_is_deterministic_and_schema_bound():
    identity = runtime_artifact_identity("a" * 40, EXPECTED_BACKUP_TOOL_SCHEMAS)

    assert identity == runtime_artifact_identity("a" * 40, EXPECTED_BACKUP_TOOL_SCHEMAS)
    assert identity != runtime_artifact_identity("b" * 40, EXPECTED_BACKUP_TOOL_SCHEMAS)
    altered = copy.deepcopy(EXPECTED_BACKUP_TOOL_SCHEMAS)
    altered["underdark_backup_create"]["properties"]["retention_count"] = {"type": "number"}
    assert identity != runtime_artifact_identity("a" * 40, altered)


@pytest.mark.skipif(not THEUNDERDARK.exists(), reason="sibling TheUnderdark checkout is unavailable")
@pytest.mark.parametrize("function,action", [("backup_create", "backup.create"), ("backup_verify_restore", "backup.verify_restore")])
def test_theunderdark_mcp_signatures_match_overseer_canonical_payload(function, action):
    tree = ast.parse((THEUNDERDARK / "src/theunderdark/production_app.py").read_text())
    node = next(item for item in ast.walk(tree) if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == function)
    assert {argument.arg for argument in node.args.args} == COMMON | set(BACKUP_ACTION_PARAMETERS[action])


@pytest.mark.skipif(not THEUNDERDARK.exists(), reason="sibling TheUnderdark checkout is unavailable")
def test_overseer_and_theunderdark_use_identical_backup_digest_formula():
    request = StorageExecutionRequest("req", "adapter", 1, "project", "storage.project", "root", "backup.create", {"source_root_id": "root", "retention_count": 3, "encryption_profile": "gpg-symmetric-aes256-iterated-s2k"}, "1", "claim", "approval", "authorization", "idem", "project", "reason", (), {"max_bytes": 1, "max_items": 1}, "2099-01-01T00:00:00+00:00").with_digest()
    payload = {"project_id": request.project_id, "root_id": request.root_id, "request_id": request.request_id, "idempotency_key": request.idempotency_key, "authorization_ref": request.authorization_ref, "policy_revision": request.policy_revision, "reason": request.reason, **request.parameters}
    underdark_digest = "sha256:" + hashlib.sha256(json.dumps({"action": request.action, "request": payload}, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
    assert canonical_adapter_request_digest(request) == underdark_digest


@pytest.mark.skipif(not THEUNDERDARK.exists(), reason="sibling TheUnderdark checkout is unavailable")
def test_theunderdark_registration_keeps_root_owned_config_immutable_and_writes_service_state(tmp_path):
    """Model root-owned config plus mutable state owned by the service identity."""
    sibling_python = THEUNDERDARK / ".venv/bin/python"
    if not sibling_python.exists():
        pytest.skip("sibling TheUnderdark virtual environment is unavailable")
    script = textwrap.dedent("""
        import hashlib, json, sys
        from pathlib import Path
        from theunderdark.production_cli import OverseerRootControlVerifier, build_runtime, register_approved_root
        from theunderdark.root_registry import ControlPlaneApproval

        base=Path(sys.argv[1]); config_dir=base/'root-owned-config'; config_dir.mkdir(mode=0o700)
        state_dir=base/'service-state'; state_dir.mkdir(mode=0o700); source=base/'source'; source.mkdir()
        token=base/'overseer.token'; token.write_text('test-token\\n'); token.chmod(0o600)
        cursor=base/'cursor.key'; cursor.write_bytes(b'k'*32); cursor.chmod(0o600)
        registration={'project_id':'project.donuthole','root_id':'backup-root','policy_revision':'1','host_path':source,'alias':'donuthole-development','max_bytes':1073741824}
        info=source.stat(); approval_payload={'project_id':registration['project_id'],'root_id':registration['root_id'],'policy_revision':registration['policy_revision'],'alias':registration['alias'],'status':'active','max_bytes':registration['max_bytes'],'root_identity':'sha256:'+hashlib.sha256(f'{info.st_dev}:{info.st_ino}'.encode()).hexdigest()}
        target_digest='sha256:'+hashlib.sha256(json.dumps(approval_payload,sort_keys=True,separators=(',',':')).encode()).hexdigest(); authorization_ref='root-auth.donuthole.backup-root'
        config={'host':'127.0.0.1','port':8799,'state_dir':str(state_dir),'journal_path':str(state_dir/'journal.sqlite3'),'admission_path':str(state_dir/'admission.sqlite3'),'pagination_path':str(state_dir/'pages.sqlite3'),'registry_path':str(state_dir/'roots.sqlite3'),'overseer_authorization_endpoint':'http://127.0.0.1:8766/storage/authorizations/verify','overseer_root_endpoint':'http://127.0.0.1:8766/storage/roots/verify','overseer_token_file':str(token),'cursor_key_file':str(cursor),'root_authorization_refs':{target_digest:authorization_ref},'limits':{'max_storage_bytes':1073741824,'max_concurrent_operations':1,'max_requests_per_window':10,'rate_window_seconds':60},'backup_bindings':[]}
        config_path=config_dir/'donuthole.json'; config_path.write_text(json.dumps(config,sort_keys=True,separators=(',',':'))); config_path.chmod(0o600); original=config_path.read_bytes(); config_dir.chmod(0o500)
        OverseerRootControlVerifier.verify=lambda _self,action,payload,digest:ControlPlaneApproval('approval.storage.root.donuthole',action,payload['project_id'],payload['root_id'],payload['policy_revision'],digest,'approved','2099-01-01T00:00:00+00:00')
        try:
            assert register_approved_root(config_path,authorization_ref=authorization_ref,**registration)==target_digest
            assert register_approved_root(config_path,authorization_ref=authorization_ref,**registration)==target_digest
            assert config_path.read_bytes()==original
            with build_runtime(config_path) as runtime: assert runtime.registry.root_ids('project.donuthole')==('backup-root',)
        finally: config_dir.chmod(0o700)
    """)
    result = subprocess.run(
        [str(sibling_python), "-c", script, str(tmp_path)],
        cwd=THEUNDERDARK,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert result.returncode == 0, result.stderr
