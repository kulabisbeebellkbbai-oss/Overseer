import ast
import hashlib
import json
from pathlib import Path

import pytest

from overseer.storage_adapter import BACKUP_ACTION_PARAMETERS, StorageExecutionRequest, canonical_adapter_request_digest


THEUNDERDARK = Path(__file__).resolve().parents[2] / "TheUnderdark"
COMMON = {"project_id", "root_id", "request_id", "idempotency_key", "authorization_ref", "policy_revision", "reason"}


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
