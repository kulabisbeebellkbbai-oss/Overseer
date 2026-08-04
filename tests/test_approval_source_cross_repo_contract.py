from __future__ import annotations

import json
from pathlib import Path


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "approval_source_contract_v1.json"
EXPECTED_STAGE_TYPES = {
    "provider": "string",
    "approvalRef": "string",
    "projectId": "string",
    "workspaceId": "string",
    "resourceRef": "string",
    "authorityClass": "string",
    "scopeDigest": "sha256",
}
EXPECTED_STATUS_TYPES = {
    **EXPECTED_STAGE_TYPES,
    "sourceKind": "string",
    "subject": "string",
    "decision": "approval-decision",
    "decisionVersion": "sha256",
    "updatedAt": "rfc3339-date-time",
}
EXPECTED_CASES = {
    "pending",
    "approved",
    "revision-requested",
    "rejected",
    "provider-failure",
    "changed-replay",
    "exact-replay",
    "malformed-payload",
    "scope-mismatch",
}


def _load_contract() -> dict[str, object]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_canonical_approval_source_contract_has_exact_safe_shapes_and_cases() -> None:
    contract = _load_contract()

    assert set(contract) == {"cases", "contractVersion", "schemas", "stageLocator", "statusProjection"}
    assert contract["contractVersion"] == "approval-source-contract/v1"

    schemas = contract["schemas"]
    assert isinstance(schemas, dict)
    assert schemas == {
        "stageLocator": {"additionalProperties": False, "fields": EXPECTED_STAGE_TYPES},
        "statusProjection": {"additionalProperties": False, "fields": EXPECTED_STATUS_TYPES},
    }

    stage_locator = contract["stageLocator"]
    assert isinstance(stage_locator, dict)
    assert set(stage_locator) == set(EXPECTED_STAGE_TYPES)
    assert "decisionVersion" not in stage_locator
    assert all(isinstance(stage_locator[field], str) for field in EXPECTED_STAGE_TYPES)
    assert stage_locator["scopeDigest"].startswith("sha256:")

    status_projection = contract["statusProjection"]
    assert isinstance(status_projection, dict)
    assert set(status_projection) == set(EXPECTED_STATUS_TYPES)
    assert status_projection["decisionVersion"].startswith("sha256:")

    cases = contract["cases"]
    assert isinstance(cases, list)
    assert {case["name"] for case in cases if isinstance(case, dict)} == EXPECTED_CASES
    assert len(cases) == len(EXPECTED_CASES)

    by_name = {case["name"]: case for case in cases}
    assert by_name["pending"]["expected"] == {"continuation": "blocked", "decision": "pending"}
    assert by_name["approved"]["expected"] == {"continuation": "eligible", "decision": "approved"}
    assert by_name["revision-requested"]["expected"] == {
        "continuation": "blocked",
        "decision": "changes-requested",
    }
    assert by_name["rejected"]["expected"] == {"continuation": "blocked", "decision": "rejected"}
    assert by_name["provider-failure"]["expected"] == {"continuation": "blocked", "retryable": True}
    assert by_name["changed-replay"]["expected"] == {"accepted": False, "result": "changed-replay"}
    assert by_name["exact-replay"]["expected"] == {"accepted": True, "result": "exact-replay"}
    assert by_name["malformed-payload"]["expected"] == {"continuation": "blocked", "result": "invalid-payload"}
    assert by_name["scope-mismatch"]["expected"] == {"continuation": "blocked", "result": "scope-mismatch"}
