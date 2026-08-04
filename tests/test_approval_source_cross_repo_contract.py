from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path

import pytest


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "approval_source_contract_v1.json"
MANIFEST_PATH = Path(__file__).parents[1] / "docs" / "verification" / "approval-source-contract-v1-manifest.md"
WORKSPACE_PATH = FIXTURE_PATH.parents[5]
REVIEWED_FIXTURE_SHA256 = "4d79ef227927c13984ca2f913017352576d3ab8721063197ae049f4f57cf12e7"

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
STAGE_LOCATOR = {
    "provider": "overseer",
    "approvalRef": "approval.fixture.v1",
    "projectId": "project.fixture",
    "workspaceId": "workspace.fixture",
    "resourceRef": "resource.fixture",
    "authorityClass": "project-workflow",
    "scopeDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
}


def _status_projection(decision: str, decision_version: str, updated_at: str) -> dict[str, str]:
    return {
        **STAGE_LOCATOR,
        "sourceKind": "fixture-source",
        "subject": "Synthetic approval fixture",
        "decision": decision,
        "decisionVersion": decision_version,
        "updatedAt": updated_at,
    }


EXPECTED_CASES = [
    {
        "name": "pending",
        "operation": "status-read",
        "statusProjection": _status_projection(
            "pending",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "2026-08-03T00:00:00+00:00",
        ),
        "expected": {"continuation": "blocked", "decision": "pending"},
    },
    {
        "name": "approved",
        "operation": "status-read",
        "statusProjection": _status_projection(
            "approved",
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "2026-08-03T00:01:00+00:00",
        ),
        "expected": {"continuation": "eligible", "decision": "approved"},
    },
    {
        "name": "revision-requested",
        "operation": "status-read",
        "statusProjection": _status_projection(
            "changes-requested",
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "2026-08-03T00:02:00+00:00",
        ),
        "expected": {"continuation": "blocked", "decision": "changes-requested"},
    },
    {
        "name": "rejected",
        "operation": "status-read",
        "statusProjection": _status_projection(
            "rejected",
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "2026-08-03T00:03:00+00:00",
        ),
        "expected": {"continuation": "blocked", "decision": "rejected"},
    },
    {
        "name": "provider-failure",
        "operation": "status-read",
        "input": {"stageLocator": STAGE_LOCATOR},
        "providerFailure": {"code": "provider_unavailable", "retryable": True},
        "expected": {"continuation": "blocked", "retryable": True},
    },
    {
        "name": "changed-replay",
        "operation": "stage",
        "input": {
            "requestDigest": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "storedRequestDigest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        },
        "expected": {"accepted": False, "result": "changed-replay"},
    },
    {
        "name": "exact-replay",
        "operation": "stage",
        "input": {
            "requestDigest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "storedRequestDigest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        },
        "expected": {"accepted": True, "result": "exact-replay"},
    },
    {
        "name": "malformed-payload",
        "operation": "status-read",
        "input": {"payload": "{\"decision\":true}"},
        "expected": {"continuation": "blocked", "result": "invalid-payload"},
    },
    {
        "name": "scope-mismatch",
        "operation": "status-read",
        "input": {
            "requestedScopeDigest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            "returnedScopeDigest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
        },
        "expected": {"continuation": "blocked", "result": "scope-mismatch"},
    },
]
EXPECTED_CONTRACT = {
    "contractVersion": "approval-source-contract/v1",
    "schemas": {
        "stageLocator": {"additionalProperties": False, "fields": EXPECTED_STAGE_TYPES},
        "statusProjection": {"additionalProperties": False, "fields": EXPECTED_STATUS_TYPES},
    },
    "stageLocator": STAGE_LOCATOR,
    "statusProjection": _status_projection(
        "pending",
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "2026-08-03T00:00:00+00:00",
    ),
    "cases": EXPECTED_CASES,
}


def _load_contract() -> dict[str, object]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _manifest_digest(manifest: str) -> str:
    match = re.search(r"^- SHA-256: `([0-9a-f]{64})`$", manifest, flags=re.MULTILINE)
    assert match is not None
    return match.group(1)


def _validate_contract(contract: dict[str, object]) -> None:
    assert contract == EXPECTED_CONTRACT


def _validate_reviewed_digest(fixture_bytes: bytes, manifest: str) -> None:
    assert _manifest_digest(manifest) == REVIEWED_FIXTURE_SHA256
    assert hashlib.sha256(fixture_bytes).hexdigest() == REVIEWED_FIXTURE_SHA256


def test_canonical_approval_source_contract_has_exact_safe_shapes_and_cases() -> None:
    _validate_contract(_load_contract())


def test_manifest_digest_binds_the_exact_canonical_fixture() -> None:
    _validate_reviewed_digest(FIXTURE_PATH.read_bytes(), MANIFEST_PATH.read_text(encoding="utf-8"))


def test_contract_validator_rejects_decision_version_operation_and_input_mutations() -> None:
    missing_decision_version = copy.deepcopy(_load_contract())
    del missing_decision_version["statusProjection"]["decisionVersion"]
    with pytest.raises(AssertionError):
        _validate_contract(missing_decision_version)

    changed_operation = copy.deepcopy(_load_contract())
    changed_operation["cases"][0]["operation"] = "stage"
    with pytest.raises(AssertionError):
        _validate_contract(changed_operation)

    changed_input = copy.deepcopy(_load_contract())
    changed_input["cases"][4]["input"]["stageLocator"] = {
        **STAGE_LOCATOR,
        "scopeDigest": "sha256:" + "0" * 64,
    }
    with pytest.raises(AssertionError):
        _validate_contract(changed_input)


def test_reviewed_digest_validator_rejects_a_stale_manifest_digest() -> None:
    stale_manifest = MANIFEST_PATH.read_text(encoding="utf-8").replace(
        REVIEWED_FIXTURE_SHA256,
        "0" * 64,
        1,
    )
    with pytest.raises(AssertionError):
        _validate_reviewed_digest(FIXTURE_PATH.read_bytes(), stale_manifest)


def test_consumer_contract_tests_do_not_depend_on_a_sibling_worktree_layout() -> None:
    consumer_tests = (
        WORKSPACE_PATH
        / "Roadex"
        / ".worktrees"
        / "reusable-approval-facility"
        / "tests"
        / "approvalSourceContract.test.ts",
        WORKSPACE_PATH
        / "Overseer"
        / ".worktrees"
        / "donuthole-reusable-approval-facility"
        / "tests"
        / "tools"
        / "test_approval_source_contract.py",
    )

    for consumer_test in consumer_tests:
        assert ".worktrees" not in consumer_test.read_text(encoding="utf-8")
