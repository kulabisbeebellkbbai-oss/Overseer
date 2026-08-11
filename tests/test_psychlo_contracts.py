from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json

import pytest

from overseer.psychlo_contracts import (
    ContractError,
    canonical_digest,
    parse_adoption_evidence,
    parse_concurrency_canary_result,
    parse_ingress_conflict_reconciliation,
    parse_external_round,
    parse_learning_observation,
    parse_registry_candidate,
    parse_telemetry_checkpoint,
)


NOW = "2026-08-10T02:00:00+00:00"


def test_telemetry_contract_accepts_hybrid_checkpoint_and_digest_is_stable():
    payload = {
        "checkpointId": "checkpoint-1", "projectId": "arcade", "planId": "plan-1",
        "roundId": "round-1", "threadId": "thread-1", "model": "gpt-5.6-luna",
        "featureClass": "backend", "sampleKind": "baseline",
        "cumulative": {"cachedInput": 1, "uncachedInput": 2, "output": 3, "reasoning": 4, "total": 10},
        "activeMs": 10, "waitingMs": 2, "providerSnapshotId": "snapshot-1",
        "providerCapturedAt": NOW, "attribution": "isolated", "sourceId": "overseer",
        "correlationId": "corr-1", "idempotencyKey": "checkpoint-1", "occurredAt": NOW,
        "schemaVersion": "psychlo.telemetry.v1",
    }
    parsed = parse_telemetry_checkpoint(payload)
    assert parsed["cumulative"]["total"] == 10
    assert canonical_digest(payload) == canonical_digest(json.loads(json.dumps(payload)))


def test_contracts_reject_unknown_fields_and_nonmonotonic_or_bad_digest():
    payload = {"id": "observation-1", "featureProfile": {"taskClass": "python-feature"}, "outcome": {"status": "completed"}, "sourceId": "overseer", "correlationId": "corr", "idempotencyKey": "observation-1", "occurredAt": NOW, "schemaVersion": "psychlo.learning.v1"}
    with pytest.raises(ContractError):
        parse_learning_observation({**payload, "prompt": "secret"})
    candidate = {"candidateId": "candidate-1", "targetProjectId": "arcade", "registryId": "registry-1", "registryDigest": "a" * 64, "evidenceIds": ["evidence-1"], "evidenceDigests": ["b" * 64], "evidenceKinds": ["registry"], "canonical": True, "sourceId": "overseer", "messageId": "candidate-1", "correlationId": "corr", "idempotencyKey": "candidate-1", "occurredAt": NOW, "schemaVersion": "psychlo.registry-candidate.v1"}
    assert parse_registry_candidate(candidate)["canonical"] is True
    with pytest.raises(ContractError):
        parse_registry_candidate({**candidate, "registryDigest": "not-a-digest"})


def test_external_round_requires_digest_and_blocker_for_blocked_result():
    payload = {"reconciliationId": "reconcile-1", "externalExecutionId": "execution-1", "projectId": "arcade", "aTeamId": "team-1", "planId": "plan-1", "planVersion": "v1", "projectLeadId": "lead-1", "threadId": "thread-1", "repository": {"pathIdentity": "repo-identity", "beforeHead": "a" * 40, "afterHead": "b" * 40, "dirtyDigest": "c" * 64}, "startingCheckpoint": "checkpoint-start", "terminalCheckpoint": "checkpoint-end", "terminalStatus": "blocked", "deliveredScope": "scope", "remainingWork": "remaining", "blockers": ["gate"], "explicitGate": "approve next round", "evidenceIds": ["evidence-1"], "correlationId": "corr-1", "idempotencyKey": "reconcile-1", "occurredAt": NOW, "schemaVersion": "psychlo.external-round.v1"}
    payload["digest"] = canonical_digest(payload)
    assert parse_external_round(payload)["digest"] == payload["digest"]
    with pytest.raises(ContractError):
        parse_external_round({**payload, "digest": hashlib.sha256(b"wrong").hexdigest(), "blockers": []})


def test_adoption_evidence_is_registry_bound_and_strict():
    reference = {"reason": "registry", "kind": "registry", "evidenceId": "evidence-1", "digest": "a" * 64}
    evidence = {"candidateId": "candidate-1", "registry": {"registryId": "registry-1", "registryDigest": "b" * 64, "evidenceIds": ["evidence-1"], "canonical": True}, "evidence": [reference], "sourceId": "overseer", "messageId": "assessment-1", "correlationId": "corr", "idempotencyKey": "assessment-1", "occurredAt": NOW, "schemaVersion": "psychlo.adoption-evidence.v1"}
    assert parse_adoption_evidence(evidence)["registry"]["canonical"] is True
    with pytest.raises(ContractError):
        parse_adoption_evidence({**evidence, "repository": {"path": "/private"}})


def test_ingress_project_id_is_the_only_exact_optional_key():
    base = {"sourceId": "overseer", "scope": "global", "ingressSourceId": "psychlo", "ingressIdempotencyKey": "ingress-1", "correlationId": "corr", "idempotencyKey": "reconcile-1", "occurredAt": NOW, "provenanceId": "prov-1", "status": "resolved", "ingressType": "overseer.usage-snapshot"}
    assert parse_ingress_conflict_reconciliation(base)["scope"] == "global"
    with pytest.raises(ContractError):
        parse_ingress_conflict_reconciliation({**base, "unexpected": "nope"})
    with pytest.raises(ContractError):
        parse_ingress_conflict_reconciliation({**base, "scope": "project"})


def test_canary_result_contract_rejects_arbitrary_protocol_shape():
    with pytest.raises(ContractError):
        parse_concurrency_canary_result({"resultId": "canary-result-1"})
