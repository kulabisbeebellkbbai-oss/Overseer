from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path

import pytest

from overseer.psychlo_contracts import (
    ContractError,
    canonical_digest,
    cross_project_work_request_digest,
    cross_project_work_request_id,
    learning_observation_digest,
    parse_adoption_evidence,
    parse_concurrency_canary_result,
    parse_cross_project_team_binding,
    parse_cross_project_supervisor_review,
    parse_ingress_conflict_reconciliation,
    parse_external_round,
    parse_learning_observation,
    parse_registry_candidate,
    parse_telemetry_checkpoint,
)


NOW = "2026-08-10T02:00:00+00:00"


def test_learning_digest_matches_frozen_psychlo_numeric_normalization_fixtures():
    fixtures = [
        ({"id": "observation-101", "featureProfile": {"taskClass": "python-feature", "expectedComponents": 2}, "outcome": {"status": "completed", "usage": 3, "observedAt": NOW}}, "ef84a116e022acb151adffc683a8b6303a3f32f5529d8c2b8c4a33f2c4e0dcd1"),
        ({"id": "observation-102", "featureProfile": {"taskClass": "python-feature"}, "outcome": {"status": "completed", "actualUsage": 0.5, "observedAt": NOW}}, "4a09c49c48a2018260df77289e432cc43624db09ca7b044d7e0d7f0ab0840b00"),
        ({"id": "observation-103", "featureProfile": {"taskClass": "python-feature"}, "outcome": {"status": "blocked", "remainingUsage": 1e3, "observedAt": NOW}}, "aad3005b5200248490e7bc7603daf525e95bf6dcec23032cf7d072ca15f4b3d8"),
        ({"id": "observation-104", "featureProfile": {"taskClass": "python-feature", "buildGate": True}, "outcome": {"status": "completed", "actualUsage": -0.0, "observedAt": NOW}}, "c00e79828eff536d72db3641e4219911f55f1edc5096c27799fd2fb4beb3c985"),
    ]
    for payload, expected in fixtures:
        assert learning_observation_digest(payload) == expected
    zero = fixtures[-1][0]
    assert learning_observation_digest({**zero, "outcome": {**zero["outcome"], "actualUsage": 0.0}}) == fixtures[-1][1]


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
    evidence = {"candidateId": "candidate-1", "assessmentId": "assessment-1", "registry": {"registryId": "registry-1", "registryDigest": "b" * 64, "evidenceIds": ["evidence-1"], "canonical": True}, "evidence": [reference], "sourceId": "overseer", "messageId": "assessment-1", "correlationId": "corr", "idempotencyKey": "assessment-1", "occurredAt": NOW, "schemaVersion": "psychlo.adoption-evidence.v1"}
    assert parse_adoption_evidence(evidence)["registry"]["canonical"] is True
    with pytest.raises(ContractError):
        parse_adoption_evidence({**evidence, "repository": {"path": "/private"}})


def test_adoption_evidence_accepts_psychlo_classification_facts_without_paths_or_secrets():
    digest = "a" * 64
    ref = lambda reason, kind, evidence_id: {"reason": reason, "kind": kind, "evidenceId": evidence_id, "digest": digest}
    evidence = {
        "candidateId": "candidate-1", "assessmentId": "assessment-1",
        "registry": {"registryId": "registry-1", "registryDigest": digest, "evidenceIds": ["registry-1", "repo-1", "artifact-1", "application-1", "team-1", "ownership-1", "plan-1", "lead-1", "checkpoint-1", "security-1"], "canonical": True},
        "repository": {"present": True, "canonical": True, "digest": digest, "clean": True, "status": "known", "evidenceRef": ref("canonical-repository", "repository", "repo-1")},
        "artifact": {"present": True, "deployable": True, "digest": digest, "evidenceRef": ref("deployable-artifact", "artifact", "artifact-1")},
        "application": {"present": True, "purpose": "service", "provenanceTrusted": True, "evidenceRef": ref("application-purpose", "application", "application-1")},
        "team": {"present": True, "authoritative": True, "provenanceTrusted": True, "teamId": "team-1", "leadId": "lead-1", "evidenceRef": ref("team-baseline", "team", "team-1")},
        "ownership": {"trusted": True, "provenanceTrusted": True, "license": "MIT", "evidenceRef": ref("ownership", "ownership", "ownership-1"), "licenseEvidenceRef": ref("license", "ownership", "ownership-1")},
        "plan": {"present": True, "status": "approved", "planId": "plan-1", "planVersion": "v1", "evidenceRef": ref("active-plan", "plan", "plan-1")},
        "lead": {"resolved": True, "authoritative": True, "leadId": "lead-1", "teamId": "team-1", "evidenceRef": ref("lead", "lead", "lead-1")},
        "checkpoint": {"present": True, "state": "pending", "checkpointId": "checkpoint-1", "threadId": "thread-1", "evidenceRef": ref("checkpoint", "checkpoint", "checkpoint-1")},
        "security": {"reasons": ["unsafe-files"], "evidence": [ref("unsafe-files", "security", "security-1")]},
        "contradictions": ["dirty-repository"],
        "evidence": [ref("registry", "registry", "registry-1"), ref("canonical-repository", "repository", "repo-1"), ref("deployable-artifact", "artifact", "artifact-1"), ref("application-purpose", "application", "application-1"), ref("team-baseline", "team", "team-1"), ref("ownership", "ownership", "ownership-1"), ref("active-plan", "plan", "plan-1"), ref("lead", "lead", "lead-1"), ref("checkpoint", "checkpoint", "checkpoint-1"), ref("unsafe-files", "security", "security-1")],
        "sourceId": "overseer", "messageId": "assessment-1", "correlationId": "corr", "idempotencyKey": "assessment-1", "occurredAt": NOW, "schemaVersion": "psychlo.adoption-evidence.v1",
    }
    assert parse_adoption_evidence(evidence)["repository"]["status"] == "known"
    wire = {"candidateId": evidence["candidateId"], "assessmentId": evidence["assessmentId"], "evidence": {key: value for key, value in evidence.items() if key in {"candidateId", "registry", "repository", "artifact", "application", "team", "ownership", "plan", "lead", "checkpoint", "security", "contradictions", "evidence"}}, "sourceId": "overseer", "messageId": evidence["assessmentId"], "correlationId": evidence["correlationId"], "idempotencyKey": evidence["idempotencyKey"], "occurredAt": evidence["occurredAt"], "schemaVersion": evidence["schemaVersion"]}
    assert parse_adoption_evidence(wire)["assessmentId"] == "assessment-1"
    with pytest.raises(ContractError):
        parse_adoption_evidence({**evidence, "repository": {**evidence["repository"], "path": "/private"}})
    with pytest.raises(ContractError):
        parse_adoption_evidence({**evidence, "secret": "do-not-store"})


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


def test_team_binding_contract_matches_exact_psychlo_schema_without_link_request_fields():
    base = {"bindingId": "binding-1", "coordinationTeamId": "team-1", "supervisorMemberId": "member-1", "supervisorLeadId": "lead-1", "approvalId": "approval-1", "approvalProvenanceId": "provenance-1", "approvedAt": NOW, "correlationId": "binding-1", "idempotencyKey": "binding-1", "occurredAt": NOW}
    binding = {**base, "digest": hashlib.sha256(json.dumps(base, separators=(",", ":")).encode()).hexdigest()}
    assert parse_cross_project_team_binding(binding) == binding
    with pytest.raises(ContractError, match="unknown"):
        parse_cross_project_team_binding({**binding, "linkId": "link-1"})


def test_cross_project_work_identity_and_digest_match_psychlo_3d178b6_fixture():
    fixture = json.loads((Path(__file__).parent / "fixtures" / "psychlo-3d178b6-cross-project-work.json").read_text(encoding="utf-8"))
    assert cross_project_work_request_id(fixture["linkId"], fixture["version"], fixture["projectId"]) == fixture["id"]
    assert cross_project_work_request_digest(fixture) == fixture["requestDigest"]


def test_supervisor_review_requires_current_psychlo_receiver_review_id():
    base = {"projectId": "fixture-alpha", "leadId": "lead-fixture-alpha", "supervisorLeadId": "lead-fixture-supervisor", "decision": "accepted", "evidenceId": "evidence:review", "linkId": "fixture-link", "version": "v1", "reviewId": "review-fixture", "resultId": "result-fixture", "participantResults": [{"resultId": "result-fixture", "digest": "a" * 64}], "coordinationTeamId": "team-fixture", "supervisorMemberId": "member-fixture", "accepted": True, "evidence": ["evidence:review"], "correlationId": "review-fixture", "idempotencyKey": "review-fixture", "occurredAt": NOW}
    review = {**base, "digest": canonical_digest(base)}
    assert parse_cross_project_supervisor_review(review) == review
    without_review_id = {key: value for key, value in review.items() if key != "reviewId"}
    with pytest.raises(ContractError, match="missing"):
        parse_cross_project_supervisor_review(without_review_id)
