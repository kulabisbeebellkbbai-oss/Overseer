from __future__ import annotations

import hashlib
import hmac
import json
import multiprocessing
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
import threading
from types import SimpleNamespace
from http.server import ThreadingHTTPServer
from http.client import HTTPConnection
import pytest
from dataclasses import replace

from overseer.api import make_api_handler

from overseer.psychlo_bridge import (
    PsychloBridge,
    PsychloBridgeStore,
    CodexProjectDispatcher,
    derive_usage_snapshot,
    sign_peer_message,
    verify_peer_request,
    _read_secret,
)
from overseer.psychlo_contracts import canonical_digest
from overseer.psychlo_store import _round_result_digest
from overseer.audit import ApprovalRequest, ApprovalStatus
from overseer.core import ApprovalLevel, OwnerDomain
from overseer.admin import plan_user_service_restart
from overseer.store import SQLiteStore


SECRET = b"0123456789abcdef0123456789abcdef"
NOW = "2026-08-10T02:00:00+00:00"


def _save_real_approval(path: Path, approval_id: str, operation: dict, action: str, target: str) -> SQLiteStore:
    primary = SQLiteStore(path)
    digest = canonical_digest(operation)
    base = plan_user_service_restart(f"plan-{approval_id}", target, "approved Psychlo bridge operation")
    plan = replace(base, owner_domain=OwnerDomain.SISKO, approval_level=ApprovalLevel.HUMAN, target=target, proposed_state=json.dumps({"action": action, "target": target, "payload": operation, "payloadDigest": digest, "evidence": [digest]}, separators=(",", ":")), approved=True, approved_by="human-user", approved_at=NOW)
    primary.save_admin_change_plan(plan)
    primary.save_approval(ApprovalRequest(approval_id, plan.id, ApprovalLevel.HUMAN, "thread-approval", OwnerDomain.SISKO, "approved Psychlo bridge operation", ApprovalStatus.APPROVED, (digest,), "human-user", NOW))
    return primary


def _coord_request(binding: str, link: str, version: str, project: str, lead: str, supervisor: str, projects: list[str], scope: str = "update shared contract", expected_digest: str = "a" * 64) -> dict:
    digest = lambda value: hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).hexdigest()
    request_id = "cross-project-work:" + digest({"linkId": link, "version": version, "projectId": project})
    value = {"schemaVersion": "psychlo.event.v1", "id": request_id, "linkId": link, "version": version, "projectId": project, "leadId": lead, "coordinationBindingId": binding, "requiredRequestIds": ["cross-project-work:" + digest({"linkId": link, "version": version, "projectId": item}) for item in sorted(projects)], "supervisorLeadId": supervisor, "scope": scope, "evidenceIds": [f"evidence-{project}"], "expectedResultDigest": expected_digest}
    selected = {"coordinationBindingId": binding, "linkId": link, "version": version, "projectId": project, "leadId": lead, "requestId": request_id, "requiredRequestIds": value["requiredRequestIds"], "supervisorLeadId": supervisor, "scope": scope, "evidenceIds": value["evidenceIds"], "expectedResultDigest": expected_digest}
    value["requestDigest"] = digest(selected)
    return value


def _registration_payload(project_id: str, lead_id: str, *, plan_id: str | None = None, plan_version: str = "v1", team_id: str | None = None) -> dict:
    plan_id = plan_id or f"plan-{project_id}"
    team_id = team_id or f"team-{project_id}"
    envelope = {"contractVersion": "a-team.psychlo.handoff.v1", "source": "a-team", "aTeamId": team_id, "approval": {"status": "approved", "approvedAt": NOW}, "project": {"id": project_id, "planId": plan_id, "planVersion": plan_version, "provenancePath": f"/a-team/{team_id}/{project_id}/{plan_id}/{plan_version}"}, "projectLead": {"id": lead_id}, "plan": {"title": project_id, "summary": "approved plan", "goals": ["deliver"], "constraints": [], "deliverables": ["working result"], "tasks": [{"id": "task-1", "ownerMemberId": lead_id, "title": "Implement", "description": "Implement the approved scope", "dependencyIds": [], "acceptanceCriteria": ["verified"]}]}, "correlationId": f"registration-{project_id}", "idempotencyKey": f"registration-{project_id}", "occurredAt": NOW}
    envelope["digest"] = canonical_digest(envelope)
    receipt = {"contractVersion": "a-team.psychlo.receipt.v1", "handoffContractVersion": envelope["contractVersion"], "source": "psychlo", "status": "admitted", "receiptId": f"receipt-{project_id}", "aTeamId": team_id, "project": {"id": project_id, "planId": plan_id, "planVersion": plan_version}, "correlationId": envelope["correlationId"], "idempotencyKey": envelope["idempotencyKey"], "envelopeDigest": envelope["digest"], "receivedAt": NOW}
    return {"envelope": envelope, "receipt": receipt}


def _record_registered_project(store: PsychloBridgeStore, project_id: str, lead_id: str) -> None:
    registration = _registration_payload(project_id, lead_id)
    store.record_project(project_id, registration, _scheduling_payload(registration))


def _scheduling_payload(registration: dict) -> dict:
    envelope = registration["envelope"]; receipt_id = registration["receipt"]["receiptId"]; tasks = envelope["plan"]["tasks"]; constraints = envelope["plan"]["constraints"]
    return {"projectId": envelope["project"]["id"], "projectLeadId": envelope["projectLead"]["id"], "state": "managed", "remainingEffort": "trivial" if len(tasks) == 1 else "standard", "hasSecurityImpact": any("security" in str(item).lower() for item in constraints), "hasDependencyImpact": any(bool(item["dependencyIds"]) for item in tasks), "gateDistance": len(tasks), "expectedUsageCost": max(1, min(10, (len(tasks) + 1) // 2)), "correlationId": f"psychlo-scheduling:{receipt_id}", "idempotencyKey": f"psychlo-scheduling:{receipt_id}", "occurredAt": NOW}


def _coordination_process(store_path: str, calls_path: str, request: dict, barrier) -> None:
    store = PsychloBridgeStore(store_path)
    if store.project(request["projectId"]) is None:
        _record_registered_project(store, request["projectId"], request["leadId"])
    barrier.wait()
    class ProcessDispatcher:
        def prepare(self, _lead_id: str, _scope: str, _idempotency_key: str) -> str:
            return "dispatch-1"

        def __call__(self, lead_id: str, scope: str, idempotency_key: str) -> str:
            connection = sqlite3.connect(calls_path, isolation_level=None)
            connection.execute("INSERT INTO calls VALUES (?,?,?)", (lead_id, scope, idempotency_key))
            connection.close()
            return self.prepare(lead_id, scope, idempotency_key)
    bridge = PsychloBridge(store=store, dispatcher=ProcessDispatcher(), sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    bridge.receive_coordination_work_request(request)


def _coordination_prepare_race_process(store_path: str, calls_path: str, request: dict, role: str, first_prepared, release_first) -> None:
    class RacingDispatcher:
        def prepare(self, _lead_id: str, _scope: str, _idempotency_key: str) -> str:
            if role == "first":
                first_prepared.set()
                if not release_first.wait(10): raise RuntimeError("race release timed out")
            elif not first_prepared.wait(10):
                raise RuntimeError("first prepare did not pause")
            return "dispatch-race"

        def __call__(self, lead_id: str, scope: str, idempotency_key: str) -> str:
            connection = sqlite3.connect(calls_path, isolation_level=None)
            connection.execute("INSERT INTO calls VALUES (?,?,?,?)", (role, lead_id, scope, idempotency_key))
            connection.close()
            if role == "second": release_first.set()
            return "dispatch-race"

    clock = (lambda: "2026-08-10T02:00:00+00:00") if role == "first" else (lambda: "2026-08-10T02:01:00+00:00")
    bridge = PsychloBridge(store=PsychloBridgeStore(store_path), dispatcher=RacingDispatcher(), sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=clock, coordination_lease_seconds=5)
    bridge.receive_coordination_work_request(request)


def _coordination_review_intent_race_process(store_path: str, barrier, result_queue, owner: str) -> None:
    store = PsychloBridgeStore(store_path)
    barrier.wait(10)
    created = store.create_coordination_review_intent("request-1", "review-1", {"requestId": "request-1", "resultId": "result-1"}, owner_id=owner, idempotency_key="review-key-1")
    result_queue.put(created["winner"])


def _single_stream_race_process(store_path: str, barrier, result_queue, suffix: str) -> None:
    store = PsychloBridgeStore(store_path)
    bridge = PsychloBridge(store=store, dispatcher=lambda *_: f"dispatch-{suffix}", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW, token_factory=lambda: f"cap-{suffix}-1234567890abcdef")
    barrier.wait(10)
    request = {"roundId": f"default-race-{suffix}", "projectId": f"project-{suffix}", "projectLeadId": f"lead-{suffix}", "planId": f"plan-{suffix}", "planVersion": "v1", "correlationId": f"corr-{suffix}", "idempotencyKey": f"default-race-{suffix}", "snapshotId": f"snapshot-{suffix}", "policyVersion": "2026-08-09", "expectedUsageCost": 1, "scope": "one bounded round", "selectionReason": "priority-selected", "priorityRationale": "project-id"}
    try:
        bridge.request_round(request)
    except ValueError as error:
        result_queue.put(str(error))
    else:
        result_queue.put("accepted")


def _successful_canary_result(authorization_id: str = "canary-1", projects=(('arcade', 'plan-1', 'v1', 'lead-1'), ('hermione', 'plan-2', 'v1', 'lead-2'))) -> dict:
    def hashed(value: dict) -> str:
        return hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).hexdigest()
    executions = []
    for index, (project_id, plan_id, plan_version, lead_id) in enumerate(projects, start=1):
        execution_id = f"round-{index}"
        started = {"executionId": execution_id, "authorizationId": authorization_id, "projectId": project_id, "planId": plan_id, "planVersion": plan_version, "roundId": execution_id, "leadId": lead_id, "startedAt": f"2026-08-10T02:00:0{index}+00:00"}
        completed = {"executionId": execution_id, "authorizationId": authorization_id, "projectId": project_id, "planId": plan_id, "planVersion": plan_version, "roundId": execution_id, "leadId": lead_id, "settledAt": f"2026-08-10T02:00:1{index}+00:00", "terminalStatus": "completed", "resultDigest": str(index) * 64, "evidenceId": f"evidence-{index}", "evidenceDigest": chr(96 + index) * 64}
        executions.append({"executionId": execution_id, "started": {**started, "digest": hashed(started)}, "completed": {**completed, "digest": hashed(completed)}})
    base = {"resultId": f"canary-result:{authorization_id}", "authorizationId": authorization_id, "targetCeiling": 2, "expectedRevision": 0, "executions": executions, "concurrencyObserved": True, "occurredAt": "2026-08-10T02:00:30+00:00"}
    return {**base, "digest": hashed(base)}


def _peer_fixtures() -> dict:
    return json.loads((Path(__file__).parent / "fixtures" / "psychlo-f0015d6-overseer-peer-fixtures.json").read_text(encoding="utf-8"))


class _PreparedDispatcher:
    def __init__(self, prefix: str = "dispatch", identity=None):
        self.prefix = prefix
        self.identity = identity
        self.calls = []

    def prepare(self, lead_id: str, prompt: str, idempotency_key: str) -> str:
        if self.identity is not None:
            return self.identity(lead_id, prompt, idempotency_key)
        return f"{self.prefix}:{hashlib.sha256(idempotency_key.encode()).hexdigest()}"

    def __call__(self, lead_id: str, prompt: str, idempotency_key: str) -> str:
        self.calls.append((lead_id, prompt, idempotency_key))
        return self.prepare(lead_id, prompt, idempotency_key)


def test_admin_canary_and_later_ceiling_initiators_require_separate_approvals(tmp_path: Path):
    sent = []
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    canary = {"authorizationId": "canary-1", "targetTemporaryCeiling": 2, "expectedGlobalCeiling": 1, "expectedRevision": 0, "projects": [{"projectId": "p1", "planId": "plan-1", "planVersion": "v1", "leadId": "lead-1"}, {"projectId": "p2", "planId": "plan-2", "planVersion": "v1", "leadId": "lead-2"}], "workflowId": "roadex-test", "decisionVersion": "v1", "deadline": "2026-08-10T03:00:00+00:00", "correlationId": "canary-corr", "idempotencyKey": "canary-key", "occurredAt": NOW}
    primary = _save_real_approval(tmp_path / "primary.sqlite3", "admin-canary-approval", canary, "concurrency-canary", "canary-1")
    bridge = PsychloBridge(store=store, dispatcher=lambda *_: "unused", sender=lambda kind, mid, payload: sent.append((kind, mid, payload)) or {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW, approval_store=primary)
    assert bridge.initiate_concurrency_canary_authorization("admin-canary-approval", canary)["inserted"] is True
    assert sent[-1][0] == "concurrency-canary-authorization"
    store.record_protocol("concurrency-canary-result", "canary-result-1", "canary-result-key", "a" * 64, {"resultId": "canary-result-1"})
    ceiling = {"authorizationId": "ceiling-1", "ceiling": 2, "expectedRevision": 0, "revision": 1, "canaryResultId": "canary-result-1", "projectId": "p1", "planId": "plan-1", "workflowId": "roadex-test", "decisionVersion": "v1", "correlationId": "ceiling-corr", "idempotencyKey": "ceiling-key", "occurredAt": NOW}
    primary.save_admin_change_plan(replace(plan_user_service_restart("plan-admin-ceiling", "ceiling-1", "approved Psychlo bridge operation"), owner_domain=OwnerDomain.SISKO, approval_level=ApprovalLevel.HUMAN, proposed_state=json.dumps({"action": "concurrency-ceiling", "target": "ceiling-1", "payload": ceiling, "payloadDigest": canonical_digest(ceiling), "evidence": [canonical_digest(ceiling)]}, separators=(",", ":")), approved=True, approved_by="human-user", approved_at=NOW))
    primary.save_approval(ApprovalRequest("admin-ceiling", "plan-admin-ceiling", ApprovalLevel.HUMAN, "thread-approval", OwnerDomain.SISKO, "approved Psychlo bridge operation", ApprovalStatus.APPROVED, (canonical_digest(ceiling),), "human-user", NOW))
    with pytest.raises(ValueError, match="delivered canary"):
        bridge.initiate_concurrency_ceiling_authorization("admin-ceiling", ceiling)


def _adoption_candidate_payload():
    digest = "a" * 64
    return {"candidateId": "candidate-adoption", "targetProjectId": "arcade", "registryId": "registry-adoption", "registryDigest": digest, "evidenceIds": ["registry-evidence"], "evidenceDigests": [digest], "evidenceKinds": ["registry"], "canonical": True, "correlationId": "registry-correlation", "idempotencyKey": "registry-idempotency", "occurredAt": NOW}


def _adoption_evidence_payload():
    digest = "a" * 64
    reference = {"reason": "registry", "kind": "registry", "evidenceId": "registry-evidence", "digest": digest}
    return {"candidateId": "candidate-adoption", "assessmentId": "assessment-adoption", "registry": {"registryId": "registry-adoption", "registryDigest": digest, "evidenceIds": ["registry-evidence"], "canonical": True}, "evidence": [reference], "correlationId": "assessment-correlation", "idempotencyKey": "assessment-idempotency", "occurredAt": NOW}


def test_adoption_producer_persists_registry_then_exact_signed_receipt_and_replays_after_restart(tmp_path: Path):
    calls = []
    evidence = _adoption_evidence_payload()

    def sender(kind, message_id, payload):
        calls.append((kind, message_id, dict(payload)))
        if kind == "registry-candidate":
            return {"accepted": True, "inserted": True, "registration": {**payload, "sourceId": "overseer", "messageId": payload["candidateId"], "sourceEventSequence": 1}}
        return {"accepted": True, "assessmentId": payload["assessmentId"], "candidateId": payload["candidateId"], "classification": "insufficient-evidence", "confidence": "low", "evidence": payload["evidence"]["evidence"], "missingArtifacts": ["repository-missing"], "contradictions": [], "recommendedWorkflow": "reject", "evidenceDigest": canonical_digest(payload["evidence"])}

    store_path = tmp_path / "adoption.sqlite3"
    bridge = PsychloBridge(store=PsychloBridgeStore(store_path), dispatcher=lambda *_: "unused", sender=sender, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    bridge.register_candidate(_adoption_candidate_payload())
    result = bridge.record_adoption_evidence(evidence)
    assert [call[0] for call in calls] == ["registry-candidate", "adoption-evidence"]
    assert set(calls[1][2]) == {"candidateId", "assessmentId", "evidence", "correlationId", "idempotencyKey", "occurredAt"}
    assert set(calls[1][2]["evidence"]) == {"candidateId", "registry", "evidence"}
    assert result["receipt"]["evidenceDigest"] == canonical_digest(calls[1][2]["evidence"])
    stored = bridge.store.protocol_record("adoption-evidence", "assessment-adoption")
    assert stored is not None and stored["state"] == "delivered" and stored["receipt"]["evidenceDigest"] == canonical_digest(calls[1][2]["evidence"])
    bridge.store.connection.close()

    replay_calls = []
    restarted = PsychloBridge(store=PsychloBridgeStore(store_path), dispatcher=lambda *_: "unused", sender=lambda *args: replay_calls.append(args) or {"accepted": False}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    replay = restarted.record_adoption_evidence(evidence)
    assert replay["replay"] is True
    assert replay["receipt"]["evidenceDigest"] == canonical_digest(calls[1][2]["evidence"])
    assert replay_calls == []

    with pytest.raises(ValueError, match="conflict"):
        restarted.record_adoption_evidence({**evidence, "evidence": [{**evidence["evidence"][0], "evidenceId": "other-evidence"}]})


def test_adoption_producer_recovers_forward_pending_after_restart(tmp_path: Path):
    candidate = _adoption_candidate_payload()
    evidence = _adoption_evidence_payload()
    attempts = []

    def failing_sender(kind, message_id, payload):
        attempts.append(kind)
        if kind == "registry-candidate": return {"accepted": True, "registration": {**payload, "sourceId": "overseer", "messageId": payload["candidateId"], "sourceEventSequence": 1}}
        raise OSError("Psychlo unavailable")

    store_path = tmp_path / "adoption-recovery.sqlite3"
    bridge = PsychloBridge(store=PsychloBridgeStore(store_path), dispatcher=lambda *_: "unused", sender=failing_sender, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    bridge.register_candidate(candidate)
    with pytest.raises(ValueError, match="forward-pending"):
        bridge.record_adoption_evidence(evidence)
    pending = bridge.store.protocol_record("adoption-evidence", "assessment-adoption")
    assert pending is not None and pending["state"] == "forward-pending"
    bridge.store.connection.close()

    def recovered_sender(kind, _message_id, payload):
        if kind == "adoption-evidence":
            return {"accepted": True, "assessmentId": payload["assessmentId"], "candidateId": payload["candidateId"], "classification": "insufficient-evidence", "confidence": "low", "evidence": payload["evidence"]["evidence"], "missingArtifacts": ["repository-missing"], "contradictions": [], "recommendedWorkflow": "reject", "evidenceDigest": canonical_digest(payload["evidence"])}
        return {"accepted": True}

    restarted = PsychloBridge(store=PsychloBridgeStore(store_path), dispatcher=lambda *_: "unused", sender=recovered_sender, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    recovered = restarted.store.protocol_record("adoption-evidence", "assessment-adoption")
    assert recovered is not None and recovered["state"] == "delivered" and recovered["receipt"]["evidenceDigest"] == canonical_digest(restarted.store.protocol_record("adoption-evidence", "assessment-adoption")["payload"]["evidence"])


def test_adoption_producer_rejects_receipt_with_wrong_stable_evidence_digest(tmp_path: Path):
    candidate = _adoption_candidate_payload()
    evidence = _adoption_evidence_payload()

    def sender(kind, _message_id, payload):
        if kind == "registry-candidate":
            return {"accepted": True}
        return {"accepted": True, "assessmentId": payload["assessmentId"], "candidateId": payload["candidateId"], "classification": "insufficient-evidence", "confidence": "low", "evidence": payload["evidence"]["evidence"], "missingArtifacts": ["repository-missing"], "contradictions": [], "recommendedWorkflow": "reject", "evidenceDigest": "f" * 64}

    store = PsychloBridgeStore(tmp_path / "wrong-digest.sqlite3")
    bridge = PsychloBridge(store=store, dispatcher=lambda *_: "unused", sender=sender, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    bridge.register_candidate(candidate)
    with pytest.raises(ValueError, match="forward-pending"):
        bridge.record_adoption_evidence(evidence)
    record = store.protocol_record("adoption-evidence", "assessment-adoption")
    assert record is not None and record["state"] == "forward-pending" and record["receipt"] is None


def test_adoption_producer_requires_fact_references_to_be_registered_and_listed(tmp_path: Path):
    candidate = _adoption_candidate_payload()
    evidence = _adoption_evidence_payload()
    digest = "a" * 64
    fact_ref = {"reason": "canonical-repository", "kind": "repository", "evidenceId": "repository-evidence", "digest": digest}
    evidence["repository"] = {"present": True, "canonical": True, "clean": True, "status": "known", "digest": digest, "evidenceRef": fact_ref}

    calls = []
    def sender(kind, _message_id, payload):
        calls.append(kind)
        return {"accepted": True}

    store = PsychloBridgeStore(tmp_path / "unbound-fact.sqlite3")
    bridge = PsychloBridge(store=store, dispatcher=lambda *_: "unused", sender=sender, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    bridge.register_candidate(candidate)
    with pytest.raises(ValueError, match="registry reference"):
        bridge.record_adoption_evidence(evidence)
    assert store.adoption_evidence("assessment-adoption") is None
    assert calls == ["registry-candidate"]


def test_initiators_reject_caller_supplied_approval_objects(tmp_path: Path):
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    with pytest.raises(ValueError, match="persisted approval record ID"):
        bridge.initiate_concurrency_canary_authorization({"status": "approved"}, {})


def _persist_approved_canary(store: PsychloBridgeStore, *, deadline: str = "2026-08-10T03:00:00+00:00", approve: bool = True) -> dict:
    base = {"authorizationId": "canary-round-admission", "targetTemporaryCeiling": 2, "expectedGlobalCeiling": 1, "expectedRevision": 0, "projects": [{"projectId": "arcade", "planId": "plan-arcade", "planVersion": "v1", "leadId": "lead-arcade"}, {"projectId": "hermione", "planId": "plan-hermione", "planVersion": "v1", "leadId": "lead-hermione"}], "workflowId": "roadex-canary", "decisionVersion": "v1", "deadline": deadline, "correlationId": "canary-round-admission", "idempotencyKey": "canary-round-admission", "occurredAt": NOW}
    digest = hashlib.sha256(json.dumps(base, separators=(",", ":")).encode()).hexdigest()
    authorization = {**base, "decisionId": f"roadex:concurrency-canary:{base['authorizationId']}", "question": f"Approve the exact live concurrency canary {digest}", "digest": digest}
    store.record_protocol("concurrency-canary-authorization", authorization["authorizationId"], authorization["idempotencyKey"], digest, authorization, state="delivered")
    decision = {"decisionId": authorization["decisionId"], "projectId": "arcade", "planId": "plan-arcade", "workflowId": authorization["workflowId"], "decisionVersion": authorization["decisionVersion"], "correlationId": authorization["correlationId"], "idempotencyKey": authorization["idempotencyKey"], "question": authorization["question"], "resultProvenanceId": digest}
    store.record_decision(decision, {**decision, "status": "staged"})
    if approve:
        store.decide(authorization["decisionId"], "approved", "human-user", NOW, "approved canary")
    return authorization


def _canary_round(round_id: str, project_id: str, plan_id: str, lead_id: str) -> dict:
    return {"roundId": round_id, "projectId": project_id, "projectLeadId": lead_id, "planId": plan_id, "planVersion": "v1", "correlationId": f"corr-{round_id}", "idempotencyKey": round_id, "snapshotId": f"snapshot-{round_id}", "policyVersion": "2026-08-09", "expectedUsageCost": 1, "scope": "one bounded round", "selectionReason": "priority-selected", "priorityRationale": "project-id"}


def _bind_canary_result_to_rounds(store: PsychloBridgeStore, canary: dict, projects) -> dict:
    executions = []
    for execution, (project_id, plan_id, plan_version, lead_id) in zip(canary["executions"], projects):
        request = _canary_round(execution["started"]["roundId"], project_id, plan_id, lead_id)
        stored_result = {**request, "sourceId": lead_id, "provenanceId": f"result:{request['roundId']}", "status": "completed", "actualUsageCost": 1, "deliveredScope": "bounded canary work", "remainingEstimate": 1, "blockers": [], "questions": [], "reachedExplicitGates": [], "occurredAt": execution["completed"]["settledAt"]}
        receipt = {**request, "sourceId": lead_id, "provenanceId": f"dispatch:{request['roundId']}", "status": "accepted"}
        store.record_canary_round(request, receipt, f"cap-{request['roundId']}-1234567890abcdef", canary["authorizationId"], canary["expectedRevision"], NOW)
        store.mark_dispatch_started(request["roundId"], execution["started"]["startedAt"])
        store.record_result(request["roundId"], stored_result, execution["completed"]["settledAt"])
        result_digest = _round_result_digest(stored_result)
        evidence_digest = canonical_digest({"provenanceId": stored_result["provenanceId"], "resultDigest": result_digest})
        started = execution["started"]
        completed_base = {"executionId": execution["executionId"], "authorizationId": execution["completed"]["authorizationId"], "projectId": project_id, "planId": plan_id, "planVersion": plan_version, "roundId": request["roundId"], "leadId": lead_id, "settledAt": execution["completed"]["settledAt"], "terminalStatus": "completed", "resultDigest": result_digest, "evidenceId": stored_result["provenanceId"], "evidenceDigest": evidence_digest}
        completed = {**completed_base, "digest": hashlib.sha256(json.dumps(completed_base, separators=(",", ":")).encode()).hexdigest()}
        executions.append({"executionId": execution["executionId"], "started": started, "completed": completed})
    result_base = {"resultId": canary["resultId"], "authorizationId": canary["authorizationId"], "targetCeiling": canary["targetCeiling"], "expectedRevision": canary["expectedRevision"], "executions": executions, "concurrencyObserved": canary["concurrencyObserved"], "occurredAt": canary["occurredAt"]}
    return {**result_base, "digest": hashlib.sha256(json.dumps(result_base, separators=(",", ":")).encode()).hexdigest()}


def _retimestamp_canary_result(canary: dict) -> dict:
    executions = []
    for index, execution in enumerate(canary["executions"], start=1):
        started_base = {**execution["started"], "startedAt": f"2026-08-11T00:00:0{index}+00:00"}
        started = {**started_base, "digest": hashlib.sha256(json.dumps({key: started_base[key] for key in ("executionId", "authorizationId", "projectId", "planId", "planVersion", "roundId", "leadId", "startedAt")}, separators=(",", ":")).encode()).hexdigest()}
        completed_base = {**execution["completed"], "settledAt": f"2026-08-11T00:00:1{index}+00:00"}
        completed = {**completed_base, "digest": hashlib.sha256(json.dumps({key: completed_base[key] for key in ("executionId", "authorizationId", "projectId", "planId", "planVersion", "roundId", "leadId", "settledAt", "terminalStatus", "resultDigest", "evidenceId", "evidenceDigest")}, separators=(",", ":")).encode()).hexdigest()}
        executions.append({"executionId": execution["executionId"], "started": started, "completed": completed})
    result_base = {**canary, "executions": executions, "occurredAt": "2026-08-11T00:00:30+00:00"}
    result_base.pop("digest")
    return {**result_base, "digest": hashlib.sha256(json.dumps(result_base, separators=(",", ":")).encode()).hexdigest()}


def _canary_result_from_bridge_rounds(authorization_id: str, requests: list[dict], results: list[dict]) -> dict:
    executions = []
    for index, (request, result) in enumerate(zip(requests, results), start=1):
        execution_id = request["roundId"]
        started_base = {"executionId": execution_id, "authorizationId": authorization_id, "projectId": request["projectId"], "planId": request["planId"], "planVersion": request["planVersion"], "roundId": execution_id, "leadId": request["projectLeadId"], "startedAt": f"2026-08-10T02:01:0{index}+00:00"}
        started = {**started_base, "digest": hashlib.sha256(json.dumps(started_base, separators=(",", ":")).encode()).hexdigest()}
        result_digest = _round_result_digest(result)
        evidence_digest = canonical_digest({"provenanceId": result["provenanceId"], "resultDigest": result_digest})
        completed_base = {"executionId": execution_id, "authorizationId": authorization_id, "projectId": request["projectId"], "planId": request["planId"], "planVersion": request["planVersion"], "roundId": execution_id, "leadId": request["projectLeadId"], "settledAt": f"2026-08-10T02:01:1{index}+00:00", "terminalStatus": "completed", "resultDigest": result_digest, "evidenceId": result["provenanceId"], "evidenceDigest": evidence_digest}
        completed = {**completed_base, "digest": hashlib.sha256(json.dumps(completed_base, separators=(",", ":")).encode()).hexdigest()}
        executions.append({"executionId": execution_id, "started": started, "completed": completed})
    base = {"resultId": f"canary-result:{authorization_id}", "authorizationId": authorization_id, "targetCeiling": 2, "expectedRevision": 0, "executions": executions, "concurrencyObserved": True, "occurredAt": "2026-08-10T02:01:30+00:00"}
    return {**base, "digest": hashlib.sha256(json.dumps(base, separators=(",", ":")).encode()).hexdigest()}


def test_approved_canary_admits_exactly_two_independent_rounds_atomically(tmp_path: Path):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    _persist_approved_canary(store)
    bridge = PsychloBridge(store=store, dispatcher=lambda *_: "dispatch", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW, token_factory=iter(("cap-arcade-1234567890abcdef", "cap-hermione-1234567890abcdef", "cap-third-1234567890abcdef", "cap-same-1234567890abcdef")).__next__)
    assert bridge.request_round(_canary_round("round-arcade", "arcade", "plan-arcade", "lead-arcade"))["accepted"] is True
    assert bridge.request_round(_canary_round("round-hermione", "hermione", "plan-hermione", "lead-hermione"))["accepted"] is True
    with pytest.raises(ValueError, match="single_stream_busy"):
        bridge.request_round(_canary_round("round-third", "other", "plan-other", "lead-other"))
    with pytest.raises(ValueError, match="single_stream_busy"):
        bridge.request_round(_canary_round("round-same", "arcade", "plan-arcade", "lead-arcade"))


def test_recovery_rejects_stale_concurrency_authorization_before_forwarding(tmp_path: Path):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    authorization = _persist_approved_canary(store)
    store.connection.execute("UPDATE protocol_records SET state='queued',digest=? WHERE kind='concurrency-canary-authorization' AND record_id=?", ("0" * 64, authorization["authorizationId"]))
    sent = []
    bridge = PsychloBridge(store=store, dispatcher=lambda *_: "unused", sender=lambda *args: sent.append(args) or {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)

    assert sent == []
    assert bridge.store.protocol_record("concurrency-canary-authorization", authorization["authorizationId"])["state"] == "forward-pending"


def test_bridge_canary_lifecycle_uses_real_rounds_then_restarts_under_persisted_ceiling(tmp_path: Path):
    store_path = tmp_path / "bridge.sqlite3"
    store = PsychloBridgeStore(store_path)
    authorization = _persist_approved_canary(store)
    sent = []
    capabilities = []
    trusted_times = iter((
        "2026-08-10T02:00:00+00:00", "2026-08-10T02:00:01+00:00", "2026-08-10T02:00:02+00:00",
        "2026-08-10T02:00:03+00:00", "2026-08-10T02:00:04+00:00", "2026-08-10T02:00:05+00:00",
        "2026-08-10T02:00:06+00:00", "2026-08-10T02:00:07+00:00", "2026-08-10T02:00:08+00:00",
        "2026-08-10T02:00:09+00:00",
    ))
    def clock():
        return next(trusted_times)
    def token_factory():
        token = f"cap-lifecycle-{len(capabilities) + 1}-1234567890abcdef"
        capabilities.append(token)
        return token
    bridge = PsychloBridge(store=store, dispatcher=lambda lead, _prompt: f"dispatch:{lead}", sender=lambda *args: sent.append(args) or {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=clock, token_factory=token_factory)
    requests = [_canary_round("lifecycle-arcade", "arcade", "plan-arcade", "lead-arcade"), _canary_round("lifecycle-hermione", "hermione", "plan-hermione", "lead-hermione")]
    receipts = [bridge.request_round(request) for request in requests]
    assert [receipt["receipt"]["status"] for receipt in receipts] == ["accepted", "accepted"]
    results = [{**request, "sourceId": request["projectLeadId"], "provenanceId": f"result:{request['roundId']}", "status": "completed", "actualUsageCost": 1, "deliveredScope": "canary work", "remainingEstimate": 0, "blockers": [], "questions": [], "reachedExplicitGates": [], "occurredAt": "2026-08-10T02:01:20+00:00"} for request in requests]
    assert bridge.receive_round_result(capabilities[0], results[0]) == {"accepted": True}
    assert bridge.receive_round_result(capabilities[1], results[1]) == {"accepted": True}
    canary = _canary_result_from_bridge_rounds(authorization["authorizationId"], requests, results)
    assert bridge.receive_concurrency_canary_result(canary)["accepted"] is True

    ceiling_base = {"authorizationId": "ceiling-lifecycle", "ceiling": 2, "expectedRevision": 0, "revision": 1, "canaryResultId": canary["resultId"], "projectId": "arcade", "planId": "plan-arcade", "workflowId": authorization["workflowId"], "decisionVersion": "v1", "correlationId": "ceiling-lifecycle", "idempotencyKey": "ceiling-lifecycle", "occurredAt": NOW}
    ceiling_digest = hashlib.sha256(json.dumps(ceiling_base, separators=(",", ":")).encode()).hexdigest()
    ceiling = {**ceiling_base, "decisionId": "roadex:concurrency:ceiling-lifecycle", "question": f"Approve the exact global concurrency operation {ceiling_digest}", "digest": ceiling_digest}
    decision = {"decisionId": ceiling["decisionId"], "projectId": ceiling["projectId"], "planId": ceiling["planId"], "workflowId": ceiling["workflowId"], "decisionVersion": ceiling["decisionVersion"], "correlationId": ceiling["correlationId"], "idempotencyKey": ceiling["idempotencyKey"], "question": ceiling["question"], "resultProvenanceId": ceiling_digest}
    store.record_decision(decision, {**decision, "status": "staged"})
    store.decide(ceiling["decisionId"], "approved", "human-user", NOW, "approved ceiling")
    assert bridge.authorize_concurrency_ceiling(ceiling)["record"]["state"] == "delivered"
    change = {"authorizationId": ceiling["authorizationId"], "correlationId": "ceiling-change-lifecycle", "idempotencyKey": "ceiling-change-lifecycle", "occurredAt": NOW}
    assert bridge.change_concurrency_ceiling(change)["record"]["state"] == "delivered"

    restarted_sent = []
    post_tokens = iter(("cap-post-ceiling-1-1234567890abcdef", "cap-post-ceiling-2-1234567890abcdef", "cap-post-ceiling-3-1234567890abcdef"))
    restarted = PsychloBridge(store=PsychloBridgeStore(store_path), dispatcher=lambda lead, _prompt: restarted_sent.append(lead) or f"dispatch:{lead}", sender=lambda *args: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: "2026-08-10T02:00:10+00:00", token_factory=lambda: next(post_tokens))
    ordinary = _canary_round("ordinary-after-restart", "ordinary", "plan-ordinary", "lead-ordinary")
    second_ordinary = _canary_round("second-ordinary-after-restart", "second-ordinary", "plan-second-ordinary", "lead-second-ordinary")
    ordinary_receipt = restarted.request_round(ordinary)
    assert ordinary_receipt["receipt"]["status"] == "accepted"
    assert restarted.request_round(second_ordinary)["receipt"]["status"] == "accepted"
    with pytest.raises(ValueError, match="single_stream_busy"):
        restarted.request_round(_canary_round("third-ordinary-after-restart", "third-ordinary", "plan-third-ordinary", "lead-third-ordinary"))
    assert restarted.request_round(ordinary) == ordinary_receipt
    assert restarted_sent == ["lead-ordinary", "lead-second-ordinary"]


def test_canary_result_rejects_real_completed_noncanary_rounds(tmp_path: Path):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    capabilities = iter(("cap-ordinary-1-1234567890abcdef", "cap-ordinary-2-1234567890abcdef"))
    bridge = PsychloBridge(store=store, dispatcher=lambda lead, _prompt: f"dispatch:{lead}", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW, token_factory=lambda: next(capabilities))
    requests = [_canary_round("noncanary-arcade", "arcade", "plan-arcade", "lead-arcade"), _canary_round("noncanary-hermione", "hermione", "plan-hermione", "lead-hermione")]
    results = [{**request, "sourceId": request["projectLeadId"], "provenanceId": f"result:{request['roundId']}", "status": "completed", "actualUsageCost": 1, "deliveredScope": "ordinary work", "remainingEstimate": 0, "blockers": [], "questions": [], "reachedExplicitGates": [], "occurredAt": NOW} for request in requests]
    assert bridge.request_round(requests[0])["accepted"] is True
    assert bridge.receive_round_result("cap-ordinary-1-1234567890abcdef", results[0]) == {"accepted": True}
    assert bridge.request_round(requests[1])["accepted"] is True
    assert bridge.receive_round_result("cap-ordinary-2-1234567890abcdef", results[1]) == {"accepted": True}
    authorization = _persist_approved_canary(store)
    canary = _canary_result_from_bridge_rounds(authorization["authorizationId"], requests, results)

    with pytest.raises(ValueError, match="authorization conflict"):
        bridge.receive_concurrency_canary_result(canary)
    assert store.protocol_record("concurrency-canary-result", canary["resultId"]) is None


def test_canary_admission_rejects_expired_or_unapproved_authority_and_preserves_single_stream(tmp_path: Path):
    for mode in ("expired", "unapproved"):
        store = PsychloBridgeStore(tmp_path / f"{mode}.sqlite3")
        authorization = _persist_approved_canary(store, deadline="2026-08-10T02:00:01+00:00" if mode == "expired" else "2026-08-10T03:00:00+00:00", approve=mode != "unapproved")
        bridge = PsychloBridge(store=store, dispatcher=lambda *_: "dispatch", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=(lambda: "2026-08-10T02:01:00+00:00") if mode == "expired" else (lambda: NOW), token_factory=lambda: f"cap-single-{mode}-1234567890abcdef")
        if mode == "unapproved":
            with pytest.raises(ValueError, match="decision_pending"):
                bridge.request_round(_canary_round(f"round-{mode}", "arcade", "plan-arcade", "lead-arcade"))
            continue
        assert bridge.request_round(_canary_round(f"round-{mode}", "arcade", "plan-arcade", "lead-arcade"))["accepted"] is True
        with pytest.raises(ValueError, match="single_stream_busy"):
            bridge.request_round(_canary_round(f"round-{mode}-second", "hermione", "plan-hermione", "lead-hermione"))


def test_durable_ceiling_keeps_two_streams_after_restart_and_denies_third(tmp_path: Path):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    authorization = _persist_approved_canary(store)
    canary = _bind_canary_result_to_rounds(store, _successful_canary_result("canary-round-admission", (("arcade", "plan-arcade", "v1", "lead-arcade"), ("hermione", "plan-hermione", "v1", "lead-hermione"))), (("arcade", "plan-arcade", "v1", "lead-arcade"), ("hermione", "plan-hermione", "v1", "lead-hermione")))
    store.record_protocol("concurrency-canary-result", canary["resultId"], canary["resultId"], canary["digest"], canary, state="delivered")
    ceiling_base = {"authorizationId": "ceiling-round-admission", "ceiling": 2, "expectedRevision": 0, "revision": 1, "canaryResultId": "canary-result:canary-round-admission", "projectId": "arcade", "planId": "plan-arcade", "workflowId": authorization["workflowId"], "decisionVersion": "v1", "correlationId": "ceiling-round-admission", "idempotencyKey": "ceiling-round-admission", "occurredAt": NOW}
    ceiling_digest = hashlib.sha256(json.dumps(ceiling_base, separators=(",", ":")).encode()).hexdigest()
    ceiling = {**ceiling_base, "decisionId": f"roadex:concurrency:{ceiling_base['authorizationId']}", "question": f"Approve the exact global concurrency operation {ceiling_digest}", "digest": ceiling_digest}
    store.record_protocol("concurrency-ceiling-authorization", ceiling["authorizationId"], ceiling["idempotencyKey"], ceiling_digest, ceiling, state="delivered")
    ceiling_decision = {"decisionId": ceiling["decisionId"], "projectId": ceiling["projectId"], "planId": ceiling["planId"], "workflowId": ceiling["workflowId"], "decisionVersion": ceiling["decisionVersion"], "correlationId": ceiling["correlationId"], "idempotencyKey": ceiling["idempotencyKey"], "question": ceiling["question"], "resultProvenanceId": ceiling_digest}
    store.record_decision(ceiling_decision, {**ceiling_decision, "status": "staged"})
    store.decide(ceiling["decisionId"], "approved", "human-user", NOW, "approved ceiling")
    change_payload = {"authorizationId": ceiling["authorizationId"], "correlationId": "ceiling-change", "idempotencyKey": "ceiling-change", "occurredAt": NOW}
    store.record_protocol("concurrency-ceiling-change", ceiling["authorizationId"], ceiling["authorizationId"], canonical_digest(change_payload), change_payload, state="delivered")
    bridge = PsychloBridge(store=store, dispatcher=lambda *_: "dispatch", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW, token_factory=iter(("cap-one-1234567890abcdef", "cap-two-1234567890abcdef", "cap-three-1234567890abcdef")).__next__)
    assert bridge.request_round(_canary_round("round-one", "alpha", "plan-alpha", "lead-alpha"))["accepted"] is True
    restarted = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "dispatch", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW, token_factory=iter(("cap-two-1234567890abcdef", "cap-three-1234567890abcdef")).__next__)
    assert restarted.request_round(_canary_round("round-two", "beta", "plan-beta", "lead-beta"))["accepted"] is True
    with pytest.raises(ValueError, match="single_stream_busy"):
        restarted.request_round(_canary_round("round-three", "gamma", "plan-gamma", "lead-gamma"))


@pytest.mark.parametrize("stale_kind", ("concurrency-ceiling-authorization", "concurrency-canary-result", "concurrency-canary-authorization"))
def test_ceiling_change_rejects_stale_protocol_row_digest_before_persistence(tmp_path: Path, stale_kind: str):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    authorization = _persist_approved_canary(store)
    projects = (("arcade", "plan-arcade", "v1", "lead-arcade"), ("hermione", "plan-hermione", "v1", "lead-hermione"))
    canary = _bind_canary_result_to_rounds(store, _successful_canary_result(authorization["authorizationId"], projects), projects)
    store.record_protocol("concurrency-canary-result", canary["resultId"], canary["resultId"], canary["digest"], canary, state="delivered")
    ceiling_base = {"authorizationId": "ceiling-stale-digest", "ceiling": 2, "expectedRevision": 0, "revision": 1, "canaryResultId": canary["resultId"], "projectId": "arcade", "planId": "plan-arcade", "workflowId": authorization["workflowId"], "decisionVersion": "v1", "correlationId": "ceiling-stale-digest", "idempotencyKey": "ceiling-stale-digest", "occurredAt": NOW}
    ceiling_digest = hashlib.sha256(json.dumps(ceiling_base, separators=(",", ":")).encode()).hexdigest()
    ceiling = {**ceiling_base, "decisionId": "roadex:concurrency:ceiling-stale-digest", "question": f"Approve the exact global concurrency operation {ceiling_digest}", "digest": ceiling_digest}
    store.record_protocol("concurrency-ceiling-authorization", ceiling["authorizationId"], ceiling["idempotencyKey"], ceiling_digest, ceiling, state="delivered")
    decision = {"decisionId": ceiling["decisionId"], "projectId": ceiling["projectId"], "planId": ceiling["planId"], "workflowId": ceiling["workflowId"], "decisionVersion": ceiling["decisionVersion"], "correlationId": ceiling["correlationId"], "idempotencyKey": ceiling["idempotencyKey"], "question": ceiling["question"], "resultProvenanceId": ceiling_digest}
    store.record_decision(decision, {**decision, "status": "staged"})
    store.decide(ceiling["decisionId"], "approved", "human-user", NOW, "approved ceiling")
    stale_ids = {"concurrency-ceiling-authorization": ceiling["authorizationId"], "concurrency-canary-result": canary["resultId"], "concurrency-canary-authorization": authorization["authorizationId"]}
    store.connection.execute("UPDATE protocol_records SET digest=? WHERE kind=? AND record_id=?", ("0" * 64, stale_kind, stale_ids[stale_kind]))
    bridge = PsychloBridge(store=store, dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    change = {"authorizationId": ceiling["authorizationId"], "correlationId": "ceiling-change", "idempotencyKey": "ceiling-change", "occurredAt": NOW}

    with pytest.raises(ValueError, match="digest conflict"):
        bridge.change_concurrency_ceiling(change)
    assert store.protocol_record("concurrency-ceiling-change", ceiling["authorizationId"]) is None


def test_default_single_stream_admission_is_cross_process_atomic(tmp_path: Path):
    store_path = tmp_path / "bridge.sqlite3"
    PsychloBridgeStore(store_path).connection.close()
    context = multiprocessing.get_context("fork")
    barrier, results = context.Barrier(2), context.Queue()
    processes = [context.Process(target=_single_stream_race_process, args=(str(store_path), barrier, results, suffix)) for suffix in ("one", "two")]
    for process in processes:
        process.start()
    outcomes = [results.get(timeout=10) for _ in processes]
    for process in processes:
        process.join(10)
    assert [process.exitcode for process in processes] == [0, 0]
    assert sorted(outcomes) == ["accepted", "single_stream_busy"]


def test_coordination_dispatch_id_is_pending_until_authenticated_lead_result(tmp_path: Path):
    sent = []
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    _record_registered_project(store, "arcade", "lead-arcade")
    bridge = PsychloBridge(store=store, dispatcher=_PreparedDispatcher(identity=lambda _lead, _scope, _key: "dispatch-1"), sender=lambda kind, mid, payload: sent.append((kind, mid, payload)) or {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    request = _coord_request("binding-1", "link-1", "v1", "arcade", "lead-arcade", "lead-supervisor", ["arcade", "hermione"])
    store.record_protocol("cross-project-team-binding", "binding-1", "binding-1", "b" * 64, {"bindingId": "binding-1", "coordinationTeamId": "team-1", "supervisorMemberId": "member-supervisor", "supervisorLeadId": "lead-supervisor"}, state="delivered")
    accepted = bridge.receive_coordination_work_request(request)
    assert accepted["accepted"] is True
    assert accepted["receipt"]["status"] == "accepted"
    assert store.protocol_record("cross-project-participant-result", request["id"]) is None
    with pytest.raises(ValueError, match="authoritative result collector"):
        bridge.receive_cross_project_participant_result({})


def test_coordination_accepts_exact_psychlo_f0015d6_fixture_and_replays_receipt(tmp_path: Path):
    fixture = _peer_fixtures()["crossProjectWork"]
    request = fixture["request"]
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    _record_registered_project(store, request["projectId"], request["leadId"])
    store.record_protocol("cross-project-team-binding", request["coordinationBindingId"], request["coordinationBindingId"], "b" * 64, {"bindingId": request["coordinationBindingId"], "coordinationTeamId": "team-runtime", "supervisorMemberId": "member-runtime", "supervisorLeadId": request["supervisorLeadId"]}, state="delivered")
    dispatcher = _PreparedDispatcher(identity=lambda _lead, _scope, _key: "dispatch-1")
    bridge = PsychloBridge(store=store, dispatcher=dispatcher, sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    assert bridge.receive_coordination_work_request(request) == fixture["response"]
    assert bridge.receive_coordination_work_request(request) == fixture["response"]
    assert dispatcher.calls == [(request["leadId"], request["scope"], request["id"])]


def test_coordination_dispatch_intent_is_cross_process_and_idempotent(tmp_path: Path):
    request = _coord_request("binding-1", "link-1", "v1", "arcade", "lead-arcade", "lead-supervisor", ["arcade", "hermione"])
    store_path = tmp_path / "bridge.sqlite3"
    store = PsychloBridgeStore(store_path)
    _record_registered_project(store, "arcade", "lead-arcade")
    store.record_protocol("cross-project-team-binding", "binding-1", "binding-1", "b" * 64, {"bindingId": "binding-1", "coordinationTeamId": "team-1", "supervisorMemberId": "member-supervisor", "supervisorLeadId": "lead-supervisor"}, state="delivered")
    calls_path = tmp_path / "calls.sqlite3"
    connection = sqlite3.connect(calls_path)
    connection.execute("CREATE TABLE calls(lead_id TEXT, scope TEXT, idempotency_key TEXT)")
    connection.close()
    context = multiprocessing.get_context("fork")
    barrier = context.Barrier(2)
    processes = [context.Process(target=_coordination_process, args=(str(store_path), str(calls_path), request, barrier)) for _ in range(2)]
    for process in processes: process.start()
    for process in processes: process.join(10)
    assert [process.exitcode for process in processes] == [0, 0]
    connection = sqlite3.connect(calls_path)
    assert connection.execute("SELECT lead_id,scope,idempotency_key FROM calls").fetchall() == [("lead-arcade", "update shared contract", request["id"])]
    connection.close()
    intent = store.coordination_dispatch(request["id"])
    assert intent is not None and intent["state"] == "pending" and intent["ownerId"] and intent["idempotencyKey"] == request["id"]


def test_prepared_intent_atomic_winner_prevents_expired_first_process_send(tmp_path: Path):
    request = _coord_request("binding-1", "link-race", "v1", "arcade", "lead-arcade", "lead-supervisor", ["arcade", "hermione"])
    store_path = tmp_path / "bridge.sqlite3"
    store = PsychloBridgeStore(store_path)
    _record_registered_project(store, "arcade", "lead-arcade")
    store.record_protocol("cross-project-team-binding", "binding-1", "binding-1", "b" * 64, {"bindingId": "binding-1", "coordinationTeamId": "team-1", "supervisorMemberId": "member-supervisor", "supervisorLeadId": "lead-supervisor"}, state="delivered")
    calls_path = tmp_path / "race-calls.sqlite3"
    connection = sqlite3.connect(calls_path)
    connection.execute("CREATE TABLE calls(role TEXT, lead_id TEXT, scope TEXT, idempotency_key TEXT)")
    connection.close()
    context = multiprocessing.get_context("fork")
    first_prepared, release_first = context.Event(), context.Event()
    first = context.Process(target=_coordination_prepare_race_process, args=(str(store_path), str(calls_path), request, "first", first_prepared, release_first))
    second = context.Process(target=_coordination_prepare_race_process, args=(str(store_path), str(calls_path), request, "second", first_prepared, release_first))
    first.start(); second.start(); first.join(15); second.join(15)
    assert (first.exitcode, second.exitcode) == (0, 0)
    connection = sqlite3.connect(calls_path)
    assert connection.execute("SELECT role,lead_id,scope,idempotency_key FROM calls").fetchall() == [("second", "lead-arcade", request["scope"], request["id"])]
    connection.close()
    dispatch = store.coordination_dispatch(request["id"])
    assert dispatch is not None and dispatch["dispatchId"] == "dispatch-race" and dispatch["state"] == "pending"


def test_progressive_supervisor_review_intent_has_one_cross_process_winner(tmp_path: Path):
    store_path = tmp_path / "bridge.sqlite3"
    PsychloBridgeStore(store_path)
    context = multiprocessing.get_context("fork")
    barrier = context.Barrier(2)
    results = context.Queue()
    processes = [context.Process(target=_coordination_review_intent_race_process, args=(str(store_path), barrier, results, f"owner-{index}")) for index in range(2)]
    for process in processes: process.start()
    for process in processes: process.join(15)
    assert [process.exitcode for process in processes] == [0, 0]
    assert sorted(results.get(timeout=2) for _ in processes) == [False, True]
    review = PsychloBridgeStore(store_path).coordination_review("request-1")
    assert review is not None and review["reviewId"] == "review-1" and review["state"] == "uncertain"


def test_existing_uncertain_intent_after_pre_send_crash_is_never_sent(tmp_path: Path):
    request = _coord_request("binding-1", "link-pre-send", "v1", "arcade", "lead-arcade", "lead-supervisor", ["arcade", "hermione"])
    store_path = tmp_path / "bridge.sqlite3"
    store = PsychloBridgeStore(store_path)
    _record_registered_project(store, "arcade", "lead-arcade")
    store.record_protocol("cross-project-team-binding", "binding-1", "binding-1", "b" * 64, {"bindingId": "binding-1", "coordinationTeamId": "team-1", "supervisorMemberId": "member-supervisor", "supervisorLeadId": "lead-supervisor"}, state="delivered")

    class PreSendCrash(_PreparedDispatcher):
        def __call__(self, *_args): raise SystemExit("fault before external send")

    crashing = PreSendCrash(identity=lambda *_: "dispatch-pre-send")
    bridge = PsychloBridge(store=store, dispatcher=crashing, sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    with pytest.raises(SystemExit, match="before external"):
        bridge.receive_coordination_work_request(request)
    assert store.coordination_dispatch(request["id"])["state"] == "uncertain"
    replacement = _PreparedDispatcher(identity=lambda *_: "dispatch-pre-send")
    restarted = PsychloBridge(store=PsychloBridgeStore(store_path), dispatcher=replacement, sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: "2026-08-10T03:00:00+00:00")
    restarted.receive_coordination_work_request(request)
    assert replacement.calls == []


def test_coordination_operation_lease_expires_and_preserves_idempotency(tmp_path: Path):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    assert store.claim_coordination_operation("lead-dispatch", "request-1", "owner-1", "2026-08-10T02:00:30+00:00", "request-1", now=NOW) is True
    claim = store.coordination_operation_claim("lead-dispatch", "request-1")
    assert claim is not None and claim["ownerId"] == "owner-1" and claim["leaseExpiresAt"] == "2026-08-10T02:00:30+00:00" and claim["attempts"] == 1
    assert store.claim_coordination_operation("lead-dispatch", "request-1", "owner-2", "2026-08-10T02:00:40+00:00", "request-1", now="2026-08-10T02:00:20+00:00") is False
    assert store.claim_coordination_operation("lead-dispatch", "request-1", "owner-2", "2026-08-10T02:01:10+00:00", "request-1", now="2026-08-10T02:00:40+00:00") is True
    renewed = store.coordination_operation_claim("lead-dispatch", "request-1")
    assert renewed is not None and renewed["ownerId"] == "owner-2" and renewed["attempts"] == 2 and renewed["idempotencyKey"] == "request-1"


@pytest.mark.parametrize("kind", ["dispatch", "review"])
def test_coordination_intent_existing_row_is_never_taken_over(kind: str, tmp_path: Path):
    first_store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    second_store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    create_first = first_store.create_coordination_dispatch_intent if kind == "dispatch" else first_store.create_coordination_review_intent
    create_second = second_store.create_coordination_dispatch_intent if kind == "dispatch" else second_store.create_coordination_review_intent
    first = create_first("operation-1", "external-1", {"scope": "bounded"}, owner_id="owner-first", idempotency_key="stable-key")
    second = create_second("operation-1", "external-1", {"scope": "bounded"}, owner_id="owner-second", idempotency_key="stable-key")
    assert first["inserted"] is True and first["winner"] is True
    assert second["inserted"] is False and second["winner"] is False
    assert second["intent"]["state"] == "uncertain" and second["intent"]["ownerId"] == "owner-first"


def test_production_dispatch_intent_survives_post_send_crash_without_repaste(tmp_path: Path, monkeypatch):
    bindings = tmp_path / "bindings.json"
    bindings.write_text(json.dumps({"lead-arcade": {"conversationId": "conversation-1"}}), encoding="utf-8")
    bindings.chmod(0o600)
    sends = []
    request = _coord_request("binding-1", "link-1", "v1", "arcade", "lead-arcade", "lead-supervisor", ["arcade", "hermione"])
    request_identity = f"legacy.dispatch.{hashlib.sha256(request['id'].encode()).hexdigest()}"
    stable_dispatch_id = f"result.{request_identity}"

    class CrashingDriver:
        def discover(self):
            return [SimpleNamespace(id="session-1", external_session_id="conversation-1")]

        def prepare_legacy_dispatch(self, _session, _prompt, *, idempotency_key):
            assert idempotency_key == request["id"]
            return SimpleNamespace(id=request_identity)

        def dispatch_legacy(self, _session, _prompt, *, idempotency_key):
            sends.append(idempotency_key)
            raise SystemExit("fault after external prompt submission")

    monkeypatch.setattr("overseer.agent_adapters.codex.CodexDriver.from_legacy_registry", lambda: CrashingDriver())
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    _record_registered_project(store, "arcade", "lead-arcade")
    store.record_protocol("cross-project-team-binding", "binding-1", "binding-1", "b" * 64, {"bindingId": "binding-1", "coordinationTeamId": "team-1", "supervisorMemberId": "member-supervisor", "supervisorLeadId": "lead-supervisor"}, state="delivered")
    dispatcher = CodexProjectDispatcher(bindings)
    bridge = PsychloBridge(store=store, dispatcher=dispatcher, sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    with pytest.raises(SystemExit, match="fault after external"):
        bridge.receive_coordination_work_request(request)
    intent = store.coordination_dispatch(request["id"])
    assert intent is not None
    assert intent["requestId"] == request["id"] and intent["dispatchId"] == stable_dispatch_id and intent["state"] == "uncertain"
    assert intent["payload"] == {"idempotencyKey": request["id"], "leadId": "lead-arcade", "request": request, "scope": request["scope"]}
    assert intent["ownerId"] and intent["idempotencyKey"] == request["id"]
    restarted = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=dispatcher, sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    assert restarted.receive_coordination_work_request(request)["receipt"]["status"] == "accepted"
    assert sends == [request["id"]]


def test_canary_result_without_recorded_rounds_is_rejected_before_terminal_persistence(tmp_path: Path):
    fixture = _peer_fixtures()["concurrencyCanaryResult"]
    result = fixture["request"]
    sent = []
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    authorization = {"authorizationId": result["authorizationId"], "targetTemporaryCeiling": result["targetCeiling"], "expectedGlobalCeiling": 1, "expectedRevision": result["expectedRevision"], "projects": [{"projectId": "fixture-alpha", "planId": "plan-fixture-alpha", "planVersion": "v1", "leadId": "lead-fixture-alpha"}, {"projectId": "fixture-beta", "planId": "plan-fixture-beta", "planVersion": "v1", "leadId": "lead-fixture-beta"}], "workflowId": "roadex-fixture", "decisionVersion": "v1", "deadline": "2026-08-11T13:00:00+00:00", "correlationId": "fixture-canary", "idempotencyKey": "fixture-canary", "occurredAt": "2026-08-11T12:00:00+00:00"}
    authorization["digest"] = hashlib.sha256(json.dumps({key: authorization[key] for key in ("authorizationId", "targetTemporaryCeiling", "expectedGlobalCeiling", "expectedRevision", "projects", "workflowId", "decisionVersion", "deadline", "correlationId", "idempotencyKey", "occurredAt")}, separators=(",", ":")).encode()).hexdigest()
    authorization.update({"decisionId": f"roadex:concurrency-canary:{authorization['authorizationId']}", "question": f"Approve the exact live concurrency canary {authorization['digest']}"})
    store.record_protocol("concurrency-canary-authorization", result["authorizationId"], result["authorizationId"], authorization["digest"], authorization, state="delivered")
    decision = {"decisionId": authorization["decisionId"], "projectId": "fixture-alpha", "planId": "plan-fixture-alpha", "workflowId": authorization["workflowId"], "decisionVersion": authorization["decisionVersion"], "correlationId": authorization["correlationId"], "idempotencyKey": authorization["idempotencyKey"], "question": authorization["question"], "resultProvenanceId": authorization["digest"]}
    store.record_decision(decision, decision)
    store.decide(authorization["decisionId"], "approved", "human-user", NOW, "approved")
    bridge = PsychloBridge(store=store, dispatcher=lambda *_: "unused", sender=lambda kind, mid, payload: sent.append((kind, mid, payload)) or {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    with pytest.raises(ValueError, match="round is unavailable"):
        bridge.receive_concurrency_canary_result(result)
    assert sent == []
    assert store.protocol_record("concurrency-canary-result", result["resultId"]) is None


def test_canary_result_derived_from_recorded_completed_rounds_is_terminal_and_replayable(tmp_path: Path):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    authorization = _persist_approved_canary(store)
    projects = (("arcade", "plan-arcade", "v1", "lead-arcade"), ("hermione", "plan-hermione", "v1", "lead-hermione"))
    canary = _bind_canary_result_to_rounds(store, _successful_canary_result(authorization["authorizationId"], projects), projects)
    bridge = PsychloBridge(store=store, dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    expected = {"accepted": True, "receipt": {"resultId": canary["resultId"], "digest": canary["digest"], "status": "accepted", "provenanceId": f"overseer:{canary['resultId']}"}}
    assert bridge.receive_concurrency_canary_result(canary) == expected
    assert bridge.receive_concurrency_canary_result(canary) == expected
    assert store.protocol_record("concurrency-canary-result", canary["resultId"])["state"] == "delivered"
    assert store.protocol_record("concurrency-canary-authorization", authorization["authorizationId"])["state"] == "settled"
    corrupt = {**canary, "digest": "f" * 64}
    with pytest.raises(ValueError):
        bridge.receive_concurrency_canary_result(corrupt)
    assert store.protocol_record("concurrency-canary-result", canary["resultId"])["payload"] == canary


def test_canary_result_rejects_stale_authorization_row_digest_before_persistence(tmp_path: Path):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    authorization = _persist_approved_canary(store)
    projects = (("arcade", "plan-arcade", "v1", "lead-arcade"), ("hermione", "plan-hermione", "v1", "lead-hermione"))
    canary = _bind_canary_result_to_rounds(store, _successful_canary_result(authorization["authorizationId"], projects), projects)
    store.connection.execute("UPDATE protocol_records SET digest=? WHERE kind='concurrency-canary-authorization' AND record_id=?", ("0" * 64, authorization["authorizationId"]))
    bridge = PsychloBridge(store=store, dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)

    with pytest.raises(ValueError, match="authorization digest conflict"):
        bridge.receive_concurrency_canary_result(canary)
    assert store.protocol_record("concurrency-canary-result", canary["resultId"]) is None


def test_ceiling_authorization_rejects_stale_canary_result_before_forwarding(tmp_path: Path):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    authorization = _persist_approved_canary(store)
    projects = (("arcade", "plan-arcade", "v1", "lead-arcade"), ("hermione", "plan-hermione", "v1", "lead-hermione"))
    canary = _bind_canary_result_to_rounds(store, _successful_canary_result(authorization["authorizationId"], projects), projects)
    bridge = PsychloBridge(store=store, dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    assert bridge.receive_concurrency_canary_result(canary)["accepted"] is True
    store.connection.execute("UPDATE protocol_records SET digest=? WHERE kind='concurrency-canary-result' AND record_id=?", ("0" * 64, canary["resultId"]))
    ceiling_base = {"authorizationId": "ceiling-stale-canary", "ceiling": 2, "expectedRevision": 0, "revision": 1, "canaryResultId": canary["resultId"], "projectId": "arcade", "planId": "plan-arcade", "workflowId": authorization["workflowId"], "decisionVersion": "v1", "correlationId": "ceiling-stale-canary", "idempotencyKey": "ceiling-stale-canary", "occurredAt": NOW}
    ceiling_digest = hashlib.sha256(json.dumps(ceiling_base, separators=(",", ":")).encode()).hexdigest()
    ceiling = {**ceiling_base, "decisionId": "roadex:concurrency:ceiling-stale-canary", "question": f"Approve the exact global concurrency operation {ceiling_digest}", "digest": ceiling_digest}

    with pytest.raises(ValueError, match="digest conflict"):
        bridge.authorize_concurrency_ceiling(ceiling)
    assert store.protocol_record("concurrency-ceiling-authorization", ceiling["authorizationId"]) is None


def test_canary_result_binds_trusted_local_overlap_without_cross_service_timestamp_equality(tmp_path: Path):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    authorization = _persist_approved_canary(store)
    projects = (("arcade", "plan-arcade", "v1", "lead-arcade"), ("hermione", "plan-hermione", "v1", "lead-hermione"))
    canary = _bind_canary_result_to_rounds(store, _successful_canary_result(authorization["authorizationId"], projects), projects)
    submitted = _retimestamp_canary_result(canary)
    bridge = PsychloBridge(store=store, dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)

    assert bridge.receive_concurrency_canary_result(submitted)["accepted"] is True
    assert store.protocol_record("concurrency-canary-result", submitted["resultId"])["payload"] == submitted


def test_canary_result_rejects_sender_invented_overlap_against_persisted_sequential_timing(tmp_path: Path):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    authorization = _persist_approved_canary(store)
    projects = (("arcade", "plan-arcade", "v1", "lead-arcade"), ("hermione", "plan-hermione", "v1", "lead-hermione"))
    canary = _bind_canary_result_to_rounds(store, _successful_canary_result(authorization["authorizationId"], projects), projects)
    store.connection.execute("UPDATE rounds SET started_at=? WHERE round_id=?", ("2026-08-10T02:00:20+00:00", "round-2"))
    bridge = PsychloBridge(store=store, dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    with pytest.raises(ValueError, match="timing"):
        bridge.receive_concurrency_canary_result(canary)
    assert store.protocol_record("concurrency-canary-result", canary["resultId"]) is None


def test_round_request_matches_psychlo_strict_shape_and_closed_values(tmp_path: Path):
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    request = _canary_round("strict-round", "arcade", "plan-arcade", "lead-arcade")
    assert bridge.request_round({**request, "threadId": "thread-1", "model": "gpt-5.6-luna", "featureClass": "typescript-feature"})["accepted"] is True
    for mutation in ({"extra": True}, {"expectedUsageCost": True}, {"expectedUsageCost": float("nan")}, {"model": "unsupported"}, {"threadId": "x" * 201}, {"priorityRationale": "unsupported"}):
        fresh = {**request, "roundId": f"strict-{len(mutation)}-{next(iter(mutation))}", "idempotencyKey": f"strict-{len(mutation)}-{next(iter(mutation))}", **mutation}
        with pytest.raises(ValueError, match="invalid round request"):
            bridge.request_round(fresh)


def test_ceiling_change_rejects_without_exact_approved_bound_evidence_and_persists_nothing(tmp_path: Path):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    bridge = PsychloBridge(store=store, dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    change = {"authorizationId": "missing-ceiling", "correlationId": "ceiling-change", "idempotencyKey": "ceiling-change", "occurredAt": NOW}
    with pytest.raises(ValueError, match="authorization is unavailable"):
        bridge.change_concurrency_ceiling(change)
    assert store.protocol_record("concurrency-ceiling-change", "missing-ceiling") is None


def test_corrupt_persisted_canary_authority_fails_closed_without_admitting_default_round(tmp_path: Path):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    authorization = _persist_approved_canary(store)
    store.connection.execute("UPDATE protocol_records SET payload_json=? WHERE kind='concurrency-canary-authorization' AND record_id=?", (json.dumps({"authorizationId": authorization["authorizationId"], "targetTemporaryCeiling": 2}), authorization["authorizationId"]))
    bridge = PsychloBridge(store=store, dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    with pytest.raises(ValueError, match="authorization is invalid"):
        bridge.request_round(_canary_round("corrupt-authority-round", "arcade", "plan-arcade", "lead-arcade"))
    assert store.get_round("corrupt-authority-round") is None


def test_admin_initiator_route_loads_only_persisted_approval_id(tmp_path: Path):
    class Sender:
        secret = SECRET
        def __call__(self, *_args):
            return {"accepted": True}
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    operation = {"authorizationId": "auth-1", "externalExecutionId": "exec-1", "reconciliationId": "recon-1", "projectId": "arcade", "aTeamId": "team-1", "planId": "plan-1", "planVersion": "v1", "projectLeadId": "lead-1", "threadId": "thread-1", "repository": {"pathIdentity": "/tmp/arcade", "beforeHead": "a" * 40, "afterHead": "b" * 40, "dirtyDigest": "c" * 64}, "startingCheckpoint": "checkpoint-start", "terminalCheckpoint": "checkpoint-end"}
    digest = canonical_digest(operation)
    primary = _save_real_approval(tmp_path / "overseer.sqlite3", "approval-1", operation, "external-work", "recon-1")
    primary.close()
    bridge = PsychloBridge(store=store, dispatcher=lambda *_: "unused", sender=Sender(), callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_api_handler(str(tmp_path / "overseer.sqlite3"), "admin-secret", psychlo_bridge=bridge))
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    body = json.dumps({"approval_id": "approval-1", "input": operation}, separators=(",", ":")).encode()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        connection.request("POST", "/psychlo/admin/external-round-binding", body=body, headers={"Authorization": "Bearer admin-secret", "Content-Type": "application/json"})
        response = connection.getresponse(); response_body = response.read()
        assert response.status == 200, response_body
        assert json.loads(response_body)["record"]["state"] == "delivered"
        connection.request("POST", "/psychlo/admin/external-round-binding", body=json.dumps({"approval_id": {"status": "approved"}, "input": operation}).encode(), headers={"Authorization": "Bearer admin-secret", "Content-Type": "application/json"})
        rejected = connection.getresponse(); rejected.read()
        assert rejected.status == 400
        connection.close()
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


def test_approval_snapshot_survives_replaceable_primary_rows_and_owner_is_designated(tmp_path: Path):
    operation = {"authorizationId": "auth-1", "externalExecutionId": "exec-1", "reconciliationId": "recon-1", "projectId": "arcade", "aTeamId": "team-1", "planId": "plan-1", "planVersion": "v1", "projectLeadId": "lead-1", "threadId": "thread-1", "repository": {"pathIdentity": "/tmp/arcade", "beforeHead": "a" * 40, "afterHead": "b" * 40, "dirtyDigest": "c" * 64}, "startingCheckpoint": "checkpoint-start", "terminalCheckpoint": "checkpoint-end"}
    primary = _save_real_approval(tmp_path / "primary.sqlite3", "approval-1", operation, "external-work", "recon-1")
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    bridge = PsychloBridge(store=store, dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW, approval_store=primary)
    assert bridge.initiate_external_round_binding("approval-1", operation)["inserted"] is True
    approval = primary.load_approval("approval-1")
    primary.save_approval(replace(approval, status=ApprovalStatus.REJECTED, decided_by=None, decided_at=None))
    assert bridge.initiate_external_round_binding("approval-1", operation)["replay"] is True
    wrong_owner = PsychloBridge(store=PsychloBridgeStore(tmp_path / "wrong.sqlite3"), dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW, approval_store=primary, approval_owner_domain="obrien")
    with pytest.raises(ValueError, match="approved administrative provenance"):
        wrong_owner.initiate_external_round_binding("approval-1", operation)


def test_coordination_polls_authoritative_lead_and_supervisor_across_restart(tmp_path: Path):
    sent = []
    lead_results = {}
    supervisor_result = None
    store_path = tmp_path / "bridge.sqlite3"
    psychlo_review_fixture = json.loads((Path(__file__).parent / "fixtures" / "psychlo-f0015d6-supervisor-review-anchor.json").read_text(encoding="utf-8"))

    def collect_lead(dispatch_id, _request):
        return lead_results.get(dispatch_id)

    def collect_supervisor(_review_id, _context):
        return supervisor_result

    def psychlo_receiver(kind, mid, payload):
        sent.append((kind, mid, payload))
        if kind == "cross-project-supervisor-review":
            parent = psychlo_review_fixture["parentResult"]
            anchor = next((item for item in payload["participantResults"] if item["resultId"] == payload["resultId"]), None)
            if anchor != {"resultId": parent["resultId"], "digest": parent["digest"]} or payload["participantResults"] != psychlo_review_fixture["participantResults"] or (payload["projectId"], payload["leadId"]) != (parent["projectId"], parent["leadId"]):
                raise ValueError("Psychlo receiver rejected unbound supervisor review anchor")
        return {"accepted": True}

    def make_bridge(*, with_supervisor=True):
        store = PsychloBridgeStore(store_path)
        if store.project("arcade") is None:
            _record_registered_project(store, "arcade", "lead-arcade")
            _record_registered_project(store, "hermione", "lead-hermione")
        return PsychloBridge(store=store, dispatcher=_PreparedDispatcher(identity=lambda lead, _scope, _key: f"dispatch-{lead}"), sender=psychlo_receiver, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW, project_result_collector=collect_lead, supervisor_dispatcher=_PreparedDispatcher(identity=lambda _member, _context, _key: "review-1") if with_supervisor else None, supervisor_result_collector=collect_supervisor)

    binding_base = {"bindingId": "binding-1", "coordinationTeamId": "team-1", "supervisorMemberId": "member-supervisor", "supervisorLeadId": "lead-supervisor", "approvalId": "approval-team", "approvalProvenanceId": "approval-team", "approvedAt": NOW, "correlationId": "binding-1", "idempotencyKey": "binding-1", "occurredAt": NOW}
    binding = {**binding_base, "digest": hashlib.sha256(json.dumps(binding_base, separators=(",", ":")).encode()).hexdigest()}
    bridge = make_bridge()
    assert bridge.authorize_cross_project_team_binding(binding)["record"]["state"] == "delivered"
    first = _coord_request("binding-1", "link-1", "v1", "arcade", "lead-arcade", "lead-supervisor", ["arcade", "hermione"], expected_digest="a" * 64)
    second = _coord_request("binding-1", "link-1", "v1", "hermione", "lead-hermione", "lead-supervisor", ["arcade", "hermione"], expected_digest="c" * 64)
    assert bridge.receive_coordination_work_request(first)["receipt"]["status"] == "accepted"
    assert bridge.receive_coordination_work_request(second)["receipt"]["status"] == "accepted"
    lead_results["dispatch-lead-arcade"] = {"linkId": "link-1", "version": "v1", "projectId": "arcade", "leadId": "lead-arcade", "requestId": first["id"], "dispatchId": "dispatch-lead-arcade", "resultId": "result-1", "scope": first["scope"], "status": "completed", "evidenceId": "evidence-result-1", "digest": "a" * 64, "correlationId": "coord-arcade", "idempotencyKey": "result-1", "occurredAt": NOW}
    lead_results["dispatch-lead-hermione"] = {"linkId": "link-1", "version": "v1", "projectId": "hermione", "leadId": "lead-hermione", "requestId": second["id"], "dispatchId": "dispatch-lead-hermione", "resultId": "result-2", "scope": second["scope"], "status": "completed", "evidenceId": "evidence-result-2", "digest": "c" * 64, "correlationId": "coord-hermione", "idempotencyKey": "result-2", "occurredAt": NOW}
    make_bridge(with_supervisor=False).receive_coordination_work_request(second)
    bridge = make_bridge()
    bridge.receive_coordination_work_request(first)
    assert bridge.store.coordination_review(first["id"]) is not None
    supervisor_result = {"accepted": True, "evidence": ["review-evidence"], "occurredAt": NOW}
    bridge = make_bridge()
    result = bridge.receive_coordination_work_request(first)
    assert result["receipt"]["status"] == "accepted"
    assert bridge.store.protocol_record("coordination-work-request", first["id"])["state"] == "settled"
    assert bridge.store.protocol_record("coordination-work-request", second["id"])["state"] != "settled"
    review = next(item for item in sent if item[0] == "cross-project-supervisor-review")[2]
    assert set(review) == {"projectId", "leadId", "supervisorLeadId", "decision", "evidenceId", "linkId", "version", "reviewId", "resultId", "participantResults", "coordinationTeamId", "supervisorMemberId", "accepted", "evidence", "digest", "correlationId", "idempotencyKey", "occurredAt"}
    assert review["reviewId"] == "review-1"
    assert (review["projectId"], review["leadId"], review["resultId"]) == ("arcade", "lead-arcade", "result-1")
    assert review["participantResults"][0] == {"resultId": review["resultId"], "digest": "a" * 64}
    assert review["supervisorMemberId"] == "member-supervisor" and review["participantResults"] == [{"resultId": "result-1", "digest": "a" * 64}, {"resultId": "result-2", "digest": "c" * 64}]


def test_coordination_requires_distinct_binding_and_complete_request_set(tmp_path: Path):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    _record_registered_project(store, "arcade", "lead-arcade")
    _record_registered_project(store, "hermione", "lead-hermione")
    bridge = PsychloBridge(store=store, dispatcher=_PreparedDispatcher(identity=lambda _lead, _scope, _key: "dispatch-1"), sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    request = _coord_request("binding-1", "link-1", "v1", "arcade", "lead-arcade", "lead-supervisor", ["arcade", "hermione"])
    store.record_protocol("cross-project-team-binding", "binding-1", "binding-1", "b" * 64, {"bindingId": "binding-1", "coordinationTeamId": "team-1", "supervisorMemberId": "member-supervisor", "supervisorLeadId": "lead-supervisor"}, state="delivered")
    assert bridge.receive_coordination_work_request(request)["receipt"]["status"] == "accepted"
    conflict = _coord_request("binding-1", "link-1", "v1", "hermione", "lead-hermione", "lead-supervisor", ["arcade", "hermione", "third"])
    with pytest.raises(ValueError, match="request set conflict"):
        bridge.receive_coordination_work_request(conflict)


def test_bridge_tick_polls_pending_coordination_without_restart(tmp_path: Path):
    result = None
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    _record_registered_project(store, "arcade", "lead-arcade")
    request = _coord_request("binding-1", "link-1", "v1", "arcade", "lead-arcade", "lead-supervisor", ["arcade", "hermione"])
    store.record_protocol("cross-project-team-binding", "binding-1", "binding-1", "b" * 64, {"bindingId": "binding-1", "coordinationTeamId": "team-1", "supervisorMemberId": "member-supervisor", "supervisorLeadId": "lead-supervisor"}, state="delivered")
    bridge = PsychloBridge(store=store, dispatcher=_PreparedDispatcher(identity=lambda _lead, _scope, _key: "dispatch-1"), sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW, project_result_collector=lambda *_: result)
    assert bridge.receive_coordination_work_request(request)["receipt"]["status"] == "accepted"
    result = {"linkId": "link-1", "version": "v1", "projectId": "arcade", "leadId": "lead-arcade", "requestId": request["id"], "dispatchId": "dispatch-1", "resultId": "result-1", "scope": request["scope"], "status": "completed", "evidenceId": "evidence-result", "digest": "a" * 64, "correlationId": "coord-arcade", "idempotencyKey": "result-1", "occurredAt": NOW}
    assert bridge.tick() == {"busy": False, "processed": 1, "failed": 0}


def test_missing_supervisor_dispatcher_never_settles_coordination(tmp_path: Path):
    results = {}
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    _record_registered_project(store, "arcade", "lead-arcade")
    _record_registered_project(store, "hermione", "lead-hermione")
    store.record_protocol("cross-project-team-binding", "binding-1", "binding-1", "b" * 64, {"bindingId": "binding-1", "coordinationTeamId": "team-1", "supervisorMemberId": "member-supervisor", "supervisorLeadId": "lead-supervisor"}, state="delivered")
    dispatcher = _PreparedDispatcher()
    bridge = PsychloBridge(store=store, dispatcher=dispatcher, sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW, project_result_collector=lambda dispatch, _request: results.get(dispatch))
    first = _coord_request("binding-1", "link-1", "v1", "arcade", "lead-arcade", "lead-supervisor", ["arcade", "hermione"], expected_digest="a" * 64)
    second = _coord_request("binding-1", "link-1", "v1", "hermione", "lead-hermione", "lead-supervisor", ["arcade", "hermione"], expected_digest="c" * 64)
    bridge.receive_coordination_work_request(first)
    bridge.receive_coordination_work_request(second)
    for request, digest in ((first, "a" * 64), (second, "c" * 64)):
        dispatch_id = dispatcher.prepare(request["leadId"], request["scope"], request["id"])
        results[dispatch_id] = {"linkId": "link-1", "version": "v1", "projectId": request["projectId"], "leadId": request["leadId"], "requestId": request["id"], "dispatchId": dispatch_id, "resultId": f"result-{request['projectId']}", "scope": request["scope"], "status": "completed", "evidenceId": f"evidence-{request['projectId']}", "digest": digest, "correlationId": f"coord-{request['projectId']}", "idempotencyKey": f"result-{request['projectId']}", "occurredAt": NOW}
        bridge.receive_coordination_work_request(request)
    assert store.protocol_record("coordination-work-request", first["id"])["state"] != "settled"
    assert store.protocol_record("coordination-work-request", second["id"])["state"] != "settled"
    assert store.coordination_review(first["requiredRequestIds"][0]) is None


def test_supervisor_post_send_crash_remains_uncertain_without_repaste(tmp_path: Path):
    results = {}
    store_path = tmp_path / "bridge.sqlite3"
    store = PsychloBridgeStore(store_path)
    for project, lead in (("arcade", "lead-arcade"), ("hermione", "lead-hermione")):
        _record_registered_project(store, project, lead)
    store.record_protocol("cross-project-team-binding", "binding-1", "binding-1", "b" * 64, {"bindingId": "binding-1", "coordinationTeamId": "team-1", "supervisorMemberId": "member-supervisor", "supervisorLeadId": "lead-supervisor"}, state="delivered")
    lead_dispatcher = _PreparedDispatcher(identity=lambda lead, _scope, _key: f"dispatch-{lead}")

    class CrashingSupervisor(_PreparedDispatcher):
        def __call__(self, lead_id, context, idempotency_key):
            self.calls.append((lead_id, context, idempotency_key))
            raise SystemExit("fault after supervisor prompt submission")

    supervisor = CrashingSupervisor(identity=lambda _lead, _context, _key: "review-stable")
    make_bridge = lambda: PsychloBridge(store=PsychloBridgeStore(store_path), dispatcher=lead_dispatcher, sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW, project_result_collector=lambda dispatch, _request: results.get(dispatch), supervisor_dispatcher=supervisor)
    bridge = make_bridge()
    first = _coord_request("binding-1", "link-1", "v1", "arcade", "lead-arcade", "lead-supervisor", ["arcade", "hermione"], expected_digest="a" * 64)
    second = _coord_request("binding-1", "link-1", "v1", "hermione", "lead-hermione", "lead-supervisor", ["arcade", "hermione"], expected_digest="c" * 64)
    bridge.receive_coordination_work_request(first)
    bridge.receive_coordination_work_request(second)
    for request, digest in ((first, "a" * 64), (second, "c" * 64)):
        dispatch_id = lead_dispatcher.prepare(request["leadId"], request["scope"], request["id"])
        results[dispatch_id] = {"linkId": "link-1", "version": "v1", "projectId": request["projectId"], "leadId": request["leadId"], "requestId": request["id"], "dispatchId": dispatch_id, "resultId": f"result-{request['projectId']}", "scope": request["scope"], "status": "completed", "evidenceId": f"evidence-{request['projectId']}", "digest": digest, "correlationId": f"coord-{request['projectId']}", "idempotencyKey": f"result-{request['projectId']}", "occurredAt": NOW}
    with pytest.raises(SystemExit, match="supervisor prompt"):
        bridge.receive_coordination_work_request(first)
    review = store.coordination_review(first["id"])
    assert review is not None and review["reviewId"] == "review-stable" and review["state"] == "uncertain"
    restarted = make_bridge()
    assert restarted.receive_coordination_work_request(first)["receipt"]["status"] == "accepted"
    assert len(supervisor.calls) == 1


def test_supervisor_reviews_progress_after_each_exact_result_with_cumulative_evidence(tmp_path: Path):
    sent = []
    results = {}
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    _record_registered_project(store, "arcade", "lead-arcade")
    _record_registered_project(store, "hermione", "lead-hermione")
    store.record_protocol("cross-project-team-binding", "binding-1", "binding-1", "b" * 64, {"bindingId": "binding-1", "coordinationTeamId": "team-1", "supervisorMemberId": "member-supervisor", "supervisorLeadId": "lead-supervisor"}, state="delivered")
    reviews = {}
    supervisor_dispatcher = _PreparedDispatcher(identity=lambda _lead, context, _key: f"review-{context['projectId']}")
    bridge = PsychloBridge(store=store, dispatcher=_PreparedDispatcher(identity=lambda lead, _scope, _key: f"dispatch-{lead}"), sender=lambda kind, mid, payload: sent.append((kind, mid, payload)) or {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW, project_result_collector=lambda dispatch, _request: results.get(dispatch), supervisor_dispatcher=supervisor_dispatcher, supervisor_result_collector=lambda review_id, _context: reviews.get(review_id))
    first = _coord_request("binding-1", "link-1", "v1", "arcade", "lead-arcade", "lead-supervisor", ["arcade", "hermione"], expected_digest="a" * 64)
    second = _coord_request("binding-1", "link-1", "v1", "hermione", "lead-hermione", "lead-supervisor", ["arcade", "hermione"], expected_digest="a" * 64)
    assert bridge.receive_coordination_work_request(first)["receipt"]["status"] == "accepted"
    results["dispatch-lead-arcade"] = {"linkId": "link-1", "version": "v1", "projectId": "arcade", "leadId": "lead-arcade", "requestId": first["id"], "dispatchId": "dispatch-lead-arcade", "resultId": "result-1", "scope": first["scope"], "status": "completed", "evidenceId": "evidence-result-1", "digest": "a" * 64, "correlationId": "coord-arcade", "idempotencyKey": "result-1", "occurredAt": NOW}
    bridge.receive_coordination_work_request(first)
    first_dispatch = supervisor_dispatcher.calls[0]
    assert first_dispatch[0] == "lead-supervisor"
    assert first_dispatch[1]["requestId"] == first["id"]
    assert first_dispatch[1]["participantResults"] == [{"resultId": "result-1", "digest": "a" * 64}]
    reviews["review-arcade"] = {"accepted": True, "evidence": ["review-arcade-evidence"], "occurredAt": NOW}
    bridge.receive_coordination_work_request(first)
    assert store.protocol_record("coordination-work-request", first["id"])["state"] == "settled"
    assert store.protocol_record("coordination-work-request", second["id"]) is None

    assert bridge.receive_coordination_work_request(second)["receipt"]["status"] == "accepted"
    results["dispatch-lead-hermione"] = {"linkId": "link-1", "version": "v1", "projectId": "hermione", "leadId": "lead-hermione", "requestId": second["id"], "dispatchId": "dispatch-lead-hermione", "resultId": "result-2", "scope": second["scope"], "status": "completed", "evidenceId": "evidence-result-2", "digest": "a" * 64, "correlationId": "coord-hermione", "idempotencyKey": "result-2", "occurredAt": NOW}
    bridge.receive_coordination_work_request(second)
    second_dispatch = supervisor_dispatcher.calls[1]
    assert second_dispatch[0] == "lead-supervisor"
    assert second_dispatch[1]["requestId"] == second["id"]
    assert second_dispatch[1]["participantResults"] == [{"resultId": "result-1", "digest": "a" * 64}, {"resultId": "result-2", "digest": "a" * 64}]
    reviews["review-hermione"] = {"accepted": True, "evidence": ["review-hermione-evidence"], "occurredAt": NOW}
    bridge.receive_coordination_work_request(second)
    assert store.protocol_record("coordination-work-request", second["id"])["state"] == "settled"
    assert [item[1] for item in sent if item[0] == "cross-project-supervisor-review"] == ["review-arcade", "review-hermione"]


def test_progressive_review_uses_exact_scoped_terminal_lookup_beyond_global_page(tmp_path: Path):
    results = {}
    reviews = {}
    store_path = tmp_path / "bridge.sqlite3"
    store = PsychloBridgeStore(store_path)
    _record_registered_project(store, "arcade", "lead-arcade")
    _record_registered_project(store, "hermione", "lead-hermione")
    store.record_protocol("cross-project-team-binding", "binding-1", "binding-1", "b" * 64, {"bindingId": "binding-1", "coordinationTeamId": "team-1", "supervisorMemberId": "member-supervisor", "supervisorLeadId": "lead-supervisor"}, state="delivered")
    for index in range(101):
        digest = hashlib.sha256(f"unrelated-{index}".encode()).hexdigest()
        payload = {"requestId": f"unrelated-request-{index}", "resultId": f"unrelated-result-{index}", "digest": digest}
        store.record_protocol("cross-project-participant-result", payload["resultId"], payload["resultId"], digest, payload, state="delivered")
    supervisor = _PreparedDispatcher(identity=lambda _lead, context, _key: f"review-{context['projectId']}")
    def make_bridge():
        return PsychloBridge(store=PsychloBridgeStore(store_path), dispatcher=_PreparedDispatcher(identity=lambda lead, *_: f"dispatch-{lead}"), sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW, project_result_collector=lambda dispatch, _request: results.get(dispatch), supervisor_dispatcher=supervisor, supervisor_result_collector=lambda review_id, _context: reviews.get(review_id))
    first = _coord_request("binding-1", "link-exact", "v1", "arcade", "lead-arcade", "lead-supervisor", ["arcade", "hermione"], expected_digest="a" * 64)
    second = _coord_request("binding-1", "link-exact", "v1", "hermione", "lead-hermione", "lead-supervisor", ["arcade", "hermione"], expected_digest="a" * 64)
    bridge = make_bridge()
    bridge.receive_coordination_work_request(first)
    results["dispatch-lead-arcade"] = {"linkId": "link-exact", "version": "v1", "projectId": "arcade", "leadId": "lead-arcade", "requestId": first["id"], "dispatchId": "dispatch-lead-arcade", "resultId": "result-exact-arcade", "scope": first["scope"], "status": "completed", "evidenceId": "evidence-exact-arcade", "digest": "a" * 64, "correlationId": "coord-exact-arcade", "idempotencyKey": "result-exact-arcade", "occurredAt": NOW}
    bridge.receive_coordination_work_request(first)
    assert supervisor.calls[0][1]["participantResults"] == [{"resultId": "result-exact-arcade", "digest": "a" * 64}]
    reviews["review-arcade"] = {"accepted": True, "evidence": ["review-exact-arcade"], "occurredAt": NOW}
    restarted = make_bridge()
    restarted.receive_coordination_work_request(first)
    restarted.receive_coordination_work_request(second)
    results["dispatch-lead-hermione"] = {"linkId": "link-exact", "version": "v1", "projectId": "hermione", "leadId": "lead-hermione", "requestId": second["id"], "dispatchId": "dispatch-lead-hermione", "resultId": "result-exact-hermione", "scope": second["scope"], "status": "completed", "evidenceId": "evidence-exact-hermione", "digest": "a" * 64, "correlationId": "coord-exact-hermione", "idempotencyKey": "result-exact-hermione", "occurredAt": NOW}
    restarted.receive_coordination_work_request(second)
    assert supervisor.calls[1][1]["participantResults"] == [{"resultId": "result-exact-arcade", "digest": "a" * 64}, {"resultId": "result-exact-hermione", "digest": "a" * 64}]


def test_legacy_protocol_digest_constraint_is_rebuilt_and_terminal_index_backfilled(tmp_path: Path):
    store_path = tmp_path / "bridge.sqlite3"
    connection = sqlite3.connect(store_path)
    connection.execute("CREATE TABLE protocol_records(kind TEXT NOT NULL, record_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, digest TEXT NOT NULL, payload_json TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, updated_at TEXT NOT NULL, receipt_json TEXT, PRIMARY KEY(kind,record_id), UNIQUE(kind,idempotency_key), UNIQUE(kind,digest))")
    first = {"requestId": "legacy-request-1", "resultId": "legacy-result-1", "digest": "a" * 64}
    connection.execute("INSERT INTO protocol_records VALUES (?,?,?,?,?,'delivered',0,NULL,?,NULL)", ("cross-project-participant-result", first["resultId"], first["resultId"], first["digest"], json.dumps(first, separators=(",", ":")), NOW))
    connection.commit(); connection.close(); store_path.chmod(0o600)
    store = PsychloBridgeStore(store_path)
    assert store.coordination_participant_terminal(first["requestId"])["id"] == first["resultId"]
    second = {"requestId": "legacy-request-2", "resultId": "legacy-result-2", "digest": "a" * 64}
    record, inserted = store.record_coordination_participant_terminal(second["requestId"], second["resultId"], second["resultId"], second["digest"], second)
    assert inserted is True and record["digest"] == first["digest"]
    store.record_protocol("cross-project-command", "command-1", "command-1", "c" * 64, {"digest": "c" * 64})
    with pytest.raises(ValueError, match="cross-project-command conflict"):
        store.record_protocol("cross-project-command", "command-2", "command-2", "c" * 64, {"digest": "c" * 64, "other": True})


def test_legacy_protocol_migration_rolls_back_if_replacement_index_cannot_bind(tmp_path: Path):
    store_path = tmp_path / "bridge.sqlite3"
    connection = sqlite3.connect(store_path)
    connection.execute("CREATE TABLE protocol_records(kind TEXT NOT NULL, record_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, digest TEXT NOT NULL, payload_json TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, updated_at TEXT NOT NULL, receipt_json TEXT, PRIMARY KEY(kind,record_id), UNIQUE(kind,idempotency_key), UNIQUE(kind,digest))")
    connection.execute("CREATE TABLE unrelated(value TEXT)")
    connection.execute("CREATE UNIQUE INDEX protocol_kind_digest_unique ON unrelated(value)")
    payload = {"requestId": "legacy-request", "resultId": "legacy-result", "digest": "a" * 64}
    connection.execute("INSERT INTO protocol_records VALUES (?,?,?,?,?,'delivered',0,NULL,?,NULL)", ("cross-project-participant-result", payload["resultId"], payload["resultId"], payload["digest"], json.dumps(payload, separators=(",", ":")), NOW))
    connection.commit(); connection.close(); store_path.chmod(0o600)
    with pytest.raises(ValueError, match="protocol digest index binding is invalid"):
        PsychloBridgeStore(store_path)
    connection = sqlite3.connect(store_path)
    schema = connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='protocol_records'").fetchone()[0]
    assert "UNIQUE(kind,digest)" in "".join(schema.split())
    assert connection.execute("SELECT record_id FROM protocol_records").fetchall() == [("legacy-result",)]
    assert connection.execute("SELECT tbl_name FROM sqlite_master WHERE type='index' AND name='protocol_kind_digest_unique'").fetchone() == ("unrelated",)
    connection.close()


@pytest.mark.parametrize("suffix", ["AND 0", "OR kind = 'cross-project-participant-result'"])
def test_protocol_migration_rejects_same_named_index_with_malformed_predicate(tmp_path: Path, suffix: str):
    store_path = tmp_path / "bridge.sqlite3"
    connection = sqlite3.connect(store_path)
    connection.execute("CREATE TABLE protocol_records(kind TEXT NOT NULL, record_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, digest TEXT NOT NULL, payload_json TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, updated_at TEXT NOT NULL, receipt_json TEXT, PRIMARY KEY(kind,record_id), UNIQUE(kind,idempotency_key))")
    index_sql = f"CREATE UNIQUE INDEX protocol_kind_digest_unique ON protocol_records(kind,digest) WHERE kind != 'cross-project-participant-result' {suffix}"
    connection.execute(index_sql)
    connection.execute("INSERT INTO protocol_records VALUES ('cross-project-command','command-1','command-1',?,'{}','delivered',0,NULL,?,NULL)", ("c" * 64, NOW))
    connection.commit(); connection.close(); store_path.chmod(0o600)
    with pytest.raises(ValueError, match="protocol digest index binding is invalid"):
        PsychloBridgeStore(store_path)
    connection = sqlite3.connect(store_path)
    assert connection.execute("SELECT sql FROM sqlite_master WHERE type='index' AND name='protocol_kind_digest_unique'").fetchone() == (index_sql,)
    assert connection.execute("SELECT record_id,digest FROM protocol_records").fetchall() == [("command-1", "c" * 64)]
    connection.close()


def test_rejected_progressive_review_blocks_only_its_trigger_and_is_not_resent_after_restart(tmp_path: Path):
    results = {}
    reviews = {}
    sent = []
    store_path = tmp_path / "bridge.sqlite3"
    store = PsychloBridgeStore(store_path)
    for project, lead in (("arcade", "lead-arcade"), ("hermione", "lead-hermione")):
        _record_registered_project(store, project, lead)
    store.record_protocol("cross-project-team-binding", "binding-1", "binding-1", "b" * 64, {"bindingId": "binding-1", "coordinationTeamId": "team-1", "supervisorMemberId": "member-supervisor", "supervisorLeadId": "lead-supervisor"}, state="delivered")
    lead_dispatcher = _PreparedDispatcher(identity=lambda lead, _scope, _key: f"dispatch-{lead}")
    supervisor = _PreparedDispatcher(identity=lambda _lead, context, _key: f"review-{context['projectId']}")
    def make_bridge():
        return PsychloBridge(store=PsychloBridgeStore(store_path), dispatcher=lead_dispatcher, sender=lambda kind, mid, payload: sent.append((kind, mid, payload)) or {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW, project_result_collector=lambda dispatch, _request: results.get(dispatch), supervisor_dispatcher=supervisor, supervisor_result_collector=lambda review_id, _context: reviews.get(review_id))
    first = _coord_request("binding-1", "link-reject", "v1", "arcade", "lead-arcade", "lead-supervisor", ["arcade", "hermione"], expected_digest="a" * 64)
    second = _coord_request("binding-1", "link-reject", "v1", "hermione", "lead-hermione", "lead-supervisor", ["arcade", "hermione"], expected_digest="c" * 64)
    bridge = make_bridge()
    bridge.receive_coordination_work_request(first)
    bridge.receive_coordination_work_request(second)
    results["dispatch-lead-arcade"] = {"linkId": "link-reject", "version": "v1", "projectId": "arcade", "leadId": "lead-arcade", "requestId": first["id"], "dispatchId": "dispatch-lead-arcade", "resultId": "result-rejected", "scope": first["scope"], "status": "completed", "evidenceId": "evidence-result", "digest": "a" * 64, "correlationId": "coord-arcade", "idempotencyKey": "result-rejected", "occurredAt": NOW}
    bridge.receive_coordination_work_request(first)
    reviews["review-arcade"] = {"accepted": False, "evidence": ["review-rejected"], "occurredAt": NOW}
    bridge.receive_coordination_work_request(first)
    assert bridge.store.coordination_review(first["id"])["state"] == "rejected"
    assert bridge.store.protocol_record("coordination-work-request", first["id"])["state"] != "settled"
    calls_before = list(supervisor.calls)
    restarted = make_bridge()
    restarted.receive_coordination_work_request(first)
    assert supervisor.calls == calls_before
    assert len([item for item in sent if item[0] == "cross-project-supervisor-review"]) == 1


def test_participant_terminal_is_immutable_per_request_across_restart(tmp_path: Path):
    current = {}
    store_path = tmp_path / "bridge.sqlite3"
    store = PsychloBridgeStore(store_path)
    _record_registered_project(store, "arcade", "lead-arcade")
    store.record_protocol("cross-project-team-binding", "binding-1", "binding-1", "b" * 64, {"bindingId": "binding-1", "coordinationTeamId": "team-1", "supervisorMemberId": "member-supervisor", "supervisorLeadId": "lead-supervisor"}, state="delivered")
    request = _coord_request("binding-1", "link-terminal", "v1", "arcade", "lead-arcade", "lead-supervisor", ["arcade", "hermione"], expected_digest="a" * 64)
    def make_bridge():
        return PsychloBridge(store=PsychloBridgeStore(store_path), dispatcher=_PreparedDispatcher(identity=lambda *_: "dispatch-arcade"), sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW, project_result_collector=lambda *_: current.get("result"))
    bridge = make_bridge()
    bridge.receive_coordination_work_request(request)
    current["result"] = {"linkId": "link-terminal", "version": "v1", "projectId": "arcade", "leadId": "lead-arcade", "requestId": request["id"], "dispatchId": "dispatch-arcade", "resultId": "result-original", "scope": request["scope"], "status": "blocked", "evidenceId": "evidence-original", "digest": "a" * 64, "correlationId": "coord-original", "idempotencyKey": "result-original", "occurredAt": NOW}
    bridge.receive_coordination_work_request(request)
    assert bridge.receive_coordination_work_request(request)["receipt"]["status"] == "accepted"
    current["result"] = {**current["result"], "status": "completed", "resultId": "result-later", "evidenceId": "evidence-later", "correlationId": "coord-later", "idempotencyKey": "result-later"}
    with pytest.raises(ValueError, match="participant result terminal conflict"):
        make_bridge().receive_coordination_work_request(request)
    assert PsychloBridgeStore(store_path).protocol_record("cross-project-participant-result", "result-later") is None


def test_verifies_exact_signed_psychlo_request_once(tmp_path: Path):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    body = json.dumps({"kind": "round-request", "messageId": "round-1", "occurredAt": NOW, "payload": {"roundId": "round-1"}}, separators=(",", ":")).encode()
    headers = sign_peer_message(SECRET, "psychlo-to-overseer", "round-request", "round-1", NOW, "nonce_1234567890abcdef", body)
    assert verify_peer_request(SECRET, store, "round-request", body, headers, now=NOW, expected_authority="127.0.0.1:8766")["messageId"] == "round-1"
    try:
        verify_peer_request(SECRET, store, "round-request", body, headers, now=NOW, expected_authority="127.0.0.1:8766")
    except ValueError as error:
        assert str(error) == "replay"
    else:
        raise AssertionError("replay was accepted")


def test_peer_verification_accepts_one_exact_injected_authority_only(tmp_path: Path):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    body = json.dumps({"kind": "round-request", "messageId": "round-dynamic", "occurredAt": NOW, "payload": {"roundId": "round-dynamic"}}, separators=(",", ":")).encode()
    authority = "127.0.0.1:43127"
    headers = sign_peer_message(SECRET, "psychlo-to-overseer", "round-request", "round-dynamic", NOW, "nonce_dynamic_123456", body, authority=authority)
    assert verify_peer_request(SECRET, store, "round-request", body, headers, now=NOW, expected_authority=authority)["messageId"] == "round-dynamic"


def test_peer_verification_rejects_wrong_or_missing_injected_authority(tmp_path: Path):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    body = json.dumps({"kind": "round-request", "messageId": "round-host", "occurredAt": NOW, "payload": {"roundId": "round-host"}}, separators=(",", ":")).encode()
    authority = "127.0.0.1:43128"
    headers = sign_peer_message(SECRET, "psychlo-to-overseer", "round-request", "round-host", NOW, "nonce_host_123456789", body, authority=authority)
    wrong = {**headers, "host": "127.0.0.1:43129"}
    for candidate in (wrong, {key: value for key, value in headers.items() if key != "host"}):
        try:
            verify_peer_request(SECRET, store, "round-request", body, candidate, now=NOW, expected_authority=authority)
        except ValueError as error:
            assert str(error) == "invalid_headers"
        else:
            raise AssertionError("wrong or missing authority was accepted")


def test_derives_prior_day_unused_weekly_capacity_from_provider_delta_only():
    history = [
        {"observed_at": "2026-08-10T02:00:00+00:00", "rate_limits": [{"limit_id": "codex", "windows": [{"duration_minutes": 10080, "used_percent": 30, "remaining_percent": 70, "resets_at": "2026-08-16T00:00:00+00:00"}]}]},
        {"observed_at": "2026-08-09T02:00:00+00:00", "rate_limits": [{"limit_id": "codex", "windows": [{"duration_minutes": 10080, "used_percent": 25, "remaining_percent": 75, "resets_at": "2026-08-16T00:00:00+00:00"}]}]},
    ]
    snapshot = derive_usage_snapshot(history, policy_version="2026-08-09")
    assert round(snapshot["snapshot"]["unusedPriorDayWeeklyCapacity"], 6) == round(100 / 7 - 5, 6)
    assert snapshot["snapshot"]["weeklyRemainingCapacity"] == 70


def test_usage_snapshot_denies_missing_same_reset_prior_day_history():
    history = [{"observed_at": "2026-08-10T02:00:00+00:00", "rate_limits": [{"limit_id": "codex", "windows": [{"window_minutes": 10080, "used_percent": 30, "remaining_percent": 70, "resets_at": "2026-08-16T00:00:00+00:00"}]}]}]
    try:
        derive_usage_snapshot(history, policy_version="2026-08-09")
    except ValueError as error:
        assert "prior-day" in str(error)
    else:
        raise AssertionError("missing history was accepted")


def test_emit_usage_ignores_malformed_lead_result_and_uses_provider_snapshot(tmp_path: Path):
    sent = []
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    store.record_round({"roundId": "round-bad"}, {}, "capability-bad")
    store.record_result("round-bad", {"occurredAt": "not-a-timestamp", "actualUsageCost": "not-a-number"})
    bridge = PsychloBridge(
        store=store,
        dispatcher=lambda _lead, _prompt: "unused",
        sender=lambda kind, message_id, payload: sent.append((kind, message_id, payload)) or {"accepted": True},
        callback_origin="http://127.0.0.1:8766",
        clock=lambda: NOW,
    )
    history = [
        {"observed_at": "2026-08-10T02:00:00+00:00", "rate_limits": [{"limit_id": "codex", "windows": [{"duration_minutes": 10080, "used_percent": 30, "remaining_percent": 70, "resets_at": "2026-08-16T00:00:00+00:00"}]}]},
        {"observed_at": "2026-08-09T02:00:00+00:00", "rate_limits": [{"limit_id": "codex", "windows": [{"duration_minutes": 10080, "used_percent": 25, "remaining_percent": 75, "resets_at": "2026-08-16T00:00:00+00:00"}]}]},
    ]
    bridge.emit_usage(history, "2026-08-09")
    assert sent[0][0] == "usage-snapshot"
    assert round(sent[0][2]["snapshot"]["unusedPriorDayWeeklyCapacity"], 6) == round(100 / 7 - 5, 6)


def test_private_peer_secret_rejects_symlink_and_group_readable_file(tmp_path: Path):
    secret = tmp_path / "secret"
    secret.write_bytes(SECRET); secret.chmod(0o640)
    try:
        _read_secret(secret)
    except ValueError:
        pass
    else:
        raise AssertionError("group-readable secret was accepted")
    secret.chmod(0o600)
    link = tmp_path / "secret-link"; link.symlink_to(secret)
    try:
        _read_secret(link)
    except ValueError:
        pass
    else:
        raise AssertionError("symlink secret was accepted")


def test_dispatches_one_round_and_forwards_one_bound_result(tmp_path: Path):
    dispatched = []
    forwarded = []
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    bridge = PsychloBridge(
        store=store,
        dispatcher=lambda project_lead_id, prompt: dispatched.append((project_lead_id, prompt)) or "dispatch:1",
        sender=lambda kind, message_id, payload: forwarded.append((kind, message_id, payload)) or {"accepted": True},
        callback_origin="http://127.0.0.1:8766",
        clock=lambda: NOW,
        token_factory=lambda: "capability_1234567890abcdef1234567890",
    )
    request = {"roundId": "round-1", "projectId": "arcade", "projectLeadId": "member-hermione", "planId": "arcade-plan", "planVersion": "v1", "correlationId": "corr-1", "idempotencyKey": "round-1", "snapshotId": "snapshot-1", "policyVersion": "2026-08-09", "expectedUsageCost": 5, "scope": "one bounded round", "selectionReason": "priority-selected", "priorityRationale": "sole-eligible-project"}
    receipt = bridge.request_round(request)
    assert receipt["receipt"]["status"] == "accepted"
    assert len(dispatched) == 1
    assert "approved A-Team project lead" in dispatched[0][1]
    result = {**request, "sourceId": "member-hermione", "provenanceId": "result:1", "status": "completed", "actualUsageCost": 4, "deliveredScope": "foundation", "remainingEstimate": 8, "blockers": [], "questions": [], "reachedExplicitGates": [], "occurredAt": NOW}
    accepted = bridge.receive_round_result("capability_1234567890abcdef1234567890", result)
    assert accepted == {"accepted": True}
    assert forwarded == [("round-result", "result:1", result)]
    assert bridge.request_round(request) == receipt


def test_round_completion_timing_uses_trusted_receipt_time_not_lead_occurred_at(tmp_path: Path):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    bridge = PsychloBridge(
        store=store,
        dispatcher=lambda *_: "dispatch:trusted-time",
        sender=lambda *_: {"accepted": True},
        callback_origin="http://127.0.0.1:8766",
        clock=lambda: NOW,
        token_factory=lambda: "capability_trusted_time_1234567890abcdef",
    )
    request = {"roundId": "round-trusted-time", "projectId": "arcade", "projectLeadId": "member-hermione", "planId": "arcade-plan", "planVersion": "v1", "correlationId": "corr-trusted-time", "idempotencyKey": "round-trusted-time", "snapshotId": "snapshot-trusted-time", "policyVersion": "2026-08-09", "expectedUsageCost": 1, "scope": "one bounded round", "selectionReason": "priority-selected", "priorityRationale": "project-id"}
    bridge.request_round(request)
    result = {**request, "sourceId": "member-hermione", "provenanceId": "result:trusted-time", "status": "completed", "actualUsageCost": 1, "deliveredScope": "bounded work", "remainingEstimate": 0, "blockers": [], "questions": [], "reachedExplicitGates": [], "occurredAt": "2026-08-10T02:59:59+00:00"}

    bridge.receive_round_result("capability_trusted_time_1234567890abcdef", result)

    timing = store.round_timing("round-trusted-time")
    assert timing == {"authorizationId": None, "startedAt": NOW, "completedAt": NOW}


def test_retries_a_durably_reserved_round_after_dispatch_failure(tmp_path: Path):
    attempts = []
    def dispatch(_lead, _prompt):
        attempts.append("attempt")
        if len(attempts) == 1: raise ValueError("provider unavailable")
        return "dispatch:recovered"
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=dispatch, sender=lambda *_args: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW, token_factory=lambda: "capability_retry_1234567890abcdef")
    request = {"roundId": "round-retry", "projectId": "arcade", "projectLeadId": "member-hermione", "planId": "arcade-plan", "planVersion": "v1", "correlationId": "corr-retry", "idempotencyKey": "round-retry", "snapshotId": "snapshot-retry", "policyVersion": "2026-08-09", "expectedUsageCost": 5, "scope": "one bounded round", "selectionReason": "priority-selected", "priorityRationale": "sole-eligible-project"}
    try:
        bridge.request_round(request)
    except ValueError as error:
        assert str(error) == "provider unavailable"
    else:
        raise AssertionError("dispatch failure was hidden")
    recovered = bridge.reconcile_round(request)
    assert recovered["receipt"]["provenanceId"] == "dispatch:recovered"
    assert len(attempts) == 2


def test_stages_and_completes_roadex_decision(tmp_path: Path):
    forwarded = []
    bridge = PsychloBridge(
        store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"),
        dispatcher=lambda _lead, _prompt: "unused",
        sender=lambda kind, message_id, payload: forwarded.append((kind, message_id, payload)) or {"accepted": True},
        callback_origin="http://127.0.0.1:8766",
        clock=lambda: NOW,
    )
    request = {"decisionId": "decision-1", "projectId": "arcade", "planId": "arcade-plan", "workflowId": "psychlo-roadex", "decisionVersion": "v1", "correlationId": "corr-decision", "idempotencyKey": "decision-1", "question": "Create the private GitHub repository?"}
    assert bridge.stage_decision(request)["receipt"]["status"] == "staged"
    item = bridge.list_decisions()[0]
    assert item["human_approval_required"] is True
    bridge.decide("decision-1", "approve", "human-user", "")
    assert forwarded[0][0] == "decision-outcome"
    assert forwarded[0][2]["status"] == "approved"


def test_registers_an_admitted_plan_and_publishes_initial_scheduling(tmp_path: Path):
    sent = []
    bridge = PsychloBridge(
        store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda _lead, _prompt: "unused",
        sender=lambda kind, message_id, payload: sent.append((kind, message_id, payload)) or {"accepted": True},
        callback_origin="http://127.0.0.1:8766", clock=lambda: NOW,
    )
    registration = _registration_payload("arcade", "member-hermione", plan_id="arcade-plan")
    registration["envelope"]["plan"]["constraints"] = ["security review required"]
    registration["envelope"]["plan"]["tasks"].append({"id": "task-2", "ownerMemberId": "member-hermione", "title": "Verify", "description": "Verify the approved scope", "dependencyIds": ["task-1"], "acceptanceCriteria": ["tests pass"]})
    registration["envelope"]["digest"] = canonical_digest(registration["envelope"])
    registration["receipt"]["envelopeDigest"] = registration["envelope"]["digest"]
    result = bridge.register_project(registration)
    assert result == {"accepted": True}
    assert sent[0][0] == "scheduling-input"
    assert sent[0][2] == {"projectId": "arcade", "projectLeadId": "member-hermione", "state": "managed", "remainingEffort": "standard", "hasSecurityImpact": True, "hasDependencyImpact": True, "gateDistance": 2, "expectedUsageCost": 1, "correlationId": "psychlo-scheduling:receipt-arcade", "idempotencyKey": "psychlo-scheduling:receipt-arcade", "occurredAt": NOW}
    bridge.register_project(registration)
    assert len(sent) == 1


def test_coordination_dispatch_accepts_exact_real_registration_shape_after_restart(tmp_path: Path):
    store_path = tmp_path / "bridge.sqlite3"
    fixture_path = Path(__file__).parent / "fixtures" / "a-team-psychlo-handoff-v1.json"
    fixture_bytes = fixture_path.read_bytes()
    assert hashlib.sha256(fixture_bytes).hexdigest() == "99f0279dc1be40836f8e6f5420cb069d66d34f9c30effd123e365099e2d5d751"
    frozen = json.loads(fixture_bytes)
    assert canonical_digest(frozen["envelope"]) == frozen["expectedDigest"] == frozen["envelope"]["digest"]
    registration = {"envelope": frozen["envelope"], "receipt": frozen["receipt"]}
    bridge = PsychloBridge(store=PsychloBridgeStore(store_path), dispatcher=_PreparedDispatcher(), sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    assert bridge.register_project(registration) == {"accepted": True}
    store = PsychloBridgeStore(store_path)
    store.record_protocol("cross-project-team-binding", "binding-1", "binding-1", "b" * 64, {"bindingId": "binding-1", "coordinationTeamId": "coordination-team", "supervisorMemberId": "member-supervisor", "supervisorLeadId": "lead-supervisor"}, state="delivered")
    dispatcher = _PreparedDispatcher(identity=lambda *_: "dispatch-real-registration")
    restarted = PsychloBridge(store=PsychloBridgeStore(store_path), dispatcher=dispatcher, sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    request = _coord_request("binding-1", "link-real", "v1", "psychlo-handoff", "lead-psychlo-01", "lead-supervisor", ["psychlo-handoff", "peer-project"])
    assert restarted.receive_coordination_work_request(request)["receipt"]["status"] == "accepted"
    assert dispatcher.calls[0][0] == "lead-psychlo-01"


@pytest.mark.parametrize("defect", ["missing", "digest", "version", "source", "approval", "approved_timestamp", "occurred_timestamp", "receipt_timestamp", "receipt_version"])
def test_register_project_rejects_malformed_real_handoff_before_persistence(tmp_path: Path, defect: str):
    registration = _registration_payload("arcade", "lead-arcade")
    if defect == "missing": del registration["envelope"]["plan"]["summary"]
    elif defect == "digest": registration["envelope"]["digest"] = "f" * 64
    elif defect == "version": registration["envelope"]["contractVersion"] = "a-team.psychlo.handoff.v9"
    elif defect == "source": registration["envelope"]["source"] = "other"
    elif defect == "approval": registration["envelope"]["approval"]["status"] = "pending"
    elif defect == "approved_timestamp": registration["envelope"]["approval"]["approvedAt"] = "2026-08-10T02:00:00"
    elif defect == "occurred_timestamp": registration["envelope"]["occurredAt"] = "not-a-time"
    elif defect == "receipt_timestamp": registration["receipt"]["receivedAt"] = "2026-08-10T02:00:00"
    else: registration["receipt"]["contractVersion"] = "a-team.psychlo.receipt.v9"
    sent = []
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    bridge = PsychloBridge(store=store, dispatcher=_PreparedDispatcher(), sender=lambda *args: sent.append(args) or {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    with pytest.raises(ValueError):
        bridge.register_project(registration)
    assert store.project("arcade") is None and sent == []


def test_register_project_accepts_exact_lifecycle_handoff_version(tmp_path: Path):
    registration = _registration_payload("arcade", "lead-arcade", plan_id="plan-arcade-v2", plan_version="v2")
    registration["envelope"]["contractVersion"] = "a-team.psychlo.handoff.v2"
    registration["envelope"]["lifecycle"] = {"kind": "change", "supersedesPlanId": "plan-arcade", "supersedesVersion": "v1"}
    registration["envelope"]["digest"] = canonical_digest(registration["envelope"])
    registration["receipt"]["handoffContractVersion"] = registration["envelope"]["contractVersion"]
    registration["receipt"]["envelopeDigest"] = registration["envelope"]["digest"]
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=_PreparedDispatcher(), sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    assert bridge.register_project(registration) == {"accepted": True}


@pytest.mark.parametrize(("kind", "classification"), [("reconstruction", "recover-active"), ("onboarding", "adopt-baseline"), ("cleanup", "cleanup-required")])
def test_register_project_accepts_exact_adoption_lifecycle_and_dispatches_after_restart(tmp_path: Path, kind: str, classification: str):
    project_id = f"arcade-{kind}"
    lead_id = f"lead-{kind}"
    store_path = tmp_path / "bridge.sqlite3"
    registration = _registration_payload(project_id, lead_id, plan_id=f"plan-{kind}", plan_version="v2")
    registration["envelope"]["contractVersion"] = "a-team.psychlo.handoff.v2"
    registration["envelope"]["lifecycle"] = {
        "kind": kind, "assessmentId": f"assessment-{kind}", "assessmentDigest": "a" * 64,
        "classification": classification, "teamId": f"team-{kind}", "projectLeadId": lead_id,
        "artifactActions": [{"artifactId": f"artifact-{kind}", "artifactDigest": "b" * 64, "action": "restore"}],
    }
    registration["envelope"]["digest"] = canonical_digest(registration["envelope"])
    registration["receipt"]["handoffContractVersion"] = registration["envelope"]["contractVersion"]
    registration["receipt"]["envelopeDigest"] = registration["envelope"]["digest"]
    bridge = PsychloBridge(store=PsychloBridgeStore(store_path), dispatcher=_PreparedDispatcher(), sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    assert bridge.register_project(registration) == {"accepted": True}
    store = PsychloBridgeStore(store_path)
    store.record_protocol("cross-project-team-binding", "binding-1", "binding-1", "b" * 64, {"bindingId": "binding-1", "coordinationTeamId": "coordination-team", "supervisorMemberId": "member-supervisor", "supervisorLeadId": "lead-supervisor"}, state="delivered")
    dispatcher = _PreparedDispatcher(identity=lambda *_: f"dispatch-{kind}")
    restarted = PsychloBridge(store=PsychloBridgeStore(store_path), dispatcher=dispatcher, sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    request = _coord_request("binding-1", f"link-{kind}", "v1", project_id, lead_id, "lead-supervisor", [project_id, f"peer-{kind}"])
    assert restarted.receive_coordination_work_request(request)["receipt"]["status"] == "accepted"
    assert dispatcher.calls[0][0] == lead_id


@pytest.mark.parametrize("defect", ["classification", "lead", "artifact_digest", "artifact_action", "artifact_extra", "reject"])
def test_register_project_rejects_malformed_adoption_lifecycle(tmp_path: Path, defect: str):
    registration = _registration_payload("arcade", "lead-arcade", plan_id="plan-arcade-v2", plan_version="v2")
    registration["envelope"]["contractVersion"] = "a-team.psychlo.handoff.v2"
    lifecycle = {"kind": "cleanup", "assessmentId": "assessment-1", "assessmentDigest": "a" * 64, "classification": "cleanup-required", "teamId": "team-arcade", "projectLeadId": "lead-arcade", "artifactActions": [{"artifactId": "artifact-1", "artifactDigest": "b" * 64, "action": "restore"}]}
    if defect == "classification": lifecycle["classification"] = "recover-active"
    elif defect == "lead": lifecycle["projectLeadId"] = "lead-other"
    elif defect == "artifact_digest": lifecycle["artifactActions"][0]["artifactDigest"] = "invalid"
    elif defect == "artifact_action": lifecycle["artifactActions"][0]["action"] = "delete"
    elif defect == "artifact_extra": lifecycle["artifactActions"][0]["extra"] = True
    else: lifecycle = {"kind": "reject", "assessmentId": "assessment-1", "assessmentDigest": "a" * 64, "candidateId": "candidate-1"}
    registration["envelope"]["lifecycle"] = lifecycle
    registration["envelope"]["digest"] = canonical_digest(registration["envelope"])
    registration["receipt"]["handoffContractVersion"] = registration["envelope"]["contractVersion"]
    registration["receipt"]["envelopeDigest"] = registration["envelope"]["digest"]
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=_PreparedDispatcher(), sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    with pytest.raises(ValueError, match="lifecycle|digest|artifact"):
        bridge.register_project(registration)


def test_takeover_registration_rejects_nul_repository_path_before_scheduling_and_after_restart(tmp_path: Path):
    store_path = tmp_path / "bridge.sqlite3"
    registration = _registration_payload("arcade", "lead-arcade", plan_id="plan-takeover", plan_version="v2")
    registration["envelope"]["contractVersion"] = "a-team.psychlo.handoff.v2"
    registration["envelope"]["lifecycle"] = {
        "kind": "takeover", "repositoryPath": "/srv/arcade\0/private", "repositoryHead": "a" * 40,
        "dirtyStateDigest": "b" * 64, "currentStateEvidence": ["evidence-takeover"],
    }
    registration["envelope"]["digest"] = canonical_digest(registration["envelope"])
    registration["receipt"]["handoffContractVersion"] = registration["envelope"]["contractVersion"]
    registration["receipt"]["envelopeDigest"] = registration["envelope"]["digest"]
    sent = []
    bridge = PsychloBridge(store=PsychloBridgeStore(store_path), dispatcher=_PreparedDispatcher(), sender=lambda *args: sent.append(args) or {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    with pytest.raises(ValueError, match="lifecycle"):
        bridge.register_project(registration)
    assert bridge.store.project("arcade") is None and sent == []
    restarted_sent = []
    restarted = PsychloBridge(store=PsychloBridgeStore(store_path), dispatcher=_PreparedDispatcher(), sender=lambda *args: restarted_sent.append(args) or {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    with pytest.raises(ValueError, match="lifecycle"):
        restarted.register_project(registration)
    assert restarted.store.project("arcade") is None and restarted_sent == []


@pytest.mark.parametrize("field", ["project", "plan", "version", "team", "lead", "scheduling"])
def test_coordination_rejects_registration_identity_conflict_before_dispatch(tmp_path: Path, field: str):
    registration = _registration_payload("arcade", "lead-arcade", plan_id="plan-arcade", plan_version="v7", team_id="team-arcade")
    if field == "project": registration["receipt"]["project"]["id"] = "other-project"
    elif field == "plan": registration["receipt"]["project"]["planId"] = "other-plan"
    elif field == "version": registration["receipt"]["project"]["planVersion"] = "v8"
    elif field == "team": registration["receipt"]["aTeamId"] = "other-team"
    elif field == "lead": registration["envelope"]["projectLead"]["id"] = "other-lead"
    scheduling = _scheduling_payload(registration)
    if field == "scheduling": del scheduling["gateDistance"]
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    store.record_project("arcade", registration, scheduling)
    store.record_protocol("cross-project-team-binding", "binding-1", "binding-1", "b" * 64, {"bindingId": "binding-1", "coordinationTeamId": "coordination-team", "supervisorMemberId": "member-supervisor", "supervisorLeadId": "lead-supervisor"}, state="delivered")
    dispatcher = _PreparedDispatcher(identity=lambda *_: "must-not-dispatch")
    bridge = PsychloBridge(store=store, dispatcher=dispatcher, sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    request = _coord_request("binding-1", "link-real", "v1", "arcade", "lead-arcade", "lead-supervisor", ["arcade", "hermione"])
    with pytest.raises(ValueError, match="handoff|registration|scheduling|lead"):
        bridge.receive_coordination_work_request(request)
    assert dispatcher.calls == []


def test_private_http_round_route_uses_hmac_not_admin_bearer(tmp_path: Path):
    class Sender:
        secret = SECRET
        def __call__(self, _kind, _message_id, _payload): return {"accepted": True}
    bridge = PsychloBridge(
        store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"),
        dispatcher=lambda _lead, _prompt: "dispatch:http",
        sender=Sender(), callback_origin="http://127.0.0.1:8766", clock=lambda: NOW,
        token_factory=lambda: "capability_http_1234567890abcdef",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_api_handler(str(tmp_path / "overseer.sqlite3"), "admin-secret", psychlo_bridge=bridge))
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    request_payload = {"roundId": "round-http", "projectId": "arcade", "projectLeadId": "member-hermione", "planId": "arcade-plan", "planVersion": "v1", "correlationId": "corr-http", "idempotencyKey": "round-http", "snapshotId": "snapshot-http", "policyVersion": "2026-08-09", "expectedUsageCost": 5, "scope": "one bounded round", "selectionReason": "priority-selected", "priorityRationale": "sole-eligible-project"}
    timestamp = datetime.now(UTC).isoformat()
    body = json.dumps({"kind": "round-request", "messageId": "round-http", "occurredAt": timestamp, "payload": request_payload}, separators=(",", ":")).encode()
    headers = sign_peer_message(SECRET, "psychlo-to-overseer", "round-request", "round-http", timestamp, "nonce_http_1234567890", body)
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        connection.request("POST", "/psychlo/rounds", body=body, headers=headers)
        response = connection.getresponse()
        response_body = response.read()
        assert response.status == 202, response_body
        assert json.loads(response_body)["receipt"]["status"] == "accepted"
        connection.request("POST", "/psychlo/rounds", body=body, headers=headers)
        replay = connection.getresponse()
        assert replay.status == 409
        replay.read()
        connection.close()
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


def test_task11_telemetry_sampling_keeps_cumulative_counters_and_provider_binding(tmp_path: Path):
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    base = {"projectId": "arcade", "planId": "plan-1", "roundId": "round-1", "threadId": "thread-1", "model": "gpt-5.6-luna", "featureClass": "backend", "activeMs": 1, "waitingMs": 0, "providerSnapshotId": "snapshot-1", "providerCapturedAt": NOW, "attribution": "isolated", "sourceId": "overseer", "correlationId": "corr", "occurredAt": NOW}
    first = bridge.record_telemetry_checkpoint({**base, "checkpointId": "checkpoint-1", "idempotencyKey": "checkpoint-1", "sampleKind": "baseline", "cumulative": {"cachedInput": 1, "uncachedInput": 1, "output": 1, "reasoning": 1, "total": 4}})
    second = bridge.record_telemetry_checkpoint({**base, "checkpointId": "checkpoint-2", "idempotencyKey": "checkpoint-2", "sampleKind": "completed-turn", "cumulative": {"cachedInput": 2, "uncachedInput": 2, "output": 2, "reasoning": 2, "total": 8}})
    assert first["inserted"] is True and second["checkpoint"]["delta"]["total"] == 4
    try:
        bridge.record_telemetry_checkpoint({**base, "checkpointId": "checkpoint-3", "idempotencyKey": "checkpoint-3", "sampleKind": "terminal", "providerSnapshotId": "snapshot-2", "cumulative": {"cachedInput": 3, "uncachedInput": 3, "output": 3, "reasoning": 3, "total": 12}})
    except ValueError as error:
        assert "provider" in str(error)
    else:
        raise AssertionError("provider binding changed")


def test_task11_telemetry_exact_replay_returns_stored_derived_delta_after_restart(tmp_path: Path):
    payload = {"checkpointId": "checkpoint-replay", "projectId": "arcade", "planId": "plan-1", "roundId": "round-replay", "threadId": "thread-1", "model": "gpt-5.6-luna", "featureClass": "backend", "sampleKind": "baseline", "cumulative": {"cachedInput": 1, "uncachedInput": 1, "output": 1, "reasoning": 1, "total": 4}, "activeMs": 1, "waitingMs": 0, "providerSnapshotId": "snapshot-1", "providerCapturedAt": NOW, "attribution": "isolated", "sourceId": "overseer", "correlationId": "corr", "idempotencyKey": "checkpoint-replay", "occurredAt": NOW}
    first_bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    first = first_bridge.record_telemetry_checkpoint(payload)
    restarted = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    replay = restarted.record_telemetry_checkpoint(payload)
    assert replay["replay"] is True
    assert replay["checkpoint"] == first["checkpoint"]


def test_task11_learning_adapter_failure_isolated_and_retry_attempts_monotonic(tmp_path: Path):
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    observation = {"id": "observation-1", "featureProfile": {"taskClass": "python-feature", "model": "gpt-5.6-luna"}, "outcome": {"status": "completed", "observedAt": NOW}, "sourceId": "overseer", "correlationId": "corr", "idempotencyKey": "observation-1", "occurredAt": NOW}
    bridge.record_learning_observation(observation)
    calls = []
    assert bridge.deliver_learning_pending({"skiller": lambda item: calls.append(item) or (_ for _ in ()).throw(RuntimeError("down"))})["failed"] == 1
    assert bridge.deliver_learning_pending({"skiller": lambda item: calls.append(item)})["delivered"] == 1
    assert bridge.store.learning_observation("observation-1")["attempts"]["skiller"] == 2
