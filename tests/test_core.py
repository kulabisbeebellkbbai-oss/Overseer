import unittest

from overseer import (
    ApprovalLevel,
    Claim,
    ClaimStatus,
    ClaimType,
    ConflictOutcome,
    OwnerDomain,
    Resource,
    ResourceRegistry,
    ResourceState,
    ResourceType,
    RiskLevel,
    decide_claim,
    classify_probe,
    recovery_evidence,
    HealthStatus,
    HealthTarget,
    InterruptionPolicy,
    LimitDecision,
    LimitKind,
    LimitedWorkRequest,
    MaintenanceKind,
    MaintenancePlan,
    MaintenanceStatus,
    MaintenanceWindow,
    ProbeResult,
    ProbeType,
    PhysicalAssetKind,
    PhysicalIdentity,
    ProtectiveAction,
    SecurityIncident,
    SecuritySignal,
    SecuritySignalType,
    SecurityStatus,
    UsageLimit,
    assess_maintenance_readiness,
    can_close_maintenance,
    physical_identity_conflicts,
    recommend_security_response,
    schedule_limited_work,
)


class ConflictDecisionTests(unittest.TestCase):
    def test_allows_low_risk_observation_without_active_exclusive_claim(self):
        resource = Resource(
            id="svc.mcp.github",
            name="GitHub MCP",
            type=ResourceType.SERVICE,
            owner_domain=OwnerDomain.JULIAN,
            risk_level=RiskLevel.LOW,
        )
        claim = Claim(
            id="claim.observe",
            resource_id=resource.id,
            claim_type=ClaimType.OBSERVATION,
            owner_thread="thread-a",
            owner_role=OwnerDomain.JULIAN,
            intent="inspect health",
            requested_action="read health endpoint",
            risk_level=RiskLevel.LOW,
        )

        decision = decide_claim(resource, claim, [])

        self.assertEqual(decision.outcome, ConflictOutcome.ALLOW)
        self.assertEqual(decision.approval_level, ApprovalLevel.NONE)

    def test_queues_conflicting_virtual_port_claim(self):
        resource = Resource(
            id="proxy.protected-gateway",
            name="Protected Gateway Proxy",
            type=ResourceType.VIRTUAL_ASSET,
            owner_domain=OwnerDomain.DAX,
            risk_level=RiskLevel.MEDIUM,
            identifiers={"ports": [8795]},
        )
        active = Claim(
            id="claim.active",
            resource_id=resource.id,
            claim_type=ClaimType.LEASE,
            owner_thread="thread-a",
            owner_role=OwnerDomain.DAX,
            intent="proxy work",
            requested_action="change proxy topology",
            risk_level=RiskLevel.MEDIUM,
            status=ClaimStatus.ACTIVE,
            port_reservations=frozenset({8795}),
        )
        requested = Claim(
            id="claim.request",
            resource_id="proxy.other",
            claim_type=ClaimType.LEASE,
            owner_thread="thread-b",
            owner_role=OwnerDomain.DAX,
            intent="reuse port",
            requested_action="bind proxy",
            risk_level=RiskLevel.MEDIUM,
            port_reservations=frozenset({8795}),
        )
        requested_resource = Resource(
            id="proxy.other",
            name="Other Proxy",
            type=ResourceType.VIRTUAL_ASSET,
            owner_domain=OwnerDomain.DAX,
            risk_level=RiskLevel.MEDIUM,
        )

        decision = decide_claim(requested_resource, requested, [active], {resource.id: resource})

        self.assertEqual(decision.outcome, ConflictOutcome.QUEUE)
        self.assertEqual(decision.blocking_claim_ids, ("claim.active",))

    def test_high_risk_gateway_change_escalates_to_sisko(self):
        resource = Resource(
            id="gateway.protected",
            name="Protected Gateway",
            type=ResourceType.VIRTUAL_ASSET,
            owner_domain=OwnerDomain.DAX,
            risk_level=RiskLevel.HIGH,
        )
        claim = Claim(
            id="claim.gateway",
            resource_id=resource.id,
            claim_type=ClaimType.LEASE,
            owner_thread="thread-a",
            owner_role=OwnerDomain.DAX,
            intent="route change",
            requested_action="modify gateway route",
            risk_level=RiskLevel.HIGH,
        )

        decision = decide_claim(resource, claim, [])

        self.assertEqual(decision.outcome, ConflictOutcome.ESCALATE)
        self.assertEqual(decision.approval_level, ApprovalLevel.SISKO)

    def test_security_surface_requires_human_approval(self):
        resource = Resource(
            id="security.firewall",
            name="Firewall",
            type=ResourceType.SECURITY_SURFACE,
            owner_domain=OwnerDomain.ODO,
            risk_level=RiskLevel.HIGH,
        )
        claim = Claim(
            id="claim.security",
            resource_id=resource.id,
            claim_type=ClaimType.LOCK,
            owner_thread="thread-a",
            owner_role=OwnerDomain.ODO,
            intent="protective action",
            requested_action="change firewall policy",
            risk_level=RiskLevel.HIGH,
        )

        decision = decide_claim(resource, claim, [])

        self.assertEqual(decision.outcome, ConflictOutcome.ESCALATE)
        self.assertEqual(decision.approval_level, ApprovalLevel.HUMAN)

    def test_quarantined_resource_blocks_with_quarantine_outcome(self):
        resource = Resource(
            id="vm.suspect",
            name="Suspect VM",
            type=ResourceType.VIRTUAL_ASSET,
            owner_domain=OwnerDomain.DAX,
            risk_level=RiskLevel.HIGH,
            state=ResourceState.QUARANTINED,
        )
        claim = Claim(
            id="claim.vm",
            resource_id=resource.id,
            claim_type=ClaimType.LEASE,
            owner_thread="thread-a",
            owner_role=OwnerDomain.DAX,
            intent="inspect vm",
            requested_action="start vm",
            risk_level=RiskLevel.MEDIUM,
        )

        decision = decide_claim(resource, claim, [])

        self.assertEqual(decision.outcome, ConflictOutcome.QUARANTINE)
        self.assertEqual(decision.approval_level, ApprovalLevel.HUMAN)

class HealthClassificationTests(unittest.TestCase):
    def test_classifies_healthy_json_probe(self):
        target = HealthTarget(
            id="mcp.github",
            resource_id="svc.mcp.github",
            name="GitHub MCP",
            probe_type=ProbeType.JSON,
            target="http://127.0.0.1:8791/health",
            expected_content_type="application/json",
        )
        result = ProbeResult(
            target=target.target,
            probe_type=ProbeType.JSON,
            status_code=200,
            content_type="application/json; charset=utf-8",
            body_summary='{"status":"ok"}',
        )

        evidence = classify_probe(target, result)

        self.assertEqual(evidence.observed_status, HealthStatus.HEALTHY)
        self.assertFalse(evidence.recovery_required)

    def test_classifies_invalid_json_as_failed(self):
        target = HealthTarget(
            id="mcp.bad",
            resource_id="svc.mcp.bad",
            name="Bad MCP",
            probe_type=ProbeType.JSON,
            target="http://127.0.0.1:9999/health",
            expected_content_type="application/json",
        )
        result = ProbeResult(
            target=target.target,
            probe_type=ProbeType.JSON,
            status_code=200,
            content_type="application/json",
            body_summary="invalid json: unexpected token",
        )

        evidence = classify_probe(target, result)

        self.assertEqual(evidence.observed_status, HealthStatus.FAILED)
        self.assertTrue(evidence.recovery_required)

    def test_marks_matching_healthy_probe_as_recovered(self):
        target = HealthTarget(
            id="page.local",
            resource_id="svc.page.local",
            name="Local Page",
            probe_type=ProbeType.HTML,
            target="https://local.test/",
            expected_content_type="text/html",
        )
        failed = classify_probe(
            target,
            ProbeResult(
                target=target.target,
                probe_type=ProbeType.HTML,
                status_code=503,
                content_type="text/html",
                body_summary="service unavailable",
            ),
        )
        healthy = classify_probe(
            target,
            ProbeResult(
                target=target.target,
                probe_type=ProbeType.HTML,
                status_code=200,
                content_type="text/html",
                body_summary="<html></html>",
            ),
        )

        recovered = recovery_evidence(failed, healthy)

        self.assertEqual(recovered.observed_status, HealthStatus.RECOVERED)
        self.assertFalse(recovered.recovery_required)


class PhysicalIdentityTests(unittest.TestCase):
    def test_detects_same_serial_port_path_conflict(self):
        left = PhysicalIdentity(
            kind=PhysicalAssetKind.SERIAL_PORT,
            stable_id="serial.rs485-a",
            observed_paths=frozenset({"/dev/serial/by-id/usb-rs485-a"}),
        )
        right = PhysicalIdentity(
            kind=PhysicalAssetKind.SERIAL_PORT,
            stable_id="serial.rs485-b",
            observed_paths=frozenset({"/dev/serial/by-id/usb-rs485-a"}),
        )

        self.assertTrue(physical_identity_conflicts(left, right))

    def test_requires_observed_path_for_serial_checkout_identity(self):
        identity = PhysicalIdentity(
            kind=PhysicalAssetKind.SERIAL_PORT,
            stable_id="serial.unknown",
        )

        self.assertFalse(identity.is_complete_for_exclusive_checkout())

    def test_flags_storage_write_risk(self):
        identity = PhysicalIdentity(
            kind=PhysicalAssetKind.STORAGE_ARRAY,
            stable_id="storage.backups",
            storage_profile="read_write",
        )

        self.assertTrue(identity.has_storage_risk())


class MaintenancePlanTests(unittest.TestCase):
    def test_blocks_medium_risk_patch_without_rollback_plan(self):
        plan = MaintenancePlan(
            id="maint.patch.gateway",
            resource_id="gateway.protected",
            kind=MaintenanceKind.PATCH,
            requested_state="1.2.3",
            risk_level=RiskLevel.MEDIUM,
            window=MaintenanceWindow(
                id="window.maint",
                starts_at="2026-07-18T08:00:00-04:00",
                ends_at="2026-07-18T08:30:00-04:00",
            ),
            interruption_policy=InterruptionPolicy.RESTART_ALLOWED,
            precheck_ids=("health.gateway.before",),
        )

        readiness = assess_maintenance_readiness(plan)

        self.assertFalse(readiness.ready)
        self.assertEqual(readiness.status, MaintenanceStatus.BLOCKED)
        self.assertEqual(readiness.missing_evidence, ("rollback_plan",))

    def test_high_risk_update_is_ready_but_requires_sisko_approval(self):
        plan = MaintenancePlan(
            id="maint.update.proxy",
            resource_id="proxy.protected",
            kind=MaintenanceKind.UPDATE,
            requested_state="2.0.0",
            risk_level=RiskLevel.HIGH,
            window=MaintenanceWindow(
                id="window.update",
                starts_at="2026-07-18T09:00:00-04:00",
                ends_at="2026-07-18T09:45:00-04:00",
            ),
            interruption_policy=InterruptionPolicy.EXCLUSIVE_WINDOW_REQUIRED,
            precheck_ids=("health.proxy.before",),
            rollback_plan="restore previous proxy package and config snapshot",
        )

        readiness = assess_maintenance_readiness(plan)

        self.assertTrue(readiness.ready)
        self.assertEqual(readiness.approval_level, ApprovalLevel.SISKO)

    def test_requires_post_change_verification_before_closure(self):
        plan = MaintenancePlan(
            id="maint.restart.mcp",
            resource_id="svc.mcp.github",
            kind=MaintenanceKind.RESTART,
            requested_state="restarted",
            risk_level=RiskLevel.LOW,
            window=MaintenanceWindow(
                id="window.restart",
                starts_at="2026-07-18T10:00:00-04:00",
                ends_at="2026-07-18T10:05:00-04:00",
            ),
            interruption_policy=InterruptionPolicy.RESTART_ALLOWED,
            precheck_ids=("health.mcp.before",),
            status=MaintenanceStatus.VERIFYING,
        )

        readiness = can_close_maintenance(plan)

        self.assertFalse(readiness.ready)
        self.assertEqual(readiness.status, MaintenanceStatus.VERIFYING)
        self.assertEqual(readiness.missing_evidence, ("verification_ids",))


class SecurityResponseTests(unittest.TestCase):
    def test_low_risk_info_signal_is_read_only_monitoring(self):
        signal = SecuritySignal(
            id="sec.info",
            resource_id="svc.mcp.github",
            resource_type=ResourceType.SERVICE,
            signal_type=SecuritySignalType.INFO,
            severity=RiskLevel.LOW,
            confidence=0.7,
            source="log",
            indicator="normal startup",
        )

        response = recommend_security_response(signal)

        self.assertEqual(response.action, ProtectiveAction.MONITOR)
        self.assertEqual(response.approval_level, ApprovalLevel.NONE)
        self.assertFalse(response.active_defense)

    def test_confirmed_high_risk_virtual_incident_requires_sisko_quarantine(self):
        signal = SecuritySignal(
            id="sec.vm",
            resource_id="vm.suspect",
            resource_type=ResourceType.VIRTUAL_ASSET,
            signal_type=SecuritySignalType.CONFIRMED_INCIDENT,
            severity=RiskLevel.HIGH,
            confidence=0.95,
            source="audit",
            indicator="unexpected outbound connection",
        )

        response = recommend_security_response(signal)

        self.assertEqual(response.action, ProtectiveAction.QUARANTINE)
        self.assertEqual(response.owner_domain, OwnerDomain.DAX)
        self.assertEqual(response.approval_level, ApprovalLevel.SISKO)
        self.assertTrue(response.active_defense)

    def test_security_surface_escalates_to_human_before_mutation(self):
        signal = SecuritySignal(
            id="sec.firewall",
            resource_id="security.firewall",
            resource_type=ResourceType.SECURITY_SURFACE,
            signal_type=SecuritySignalType.INTRUSION_LIKELY,
            severity=RiskLevel.HIGH,
            confidence=0.9,
            source="ids",
            indicator="port scan and exploit attempt",
        )

        response = recommend_security_response(signal)

        self.assertEqual(response.action, ProtectiveAction.ESCALATE)
        self.assertEqual(response.approval_level, ApprovalLevel.HUMAN)
        self.assertFalse(response.active_defense)

    def test_incident_requires_containment_evidence_and_closure_note(self):
        response = recommend_security_response(
            SecuritySignal(
                id="sec.service",
                resource_id="svc.page",
                resource_type=ResourceType.SERVICE,
                signal_type=SecuritySignalType.CONFIRMED_INCIDENT,
                severity=RiskLevel.MEDIUM,
                confidence=0.8,
                source="health",
                indicator="unauthorized admin path access",
            )
        )
        incident = SecurityIncident(
            id="incident.service",
            signal_id="sec.service",
            resource_id="svc.page",
            status=SecurityStatus.CONTAINED,
            response=response,
            evidence_ids=("health.after",),
            closure_note="service isolated and access path verified closed",
        )

        self.assertTrue(incident.can_close())


class UsageLimitScheduleTests(unittest.TestCase):
    def test_runs_now_when_capacity_is_available(self):
        limit = UsageLimit(
            id="limit.github.requests",
            resource_id="svc.github",
            kind=LimitKind.REQUESTS,
            capacity=5000,
            remaining=100,
            resets_at="2026-07-18T11:00:00-04:00",
            window="hourly",
        )
        request = LimitedWorkRequest(
            id="work.issue-sync",
            resource_id="svc.github",
            owner_thread="thread-a",
            requested_units=10,
            intent="sync issues",
        )

        schedule = schedule_limited_work(limit, request)

        self.assertEqual(schedule.decision, LimitDecision.RUN_NOW)
        self.assertEqual(schedule.approval_level, ApprovalLevel.NONE)

    def test_queues_work_until_reset_when_capacity_is_insufficient(self):
        limit = UsageLimit(
            id="limit.ai.tokens",
            resource_id="svc.ai",
            kind=LimitKind.TOKENS,
            capacity=100000,
            remaining=1000,
            resets_at="2026-07-18T12:00:00-04:00",
            window="daily",
        )
        request = LimitedWorkRequest(
            id="work.large-eval",
            resource_id="svc.ai",
            owner_thread="thread-b",
            requested_units=5000,
            intent="run eval",
        )

        schedule = schedule_limited_work(limit, request)

        self.assertEqual(schedule.decision, LimitDecision.QUEUE_UNTIL_RESET)
        self.assertEqual(schedule.scheduled_for, "2026-07-18T12:00:00-04:00")

    def test_escalates_uncertain_high_risk_limit_to_sisko(self):
        limit = UsageLimit(
            id="limit.gateway.manual",
            resource_id="gateway.protected",
            kind=LimitKind.MANUAL,
            capacity=1,
            remaining=1,
            resets_at=None,
            window="manual",
            confidence=0.2,
        )
        request = LimitedWorkRequest(
            id="work.gateway-change",
            resource_id="gateway.protected",
            owner_thread="thread-c",
            requested_units=1,
            intent="change protected gateway",
            risk_level=RiskLevel.HIGH,
        )

        schedule = schedule_limited_work(limit, request)

        self.assertEqual(schedule.decision, LimitDecision.ESCALATE)
        self.assertEqual(schedule.approval_level, ApprovalLevel.SISKO)


class ResourceRegistryTests(unittest.TestCase):
    def test_activates_allowed_claim_and_releases_it(self):
        registry = ResourceRegistry()
        registry.register_resource(
            Resource(
                id="svc.local",
                name="Local Service",
                type=ResourceType.SERVICE,
                owner_domain=OwnerDomain.JULIAN,
                risk_level=RiskLevel.LOW,
            )
        )
        claim = Claim(
            id="claim.observe.local",
            resource_id="svc.local",
            claim_type=ClaimType.OBSERVATION,
            owner_thread="thread-a",
            owner_role=OwnerDomain.JULIAN,
            intent="inspect service",
            requested_action="read health",
            risk_level=RiskLevel.LOW,
        )

        record = registry.request_claim(claim)
        released = registry.release_claim(record.claim.id)

        self.assertEqual(record.decision.outcome, ConflictOutcome.ALLOW)
        self.assertEqual(record.claim.status, ClaimStatus.ACTIVE)
        self.assertEqual(released.status, ClaimStatus.RELEASED)

    def test_queues_conflicting_exclusive_claim(self):
        registry = ResourceRegistry()
        registry.register_resource(
            Resource(
                id="proxy.gateway",
                name="Gateway Proxy",
                type=ResourceType.VIRTUAL_ASSET,
                owner_domain=OwnerDomain.DAX,
                risk_level=RiskLevel.LOW,
            )
        )

        first = registry.request_claim(
            Claim(
                id="claim.gateway.first",
                resource_id="proxy.gateway",
                claim_type=ClaimType.LEASE,
                owner_thread="thread-a",
                owner_role=OwnerDomain.DAX,
                intent="use gateway",
                requested_action="bind proxy",
                risk_level=RiskLevel.LOW,
            )
        )
        activated = registry.activate_claim(first.claim.id, approval_id="approval.dax.role")
        second = registry.request_claim(
            Claim(
                id="claim.gateway.second",
                resource_id="proxy.gateway",
                claim_type=ClaimType.LEASE,
                owner_thread="thread-b",
                owner_role=OwnerDomain.DAX,
                intent="use same gateway",
                requested_action="bind proxy",
                risk_level=RiskLevel.LOW,
            )
        )

        self.assertEqual(first.claim.status, ClaimStatus.REQUESTED)
        self.assertEqual(activated.claim.status, ClaimStatus.ACTIVE)
        self.assertEqual(second.claim.status, ClaimStatus.QUEUED)
        self.assertEqual(registry.queued_claims()[0].id, "claim.gateway.second")

    def test_preserves_escalated_claim_as_requested(self):
        registry = ResourceRegistry()
        registry.register_resource(
            Resource(
                id="gateway.protected",
                name="Protected Gateway",
                type=ResourceType.VIRTUAL_ASSET,
                owner_domain=OwnerDomain.DAX,
                risk_level=RiskLevel.HIGH,
            )
        )

        record = registry.request_claim(
            Claim(
                id="claim.gateway.high",
                resource_id="gateway.protected",
                claim_type=ClaimType.LEASE,
                owner_thread="thread-c",
                owner_role=OwnerDomain.DAX,
                intent="change route",
                requested_action="modify gateway route",
                risk_level=RiskLevel.HIGH,
            )
        )

        self.assertEqual(record.decision.outcome, ConflictOutcome.ESCALATE)
        self.assertEqual(record.claim.status, ClaimStatus.REQUESTED)
        self.assertEqual(record.decision.approval_level, ApprovalLevel.SISKO)


if __name__ == "__main__":
    unittest.main()
