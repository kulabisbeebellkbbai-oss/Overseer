import unittest

from overseer import (
    ApprovalLevel,
    Claim,
    ClaimStatus,
    ClaimType,
    ConflictOutcome,
    OwnerDomain,
    Resource,
    ResourceState,
    ResourceType,
    RiskLevel,
    decide_claim,
    classify_probe,
    recovery_evidence,
    HealthStatus,
    HealthTarget,
    InterruptionPolicy,
    MaintenanceKind,
    MaintenancePlan,
    MaintenanceStatus,
    MaintenanceWindow,
    ProbeResult,
    ProbeType,
    PhysicalAssetKind,
    PhysicalIdentity,
    assess_maintenance_readiness,
    can_close_maintenance,
    physical_identity_conflicts,
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


if __name__ == "__main__":
    unittest.main()
