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


if __name__ == "__main__":
    unittest.main()
