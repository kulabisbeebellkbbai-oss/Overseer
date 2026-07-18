import tempfile
import threading
import unittest
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from overseer import (
    ApprovalLevel,
    ApprovalStatus,
    AuditEventType,
    Claim,
    ClaimStatus,
    ClaimType,
    ConflictDecision,
    ConflictOutcome,
    DryRunExecutor,
    ExecutionMode,
    ExecutionRequest,
    ExecutionStatus,
    OwnerDomain,
    Resource,
    ResourceRegistry,
    ResourceState,
    ResourceType,
    RiskLevel,
    OverseerRuntime,
    decide_claim,
    classify_probe,
    recovery_evidence,
    HealthStatus,
    HealthTarget,
    HttpHealthProbeAdapter,
    InterruptionPolicy,
    LimitDecision,
    LimitKind,
    LimitedWorkRequest,
    MaintenanceKind,
    MaintenancePlan,
    MaintenanceStatus,
    MaintenanceWindow,
    OperationPlanner,
    OverseerConfig,
    OverseerCoordinator,
    PathPhysicalDiscoveryAdapter,
    ProbeResult,
    ProbeType,
    PhysicalAssetKind,
    PhysicalIdentity,
    ProtectiveAction,
    SecurityIncident,
    SecuritySignal,
    SecuritySignalType,
    SecurityStatus,
    SQLiteStore,
    ScheduledWorkStatus,
    UsageLimit,
    approval_from_decision,
    assess_maintenance_readiness,
    audit_event_from_decision,
    can_close_maintenance,
    config_from_mapping,
    needs_operator_approval,
    physical_identity_conflicts,
    recommend_security_response,
    schedule_maintenance_window,
    schedule_limited_work,
    schedule_usage_limited_work,
    seed_store_from_config,
    validate_config,
)
from overseer.cli import demo_status
from overseer.cli import discover_physical_status
from overseer.cli import persisted_demo_status
from overseer.cli import probe_health_status
from overseer.cli import run_status
from overseer.cli import seed_config_status


class _JsonHealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            body = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        return


class LocalHttpServer:
    def __enter__(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _JsonHealthHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.url = f"http://{host}:{port}/health"
        return self

    def __exit__(self, exc_type, exc, tb):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


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


class AdapterDryRunTests(unittest.TestCase):
    def test_dry_run_executor_plans_without_host_state_change(self):
        executor = DryRunExecutor()
        result = executor.execute(
            ExecutionRequest(
                id="restart.mcp",
                action="restart service",
                target_resource_id="svc.mcp.github",
                owner_domain=OwnerDomain.OBRIEN,
            )
        )

        self.assertEqual(result.status, ExecutionStatus.PLANNED)
        self.assertEqual(result.mode, ExecutionMode.DRY_RUN)
        self.assertFalse(result.changed_host_state())
        self.assertEqual(result.evidence_ids, ("dryrun.restart.mcp",))

    def test_dry_run_executor_blocks_live_execution_without_adapter(self):
        executor = DryRunExecutor()
        result = executor.execute(
            ExecutionRequest(
                id="firewall.block",
                action="block traffic",
                target_resource_id="security.firewall",
                owner_domain=OwnerDomain.ODO,
                mode=ExecutionMode.LIVE,
            )
        )

        self.assertEqual(result.status, ExecutionStatus.BLOCKED)
        self.assertFalse(result.changed_host_state())


class OperationPlannerTests(unittest.TestCase):
    def test_plans_ready_high_risk_maintenance_as_dry_run_with_approval(self):
        planner = OperationPlanner()
        plan = MaintenancePlan(
            id="maint.gateway.patch",
            resource_id="gateway.protected",
            kind=MaintenanceKind.PATCH,
            requested_state="1.2.3",
            risk_level=RiskLevel.HIGH,
            window=MaintenanceWindow(
                id="window.patch",
                starts_at="2026-07-18T12:00:00-04:00",
                ends_at="2026-07-18T12:30:00-04:00",
            ),
            interruption_policy=InterruptionPolicy.EXCLUSIVE_WINDOW_REQUIRED,
            precheck_ids=("health.before",),
            rollback_plan="restore previous gateway config",
        )

        operation = planner.plan_maintenance(plan)

        self.assertTrue(operation.requires_approval())
        self.assertEqual(operation.approval_level, ApprovalLevel.SISKO)
        self.assertEqual(operation.result.mode, ExecutionMode.DRY_RUN)
        self.assertFalse(operation.result.changed_host_state())

    def test_plans_security_response_as_dry_run_even_for_active_defense(self):
        planner = OperationPlanner()
        signal = SecuritySignal(
            id="vm.intrusion",
            resource_id="vm.suspect",
            resource_type=ResourceType.VIRTUAL_ASSET,
            signal_type=SecuritySignalType.CONFIRMED_INCIDENT,
            severity=RiskLevel.HIGH,
            confidence=0.9,
            source="audit",
            indicator="unexpected outbound connection",
        )

        operation = planner.plan_security_response(signal)

        self.assertTrue(operation.requires_approval())
        self.assertEqual(operation.approval_level, ApprovalLevel.SISKO)
        self.assertEqual(operation.request.action, "security:quarantine")
        self.assertEqual(operation.result.mode, ExecutionMode.DRY_RUN)


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


class LiveHealthProbeTests(unittest.TestCase):
    def test_http_health_probe_adapter_classifies_local_json_endpoint(self):
        with LocalHttpServer() as server:
            target = HealthTarget(
                id="local-json",
                resource_id="svc.local.json",
                name="Local JSON",
                probe_type=ProbeType.JSON,
                target=server.url,
                expected_content_type="application/json",
            )

            evidence = HttpHealthProbeAdapter(timeout_seconds=2).probe(target)

            self.assertEqual(evidence.observed_status, HealthStatus.HEALTHY)
            self.assertFalse(evidence.recovery_required)

    def test_probe_health_status_reports_local_json_endpoint(self):
        with LocalHttpServer() as server:
            status = probe_health_status(
                "svc.local.json",
                "Local JSON",
                server.url,
                ProbeType.JSON.value,
                expected_content_type="application/json",
                timeout_seconds=2,
            )

            self.assertEqual(status["status"], HealthStatus.HEALTHY.value)
            self.assertEqual(status["resource_id"], "svc.local.json")

    def test_probe_health_status_persists_evidence_to_explicit_store(self):
        with tempfile.TemporaryDirectory() as directory, LocalHttpServer() as server:
            store_path = Path(directory) / "overseer.sqlite3"

            status = probe_health_status(
                "svc.local.json",
                "Local JSON",
                server.url,
                ProbeType.JSON.value,
                expected_content_type="application/json",
                timeout_seconds=2,
                store_path=store_path,
            )
            store = SQLiteStore(store_path)

            self.assertEqual(status["store"], str(store_path))
            self.assertEqual(store.load_health_evidence(status["id"]).observed_status, HealthStatus.HEALTHY)
            store.close()


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


class PhysicalDiscoveryTests(unittest.TestCase):
    def test_path_physical_discovery_reads_temp_serial_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "usb-FTDI_RS485_A-if00-port0").touch()

            identities = PathPhysicalDiscoveryAdapter((root,)).discover()

            self.assertEqual(len(identities), 1)
            self.assertEqual(identities[0].kind, PhysicalAssetKind.SERIAL_PORT)
            self.assertTrue(identities[0].is_complete_for_exclusive_checkout())

    def test_discover_physical_status_reports_temp_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "usb-Serial_Device-if00-port0").touch()

            status = discover_physical_status((str(root),))

            self.assertEqual(status["count"], 1)
            self.assertEqual(status["assets"][0]["kind"], PhysicalAssetKind.SERIAL_PORT.value)


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


class LocalSchedulerTests(unittest.TestCase):
    def test_schedules_usage_limited_work_until_reset(self):
        work = schedule_usage_limited_work(
            UsageLimit(
                id="limit.ai",
                resource_id="svc.ai",
                kind=LimitKind.TOKENS,
                capacity=100,
                remaining=0,
                resets_at="2026-07-18T14:00:00-04:00",
                window="hourly",
            ),
            LimitedWorkRequest(
                id="work.ai",
                resource_id="svc.ai",
                owner_thread="thread-ai",
                requested_units=10,
                intent="continue generation",
            ),
        )

        self.assertEqual(work.status, ScheduledWorkStatus.WAITING)
        self.assertEqual(work.scheduled_for, "2026-07-18T14:00:00-04:00")

    def test_blocks_overlapping_exclusive_maintenance_window(self):
        active = MaintenancePlan(
            id="maint.active",
            resource_id="gateway.protected",
            kind=MaintenanceKind.PATCH,
            requested_state="1.0.1",
            risk_level=RiskLevel.MEDIUM,
            window=MaintenanceWindow(
                id="window.active",
                starts_at="2026-07-18T13:00:00-04:00",
                ends_at="2026-07-18T13:30:00-04:00",
            ),
            interruption_policy=InterruptionPolicy.EXCLUSIVE_WINDOW_REQUIRED,
            precheck_ids=("health.before",),
            rollback_plan="restore snapshot",
        )
        requested = MaintenancePlan(
            id="maint.requested",
            resource_id="gateway.protected",
            kind=MaintenanceKind.RESTART,
            requested_state="restarted",
            risk_level=RiskLevel.LOW,
            window=MaintenanceWindow(
                id="window.requested",
                starts_at="2026-07-18T13:15:00-04:00",
                ends_at="2026-07-18T13:45:00-04:00",
            ),
            interruption_policy=InterruptionPolicy.EXCLUSIVE_WINDOW_REQUIRED,
            precheck_ids=("health.before",),
        )

        work = schedule_maintenance_window(requested, (active,))

        self.assertEqual(work.status, ScheduledWorkStatus.WAITING)
        self.assertEqual(work.blocking_ids, ("maint.active",))


class ConfigLoadingTests(unittest.TestCase):
    def test_loads_resources_and_usage_limits_from_mapping(self):
        config = config_from_mapping(
            {
                "resources": [
                    {
                        "id": "gateway.config",
                        "name": "Configured Gateway",
                        "type": "virtual_asset",
                        "owner_domain": "dax",
                        "risk_level": "high",
                        "identifiers": {"ports": [8795]},
                        "exclusive_groups": ["gateway"],
                    },
                    {
                        "id": "svc.config",
                        "name": "Configured Service",
                        "type": "service",
                        "owner_domain": "julian",
                        "risk_level": "low",
                    }
                ],
                "usage_limits": [
                    {
                        "id": "limit.config",
                        "resource_id": "svc.config",
                        "kind": "requests",
                        "capacity": 100,
                        "remaining": 50,
                        "resets_at": "2026-07-18T15:00:00-04:00",
                        "window": "hourly",
                    }
                ],
            }
        )

        self.assertIsInstance(config, OverseerConfig)
        self.assertEqual(config.resources[0].owner_domain, OwnerDomain.DAX)
        self.assertEqual(config.resources[0].ports(), frozenset({8795}))
        self.assertEqual(config.usage_limits[0].remaining, 50)

    def test_rejects_secret_like_config_keys(self):
        with self.assertRaises(ValueError):
            config_from_mapping(
                {
                    "resources": [
                        {
                            "id": "svc.secret",
                            "name": "Secret Service",
                            "type": "service",
                            "owner_domain": "julian",
                            "risk_level": "low",
                            "identifiers": {"api_key": "not-allowed"},
                        }
                    ]
                }
            )

    def test_rejects_usage_limit_for_unknown_resource(self):
        with self.assertRaises(ValueError):
            config_from_mapping(
                {
                    "usage_limits": [
                        {
                            "id": "limit.unknown",
                            "resource_id": "svc.missing",
                            "kind": "requests",
                            "capacity": 10,
                            "remaining": 1,
                            "window": "hourly",
                        }
                    ]
                }
            )

    def test_validate_config_rejects_remaining_above_capacity(self):
        config = OverseerConfig(
            resources=(
                Resource(
                    id="svc.limit",
                    name="Limit Service",
                    type=ResourceType.SERVICE,
                    owner_domain=OwnerDomain.JULIAN,
                    risk_level=RiskLevel.LOW,
                ),
            ),
            usage_limits=(
                UsageLimit(
                    id="limit.bad",
                    resource_id="svc.limit",
                    kind=LimitKind.REQUESTS,
                    capacity=1,
                    remaining=2,
                    resets_at=None,
                    window="hourly",
                ),
            ),
        )

        with self.assertRaises(ValueError):
            validate_config(config)


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


class CliDemoTests(unittest.TestCase):
    def test_demo_status_reports_approval_gated_gateway_claim(self):
        status = demo_status()

        self.assertEqual(status["resources"], ["gateway.protected"])
        self.assertEqual(status["decision"], ConflictOutcome.ESCALATE.value)
        self.assertEqual(status["approval"], ApprovalLevel.SISKO.value)

    def test_persisted_demo_status_uses_explicit_store_path(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "demo.sqlite3"

            status = persisted_demo_status(store_path)

            self.assertEqual(status["store"], str(store_path))
            self.assertEqual(status["decision"], ConflictOutcome.ESCALATE.value)
            self.assertTrue(store_path.exists())

    def test_seed_config_status_uses_explicit_config_and_store_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "overseer.json"
            store_path = Path(directory) / "overseer.sqlite3"
            config_path.write_text(
                json.dumps(
                    {
                        "resources": [
                            {
                                "id": "svc.cli.config",
                                "name": "CLI Config Service",
                                "type": "service",
                                "owner_domain": "julian",
                                "risk_level": "low",
                            }
                        ],
                        "usage_limits": [
                            {
                                "id": "limit.cli.config",
                                "resource_id": "svc.cli.config",
                                "kind": "requests",
                                "capacity": 10,
                                "remaining": 5,
                                "resets_at": "2026-07-18T16:00:00-04:00",
                                "window": "hourly",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            status = seed_config_status(config_path, store_path)

            self.assertEqual(status["store"], str(store_path))
            self.assertEqual(status["resources"], 1)
            self.assertEqual(status["usage_limits"], 1)


class ApprovalAuditTests(unittest.TestCase):
    def test_creates_approval_request_for_escalated_claim_decision(self):
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
                id="claim.gateway.audit",
                resource_id="gateway.protected",
                claim_type=ClaimType.LEASE,
                owner_thread="thread-a",
                owner_role=OwnerDomain.DAX,
                intent="change gateway",
                requested_action="modify route",
                risk_level=RiskLevel.HIGH,
            )
        )

        approval = approval_from_decision(
            "approval.gateway.audit",
            record.claim.id,
            record.claim.owner_thread,
            record.claim.owner_role,
            record.decision,
            ("health.gateway.before",),
        )

        self.assertIsNotNone(approval)
        self.assertEqual(approval.status, ApprovalStatus.PENDING)
        self.assertEqual(approval.approval_level, ApprovalLevel.SISKO)
        self.assertFalse(approval.can_execute())

    def test_maps_queue_decision_to_audit_event(self):
        decision = ConflictDecision(
            outcome=ConflictOutcome.QUEUE,
            reason="resource already claimed",
            blocking_claim_ids=("claim.active",),
        )

        event = audit_event_from_decision(
            "audit.queue",
            "claim.waiting",
            OwnerDomain.DAX,
            RiskLevel.MEDIUM,
            decision,
            ("claim.active",),
        )

        self.assertEqual(event.event_type, AuditEventType.QUEUED)
        self.assertEqual(event.evidence_ids, ("claim.active",))


class SQLiteStoreTests(unittest.TestCase):
    def test_persists_resource_claim_and_decision_in_explicit_temp_database(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteStore(Path(directory) / "overseer.sqlite3")
            resource = Resource(
                id="svc.persisted",
                name="Persisted Service",
                type=ResourceType.SERVICE,
                owner_domain=OwnerDomain.JULIAN,
                risk_level=RiskLevel.LOW,
                identifiers={"ports": [8080]},
            )
            claim = Claim(
                id="claim.persisted",
                resource_id=resource.id,
                claim_type=ClaimType.OBSERVATION,
                owner_thread="thread-store",
                owner_role=OwnerDomain.JULIAN,
                intent="inspect persisted service",
                requested_action="read health",
                risk_level=RiskLevel.LOW,
            )
            decision = decide_claim(resource, claim, [])

            store.save_resource(resource)
            store.save_claim(claim, decision)

            self.assertEqual(store.load_resource(resource.id).ports(), frozenset({8080}))
            self.assertEqual(store.load_claim(claim.id).owner_thread, "thread-store")
            self.assertEqual(store.load_decision(claim.id).outcome, ConflictOutcome.ALLOW)
            store.close()

    def test_persists_approval_and_audit_records(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteStore(Path(directory) / "overseer.sqlite3")
            decision = ConflictDecision(ConflictOutcome.ESCALATE, "sisko approval required", ApprovalLevel.SISKO)
            approval = approval_from_decision(
                "approval.persisted",
                "claim.persisted",
                "thread-store",
                OwnerDomain.DAX,
                decision,
            )
            event = audit_event_from_decision(
                "audit.persisted",
                "claim.persisted",
                OwnerDomain.DAX,
                RiskLevel.HIGH,
                decision,
            )

            self.assertIsNotNone(approval)
            store.save_approval(approval)
            store.save_audit_event(event)

            self.assertEqual(store.load_approval("approval.persisted").approval_level, ApprovalLevel.SISKO)
            self.assertEqual(store.list_audit_events()[0].event_type, AuditEventType.ESCALATED)
            store.close()

    def test_seeds_resources_and_usage_limits_from_config(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteStore(Path(directory) / "overseer.sqlite3")
            config = config_from_mapping(
                {
                    "resources": [
                        {
                            "id": "svc.seeded",
                            "name": "Seeded Service",
                            "type": "service",
                            "owner_domain": "julian",
                            "risk_level": "low",
                        }
                    ],
                    "usage_limits": [
                        {
                            "id": "limit.seeded",
                            "resource_id": "svc.seeded",
                            "kind": "requests",
                            "capacity": 20,
                            "remaining": 10,
                            "resets_at": "2026-07-18T16:00:00-04:00",
                            "window": "hourly",
                        }
                    ],
                }
            )

            result = seed_store_from_config(config, store)

            self.assertEqual(result.resource_count, 1)
            self.assertEqual(result.usage_limit_count, 1)
            self.assertEqual(store.load_resource("svc.seeded").owner_domain, OwnerDomain.JULIAN)
            self.assertEqual(store.load_usage_limit("limit.seeded").remaining, 10)
            store.close()


class RuntimeTests(unittest.TestCase):
    def test_runtime_tick_reports_seeded_store_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteStore(Path(directory) / "overseer.sqlite3")
            seed_store_from_config(
                config_from_mapping(
                    {
                        "resources": [
                            {
                                "id": "svc.runtime",
                                "name": "Runtime Service",
                                "type": "service",
                                "owner_domain": "julian",
                                "risk_level": "low",
                            }
                        ],
                        "usage_limits": [
                            {
                                "id": "limit.runtime",
                                "resource_id": "svc.runtime",
                                "kind": "requests",
                                "capacity": 10,
                                "remaining": 5,
                                "resets_at": "2026-07-18T16:00:00-04:00",
                                "window": "hourly",
                            }
                        ],
                    }
                ),
                store,
            )

            tick = OverseerRuntime(store).run(once=True)

            self.assertEqual(tick.resources, 1)
            self.assertEqual(tick.usage_limits, 1)
            self.assertEqual(tick.health_evidence, 0)
            store.close()

    def test_run_status_reports_explicit_store_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="svc.run",
                    name="Run Service",
                    type=ResourceType.SERVICE,
                    owner_domain=OwnerDomain.JULIAN,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.close()

            status = run_status(store_path, once=True)

            self.assertEqual(status["store"], str(store_path))
            self.assertEqual(status["resources"], 1)
            self.assertEqual(status["health_evidence"], 0)


class OverseerCoordinatorTests(unittest.TestCase):
    def test_request_claim_persists_decision_approval_and_audit_event(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteStore(Path(directory) / "overseer.sqlite3")
            coordinator = OverseerCoordinator(store=store)
            resource = coordinator.register_resource(
                Resource(
                    id="gateway.coordinator",
                    name="Coordinator Gateway",
                    type=ResourceType.VIRTUAL_ASSET,
                    owner_domain=OwnerDomain.DAX,
                    risk_level=RiskLevel.HIGH,
                )
            )
            claim = Claim(
                id="claim.coordinator.gateway",
                resource_id=resource.id,
                claim_type=ClaimType.LEASE,
                owner_thread="thread-coordinator",
                owner_role=OwnerDomain.DAX,
                intent="change protected gateway",
                requested_action="modify route",
                risk_level=RiskLevel.HIGH,
            )

            result = coordinator.request_claim(claim)

            self.assertTrue(needs_operator_approval(result))
            self.assertEqual(store.load_claim(claim.id).status, ClaimStatus.REQUESTED)
            self.assertEqual(store.load_decision(claim.id).approval_level, ApprovalLevel.SISKO)
            self.assertEqual(store.load_approval(f"approval.{claim.id}").approval_level, ApprovalLevel.SISKO)
            self.assertEqual(store.list_audit_events()[0].event_type, AuditEventType.ESCALATED)
            store.close()

    def test_activate_and_release_claim_updates_store(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteStore(Path(directory) / "overseer.sqlite3")
            coordinator = OverseerCoordinator(store=store)
            resource = coordinator.register_resource(
                Resource(
                    id="proxy.coordinator",
                    name="Coordinator Proxy",
                    type=ResourceType.VIRTUAL_ASSET,
                    owner_domain=OwnerDomain.DAX,
                    risk_level=RiskLevel.LOW,
                )
            )
            result = coordinator.request_claim(
                Claim(
                    id="claim.coordinator.proxy",
                    resource_id=resource.id,
                    claim_type=ClaimType.LEASE,
                    owner_thread="thread-coordinator",
                    owner_role=OwnerDomain.DAX,
                    intent="use proxy",
                    requested_action="bind proxy",
                    risk_level=RiskLevel.LOW,
                )
            )

            activated = coordinator.activate_claim(result.record.claim.id, "approval.role")
            released = coordinator.release_claim(activated.claim.id)

            self.assertEqual(activated.claim.status, ClaimStatus.ACTIVE)
            self.assertEqual(released.status, ClaimStatus.RELEASED)
            self.assertEqual(store.load_claim(activated.claim.id).status, ClaimStatus.RELEASED)
            store.close()


if __name__ == "__main__":
    unittest.main()
