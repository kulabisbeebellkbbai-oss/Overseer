import tempfile
import threading
import unittest
import json
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from overseer import (
    ApprovalLevel,
    ApprovalRequest,
    ApprovalStatus,
    AuditEvent,
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
    FreshnessStatus,
    AdminChangeKind,
    AdminAdapterStatus,
    AdminCommandResult,
    AdminExecutionResult,
    AdminExecutionStatus,
    AdminHistoryArchiveRecord,
    OwnerDomain,
    Resource,
    ResourceRegistry,
    ResourceState,
    ResourceType,
    RiskLevel,
    OverseerRuntime,
    RuntimeHeartbeat,
    decide_claim,
    classify_probe,
    recovery_evidence,
    summarize_health_targets,
    HealthStatus,
    HealthEvidence,
    HealthTarget,
    HostCommandObservation,
    HostFindingSeverity,
    HostInspectionAdapter,
    HttpHealthProbeAdapter,
    InterruptionPolicy,
    IDSReviewPackageStatus,
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
    assess_freshness,
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
    approve_admin_change_plan,
    admin_execution_capability_for,
    audit_event_from_admin_execution,
    assess_host_security,
    execute_admin_change_plan,
    plan_apt_install,
    plan_block_ip,
    plan_firewall_allow_tcp,
    plan_firewall_deny_tcp,
    plan_user_service_restart,
    SourceReviewDisposition,
)
from overseer.api import make_api_handler, run_api_server
from overseer.client import OverseerApiClient
from overseer.cli import demo_status
from overseer.cli import discover_physical_status
from overseer.cli import persisted_demo_status
from overseer.cli import activate_claim_status
from overseer.cli import admin_adapter_capabilities_status
from overseer.cli import admin_adapter_enablement_plan_status
from overseer.cli import admin_executions_status
from overseer.cli import admin_execution_readiness_status
from overseer.cli import admin_history_archive_plan_status
from overseer.cli import admin_history_archives_status
from overseer.cli import admin_history_review_status
from overseer.cli import admin_history_restore_readiness_status
from overseer.cli import admin_summary_status
from overseer.cli import archive_admin_history_status
from overseer.cli import approve_admin_change_status
from overseer.cli import approve_admin_adapter_enablement_status
from overseer.cli import approve_admin_history_restore_status
from overseer.cli import approve_claim_status
from overseer.cli import alerts_summary_status
from overseer.cli import audit_summary_status
from overseer.cli import assess_host_security_status
from overseer.cli import authorizations_required_status
from overseer.cli import cancel_admin_change_status
from overseer.cli import claim_review_status
from overseer.cli import command_summary_status
from overseer.cli import execute_admin_change_status
from overseer.cli import export_state_redacted_status
from overseer.cli import export_host_security_ids_review_prompt_status
from overseer.cli import health_efficiency_summary_status
from overseer.cli import health_summary_status
from overseer.cli import host_security_findings_status
from overseer.cli import host_security_sources_status
from overseer.cli import create_host_security_source_review_status
from overseer.cli import host_security_source_reviews_status
from overseer.cli import host_security_triage_status
from overseer.cli import inspect_host_status
from overseer.cli import list_state_status
from overseer.cli import main as cli_main
from overseer.cli import maintenance_summary_status
from overseer.cli import operator_dashboard_status
from overseer.cli import physical_summary_status
from overseer.cli import persistence_security_status
from overseer.cli import prepare_host_security_ids_review_package_status
from overseer.cli import host_security_ids_review_packages_status
from overseer.cli import host_security_ids_review_summary_status
from overseer.cli import record_host_security_ids_review_result_status
from overseer.cli import plan_host_security_source_block_status
from overseer.cli import plan_host_security_remediation_status
from overseer.cli import plan_admin_change_status
from overseer.cli import probe_config_status
from overseer.cli import probe_health_status
from overseer.cli import release_claim_status
from overseer.cli import request_admin_adapter_enablement_status
from overseer.cli import request_admin_history_restore_status
from overseer.cli import request_claim_status
from overseer.cli import run_status
from overseer.cli import runtime_status
from overseer.cli import security_summary_status
from overseer.cli import submit_host_security_ids_review_package_status
from overseer.cli import service_status
from overseer.cli import unarchive_admin_history_status
from overseer.cli import seed_config_status
from overseer.cli import usage_summary_status
from overseer.cli import virtual_summary_status


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


class LocalOverseerApiServer:
    def __init__(self, store_path, auth_token=None):
        self.store_path = str(store_path)
        self.auth_token = auth_token

    def __enter__(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_api_handler(self.store_path, self.auth_token))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.url = f"http://{host}:{port}"
        return self

    def __exit__(self, exc_type, exc, tb):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def get(self, path):
        request = Request(f"{self.url}{path}", headers=self._headers())
        with urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    def post(self, path, payload):
        request = Request(
            f"{self.url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers=self._headers({"content-type": "application/json"}),
            method="POST",
        )
        with urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    def _headers(self, headers=None):
        merged = dict(headers or {})
        if self.auth_token:
            merged["authorization"] = f"Bearer {self.auth_token}"
        return merged


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

    def test_probe_config_status_probes_declared_targets_and_persists_evidence(self):
        with tempfile.TemporaryDirectory() as directory, LocalHttpServer() as server:
            root = Path(directory)
            config_path = root / "overseer.json"
            store_path = root / "overseer.sqlite3"
            config_path.write_text(
                json.dumps(
                    {
                        "resources": [
                            {
                                "id": "svc.local.json",
                                "name": "Local JSON",
                                "type": "service",
                                "owner_domain": "julian",
                                "risk_level": "low",
                            }
                        ],
                        "health_targets": [
                            {
                                "id": "health.local.json",
                                "resource_id": "svc.local.json",
                                "name": "Local JSON",
                                "probe_type": "json",
                                "target": server.url,
                                "expected_content_type": "application/json",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            status = probe_config_status(config_path, store_path, timeout_seconds=2)
            store = SQLiteStore(store_path)

            self.assertEqual(status["targets"], 1)
            self.assertEqual(status["healthy"], 1)
            self.assertEqual(status["evidence"][0]["status"], HealthStatus.HEALTHY.value)
            self.assertEqual(store.list_health_evidence()[0].observed_status, HealthStatus.HEALTHY)
            store.close()


class HealthSummaryTests(unittest.TestCase):
    def test_summarizes_missing_evidence_as_unknown(self):
        target = HealthTarget(
            id="health.missing",
            resource_id="svc.missing",
            name="Missing",
            probe_type=ProbeType.JSON,
            target="http://127.0.0.1:1/health",
        )

        summary = summarize_health_targets((target,), ())[0]

        self.assertEqual(summary.latest_status, HealthStatus.UNKNOWN)
        self.assertTrue(summary.recovery_required)

    def test_health_summary_status_reports_latest_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_health_target(
                HealthTarget(
                    id="health.summary",
                    resource_id="svc.summary",
                    name="Summary Health",
                    probe_type=ProbeType.JSON,
                    target="http://127.0.0.1:8787/health",
                )
            )
            store.save_health_evidence(
                HealthEvidence(
                    id="evidence.old",
                    resource_id="svc.summary",
                    target="http://127.0.0.1:8787/health",
                    probe_type=ProbeType.JSON,
                    observed_status=HealthStatus.FAILED,
                    owner_domain=OwnerDomain.JULIAN,
                    recovery_required=True,
                    captured_at="2026-07-18T13:00:00+00:00",
                )
            )
            store.save_health_evidence(
                HealthEvidence(
                    id="evidence.new",
                    resource_id="svc.summary",
                    target="http://127.0.0.1:8787/health",
                    probe_type=ProbeType.JSON,
                    observed_status=HealthStatus.HEALTHY,
                    owner_domain=OwnerDomain.JULIAN,
                    captured_at="2026-07-18T13:01:00+00:00",
                )
            )
            store.close()

            status = health_summary_status(store_path)

            self.assertEqual(status["targets"], 1)
            self.assertEqual(status["healthy"], 1)
            self.assertEqual(status["unhealthy"], 0)
            self.assertEqual(status["summaries"][0]["latest_evidence_id"], "evidence.new")

    def test_health_summary_cli_can_fail_on_unhealthy(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_health_target(
                HealthTarget(
                    id="health.unhealthy",
                    resource_id="svc.unhealthy",
                    name="Unhealthy",
                    probe_type=ProbeType.JSON,
                    target="http://127.0.0.1:1/health",
                )
            )
            store.close()

            exit_code = cli_main(["health-summary", "--store", str(store_path), "--fail-on-unhealthy"])

            self.assertEqual(exit_code, 1)

    def test_admin_executions_status_reports_persisted_results(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            plan = plan_user_service_restart("admin.restart.test", "overseer-api.service", "reload code", "active")
            result = execute_admin_change_plan(plan)
            store.save_admin_execution(result)
            store.close()

            status = admin_executions_status(store_path)

        self.assertEqual(status["execution_count"], 1)
        self.assertEqual(status["executions"][0]["plan_id"], "admin.restart.test")
        self.assertEqual(status["executions"][0]["status"], AdminExecutionStatus.BLOCKED.value)

    def test_admin_adapter_capabilities_list_live_enablement(self):
        status = admin_adapter_capabilities_status()
        restart = next(item for item in status["items"] if item["kind"] == AdminChangeKind.USER_SERVICE_RESTART.value)
        package = next(item for item in status["items"] if item["kind"] == AdminChangeKind.APT_INSTALL.value)

        self.assertEqual(status["enabled"], 1)
        self.assertEqual(status["disabled"], 4)
        self.assertEqual(restart["status"], AdminAdapterStatus.ENABLED.value)
        self.assertFalse(restart["authorization_required_before_enable"])
        self.assertEqual(package["status"], AdminAdapterStatus.DISABLED.value)
        self.assertTrue(package["approval_plan_required"])

    def test_admin_adapter_enablement_plan_describes_high_risk_gate(self):
        status = admin_adapter_enablement_plan_status(AdminChangeKind.BLOCK_IP.value)
        item = status["items"][0]

        self.assertEqual(status["mode"], "read_only_enablement_plan")
        self.assertFalse(status["mutation_performed"])
        self.assertEqual(status["plans"], 1)
        self.assertEqual(status["approval_required"], 1)
        self.assertEqual(item["kind"], AdminChangeKind.BLOCK_IP.value)
        self.assertEqual(item["current_status"], AdminAdapterStatus.DISABLED.value)
        self.assertTrue(item["approval_required_before_enable"])
        self.assertIn("sudo", item["commands_in_scope"][0])
        self.assertIn("disable block_ip adapter capability", item["rollback_plan"][0])

    def test_admin_adapter_enablement_request_is_approval_only(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            requested = request_admin_adapter_enablement_status(
                store_path,
                AdminChangeKind.BLOCK_IP.value,
                "sisko",
                "2026-07-18T20:00:00+00:00",
            )
            pending = authorizations_required_status(store_path)
            summary = admin_summary_status(store_path)
            approved = approve_admin_adapter_enablement_status(
                store_path,
                requested["approval_id"],
                "sisko",
                "2026-07-18T20:05:00+00:00",
            )
            after = authorizations_required_status(store_path)
            after_summary = admin_summary_status(store_path)

        block = next(item for item in admin_adapter_capabilities_status()["items"] if item["kind"] == AdminChangeKind.BLOCK_IP.value)
        self.assertTrue(requested["mutation_performed"])
        self.assertEqual(requested["approval_status"], ApprovalStatus.PENDING.value)
        self.assertEqual(requested["kind"], AdminChangeKind.BLOCK_IP.value)
        self.assertEqual(pending["pending_count"], 1)
        self.assertEqual(pending["pending_adapter_enablement_approval_count"], 1)
        self.assertEqual(pending["adapter_enablement_approvals"][0]["next_step"], "approve-admin-adapter-enablement before enabling adapter code")
        self.assertEqual(summary["pending_authorizations"], 1)
        self.assertEqual(summary["adapter_enablement_approvals"]["pending"], 1)
        self.assertEqual(approved["approval_status"], ApprovalStatus.APPROVED.value)
        self.assertTrue(approved["adapter_enablement_approval"])
        self.assertEqual(after["pending_count"], 0)
        self.assertEqual(after_summary["adapter_enablement_approvals"]["approved"], 1)
        self.assertEqual(block["status"], AdminAdapterStatus.DISABLED.value)

    def test_admin_summary_reports_plans_executions_and_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            plan_admin_change_status(
                store_path,
                "admin.restart.summary",
                AdminChangeKind.USER_SERVICE_RESTART.value,
                "overseer-api.service",
                "reload approved code",
                "active",
            )
            execute_admin_change_status(store_path, "admin.restart.summary")

            status = admin_summary_status(store_path)

        self.assertEqual(status["plans"], 1)
        self.assertEqual(status["pending_authorizations"], 1)
        self.assertEqual(status["executions"], 1)
        self.assertEqual(status["executions_by_status"][AdminExecutionStatus.BLOCKED.value], 1)
        self.assertEqual(status["latest_audit_events"][0]["subject_id"], "admin.restart.summary")
        self.assertEqual(status["history_review"]["active_or_pending"], 1)

    def test_admin_execution_readiness_explains_plan_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            restart = plan_admin_change_status(
                store_path,
                "admin.restart.ready",
                AdminChangeKind.USER_SERVICE_RESTART.value,
                "overseer-api.service",
                "reload approved code",
                "active",
            )
            approve_admin_change_status(store_path, restart["id"], "sisko")
            block_plan = plan_admin_change_status(
                store_path,
                "admin.block.readiness",
                AdminChangeKind.BLOCK_IP.value,
                "8.8.8.8",
                "block hostile source",
                "not blocked",
            )
            ids_package = prepare_host_security_ids_review_package_status(
                store_path,
                block_plan["id"],
                package_id="ids-review.admin.block.readiness",
            )
            submitted = submit_host_security_ids_review_package_status(
                store_path,
                ids_package["id"],
                "odo",
            )
            record_host_security_ids_review_result_status(
                store_path,
                submitted["id"],
                "accepted",
                "approved staged block package",
                "odo",
            )
            approve_admin_change_status(store_path, block_plan["id"], "sisko")

            status = admin_execution_readiness_status(store_path)

        restart_item = next(item for item in status["items"] if item["id"] == "admin.restart.ready")
        block_item = next(item for item in status["items"] if item["id"] == "admin.block.readiness")
        self.assertEqual(status["plans"], 2)
        self.assertEqual(status["ready_for_overseer_execution"], 1)
        self.assertEqual(status["manual_execution_required"], 1)
        self.assertEqual(status["adapter_enabled"], 1)
        self.assertEqual(status["adapter_disabled"], 1)
        self.assertEqual(restart_item["readiness_state"], "ready_for_overseer_execution")
        self.assertTrue(restart_item["live_execution_supported"])
        self.assertEqual(restart_item["adapter_status"], AdminAdapterStatus.ENABLED.value)
        self.assertEqual(block_item["readiness_state"], "manual_execution_required")
        self.assertFalse(block_item["live_execution_supported"])
        self.assertEqual(block_item["adapter_status"], AdminAdapterStatus.DISABLED.value)
        self.assertTrue(block_item["adapter"]["approval_plan_required"])
        self.assertTrue(block_item["ids_review_gate_satisfied"])

    def test_admin_history_review_identifies_archive_candidates(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            completed = plan_admin_change_status(
                store_path,
                "admin.restart.completed",
                AdminChangeKind.USER_SERVICE_RESTART.value,
                "overseer-api.service",
                "reload approved code",
                "active",
            )
            approve_admin_change_status(store_path, completed["id"], "sisko")
            store = SQLiteStore(store_path)
            store.save_admin_execution(
                AdminExecutionResult(
                    id="admin.exec.admin.restart.completed.completed",
                    plan_id=completed["id"],
                    status=AdminExecutionStatus.COMPLETED,
                    summary="admin change completed and verified",
                    command_results=(),
                )
            )
            store.close()
            canceled = plan_admin_change_status(
                store_path,
                "admin.restart.canceled",
                AdminChangeKind.USER_SERVICE_RESTART.value,
                "overseer-api.service",
                "reload superseded code",
                "active",
            )
            cancel_admin_change_status(store_path, canceled["id"], "sisko", "superseded")
            plan_admin_change_status(
                store_path,
                "admin.restart.active",
                AdminChangeKind.USER_SERVICE_RESTART.value,
                "overseer-api.service",
                "reload active code",
                "active",
            )

            status = admin_history_review_status(store_path)
            archive_plan = admin_history_archive_plan_status(store_path)
            archived = archive_admin_history_status(
                store_path,
                "sisko",
                "2026-07-18T22:10:00+00:00",
                plan_id="admin.restart.completed",
            )
            post_archive_review = admin_history_review_status(store_path)
            post_archive_plan = admin_history_archive_plan_status(store_path)
            post_archive_records = admin_history_archives_status(store_path)
            filtered_archive_records = admin_history_archives_status(store_path, "admin.restart.completed")
            restore_readiness = admin_history_restore_readiness_status(store_path)
            filtered_restore_readiness = admin_history_restore_readiness_status(store_path, "admin.restart.completed")
            restore_request = request_admin_history_restore_status(
                store_path,
                "admin.restart.completed",
                "sisko",
                "2026-07-18T22:18:00+00:00",
            )
            pending_restore_summary = admin_summary_status(store_path)
            pending_restore_authorizations = authorizations_required_status(store_path)
            restore_approval = approve_admin_history_restore_status(
                store_path,
                restore_request["approval_id"],
                "sisko",
                "2026-07-18T22:19:00+00:00",
            )
            post_archive_summary = admin_summary_status(store_path)
            post_archive_state = list_state_status(store_path)
            restored = unarchive_admin_history_status(
                store_path,
                "admin.restart.completed",
                "sisko",
                restore_request["approval_id"],
                "2026-07-18T22:20:00+00:00",
            )
            post_restore_review = admin_history_review_status(store_path)
            post_restore_summary = admin_summary_status(store_path)
            post_restore_state = list_state_status(store_path)

        completed_item = next(item for item in status["items"] if item["id"] == "admin.restart.completed")
        canceled_item = next(item for item in status["items"] if item["id"] == "admin.restart.canceled")
        active_item = next(item for item in status["items"] if item["id"] == "admin.restart.active")
        self.assertEqual(status["archive_candidates"], 2)
        self.assertEqual(status["active_or_pending"], 1)
        self.assertEqual(status["by_disposition"]["archive_completed"], 1)
        self.assertEqual(status["by_disposition"]["archive_canceled"], 1)
        self.assertEqual(completed_item["disposition"], "archive_completed")
        self.assertTrue(canceled_item["archive_candidate"])
        self.assertEqual(active_item["disposition"], "retain_active")
        completed_bundle = next(item for item in archive_plan["items"] if item["id"] == "admin.restart.completed")
        self.assertEqual(archive_plan["mode"], "read_only_plan")
        self.assertFalse(archive_plan["mutation_performed"])
        self.assertTrue(archive_plan["approval_required_before_archive"])
        self.assertEqual(archive_plan["planned_bundles"], 2)
        self.assertEqual(completed_bundle["records"]["admin_change_plan"], 1)
        self.assertEqual(completed_bundle["records"]["admin_executions"], 1)
        self.assertEqual(completed_bundle["action"], "export_then_mark_archived")
        self.assertTrue(archived["mutation_performed"])
        self.assertEqual(archived["archived"], 1)
        self.assertEqual(archived["records"][0]["plan_id"], "admin.restart.completed")
        self.assertEqual(post_archive_review["archive_candidates"], 1)
        self.assertEqual(post_archive_review["archived_plans"], 1)
        self.assertEqual(post_archive_plan["planned_bundles"], 1)
        self.assertEqual(post_archive_records["archive_records"], 1)
        self.assertFalse(post_archive_records["mutation_performed"])
        self.assertEqual(post_archive_records["records"][0]["plan_id"], "admin.restart.completed")
        self.assertEqual(filtered_archive_records["archive_records"], 1)
        self.assertEqual(filtered_archive_records["filters"]["plan_id"], "admin.restart.completed")
        self.assertEqual(restore_readiness["mode"], "read_only_restore_plan")
        self.assertFalse(restore_readiness["mutation_performed"])
        self.assertEqual(restore_readiness["archived_plans"], 1)
        self.assertEqual(restore_readiness["ready_for_restore_request"], 1)
        self.assertEqual(restore_readiness["approval_required_before_restore"], 1)
        self.assertEqual(restore_readiness["items"][0]["approval_level_before_restore"], ApprovalLevel.SISKO.value)
        self.assertEqual(restore_readiness["items"][0]["restore_risk_level"], RiskLevel.MEDIUM.value)
        self.assertEqual(restore_readiness["items"][0]["evidence"]["archive_record"]["id"], "admin.archive.admin.restart.completed")
        self.assertEqual(filtered_restore_readiness["filters"]["plan_id"], "admin.restart.completed")
        self.assertTrue(restore_request["mutation_performed"])
        self.assertEqual(restore_request["approval_status"], ApprovalStatus.PENDING.value)
        self.assertEqual(pending_restore_summary["restore_approvals"]["total"], 1)
        self.assertEqual(pending_restore_summary["restore_approvals"]["pending"], 1)
        self.assertEqual(pending_restore_summary["restore_approvals"]["items"][0]["plan_id"], "admin.restart.completed")
        self.assertEqual(pending_restore_authorizations["pending_restore_approval_count"], 1)
        self.assertEqual(pending_restore_authorizations["restore_approvals"][0]["plan_id"], "admin.restart.completed")
        self.assertEqual(
            pending_restore_authorizations["restore_approvals"][0]["next_step"],
            "approve-admin-history-restore before unarchive-admin-history",
        )
        self.assertEqual(restore_approval["approval_status"], ApprovalStatus.APPROVED.value)
        self.assertTrue(restore_approval["restore_approval"])
        self.assertEqual(restore_approval["plan_id"], "admin.restart.completed")
        self.assertEqual(restore_approval["archive_record_id"], "admin.archive.admin.restart.completed")
        self.assertEqual(post_archive_summary["archived_plans"], 1)
        self.assertEqual(post_archive_summary["restore_approvals"]["pending"], 0)
        self.assertEqual(post_archive_summary["restore_approvals"]["approved"], 1)
        archived_state_plan = next(item for item in post_archive_state["admin_change_plans"] if item["id"] == "admin.restart.completed")
        self.assertTrue(archived_state_plan["archived"])
        self.assertEqual(post_archive_state["admin_history_archives"][0]["id"], "admin.archive.admin.restart.completed")
        self.assertTrue(restored["mutation_performed"])
        self.assertFalse(restored["plan"]["archived"])
        self.assertEqual(restored["approval_id"], restore_request["approval_id"])
        self.assertEqual(restored["archive_record_id"], "admin.archive.admin.restart.completed")
        self.assertEqual(post_restore_review["archive_candidates"], 2)
        self.assertEqual(post_restore_review["archived_plans"], 0)
        self.assertEqual(post_restore_summary["archived_plans"], 0)
        restored_state_plan = next(item for item in post_restore_state["admin_change_plans"] if item["id"] == "admin.restart.completed")
        self.assertFalse(restored_state_plan["archived"])
        self.assertEqual(post_restore_state["admin_history_archives"][0]["id"], "admin.archive.admin.restart.completed")

    def test_usage_summary_reports_capacity_and_reset_state(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_usage_limit(
                UsageLimit(
                    id="limit.available",
                    resource_id="svc.ai",
                    kind=LimitKind.REQUESTS,
                    capacity=100,
                    remaining=40,
                    resets_at="2026-07-18T18:00:00+00:00",
                    window="daily",
                    confidence=1.0,
                )
            )
            store.save_usage_limit(
                UsageLimit(
                    id="limit.exhausted",
                    resource_id="svc.render",
                    kind=LimitKind.CREDITS,
                    capacity=10,
                    remaining=0,
                    resets_at=None,
                    window="monthly",
                    confidence=0.4,
                )
            )
            store.close()

            status = usage_summary_status(store_path)

        self.assertEqual(status["limits"], 2)
        self.assertEqual(status["available"], 1)
        self.assertEqual(status["exhausted"], 1)
        self.assertEqual(status["unknown_reset"], 1)
        self.assertEqual(status["low_confidence"], 1)
        self.assertEqual(status["next_reset_at"], "2026-07-18T18:00:00+00:00")
        self.assertEqual(status["limits_by_kind"][LimitKind.REQUESTS.value], 1)

    def test_physical_summary_reports_identity_readiness_and_risk(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_physical_identity(
                PhysicalIdentity(
                    kind=PhysicalAssetKind.SERIAL_PORT,
                    stable_id="serial.rs485-a",
                    observed_paths=frozenset({"/dev/serial/by-id/rs485-a"}),
                    capabilities=frozenset({"rs485"}),
                    exclusive_groups=frozenset({"bus.rs485.a"}),
                )
            )
            store.save_physical_identity(
                PhysicalIdentity(
                    kind=PhysicalAssetKind.STORAGE_ARRAY,
                    stable_id="storage.array-a",
                    storage_profile="write_shared",
                )
            )
            store.save_physical_identity(
                PhysicalIdentity(
                    kind=PhysicalAssetKind.POWER_RESOURCE,
                    stable_id="power.usb-hub-a",
                    power_profile="high",
                )
            )
            store.close()

            status = physical_summary_status(store_path)

        self.assertEqual(status["assets"], 3)
        self.assertEqual(status["complete_for_checkout"], 3)
        self.assertEqual(status["power_risk"], 1)
        self.assertEqual(status["storage_risk"], 1)
        self.assertEqual(status["assets_by_kind"][PhysicalAssetKind.SERIAL_PORT.value], 1)
        serial = next(item for item in status["items"] if item["stable_id"] == "serial.rs485-a")
        self.assertEqual(serial["observed_paths"], ["/dev/serial/by-id/rs485-a"])

    def test_virtual_summary_reports_checkout_readiness_and_claims(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="gateway.protected",
                    name="Protected Gateway",
                    type=ResourceType.VIRTUAL_ASSET,
                    owner_domain=OwnerDomain.DAX,
                    risk_level=RiskLevel.HIGH,
                    identifiers={
                        "kind": "gateway",
                        "host": "127.0.0.1",
                        "ports": [8795],
                        "networks": ["loopback"],
                        "state_path": "state/gateway",
                    },
                    exclusive_groups=frozenset({"gateway.protected"}),
                    current_claim_id="claim.gateway.active",
                )
            )
            store.save_resource(
                Resource(
                    id="proxy.local",
                    name="Local Proxy",
                    type=ResourceType.VIRTUAL_ASSET,
                    owner_domain=OwnerDomain.DAX,
                    risk_level=RiskLevel.MEDIUM,
                    identifiers={"kind": "proxy", "ports": [8766], "config_paths": ["config/proxy.json"]},
                )
            )
            store.save_claim(
                Claim(
                    id="claim.gateway.active",
                    resource_id="gateway.protected",
                    claim_type=ClaimType.LEASE,
                    owner_thread="thread-a",
                    owner_role=OwnerDomain.DAX,
                    intent="use gateway",
                    requested_action="bind protected gateway",
                    risk_level=RiskLevel.HIGH,
                    status=ClaimStatus.ACTIVE,
                    port_reservations=frozenset({8795}),
                )
            )
            store.save_claim(
                Claim(
                    id="claim.gateway.queued",
                    resource_id="gateway.protected",
                    claim_type=ClaimType.LEASE,
                    owner_thread="thread-b",
                    owner_role=OwnerDomain.DAX,
                    intent="use gateway later",
                    requested_action="bind protected gateway",
                    risk_level=RiskLevel.LOW,
                    status=ClaimStatus.QUEUED,
                    port_reservations=frozenset({8795}),
                )
            )
            store.close()

            status = virtual_summary_status(store_path)

        self.assertEqual(status["assets"], 2)
        self.assertEqual(status["ready_for_checkout"], 1)
        self.assertEqual(status["checked_out_or_reserved"], 1)
        self.assertEqual(status["active_claims"], 1)
        self.assertEqual(status["queued_claims"], 1)
        self.assertEqual(status["reserved_ports"], [8795])
        self.assertEqual(status["assets_by_kind"]["gateway"], 1)
        gateway = next(item for item in status["items"] if item["id"] == "gateway.protected")
        self.assertEqual(gateway["active_claim_ids"], ["claim.gateway.active"])
        self.assertEqual(gateway["queued_claim_ids"], ["claim.gateway.queued"])
        self.assertFalse(gateway["ready_for_checkout"])

    def test_command_summary_reports_cross_domain_state_without_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="gateway.command",
                    name="Command Gateway",
                    type=ResourceType.VIRTUAL_ASSET,
                    owner_domain=OwnerDomain.DAX,
                    risk_level=RiskLevel.HIGH,
                    identifiers={"kind": "gateway", "ports": [8795]},
                )
            )
            store.save_claim(
                Claim(
                    id="claim.command",
                    resource_id="gateway.command",
                    claim_type=ClaimType.LEASE,
                    owner_thread="thread-a",
                    owner_role=OwnerDomain.DAX,
                    intent="use command gateway",
                    requested_action="bind gateway",
                    risk_level=RiskLevel.HIGH,
                    status=ClaimStatus.APPROVED,
                    port_reservations=frozenset({8795}),
                )
            )
            store.save_approval(
                ApprovalRequest(
                    id="approval.command",
                    subject_id="claim.command",
                    approval_level=ApprovalLevel.SISKO,
                    requester_thread="thread-a",
                    owner_domain=OwnerDomain.SISKO,
                    reason="high-risk gateway use",
                )
            )
            store.save_usage_limit(
                UsageLimit(
                    id="limit.command",
                    resource_id="svc.command",
                    kind=LimitKind.REQUESTS,
                    capacity=10,
                    remaining=0,
                    resets_at=None,
                    window="hourly",
                )
            )
            store.save_health_target(
                HealthTarget(
                    id="health.command",
                    resource_id="gateway.command",
                    name="Command Gateway",
                    probe_type=ProbeType.HTTP,
                    target="http://127.0.0.1:8795/health",
                )
            )
            store.save_physical_identity(
                PhysicalIdentity(
                    kind=PhysicalAssetKind.USB_DEVICE,
                    stable_id="usb.command",
                    vendor_id="1234",
                    product_id="5678",
                    serial_number="abc",
                )
            )
            store.save_audit_event(
                AuditEvent(
                    id="alert.command",
                    event_type=AuditEventType.ALERT,
                    owner_domain=OwnerDomain.ODO,
                    subject_id="gateway.command",
                    summary="gateway alert",
                    risk_level=RiskLevel.HIGH,
                )
            )
            store.save_runtime_heartbeat(
                RuntimeHeartbeat(
                    id="overseer",
                    service_name="overseer",
                    started_at="2026-07-18T17:00:00+00:00",
                    last_tick_at="2026-07-18T17:00:00+00:00",
                    tick_count=1,
                )
            )
            before_audit_count = len(store.list_audit_events())
            store.close()

            status = command_summary_status(store_path, now="2026-07-18T17:00:10+00:00")
            store = SQLiteStore(store_path)
            after_audit_count = len(store.list_audit_events())
            store.close()

        self.assertEqual(status["service"]["freshness"]["status"], FreshnessStatus.OK.value)
        self.assertEqual(status["resources"]["total"], 1)
        self.assertEqual(status["resources"]["by_type"][ResourceType.VIRTUAL_ASSET.value], 1)
        self.assertEqual(status["claims"]["active_like"], 1)
        self.assertEqual(status["claims"]["pending_approvals"], 1)
        self.assertEqual(status["health"]["unhealthy"], 1)
        self.assertEqual(status["usage_limits"]["exhausted"], 1)
        self.assertEqual(status["physical_assets"]["ready_for_checkout"], 1)
        self.assertEqual(status["virtual_assets"]["active_claims"], 1)
        self.assertEqual(status["alerts"]["high_or_critical"], 1)
        self.assertEqual(after_audit_count, before_audit_count)

    def test_maintenance_summary_reports_plans_targets_and_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="maint.overseer-api",
                    name="Overseer API Maintenance",
                    type=ResourceType.MAINTENANCE_TARGET,
                    owner_domain=OwnerDomain.OBRIEN,
                    risk_level=RiskLevel.MEDIUM,
                    state=ResourceState.MAINTENANCE,
                )
            )
            restart_plan = plan_user_service_restart(
                "admin.restart.maintenance",
                "overseer-api.service",
                "reload tested code",
                "active",
            )
            store.save_admin_change_plan(restart_plan)
            install_plan = approve_admin_change_plan(
                plan_apt_install("admin.install.maintenance", ("sqlite3",), "install sqlite tooling", "not installed"),
                "sisko",
                "2026-07-18T18:00:00+00:00",
            )
            store.save_admin_change_plan(install_plan)
            store.save_admin_execution(
                AdminExecutionResult(
                    id="admin.exec.install.maintenance",
                    plan_id=install_plan.id,
                    status=AdminExecutionStatus.COMPLETED,
                    summary="installed sqlite tooling",
                    command_results=(),
                )
            )
            store.close()

            status = maintenance_summary_status(store_path)

        self.assertEqual(status["targets"], 1)
        self.assertEqual(status["plans"], 2)
        self.assertEqual(status["pending_authorizations"], 1)
        self.assertEqual(status["approved_plans"], 1)
        self.assertEqual(status["executable_plans"], 1)
        self.assertEqual(status["executions"], 1)
        self.assertEqual(status["plans_by_kind"][AdminChangeKind.USER_SERVICE_RESTART.value], 1)
        self.assertEqual(status["plans_by_kind"][AdminChangeKind.APT_INSTALL.value], 1)
        self.assertEqual(status["execution_by_status"][AdminExecutionStatus.COMPLETED.value], 1)
        self.assertEqual(status["targets_by_state"][ResourceState.MAINTENANCE.value], 1)
        restart = next(item for item in status["items"] if item["id"] == "admin.restart.maintenance")
        self.assertTrue(restart["requires_explicit_approval"])
        self.assertIsNone(restart["latest_execution_status"])

    def test_security_summary_reports_surfaces_alerts_host_findings_and_plans(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="security.firewall",
                    name="Host Firewall",
                    type=ResourceType.SECURITY_SURFACE,
                    owner_domain=OwnerDomain.ODO,
                    risk_level=RiskLevel.CRITICAL,
                    state=ResourceState.AVAILABLE,
                )
            )
            store.save_audit_event(
                AuditEvent(
                    id="alert.security",
                    event_type=AuditEventType.ALERT,
                    owner_domain=OwnerDomain.ODO,
                    subject_id="security.firewall",
                    summary="non-loopback listener needs review",
                    risk_level=RiskLevel.HIGH,
                )
            )
            snapshot = HostInspectionAdapter(
                command_runner=lambda command, timeout_seconds: HostCommandObservation(
                    name=command[0],
                    command=tuple(command),
                    exit_code=0,
                    stdout=(
                        "host-a"
                        if tuple(command) == ("hostname",)
                        else "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                        "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
                        if tuple(command) == ("ss", "-ltnp")
                        else "ok"
                    ),
                ),
                file_reader=lambda path: "ID=debian\n",
            ).inspect("2026-07-18T18:00:00+00:00")
            store.save_host_snapshot(snapshot)
            store.save_admin_change_plan(
                plan_block_ip(
                    "admin.block.security",
                    "203.0.113.10",
                    "block suspicious source",
                    "not blocked",
                )
            )
            store.close()
            prepare_host_security_ids_review_package_status(
                store_path,
                "admin.block.security",
                package_id="ids-review.admin.block.security",
            )

            status = security_summary_status(store_path)

        self.assertEqual(status["security_surfaces"], 1)
        self.assertEqual(status["alerts"], 1)
        self.assertEqual(status["alerts_by_risk"][RiskLevel.HIGH.value], 1)
        self.assertEqual(status["host_security"]["high_findings"], 1)
        self.assertEqual(status["protective_plans"]["total"], 1)
        self.assertEqual(status["protective_plans"]["pending_authorizations"], 1)
        self.assertEqual(status["protective_plans"]["by_kind"][AdminChangeKind.BLOCK_IP.value], 1)
        self.assertEqual(status["ids_review"]["package_count"], 1)
        self.assertEqual(status["ids_review"]["gate_blocked"], 1)
        self.assertEqual(status["ids_review"]["packages"][0]["next_step"], "export IDS/firewall review prompt and submit package before approval")
        self.assertEqual(status["surfaces"][0]["id"], "security.firewall")
        self.assertEqual(status["events"][0]["id"], "alert.security")

    def test_health_efficiency_summary_reports_probe_failures_and_owner_routing(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            targets = (
                HealthTarget(
                    id="health.mcp",
                    resource_id="svc.mcp",
                    name="MCP Service",
                    probe_type=ProbeType.MCP,
                    target="http://127.0.0.1:8791/health",
                    owner_domain=OwnerDomain.JULIAN,
                ),
                HealthTarget(
                    id="health.json",
                    resource_id="svc.json",
                    name="JSON Service",
                    probe_type=ProbeType.JSON,
                    target="http://127.0.0.1:8766/state",
                    owner_domain=OwnerDomain.JULIAN,
                ),
                HealthTarget(
                    id="health.html",
                    resource_id="svc.page",
                    name="Hosted Page",
                    probe_type=ProbeType.HTML,
                    target="http://127.0.0.1:8000/",
                    owner_domain=OwnerDomain.DAX,
                ),
            )
            for target in targets:
                store.save_health_target(target)
            store.save_health_evidence(
                HealthEvidence(
                    id="evidence.mcp.failed",
                    resource_id="svc.mcp",
                    target="http://127.0.0.1:8791/health",
                    probe_type=ProbeType.MCP,
                    observed_status=HealthStatus.FAILED,
                    owner_domain=OwnerDomain.JULIAN,
                    observed_error="connection refused",
                    recovery_required=True,
                    captured_at="2026-07-18T18:00:00+00:00",
                )
            )
            store.save_health_evidence(
                HealthEvidence(
                    id="evidence.json.healthy",
                    resource_id="svc.json",
                    target="http://127.0.0.1:8766/state",
                    probe_type=ProbeType.JSON,
                    observed_status=HealthStatus.HEALTHY,
                    owner_domain=OwnerDomain.JULIAN,
                    captured_at="2026-07-18T18:01:00+00:00",
                )
            )
            store.save_health_evidence(
                HealthEvidence(
                    id="evidence.html.degraded",
                    resource_id="svc.page",
                    target="http://127.0.0.1:8000/",
                    probe_type=ProbeType.HTML,
                    observed_status=HealthStatus.DEGRADED,
                    owner_domain=OwnerDomain.DAX,
                    observed_error="expected content type text/html, got application/json",
                    recovery_required=True,
                    captured_at="2026-07-18T18:02:00+00:00",
                )
            )
            store.close()

            status = health_efficiency_summary_status(store_path)

        self.assertEqual(status["targets"], 3)
        self.assertEqual(status["evidence_records"], 3)
        self.assertEqual(status["healthy"], 1)
        self.assertEqual(status["unhealthy"], 2)
        self.assertEqual(status["recovery_required"], 2)
        self.assertEqual(status["by_status"][HealthStatus.FAILED.value], 1)
        self.assertEqual(status["by_status"][HealthStatus.DEGRADED.value], 1)
        self.assertEqual(status["by_probe_type"][ProbeType.MCP.value], 1)
        self.assertEqual(status["errors_by_probe_type"][ProbeType.HTML.value], 1)
        self.assertEqual(status["by_owner"][OwnerDomain.DAX.value], 1)
        mcp_failure = next(
            failure for failure in status["latest_failures"] if failure["target_id"] == "health.mcp"
        )
        self.assertEqual(mcp_failure["error"], "connection refused")
        self.assertTrue(mcp_failure["recovery_required"])

    def test_operator_dashboard_rolls_up_domain_attention(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="gateway.dashboard",
                    name="Dashboard Gateway",
                    type=ResourceType.VIRTUAL_ASSET,
                    owner_domain=OwnerDomain.DAX,
                    risk_level=RiskLevel.HIGH,
                    identifiers={"kind": "gateway", "ports": [8766]},
                )
            )
            store.save_resource(
                Resource(
                    id="security.dashboard",
                    name="Dashboard Security Surface",
                    type=ResourceType.SECURITY_SURFACE,
                    owner_domain=OwnerDomain.ODO,
                    risk_level=RiskLevel.CRITICAL,
                )
            )
            store.save_usage_limit(
                UsageLimit(
                    id="limit.dashboard",
                    resource_id="svc.limited",
                    kind=LimitKind.REQUESTS,
                    capacity=10,
                    remaining=0,
                    resets_at="2026-07-18T19:00:00+00:00",
                    window="hourly",
                    observed_at="2026-07-18T18:00:00+00:00",
                )
            )
            store.save_health_target(
                HealthTarget(
                    id="health.dashboard",
                    resource_id="svc.dashboard",
                    name="Dashboard Health",
                    probe_type=ProbeType.JSON,
                    target="http://127.0.0.1:8766/state",
                    owner_domain=OwnerDomain.JULIAN,
                )
            )
            store.save_health_evidence(
                HealthEvidence(
                    id="evidence.dashboard.failed",
                    resource_id="svc.dashboard",
                    target="http://127.0.0.1:8766/state",
                    probe_type=ProbeType.JSON,
                    observed_status=HealthStatus.FAILED,
                    owner_domain=OwnerDomain.JULIAN,
                    observed_error="json parse failed",
                    recovery_required=True,
                    captured_at="2026-07-18T18:00:00+00:00",
                )
            )
            store.save_audit_event(
                AuditEvent(
                    id="alert.dashboard",
                    event_type=AuditEventType.ALERT,
                    owner_domain=OwnerDomain.ODO,
                    subject_id="security.dashboard",
                    summary="dashboard alert",
                    risk_level=RiskLevel.HIGH,
                )
            )
            store.save_admin_change_plan(
                plan_block_ip(
                    "admin.block.dashboard",
                    "203.0.113.20",
                    "block dashboard test source",
                    "not blocked",
                )
            )
            completed = plan_user_service_restart(
                "admin.restart.dashboard.completed",
                "overseer-api.service",
                "reload old dashboard code",
                "active",
            )
            completed = replace(completed, approved=True, approved_by="sisko", approved_at="2026-07-18T00:00:00Z")
            store.save_admin_change_plan(completed)
            store.save_admin_execution(
                AdminExecutionResult(
                    id="admin.exec.admin.restart.dashboard.completed.completed",
                    plan_id=completed.id,
                    status=AdminExecutionStatus.COMPLETED,
                    summary="admin change completed and verified",
                    command_results=(),
                )
            )
            archived = replace(
                plan_user_service_restart(
                    "admin.restart.dashboard.archived",
                    "overseer-api.service",
                    "restore old dashboard code",
                    "active",
                ),
                approved=True,
                approved_by="sisko",
                approved_at="2026-07-18T00:30:00Z",
                archived=True,
                archived_by="sisko",
                archived_at="2026-07-18T01:00:00Z",
                archive_record_id="admin.archive.admin.restart.dashboard.archived",
            )
            store.save_admin_change_plan(archived)
            store.save_admin_history_archive(
                AdminHistoryArchiveRecord(
                    id="admin.archive.admin.restart.dashboard.archived",
                    plan_id=archived.id,
                    disposition="archive_completed",
                    archived_by="sisko",
                    archived_at="2026-07-18T01:00:00Z",
                    summary="Archived completed dashboard restart",
                    evidence_ids=("admin.exec.admin.restart.dashboard.completed.completed",),
                )
            )
            store.save_approval(
                ApprovalRequest(
                    id=f"approval.admin.restore.{archived.id}",
                    subject_id=archived.id,
                    approval_level=ApprovalLevel.SISKO,
                    requester_thread="sisko",
                    owner_domain=OwnerDomain.SISKO,
                    reason=f"Restore archived admin plan {archived.id} to active admin history",
                    evidence_required=(archived.archive_record_id,),
                )
            )
            store.close()
            prepare_host_security_ids_review_package_status(
                store_path,
                "admin.block.dashboard",
                package_id="ids-review.admin.block.dashboard",
            )

            status = operator_dashboard_status(store_path)

        self.assertEqual(status["overall_status"], "attention_required")
        self.assertEqual(status["attention"]["unhealthy_health_targets"], 1)
        self.assertEqual(status["attention"]["recovery_required"], 1)
        self.assertEqual(status["attention"]["exhausted_usage_limits"], 1)
        self.assertEqual(status["attention"]["security_alerts"], 1)
        self.assertEqual(status["attention"]["security_pending_authorizations"], 1)
        self.assertEqual(status["attention"]["security_ids_review_gate_blocked"], 1)
        self.assertEqual(status["attention"]["admin_archive_candidates"], 1)
        self.assertEqual(status["attention"]["pending_restore_approvals"], 1)
        self.assertEqual(status["role_focus"]["sisko"]["pending_authorizations"], 1)
        self.assertEqual(status["role_focus"]["sisko"]["admin_archive_candidates"], 1)
        self.assertEqual(status["role_focus"]["sisko"]["pending_restore_approvals"], 1)
        self.assertEqual(status["role_focus"]["odo"]["alerts"], 1)
        self.assertEqual(status["role_focus"]["odo"]["ids_review_gate_blocked"], 1)
        self.assertEqual(status["role_focus"]["quark"]["exhausted"], 1)
        self.assertEqual(status["role_focus"]["julian"]["latest_failures"], 1)
        self.assertIn("command", status["summaries"])
        self.assertEqual(status["summaries"]["admin"]["restore_approvals"]["pending"], 1)
        self.assertIn("admin_history", status["summaries"])
        self.assertIn("health_efficiency", status["summaries"])


class OverseerApiTests(unittest.TestCase):
    def test_loopback_api_reports_health_and_state(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="svc.api",
                    name="API Service",
                    type=ResourceType.SERVICE,
                    owner_domain=OwnerDomain.JULIAN,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path) as server:
                health = server.get("/health")
                state = server.get("/state")

            self.assertTrue(health["ok"])
            self.assertEqual(state["resources"][0]["id"], "svc.api")

    def test_loopback_api_reports_runtime_status(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_runtime_heartbeat(
                RuntimeHeartbeat(
                    id="overseer",
                    service_name="overseer",
                    started_at="2026-07-18T16:00:00+00:00",
                    last_tick_at="2026-07-18T16:01:00+00:00",
                    tick_count=3,
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path) as server:
                status = server.get("/runtime-status")

            self.assertEqual(status["service"]["tick_count"], 3)
            self.assertFalse(status["host_inspection"]["enabled"])

    def test_loopback_api_reports_alerts_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_audit_event(
                AuditEvent(
                    id="alert.api.runtime",
                    event_type=AuditEventType.ALERT,
                    owner_domain=OwnerDomain.JULIAN,
                    subject_id="runtime.heartbeat",
                    summary="runtime heartbeat is stale",
                    risk_level=RiskLevel.MEDIUM,
                    evidence_ids=("heartbeat.old",),
                    occurred_at="2026-07-18T16:00:00+00:00",
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path) as server:
                status = server.get("/alerts-summary")

            self.assertEqual(status["alerts"], 1)
            self.assertEqual(status["events"][0]["id"], "alert.api.runtime")

    def test_loopback_api_reports_filtered_audit_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_audit_event(
                AuditEvent(
                    id="audit.api.ids-review.prepared",
                    event_type=AuditEventType.REQUESTED,
                    owner_domain=OwnerDomain.ODO,
                    subject_id="ids-review.admin.block.source",
                    summary="IDS review prepared",
                    risk_level=RiskLevel.CRITICAL,
                )
            )
            store.save_audit_event(
                AuditEvent(
                    id="audit.api.claim.allowed",
                    event_type=AuditEventType.ALLOWED,
                    owner_domain=OwnerDomain.DAX,
                    subject_id="claim.gateway",
                    summary="claim allowed",
                    risk_level=RiskLevel.LOW,
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path) as server:
                status = server.get("/audit-summary?owner=odo&subject_prefix=ids-review.")

            self.assertEqual(status["event_count"], 1)
            self.assertEqual(status["filters"]["owner"], OwnerDomain.ODO.value)
            self.assertEqual(status["events"][0]["id"], "audit.api.ids-review.prepared")

    def test_loopback_api_runs_claim_lifecycle(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="proxy.api",
                    name="API Proxy",
                    type=ResourceType.VIRTUAL_ASSET,
                    owner_domain=OwnerDomain.DAX,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path) as server:
                requested = server.post(
                    "/claims/request",
                    {
                        "claim_id": "claim.api.proxy",
                        "resource_id": "proxy.api",
                        "claim_type": ClaimType.LEASE.value,
                        "owner_thread": "thread-api",
                        "owner_role": OwnerDomain.DAX.value,
                        "intent": "use proxy",
                        "requested_action": "bind proxy",
                        "risk_level": RiskLevel.LOW.value,
                    },
                )
                approved = server.post(
                    "/claims/approve",
                    {
                        "approval_id": requested["approval_id"],
                        "decided_by": "sisko",
                    },
                )
                activated = server.post(
                    "/claims/activate",
                    {
                        "claim_id": requested["claim"],
                        "approval_id": approved["approval_id"],
                    },
                )
                released = server.post(
                    "/claims/release",
                    {
                        "claim_id": requested["claim"],
                        "released_by": "dax",
                        "reason": "work complete and proxy health verified",
                        "evidence_ids": ["health.proxy.ok"],
                    },
                )

            self.assertEqual(requested["claim_status"], ClaimStatus.REQUESTED.value)
            self.assertEqual(approved["approval_status"], ApprovalStatus.APPROVED.value)
            self.assertEqual(activated["claim_status"], ClaimStatus.ACTIVE.value)
            self.assertEqual(released["claim_status"], ClaimStatus.RELEASED.value)
            self.assertTrue(released["release_evidence_complete"])
            self.assertEqual(released["audit_event"]["evidence_ids"], ["health.proxy.ok"])

    def test_api_rejects_non_loopback_bind(self):
        with self.assertRaises(ValueError):
            run_api_server("state/unused.sqlite3", host="0.0.0.0", port=8766)

    def test_api_requires_bearer_token_when_configured(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="svc.secured",
                    name="Secured API",
                    type=ResourceType.SERVICE,
                    owner_domain=OwnerDomain.JULIAN,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="local-secret") as server:
                with self.assertRaises(HTTPError) as error:
                    urlopen(f"{server.url}/state", timeout=5)
                state = server.get("/state")

            self.assertEqual(error.exception.code, 401)
            self.assertEqual(state["resources"][0]["id"], "svc.secured")

    def test_admin_execute_reports_missing_field_and_missing_record_distinctly(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            with LocalOverseerApiServer(store_path) as server:
                with self.assertRaises(HTTPError) as missing_field_error:
                    server.post("/admin/execute", {})
                missing_field_body = json.loads(missing_field_error.exception.read().decode("utf-8"))

                with self.assertRaises(HTTPError) as missing_record_error:
                    server.post("/admin/execute", {"plan_id": "admin.missing"})
                missing_record_body = json.loads(missing_record_error.exception.read().decode("utf-8"))

            self.assertEqual(missing_field_error.exception.code, 400)
            self.assertEqual(missing_field_body["error"], "missing field: plan_id")
            self.assertEqual(missing_record_error.exception.code, 404)
            self.assertEqual(missing_record_body["error"], "missing record: admin.missing")


class OverseerApiClientTests(unittest.TestCase):
    def test_client_reads_state_with_token_file(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            token_path = Path(directory) / "api-token"
            token_path.write_text("client-secret\n", encoding="utf-8")
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="svc.client",
                    name="Client Service",
                    type=ResourceType.SERVICE,
                    owner_domain=OwnerDomain.JULIAN,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token_file=str(token_path))
                health = client.health()
                state = client.state()

            self.assertTrue(health["ok"])
            self.assertEqual(state["resources"][0]["id"], "svc.client")

    def test_client_reads_redacted_state(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="svc.redacted.client",
                    name="Client Redacted Service",
                    type=ResourceType.SERVICE,
                    owner_domain=OwnerDomain.JULIAN,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.save_health_target(
                HealthTarget(
                    id="health.redacted.client",
                    resource_id="svc.redacted.client",
                    name="Client Redacted Health",
                    probe_type=ProbeType.JSON,
                    target="http://127.0.0.1:8766/state",
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                state = client.state_redacted()

            self.assertEqual(state["store"], "[REDACTED]")
            self.assertEqual(state["health_targets"][0]["target"], "[REDACTED]")
            self.assertGreater(state["export"]["redaction_count"], 0)

    def test_client_reads_runtime_status(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_runtime_heartbeat(
                RuntimeHeartbeat(
                    id="overseer",
                    service_name="overseer",
                    started_at="2026-07-18T16:00:00+00:00",
                    last_tick_at="2026-07-18T16:01:00+00:00",
                    tick_count=4,
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                status = client.runtime_status()

            self.assertEqual(status["service"]["tick_count"], 4)

    def test_client_reads_persistence_security(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            SQLiteStore(store_path).close()
            store_path.chmod(0o600)

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                status = client.persistence_security()

            self.assertFalse(status["mutation_performed"])
            self.assertEqual(status["status"], "ok")
            self.assertEqual(status["items"][0]["octal_mode"], "0o600")

    def test_client_reads_alerts_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_audit_event(
                AuditEvent(
                    id="alert.client.host",
                    event_type=AuditEventType.ALERT,
                    owner_domain=OwnerDomain.ODO,
                    subject_id="host.inspection",
                    summary="host inspection is missing",
                    risk_level=RiskLevel.HIGH,
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                status = client.alerts_summary()

            self.assertEqual(status["alerts"], 1)
            self.assertEqual(status["events"][0]["owner_domain"], OwnerDomain.ODO.value)

    def test_client_reads_filtered_audit_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_audit_event(
                AuditEvent(
                    id="audit.client.ids-review.approved",
                    event_type=AuditEventType.APPROVED,
                    owner_domain=OwnerDomain.ODO,
                    subject_id="ids-review.admin.block.source",
                    summary="IDS review approved",
                    risk_level=RiskLevel.CRITICAL,
                )
            )
            store.save_audit_event(
                AuditEvent(
                    id="audit.client.claim.allowed",
                    event_type=AuditEventType.ALLOWED,
                    owner_domain=OwnerDomain.DAX,
                    subject_id="claim.gateway",
                    summary="claim allowed",
                    risk_level=RiskLevel.LOW,
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                status = client.audit_summary(owner=OwnerDomain.ODO.value, subject_prefix="ids-review.")

            self.assertEqual(status["event_count"], 1)
            self.assertEqual(status["events"][0]["id"], "audit.client.ids-review.approved")

    def test_client_reads_usage_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_usage_limit(
                UsageLimit(
                    id="limit.client",
                    resource_id="svc.client.limited",
                    kind=LimitKind.TOKENS,
                    capacity=1000,
                    remaining=250,
                    resets_at="2026-07-18T19:00:00+00:00",
                    window="hourly",
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                status = client.usage_summary()

            self.assertEqual(status["limits"], 1)
            self.assertEqual(status["items"][0]["kind"], LimitKind.TOKENS.value)

    def test_client_reads_physical_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_physical_identity(
                PhysicalIdentity(
                    kind=PhysicalAssetKind.USB_DEVICE,
                    stable_id="usb.device-a",
                    vendor_id="1234",
                    product_id="5678",
                    serial_number="abc",
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                status = client.physical_summary()

            self.assertEqual(status["assets"], 1)
            self.assertEqual(status["items"][0]["stable_id"], "usb.device-a")

    def test_client_reads_virtual_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="vm.client",
                    name="Client VM",
                    type=ResourceType.VIRTUAL_ASSET,
                    owner_domain=OwnerDomain.DAX,
                    risk_level=RiskLevel.MEDIUM,
                    identifiers={"kind": "vm", "host": "localhost"},
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                status = client.virtual_summary()

            self.assertEqual(status["assets"], 1)
            self.assertEqual(status["items"][0]["kind"], "vm")

    def test_client_reads_command_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="svc.command.client",
                    name="Command Client Service",
                    type=ResourceType.SERVICE,
                    owner_domain=OwnerDomain.JULIAN,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                status = client.command_summary()

            self.assertEqual(status["resources"]["total"], 1)
            self.assertEqual(status["resources"]["by_owner"][OwnerDomain.JULIAN.value], 1)

    def test_client_reads_operator_dashboard(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="svc.dashboard.client",
                    name="Dashboard Client Service",
                    type=ResourceType.SERVICE,
                    owner_domain=OwnerDomain.JULIAN,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                status = client.operator_dashboard()

            self.assertEqual(status["service_name"], "overseer")
            self.assertIn(status["overall_status"], {"nominal", "warning", "attention_required"})
            self.assertEqual(status["summaries"]["command"]["resources"]["total"], 1)

    def test_client_reads_maintenance_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_admin_change_plan(
                plan_user_service_restart(
                    "admin.restart.client",
                    "overseer-api.service",
                    "reload client test",
                    "active",
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                status = client.maintenance_summary()

            self.assertEqual(status["plans"], 1)
            self.assertEqual(status["items"][0]["kind"], AdminChangeKind.USER_SERVICE_RESTART.value)

    def test_client_reads_security_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="security.client",
                    name="Client Security Surface",
                    type=ResourceType.SECURITY_SURFACE,
                    owner_domain=OwnerDomain.ODO,
                    risk_level=RiskLevel.HIGH,
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                status = client.security_summary()

            self.assertEqual(status["security_surfaces"], 1)
            self.assertEqual(status["surfaces"][0]["owner_domain"], OwnerDomain.ODO.value)

    def test_client_reads_host_security_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            snapshot = HostInspectionAdapter(
                command_runner=lambda command, timeout_seconds: HostCommandObservation(
                    name=command[0],
                    command=tuple(command),
                    exit_code=0,
                    stdout=(
                        "host-client"
                        if tuple(command) == ("hostname",)
                        else "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"
                        if tuple(command) == ("ss", "-ltnp")
                        else "ok"
                    ),
                ),
                file_reader=lambda path: "ID=debian\n",
            ).inspect("2026-07-18T16:03:00+00:00")
            store = SQLiteStore(store_path)
            store.save_host_snapshot(snapshot)
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                status = client.host_security_findings()

            self.assertEqual(status["snapshot_id"], snapshot.id)
            self.assertEqual(status["finding_count"], 1)
            self.assertEqual(status["findings"][0]["severity"], HostFindingSeverity.HIGH.value)

    def test_client_reads_host_security_triage(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            snapshot = HostInspectionAdapter(
                command_runner=lambda command, timeout_seconds: HostCommandObservation(
                    name=command[0],
                    command=tuple(command),
                    exit_code=0,
                    stdout=(
                        "host-client"
                        if tuple(command) == ("hostname",)
                        else "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"
                        if tuple(command) == ("ss", "-ltnp")
                        else "ok"
                    ),
                ),
                file_reader=lambda path: "ID=debian\n",
            ).inspect("2026-07-18T16:03:00+00:00")
            store = SQLiteStore(store_path)
            store.save_host_snapshot(snapshot)
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                status = client.host_security_triage()

            self.assertEqual(status["snapshot_id"], snapshot.id)
            self.assertEqual(status["group_count"], 1)
            self.assertEqual(status["listener_groups"][0]["port"], "22")

    def test_client_reads_host_security_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            snapshot = HostInspectionAdapter(
                command_runner=lambda command, timeout_seconds: HostCommandObservation(
                    name=command[0],
                    command=tuple(command),
                    exit_code=0,
                    stdout=(
                        "host-client"
                        if tuple(command) == ("hostname",)
                        else "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"
                        if tuple(command) == ("ss", "-ltnp")
                        else "ESTAB 0 0 192.168.1.20:22 8.8.8.8:53122"
                        if tuple(command) == ("ss", "-tnp")
                        else "ok"
                    ),
                ),
                file_reader=lambda path: "ID=debian\n",
            ).inspect("2026-07-18T16:03:00+00:00")
            store = SQLiteStore(store_path)
            store.save_host_snapshot(snapshot)
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                status = client.host_security_sources()

            self.assertEqual(status["snapshot_id"], snapshot.id)
            self.assertEqual(status["connection_count"], 1)
            self.assertEqual(status["connections"][0]["remote_address"], "8.8.8.8")
            self.assertEqual(status["connections"][0]["source_scope"], "external")

    def test_client_creates_host_security_source_review(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            snapshot = HostInspectionAdapter(
                command_runner=lambda command, timeout_seconds: HostCommandObservation(
                    name=command[0],
                    command=tuple(command),
                    exit_code=0,
                    stdout=(
                        "host-client"
                        if tuple(command) == ("hostname",)
                        else "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"
                        if tuple(command) == ("ss", "-ltnp")
                        else "ESTAB 0 0 192.168.1.20:22 8.8.8.8:53122"
                        if tuple(command) == ("ss", "-tnp")
                        else "ok"
                    ),
                ),
                file_reader=lambda path: "ID=debian\n",
            ).inspect("2026-07-18T16:03:00+00:00")
            store = SQLiteStore(store_path)
            store.save_host_snapshot(snapshot)
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                created = client.create_host_security_source_review(
                    {
                        "remote_address": "8.8.8.8",
                        "disposition": SourceReviewDisposition.SUSPICIOUS.value,
                        "reviewed_by": "odo",
                        "rationale": "unexpected remote source",
                    }
                )
                hostile = client.create_host_security_source_review(
                    {
                        "remote_address": "8.8.8.8",
                        "review_id": "source-review.client.hostile",
                        "disposition": SourceReviewDisposition.HOSTILE.value,
                        "reviewed_by": "odo",
                        "rationale": "confirmed malicious source activity",
                    }
                )
                block_plan = client.plan_host_security_source_block({"review_id": hostile["id"]})
                with self.assertRaises(HTTPError):
                    client.approve_admin_change({"plan_id": block_plan["id"], "approved_by": "sisko"})
                ids_package = client.prepare_host_security_ids_review_package(
                    {"plan_id": block_plan["id"], "source_review_id": hostile["id"]}
                )
                with self.assertRaises(HTTPError):
                    client.approve_admin_change({"plan_id": block_plan["id"], "approved_by": "sisko"})
                exported = client.export_host_security_ids_review_prompt({"package_id": ids_package["id"]})
                submitted = client.submit_host_security_ids_review_package(
                    {
                        "package_id": ids_package["id"],
                        "submitted_by": "odo",
                        "prompt_path": exported["prompt_path"],
                    }
                )
                with self.assertRaises(HTTPError):
                    client.approve_admin_change({"plan_id": block_plan["id"], "approved_by": "sisko"})
                advisory_result = client.record_host_security_ids_review_result(
                    {
                        "package_id": ids_package["id"],
                        "status": "accepted",
                        "advisory_result": "approved staged source block package",
                        "reviewed_by": "odo",
                    }
                )
                approved = client.approve_admin_change({"plan_id": block_plan["id"], "approved_by": "sisko"})
                packages = client.host_security_ids_review_packages()
                ids_summary = client.host_security_ids_review_summary()
                reviews = client.host_security_source_reviews()

            self.assertEqual(created["remote_address"], "8.8.8.8")
            self.assertEqual(created["disposition"], SourceReviewDisposition.SUSPICIOUS.value)
            self.assertFalse(created["can_stage_block_plan"])
            self.assertEqual(block_plan["kind"], AdminChangeKind.BLOCK_IP.value)
            self.assertEqual(block_plan["target"], "8.8.8.8")
            self.assertFalse(block_plan["can_execute"])
            self.assertEqual(ids_package["plan_id"], block_plan["id"])
            self.assertIn("Intrusion Detection", ids_package["prompt"])
            self.assertTrue(Path(exported["prompt_path"]).exists())
            self.assertTrue(exported["prompt_path"].endswith(".prompt.md"))
            self.assertEqual(submitted["status"], "submitted")
            self.assertEqual(submitted["prompt_path"], exported["prompt_path"])
            self.assertEqual(advisory_result["status"], "accepted")
            self.assertTrue(advisory_result["satisfies_pre_execution_review_gate"])
            self.assertTrue(approved["approved"])
            self.assertEqual(packages["package_count"], 1)
            self.assertEqual(ids_summary["package_count"], 1)
            self.assertEqual(ids_summary["gate_satisfied"], 1)
            self.assertTrue(ids_summary["packages"][0]["advisory_result_present"])
            self.assertNotIn("prompt", ids_summary["packages"][0])
            self.assertEqual(reviews["review_count"], 2)

    def test_client_plans_host_security_remediation(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            snapshot = HostInspectionAdapter(
                command_runner=lambda command, timeout_seconds: HostCommandObservation(
                    name=command[0],
                    command=tuple(command),
                    exit_code=0,
                    stdout=(
                        "host-client"
                        if tuple(command) == ("hostname",)
                        else "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"
                        if tuple(command) == ("ss", "-ltnp")
                        else "ok"
                    ),
                ),
                file_reader=lambda path: "ID=debian\n",
            ).inspect("2026-07-18T16:03:00+00:00")
            store = SQLiteStore(store_path)
            store.save_host_snapshot(snapshot)
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                status = client.plan_host_security_remediation({"listener": "0.0.0.0:22"})
                pending = client.authorizations_required()

            self.assertEqual(status["kind"], AdminChangeKind.FIREWALL_DENY_TCP.value)
            self.assertEqual(status["target"], "tcp/22")
            self.assertEqual(status["steps"][0]["command"], ["sudo", "ufw", "deny", "22/tcp"])
            self.assertEqual(pending["pending_count"], 1)

    def test_client_reads_health_efficiency(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_health_target(
                HealthTarget(
                    id="health.client",
                    resource_id="svc.client",
                    name="Client Health",
                    probe_type=ProbeType.JSON,
                    target="http://127.0.0.1:8766/health",
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                status = client.health_efficiency()

            self.assertEqual(status["targets"], 1)
            self.assertEqual(status["missing_evidence"], 1)

    def test_client_runs_claim_lifecycle(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="proxy.client",
                    name="Client Proxy",
                    type=ResourceType.VIRTUAL_ASSET,
                    owner_domain=OwnerDomain.DAX,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                requested = client.request_claim(
                    {
                        "claim_id": "claim.client.proxy",
                        "resource_id": "proxy.client",
                        "claim_type": ClaimType.LEASE.value,
                        "owner_thread": "thread-client",
                        "owner_role": OwnerDomain.DAX.value,
                        "intent": "use proxy",
                        "requested_action": "bind proxy",
                        "risk_level": RiskLevel.LOW.value,
                    }
                )
                approved = client.approve_claim(
                    {
                        "approval_id": requested["approval_id"],
                        "decided_by": "sisko",
                    }
                )
                activated = client.activate_claim(
                    {
                        "claim_id": requested["claim"],
                        "approval_id": approved["approval_id"],
                    }
                )
                released = client.release_claim(
                    requested["claim"],
                    released_by="dax",
                    reason="work complete",
                    evidence_ids=("health.proxy.client.ok",),
                )

            self.assertEqual(requested["claim_status"], ClaimStatus.REQUESTED.value)
            self.assertEqual(approved["approval_status"], ApprovalStatus.APPROVED.value)
            self.assertEqual(activated["claim_status"], ClaimStatus.ACTIVE.value)
            self.assertEqual(released["claim_status"], ClaimStatus.RELEASED.value)
            self.assertTrue(released["release_evidence_complete"])
            self.assertEqual(released["audit_event"]["evidence_ids"], ["health.proxy.client.ok"])

    def test_client_reviews_expired_claims(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="gateway.review",
                    name="Review Gateway",
                    type=ResourceType.VIRTUAL_ASSET,
                    owner_domain=OwnerDomain.DAX,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                requested = client.request_claim(
                    {
                        "claim_id": "claim.gateway.review",
                        "resource_id": "gateway.review",
                        "claim_type": ClaimType.LEASE.value,
                        "owner_thread": "thread-a",
                        "owner_role": OwnerDomain.DAX.value,
                        "intent": "use gateway",
                        "requested_action": "bind gateway",
                        "risk_level": RiskLevel.LOW.value,
                        "expires_at": "2026-07-18T20:00:00+00:00",
                    }
                )
                approved = client.approve_claim(
                    {
                        "approval_id": requested["approval_id"],
                        "decided_by": "sisko",
                    }
                )
                client.activate_claim({"claim_id": requested["claim"], "approval_id": approved["approval_id"]})
                review = client.claim_review("2026-07-18T20:30:00+00:00")

            self.assertEqual(review["expired_active_like"], 1)
            self.assertEqual(review["missing_release_condition"], 1)
            self.assertEqual(review["operator_review_required"], 1)
            self.assertEqual(review["items"][0]["next_step"], "operator review required before release, revocation, renewal, or takeover")

    def test_client_creates_admin_change_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                plan = client.plan_admin_change(
                    {
                        "plan_id": "admin.block.source",
                        "kind": AdminChangeKind.BLOCK_IP.value,
                        "target": "192.0.2.10",
                        "reason": "block documented hostile source",
                        "current_state": "allowed",
                    }
                )
                state = client.state()

            self.assertEqual(plan["approval_level"], ApprovalLevel.HUMAN.value)
            self.assertEqual(plan["steps"][0]["command"], ["sudo", "ufw", "deny", "from", "192.0.2.10"])
            self.assertEqual(state["admin_change_plans"][0]["id"], "admin.block.source")

    def test_client_lists_and_approves_admin_change_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                client.plan_admin_change(
                    {
                        "plan_id": "admin.restart.client",
                        "kind": AdminChangeKind.USER_SERVICE_RESTART.value,
                        "target": "overseer-api.service",
                        "reason": "reload approved code",
                        "current_state": "active",
                    }
                )
                pending = client.authorizations_required()
                approved = client.approve_admin_change(
                    {
                        "plan_id": "admin.restart.client",
                        "approved_by": "sisko",
                        "approved_at": "2026-07-18T16:30:00+00:00",
                    }
                )
                after = client.authorizations_required()

            self.assertEqual(pending["pending_count"], 1)
            self.assertEqual(approved["approved_by"], "sisko")
            self.assertTrue(approved["can_execute"])
            self.assertEqual(after["pending_count"], 0)

    def test_client_reads_admin_adapter_capabilities(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                capabilities = client.admin_adapter_capabilities()

            restart = next(item for item in capabilities["items"] if item["kind"] == AdminChangeKind.USER_SERVICE_RESTART.value)
            block = next(item for item in capabilities["items"] if item["kind"] == AdminChangeKind.BLOCK_IP.value)
            self.assertEqual(restart["status"], AdminAdapterStatus.ENABLED.value)
            self.assertEqual(block["status"], AdminAdapterStatus.DISABLED.value)
            self.assertTrue(block["authorization_required_before_enable"])

    def test_client_reads_admin_adapter_enablement_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                plan = client.admin_adapter_enablement_plan(AdminChangeKind.APT_INSTALL.value)

            self.assertEqual(plan["filters"]["kind"], AdminChangeKind.APT_INSTALL.value)
            self.assertEqual(plan["plans"], 1)
            self.assertEqual(plan["approval_required"], 1)
            self.assertEqual(plan["items"][0]["current_status"], AdminAdapterStatus.DISABLED.value)
            self.assertTrue(plan["items"][0]["approval_required_before_enable"])

    def test_client_requests_and_approves_admin_adapter_enablement(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                requested = client.request_admin_adapter_enablement(
                    {
                        "kind": AdminChangeKind.FIREWALL_DENY_TCP.value,
                        "requested_by": "sisko",
                        "requested_at": "2026-07-18T20:10:00+00:00",
                    }
                )
                pending = client.authorizations_required()
                approved = client.approve_admin_adapter_enablement(
                    {
                        "approval_id": requested["approval_id"],
                        "approved_by": "sisko",
                        "approved_at": "2026-07-18T20:15:00+00:00",
                    }
                )
                after = client.authorizations_required()

            self.assertEqual(requested["approval_status"], ApprovalStatus.PENDING.value)
            self.assertEqual(requested["kind"], AdminChangeKind.FIREWALL_DENY_TCP.value)
            self.assertEqual(pending["pending_adapter_enablement_approval_count"], 1)
            self.assertEqual(approved["approval_status"], ApprovalStatus.APPROVED.value)
            self.assertTrue(approved["adapter_enablement_approval"])
            self.assertEqual(after["pending_count"], 0)

    def test_client_approves_admin_history_restore_request(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            completed = plan_admin_change_status(
                store_path,
                "admin.restart.client.completed",
                AdminChangeKind.USER_SERVICE_RESTART.value,
                "overseer-api.service",
                "reload approved code",
                "active",
            )
            approve_admin_change_status(store_path, completed["id"], "sisko")
            store = SQLiteStore(store_path)
            store.save_admin_execution(
                AdminExecutionResult(
                    id="admin.exec.admin.restart.client.completed.completed",
                    plan_id=completed["id"],
                    status=AdminExecutionStatus.COMPLETED,
                    summary="admin change completed and verified",
                    command_results=(),
                )
            )
            store.close()
            archive_admin_history_status(
                store_path,
                "sisko",
                "2026-07-18T22:40:00+00:00",
                plan_id=completed["id"],
            )

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                requested = client.request_admin_history_restore(
                    {
                        "plan_id": completed["id"],
                        "requested_by": "sisko",
                        "requested_at": "2026-07-18T22:41:00+00:00",
                    }
                )
                pending = client.authorizations_required()
                approved = client.approve_admin_history_restore(
                    {
                        "approval_id": requested["approval_id"],
                        "approved_by": "sisko",
                        "approved_at": "2026-07-18T22:42:00+00:00",
                    }
                )
                after = client.authorizations_required()

            self.assertEqual(pending["pending_restore_approval_count"], 1)
            self.assertTrue(approved["restore_approval"])
            self.assertEqual(approved["approval_status"], ApprovalStatus.APPROVED.value)
            self.assertEqual(approved["plan_id"], completed["id"])
            self.assertEqual(after["pending_restore_approval_count"], 0)

    def test_client_cancels_placeholder_admin_change_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                client.plan_admin_change(
                    {
                        "plan_id": "admin.block.placeholder",
                        "kind": AdminChangeKind.BLOCK_IP.value,
                        "target": "192.0.2.10",
                        "reason": "placeholder example",
                        "current_state": "no observed traffic",
                    }
                )
                canceled = client.cancel_admin_change(
                    {
                        "plan_id": "admin.block.placeholder",
                        "canceled_by": "odo",
                        "cancellation_reason": "reserved documentation address; no observed hostile traffic",
                    }
                )
                pending = client.authorizations_required()
                state = client.state()

            self.assertTrue(canceled["canceled"])
            self.assertFalse(canceled["can_execute"])
            self.assertEqual(pending["pending_count"], 0)
            self.assertTrue(state["admin_change_plans"][0]["canceled"])

    def test_client_executes_and_lists_blocked_admin_change_result(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                client.plan_admin_change(
                    {
                        "plan_id": "admin.restart.blocked",
                        "kind": AdminChangeKind.USER_SERVICE_RESTART.value,
                        "target": "overseer-api.service",
                        "reason": "reload approved code",
                        "current_state": "active",
                    }
                )
                executed = client.execute_admin_change({"plan_id": "admin.restart.blocked"})
                executions = client.admin_executions()
                readiness = client.admin_execution_readiness()
                history = client.admin_history_review()
                archive_plan = client.admin_history_archive_plan()
                archives = client.admin_history_archives()
                filtered_archives = client.admin_history_archives("admin.restart.blocked")
                restore_readiness = client.admin_history_restore_readiness()
                filtered_restore_readiness = client.admin_history_restore_readiness("admin.restart.blocked")
                restore_request_error = None
                try:
                    client.request_admin_history_restore(
                        {
                            "plan_id": "admin.restart.blocked",
                            "requested_by": "sisko",
                            "requested_at": "2026-07-18T22:15:30+00:00",
                        }
                    )
                except HTTPError as error:
                    restore_request_error = error
                archive_result = client.archive_admin_history(
                    {
                        "archived_by": "sisko",
                        "archived_at": "2026-07-18T22:15:00+00:00",
                    }
                )
                unarchive_error = None
                try:
                    client.unarchive_admin_history(
                        {
                            "plan_id": "admin.restart.blocked",
                            "restored_by": "sisko",
                            "approval_id": "approval.admin.restore.admin.restart.blocked",
                            "restored_at": "2026-07-18T22:16:00+00:00",
                        }
                    )
                except HTTPError as error:
                    unarchive_error = error
                summary = client.admin_summary()
                state = client.state()

            self.assertEqual(executed["status"], AdminExecutionStatus.BLOCKED.value)
            self.assertEqual(executions["execution_count"], 1)
            self.assertEqual(readiness["items"][0]["readiness_state"], "approval_required")
            self.assertEqual(history["items"][0]["disposition"], "retain_active")
            self.assertEqual(archive_plan["planned_bundles"], 0)
            self.assertEqual(archives["archive_records"], 0)
            self.assertEqual(filtered_archives["filters"]["plan_id"], "admin.restart.blocked")
            self.assertEqual(restore_readiness["archived_plans"], 0)
            self.assertEqual(filtered_restore_readiness["filters"]["plan_id"], "admin.restart.blocked")
            self.assertIsNotNone(restore_request_error)
            self.assertEqual(restore_request_error.code, 400)
            self.assertFalse(archive_result["mutation_performed"])
            self.assertIsNotNone(unarchive_error)
            self.assertEqual(unarchive_error.code, 400)
            self.assertIn("is not archived", unarchive_error.read().decode("utf-8"))
            self.assertEqual(summary["executions_by_status"][AdminExecutionStatus.BLOCKED.value], 1)
            self.assertEqual(executions["executions"][0]["plan_id"], "admin.restart.blocked")
            self.assertEqual(state["audit_events"][0]["event_type"], AuditEventType.BLOCKED.value)
            self.assertEqual(state["audit_events"][0]["subject_id"], "admin.restart.blocked")


class HostInspectionTests(unittest.TestCase):
    def test_alerts_summary_reports_only_alert_audit_events(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_audit_event(
                AuditEvent(
                    id="alert.runtime.warning",
                    event_type=AuditEventType.ALERT,
                    owner_domain=OwnerDomain.JULIAN,
                    subject_id="runtime.heartbeat",
                    summary="runtime heartbeat is stale",
                    risk_level=RiskLevel.MEDIUM,
                    evidence_ids=("2026-07-18T16:00:00+00:00",),
                    occurred_at="2026-07-18T16:00:00+00:00",
                )
            )
            store.save_audit_event(
                AuditEvent(
                    id="alert.host.high",
                    event_type=AuditEventType.ALERT,
                    owner_domain=OwnerDomain.ODO,
                    subject_id="host.inspection",
                    summary="host inspection is missing",
                    risk_level=RiskLevel.HIGH,
                )
            )
            store.save_audit_event(
                AuditEvent(
                    id="audit.claim.allowed",
                    event_type=AuditEventType.ALLOWED,
                    owner_domain=OwnerDomain.DAX,
                    subject_id="claim.gateway",
                    summary="claim allowed",
                    risk_level=RiskLevel.LOW,
                )
            )
            store.close()

            status = alerts_summary_status(store_path)

        self.assertEqual(status["alerts"], 2)
        self.assertEqual(status["by_risk"][RiskLevel.MEDIUM.value], 1)
        self.assertEqual(status["by_risk"][RiskLevel.HIGH.value], 1)
        self.assertEqual(status["by_owner"][OwnerDomain.JULIAN.value], 1)
        self.assertEqual(status["by_owner"][OwnerDomain.ODO.value], 1)
        self.assertEqual([event["id"] for event in status["events"]], ["alert.host.high", "alert.runtime.warning"])

    def test_audit_summary_filters_persisted_audit_events(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_audit_event(
                AuditEvent(
                    id="audit.ids-review.package.prepared",
                    event_type=AuditEventType.REQUESTED,
                    owner_domain=OwnerDomain.ODO,
                    subject_id="ids-review.admin.block.source",
                    summary="IDS review prepared",
                    risk_level=RiskLevel.CRITICAL,
                )
            )
            store.save_audit_event(
                AuditEvent(
                    id="audit.ids-review.package.approved",
                    event_type=AuditEventType.APPROVED,
                    owner_domain=OwnerDomain.ODO,
                    subject_id="ids-review.admin.block.source",
                    summary="IDS review accepted",
                    risk_level=RiskLevel.CRITICAL,
                )
            )
            store.save_audit_event(
                AuditEvent(
                    id="audit.claim.allowed",
                    event_type=AuditEventType.ALLOWED,
                    owner_domain=OwnerDomain.DAX,
                    subject_id="claim.gateway",
                    summary="claim allowed",
                    risk_level=RiskLevel.LOW,
                )
            )
            store.close()

            all_events = audit_summary_status(store_path)
            filtered = audit_summary_status(
                store_path,
                owner=OwnerDomain.ODO.value,
                subject_prefix="ids-review.",
            )

        self.assertEqual(all_events["event_count"], 3)
        self.assertEqual(all_events["by_owner"][OwnerDomain.ODO.value], 2)
        self.assertEqual(filtered["event_count"], 2)
        self.assertEqual(filtered["by_event_type"][AuditEventType.REQUESTED.value], 1)
        self.assertEqual(filtered["by_event_type"][AuditEventType.APPROVED.value], 1)
        self.assertEqual([event["id"] for event in filtered["events"]], ["audit.ids-review.package.approved", "audit.ids-review.package.prepared"])

    def test_freshness_assessment_marks_stale_thresholds(self):
        fresh = assess_freshness(
            "2026-07-18T16:00:00+00:00",
            now="2026-07-18T16:00:30+00:00",
        )
        warning = assess_freshness(
            "2026-07-18T16:00:00+00:00",
            now="2026-07-18T16:02:00+00:00",
        )
        high = assess_freshness(
            "2026-07-18T16:00:00+00:00",
            now="2026-07-18T16:05:00+00:00",
        )
        missing = assess_freshness(None, now="2026-07-18T16:05:00+00:00")

        self.assertEqual(fresh.status, FreshnessStatus.OK)
        self.assertEqual(warning.status, FreshnessStatus.WARNING)
        self.assertEqual(high.status, FreshnessStatus.HIGH)
        self.assertEqual(missing.status, FreshnessStatus.MISSING)

    def test_host_inspection_uses_read_only_observations(self):
        commands = []

        def runner(command, timeout_seconds):
            commands.append(tuple(command))
            stdout = {
                ("hostname",): "workstation\n",
                ("uname", "-a"): "Linux workstation test-kernel\n",
                ("systemctl", "--user", "list-units", "--type=service", "--state=running", "--no-pager"): "overseer.service loaded active running\n",
                ("ss", "-ltnp"): "LISTEN 0 5 127.0.0.1:8766 0.0.0.0:*\n",
                ("ss", "-tnp"): "ESTAB 0 0 127.0.0.1:8766 127.0.0.1:40000\n",
                ("df", "-h", "--output=source,size,used,avail,pcent,target"): "Filesystem Size Used Avail Use% Mounted on\n/dev/root 20G 10G 10G 50% /\n",
            }[tuple(command)]
            return HostCommandObservation(
                name=command[0],
                command=tuple(command),
                exit_code=0,
                stdout=stdout.strip(),
            )

        adapter = HostInspectionAdapter(
            command_runner=runner,
            file_reader=lambda path: 'ID=debian\nPRETTY_NAME="Debian GNU/Linux"\nVERSION_ID="13"\n',
        )

        snapshot = adapter.inspect("2026-07-18T16:00:00+00:00")

        self.assertEqual(snapshot.hostname, "workstation")
        self.assertEqual(snapshot.os_release["ID"], "debian")
        self.assertEqual(snapshot.observation("ss").stdout, "LISTEN 0 5 127.0.0.1:8766 0.0.0.0:*")
        self.assertEqual(snapshot.observation("ss-established").stdout, "ESTAB 0 0 127.0.0.1:8766 127.0.0.1:40000")
        self.assertIn(("df", "-h", "--output=source,size,used,avail,pcent,target"), commands)

    def test_host_snapshot_persists_and_appears_in_state(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            snapshot = HostInspectionAdapter(
                command_runner=lambda command, timeout_seconds: HostCommandObservation(
                    name=command[0],
                    command=tuple(command),
                    exit_code=0,
                    stdout="host-a" if tuple(command) == ("hostname",) else "ok",
                ),
                file_reader=lambda path: "ID=debian\n",
            ).inspect("2026-07-18T16:00:00+00:00")
            store = SQLiteStore(store_path)
            store.save_host_snapshot(snapshot)
            loaded = store.load_host_snapshot(snapshot.id)
            store.close()

            state = list_state_status(store_path)

        self.assertEqual(loaded.hostname, "host-a")
        self.assertEqual(state["host_snapshots"][0]["id"], snapshot.id)
        self.assertEqual(state["host_snapshots"][0]["observation_count"], 5)

    def test_host_security_assessment_flags_non_loopback_listeners(self):
        snapshot = HostInspectionAdapter(
            command_runner=lambda command, timeout_seconds: HostCommandObservation(
                name=command[0],
                command=tuple(command),
                exit_code=0,
                stdout=(
                    "host-a"
                    if tuple(command) == ("hostname",)
                    else "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                    "LISTEN 0 5 127.0.0.1:8766 0.0.0.0:*\n"
                    "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
                    if tuple(command) == ("ss", "-ltnp")
                    else "ok"
                ),
            ),
            file_reader=lambda path: "ID=debian\n",
        ).inspect("2026-07-18T16:00:00+00:00")

        findings = assess_host_security(snapshot)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, HostFindingSeverity.HIGH)
        self.assertIn("0.0.0.0:22", findings[0].summary)

    def test_host_security_status_uses_latest_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            first = HostInspectionAdapter(
                command_runner=lambda command, timeout_seconds: HostCommandObservation(
                    name=command[0],
                    command=tuple(command),
                    exit_code=0,
                    stdout="host-a" if tuple(command) == ("hostname",) else "LISTEN 0 5 127.0.0.1:8766 0.0.0.0:*",
                ),
                file_reader=lambda path: "ID=debian\n",
            ).inspect("2026-07-18T16:00:00+00:00")
            second = HostInspectionAdapter(
                command_runner=lambda command, timeout_seconds: HostCommandObservation(
                    name=command[0],
                    command=tuple(command),
                    exit_code=0,
                    stdout="host-b" if tuple(command) == ("hostname",) else "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*",
                ),
                file_reader=lambda path: "ID=debian\n",
            ).inspect("2026-07-18T16:01:00+00:00")
            store.save_host_snapshot(first)
            store.save_host_snapshot(second)
            store.close()

            status = assess_host_security_status(store_path)

        self.assertEqual(status["snapshot_id"], second.id)
        self.assertEqual(status["high_findings"], 1)

    def test_host_security_findings_lists_details_and_filters_severity(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            snapshot = HostInspectionAdapter(
                command_runner=lambda command, timeout_seconds: HostCommandObservation(
                    name=command[0],
                    command=tuple(command),
                    exit_code=0,
                    stdout=(
                        "host-c"
                        if tuple(command) == ("hostname",)
                        else "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                        "LISTEN 0 5 192.168.1.20:8080 0.0.0.0:*\n"
                        "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
                        if tuple(command) == ("ss", "-ltnp")
                        else "ok"
                    ),
                ),
                file_reader=lambda path: "ID=debian\n",
            ).inspect("2026-07-18T16:02:00+00:00")
            store = SQLiteStore(store_path)
            store.save_host_snapshot(snapshot)
            store.close()

            status = host_security_findings_status(store_path)
            high = host_security_findings_status(store_path, severity=HostFindingSeverity.HIGH.value)

        self.assertEqual(status["snapshot_id"], snapshot.id)
        self.assertEqual(status["finding_count"], 2)
        self.assertEqual(status["by_severity"][HostFindingSeverity.HIGH.value], 1)
        self.assertEqual(status["by_severity"][HostFindingSeverity.WARNING.value], 1)
        self.assertEqual(high["severity_filter"], HostFindingSeverity.HIGH.value)
        self.assertEqual(high["finding_count"], 1)
        self.assertIn("0.0.0.0:22", high["findings"][0]["summary"])
        self.assertIn("recommended_action", high["findings"][0])

    def test_host_security_triage_groups_findings_by_listener_and_approval_path(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            snapshot = HostInspectionAdapter(
                command_runner=lambda command, timeout_seconds: HostCommandObservation(
                    name=command[0],
                    command=tuple(command),
                    exit_code=0,
                    stdout=(
                        "host-d"
                        if tuple(command) == ("hostname",)
                        else "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                        "LISTEN 0 5 127.0.0.1:8766 0.0.0.0:*\n"
                        "LISTEN 0 5 192.168.1.20:8080 0.0.0.0:*\n"
                        "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
                        if tuple(command) == ("ss", "-ltnp")
                        else "ok"
                    ),
                ),
                file_reader=lambda path: "ID=debian\n",
            ).inspect("2026-07-18T16:04:00+00:00")
            store = SQLiteStore(store_path)
            store.save_host_snapshot(snapshot)
            store.close()

            status = host_security_triage_status(store_path)

        self.assertEqual(status["snapshot_id"], snapshot.id)
        self.assertEqual(status["finding_count"], 2)
        self.assertEqual(status["group_count"], 2)
        self.assertIn("Intrusion Detection review", status["approval_boundary"])
        high_group = next(group for group in status["listener_groups"] if group["local"] == "0.0.0.0:22")
        warning_group = next(group for group in status["listener_groups"] if group["local"] == "192.168.1.20:8080")
        self.assertEqual(high_group["address"], "0.0.0.0")
        self.assertEqual(high_group["port"], "22")
        self.assertEqual(high_group["bind_scope"], "all_interfaces")
        self.assertEqual(high_group["severity"], HostFindingSeverity.HIGH.value)
        self.assertTrue(high_group["requires_approval"])
        self.assertIn("approval-gated", high_group["recommended_mitigation_path"])
        self.assertEqual(warning_group["bind_scope"], "non_loopback_specific")
        self.assertIn("confirm expected clients", warning_group["recommended_mitigation_path"])

    def test_host_security_sources_correlates_remote_addresses_to_listeners(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            snapshot = HostInspectionAdapter(
                command_runner=lambda command, timeout_seconds: HostCommandObservation(
                    name=command[0],
                    command=tuple(command),
                    exit_code=0,
                    stdout=(
                        "host-sources"
                        if tuple(command) == ("hostname",)
                        else "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                        "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
                        if tuple(command) == ("ss", "-ltnp")
                        else "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                        "ESTAB 0 0 192.168.1.20:22 8.8.8.8:53122\n"
                        "ESTAB 0 0 192.168.1.20:22 192.0.2.10:54000\n"
                        "ESTAB 0 0 127.0.0.1:8766 127.0.0.1:42000\n"
                        if tuple(command) == ("ss", "-tnp")
                        else "ok"
                    ),
                ),
                file_reader=lambda path: "ID=debian\n",
            ).inspect("2026-07-18T16:06:00+00:00")
            store = SQLiteStore(store_path)
            store.save_host_snapshot(snapshot)
            store.close()

            status = host_security_sources_status(store_path)

        self.assertEqual(status["snapshot_id"], snapshot.id)
        self.assertEqual(status["connection_count"], 2)
        self.assertEqual(status["by_source_scope"]["external"], 1)
        self.assertEqual(status["by_source_scope"]["documentation"], 1)
        connection = next(item for item in status["connections"] if item["remote_address"] == "8.8.8.8")
        documentation_connection = next(item for item in status["connections"] if item["remote_address"] == "192.0.2.10")
        self.assertEqual(connection["listener"], "0.0.0.0:22")
        self.assertEqual(connection["local_port"], "22")
        self.assertEqual(connection["remote"], "8.8.8.8:53122")
        self.assertEqual(connection["source_scope"], "external")
        self.assertTrue(connection["can_stage_block_plan"])
        self.assertEqual(documentation_connection["source_scope"], "documentation")
        self.assertFalse(documentation_connection["can_stage_block_plan"])
        self.assertIn("read-only source correlation", status["correlation_boundary"])

    def test_host_security_source_review_requires_review_before_block_plan_readiness(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            snapshot = HostInspectionAdapter(
                command_runner=lambda command, timeout_seconds: HostCommandObservation(
                    name=command[0],
                    command=tuple(command),
                    exit_code=0,
                    stdout=(
                        "host-review"
                        if tuple(command) == ("hostname",)
                        else "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                        "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
                        if tuple(command) == ("ss", "-ltnp")
                        else "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                        "ESTAB 0 0 192.168.1.20:22 8.8.8.8:53122\n"
                        if tuple(command) == ("ss", "-tnp")
                        else "ok"
                    ),
                ),
                file_reader=lambda path: "ID=debian\n",
            ).inspect("2026-07-18T16:07:00+00:00")
            store = SQLiteStore(store_path)
            store.save_host_snapshot(snapshot)
            store.close()

            pending = create_host_security_source_review_status(store_path, "8.8.8.8")
            hostile = create_host_security_source_review_status(
                store_path,
                "8.8.8.8",
                review_id="source-review.hostile.8-8-8-8",
                disposition=SourceReviewDisposition.HOSTILE.value,
                rationale="confirmed malicious login attempts in external evidence",
                reviewed_by="odo",
                reviewed_at="2026-07-18T16:08:00+00:00",
            )
            reviews = host_security_source_reviews_status(store_path)
            block_plan = plan_host_security_source_block_status(store_path, hostile["id"])
            state = list_state_status(store_path)
            loaded = SQLiteStore(store_path)
            plan = loaded.load_admin_change_plan("admin.host-security.block-source.8-8-8-8")
            loaded.close()
            with self.assertRaises(ValueError):
                plan_host_security_source_block_status(store_path, pending["id"], plan_id="admin.block.pending")
            auth_missing_package = authorizations_required_status(store_path)
            with self.assertRaises(ValueError):
                approve_admin_change_status(store_path, block_plan["id"], "sisko")
            ids_package = prepare_host_security_ids_review_package_status(
                store_path,
                block_plan["id"],
                source_review_id=hostile["id"],
                requested_by="odo",
                created_at="2026-07-18T16:09:00+00:00",
            )
            auth_prepared_package = authorizations_required_status(store_path)
            with self.assertRaises(ValueError):
                approve_admin_change_status(store_path, block_plan["id"], "sisko")
            exported = export_host_security_ids_review_prompt_status(
                store_path,
                ids_package["id"],
                "advisories",
                "source-block.prompt.md",
            )
            exported_prompt_exists = Path(exported["prompt_path"]).exists()
            exported_prompt_text = Path(exported["prompt_path"]).read_text(encoding="utf-8").strip()
            with self.assertRaises(ValueError):
                export_host_security_ids_review_prompt_status(store_path, ids_package["id"], "../outside")
            auth_exported_prompt = authorizations_required_status(store_path)
            submitted = submit_host_security_ids_review_package_status(
                store_path,
                ids_package["id"],
                "odo",
                submitted_at="2026-07-18T16:10:00+00:00",
                prompt_path=exported["prompt_path"],
            )
            auth_submitted_package = authorizations_required_status(store_path)
            with self.assertRaises(ValueError):
                approve_admin_change_status(store_path, block_plan["id"], "sisko")
            advisory_result = record_host_security_ids_review_result_status(
                store_path,
                ids_package["id"],
                "accepted",
                "approved staged source block package",
                "odo",
                reviewed_at="2026-07-18T16:11:00+00:00",
            )
            auth_advisory_accepted = authorizations_required_status(store_path)
            ids_packages = host_security_ids_review_packages_status(store_path)
            ids_review_summary = host_security_ids_review_summary_status(store_path)
            approved = approve_admin_change_status(store_path, block_plan["id"], "sisko")
            auth_after_approval = authorizations_required_status(store_path)
            gated_state = list_state_status(store_path)
            ids_review_audit_events = [
                event
                for event in gated_state["audit_events"]
                if event["subject_id"] == ids_package["id"]
            ]

        self.assertEqual(pending["disposition"], SourceReviewDisposition.NEEDS_REVIEW.value)
        self.assertFalse(pending["can_stage_block_plan"])
        self.assertEqual(hostile["disposition"], SourceReviewDisposition.HOSTILE.value)
        self.assertTrue(hostile["can_stage_block_plan"])
        self.assertEqual(block_plan["kind"], AdminChangeKind.BLOCK_IP.value)
        self.assertEqual(block_plan["source_review"]["id"], hostile["id"])
        self.assertEqual(block_plan["approval_level"], ApprovalLevel.HUMAN.value)
        self.assertFalse(block_plan["can_execute"])
        self.assertTrue(block_plan["ids_review_required_before_execution"])
        self.assertEqual(auth_missing_package["pending"][0]["ids_review_next_step"], "prepare IDS/firewall review package before requesting approval")
        self.assertFalse(auth_missing_package["pending"][0]["authorization_required"])
        self.assertEqual(auth_prepared_package["pending"][0]["ids_review_next_step"], "export IDS/firewall review prompt and submit package before approval")
        self.assertEqual(auth_exported_prompt["pending"][0]["ids_review_next_step"], "submit IDS/firewall review package with exported prompt before approval")
        self.assertEqual(auth_submitted_package["pending"][0]["ids_review_next_step"], "await Intrusion Detection advisory result before approval")
        self.assertEqual(auth_advisory_accepted["pending"][0]["ids_review_next_step"], "IDS/firewall advisory accepted; human approval may proceed")
        self.assertTrue(auth_advisory_accepted["pending"][0]["authorization_required"])
        self.assertEqual(auth_after_approval["pending_count"], 0)
        self.assertEqual(plan.target, "8.8.8.8")
        self.assertEqual(ids_package["plan_id"], block_plan["id"])
        self.assertEqual(ids_package["source_review_id"], hostile["id"])
        self.assertEqual(ids_package["status"], "prepared")
        self.assertIn("codex-advisor.sh", ids_package["advisory_command"][0])
        self.assertIn("custom firewall or IDS rules", ids_package["prompt"])
        self.assertFalse(ids_package["satisfies_pre_execution_review_gate"])
        self.assertTrue(exported_prompt_exists)
        self.assertEqual(exported_prompt_text, ids_package["prompt"])
        self.assertEqual(submitted["status"], "submitted")
        self.assertEqual(submitted["prompt_path"], exported["prompt_path"])
        self.assertFalse(submitted["satisfies_pre_execution_review_gate"])
        self.assertEqual(advisory_result["status"], "accepted")
        self.assertEqual(advisory_result["reviewed_by"], "odo")
        self.assertTrue(advisory_result["satisfies_pre_execution_review_gate"])
        self.assertEqual(ids_packages["package_count"], 1)
        self.assertEqual(ids_review_summary["package_count"], 1)
        self.assertEqual(ids_review_summary["by_status"][IDSReviewPackageStatus.ACCEPTED.value], 1)
        self.assertEqual(ids_review_summary["gate_satisfied"], 1)
        self.assertEqual(ids_review_summary["gate_blocked"], 0)
        self.assertEqual(ids_review_summary["submitted_without_result"], 0)
        self.assertEqual(ids_review_summary["packages"][0]["next_step"], "IDS/firewall advisory accepted; human approval may proceed")
        self.assertTrue(ids_review_summary["packages"][0]["advisory_result_present"])
        self.assertNotIn("prompt", ids_review_summary["packages"][0])
        self.assertEqual(ids_review_summary["latest_audit_events"][0]["owner_domain"], OwnerDomain.ODO.value)
        self.assertTrue(approved["approved"])
        self.assertEqual(reviews["review_count"], 2)
        self.assertEqual(reviews["ready_for_block_plan"], 1)
        self.assertEqual(reviews["by_disposition"][SourceReviewDisposition.HOSTILE.value], 1)
        self.assertEqual(len(state["host_security_source_reviews"]), 2)
        self.assertEqual(len(gated_state["host_security_ids_review_packages"]), 1)
        self.assertEqual(
            {event["event_type"] for event in ids_review_audit_events},
            {AuditEventType.REQUESTED.value, AuditEventType.VERIFIED.value, AuditEventType.APPROVED.value},
        )
        self.assertEqual(len(ids_review_audit_events), 4)

    def test_host_security_remediation_stages_deny_plan_without_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            snapshot = HostInspectionAdapter(
                command_runner=lambda command, timeout_seconds: HostCommandObservation(
                    name=command[0],
                    command=tuple(command),
                    exit_code=0,
                    stdout=(
                        "host-e"
                        if tuple(command) == ("hostname",)
                        else "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"
                        if tuple(command) == ("ss", "-ltnp")
                        else "ok"
                    ),
                ),
                file_reader=lambda path: "ID=debian\n",
            ).inspect("2026-07-18T16:05:00+00:00")
            store = SQLiteStore(store_path)
            store.save_host_snapshot(snapshot)
            store.close()

            status = plan_host_security_remediation_status(store_path, "0.0.0.0:22")
            loaded = SQLiteStore(store_path)
            plan = loaded.load_admin_change_plan("admin.host-security.deny-tcp.22")
            loaded.close()

        self.assertEqual(status["remediation_action"], "deny_tcp")
        self.assertEqual(status["listener"]["bind_scope"], "all_interfaces")
        self.assertEqual(status["kind"], AdminChangeKind.FIREWALL_DENY_TCP.value)
        self.assertEqual(status["approval_level"], ApprovalLevel.HUMAN.value)
        self.assertFalse(status["can_execute"])
        self.assertEqual(plan.target, "tcp/22")

    def test_runtime_status_reports_latest_host_security_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_runtime_heartbeat(
                RuntimeHeartbeat(
                    id="overseer",
                    service_name="overseer",
                    started_at="2026-07-18T16:00:00+00:00",
                    last_tick_at="2026-07-18T16:01:00+00:00",
                    tick_count=2,
                )
            )
            snapshot = HostInspectionAdapter(
                command_runner=lambda command, timeout_seconds: HostCommandObservation(
                    name=command[0],
                    command=tuple(command),
                    exit_code=0,
                    stdout=(
                        "host-b"
                        if tuple(command) == ("hostname",)
                        else "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"
                        if tuple(command) == ("ss", "-ltnp")
                        else "ok"
                    ),
                ),
                file_reader=lambda path: "ID=debian\n",
            ).inspect("2026-07-18T16:01:30+00:00")
            store.save_host_snapshot(snapshot)
            store.close()

            status = runtime_status(store_path, now="2026-07-18T16:01:45+00:00")

        self.assertEqual(status["service"]["tick_count"], 2)
        self.assertEqual(status["service"]["freshness"]["status"], FreshnessStatus.OK.value)
        self.assertEqual(status["service"]["freshness"]["age_seconds"], 45)
        self.assertTrue(status["host_inspection"]["enabled"])
        self.assertEqual(status["host_inspection"]["latest_snapshot_id"], snapshot.id)
        self.assertEqual(status["host_inspection"]["latest_captured_at"], "2026-07-18T16:01:30+00:00")
        self.assertEqual(status["host_inspection"]["freshness"]["status"], FreshnessStatus.OK.value)
        self.assertEqual(status["host_inspection"]["freshness"]["age_seconds"], 15)
        self.assertEqual(status["host_inspection"]["high_findings"], 1)
        self.assertEqual(status["host_inspection"]["warning_findings"], 0)
        self.assertEqual(status["freshness_alerts"], [])

    def test_runtime_status_handles_missing_host_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_runtime_heartbeat(
                RuntimeHeartbeat(
                    id="overseer",
                    service_name="overseer",
                    started_at="2026-07-18T16:00:00+00:00",
                    last_tick_at="2026-07-18T16:01:00+00:00",
                    tick_count=1,
                )
            )
            store.close()

            status = runtime_status(store_path, now="2026-07-18T16:06:30+00:00")
            store = SQLiteStore(store_path)
            audit_events = store.list_audit_events()
            store.close()

        self.assertEqual(status["service"]["freshness"]["status"], FreshnessStatus.HIGH.value)
        self.assertFalse(status["host_inspection"]["enabled"])
        self.assertEqual(status["host_inspection"]["freshness"]["status"], FreshnessStatus.MISSING.value)
        self.assertIsNone(status["host_inspection"]["latest_snapshot_id"])
        self.assertEqual(status["host_inspection"]["high_findings"], 0)
        self.assertEqual(len(status["freshness_alerts"]), 2)
        self.assertEqual({event.event_type for event in audit_events}, {AuditEventType.ALERT})
        self.assertEqual({event.subject_id for event in audit_events}, {"runtime.heartbeat", "host.inspection"})
        self.assertEqual({event.risk_level for event in audit_events}, {RiskLevel.HIGH})

    def test_runtime_status_persists_warning_freshness_alert(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_runtime_heartbeat(
                RuntimeHeartbeat(
                    id="overseer",
                    service_name="overseer",
                    started_at="2026-07-18T16:00:00+00:00",
                    last_tick_at="2026-07-18T16:01:00+00:00",
                    tick_count=2,
                )
            )
            snapshot = HostInspectionAdapter(
                command_runner=lambda command, timeout_seconds: HostCommandObservation(
                    name=command[0],
                    command=tuple(command),
                    exit_code=0,
                    stdout="host-b" if tuple(command) == ("hostname",) else "ok",
                ),
                file_reader=lambda path: "ID=debian\n",
            ).inspect("2026-07-18T16:01:30+00:00")
            store.save_host_snapshot(snapshot)
            store.close()

            status = runtime_status(store_path, now="2026-07-18T16:03:00+00:00")
            store = SQLiteStore(store_path)
            audit_events = store.list_audit_events()
            store.close()

        self.assertEqual(status["service"]["freshness"]["status"], FreshnessStatus.WARNING.value)
        self.assertEqual(status["host_inspection"]["freshness"]["status"], FreshnessStatus.OK.value)
        self.assertEqual(len(status["freshness_alerts"]), 1)
        self.assertEqual(audit_events[0].event_type, AuditEventType.ALERT)
        self.assertEqual(audit_events[0].subject_id, "runtime.heartbeat")
        self.assertEqual(audit_events[0].risk_level, RiskLevel.MEDIUM)


class AdminChangePlanTests(unittest.TestCase):
    def test_package_install_plan_requires_human_approval_and_rollback(self):
        plan = plan_apt_install(
            "admin.install.nmap",
            ("nmap",),
            "enable approved local security auditing",
            "package absent",
        )

        self.assertEqual(plan.kind, AdminChangeKind.APT_INSTALL)
        self.assertEqual(plan.approval_level, ApprovalLevel.HUMAN)
        self.assertTrue(plan.requires_explicit_approval())
        self.assertFalse(plan.can_execute())
        self.assertEqual(plan.steps[0].command, ("sudo", "apt-get", "install", "--dry-run", "nmap"))
        self.assertEqual(plan.steps[1].command, ("sudo", "apt-get", "install", "-y", "nmap"))
        self.assertEqual(plan.rollback_steps[0].command, ("sudo", "apt-get", "remove", "-y", "nmap"))

    def test_firewall_plan_has_critical_risk_and_delete_rollback(self):
        plan = plan_firewall_allow_tcp(
            "admin.firewall.8443",
            8443,
            "publish approved local service",
            "closed",
        )

        self.assertEqual(plan.risk_level, RiskLevel.CRITICAL)
        self.assertEqual(plan.approval_level, ApprovalLevel.HUMAN)
        self.assertEqual(plan.steps[0].command, ("sudo", "ufw", "allow", "8443/tcp"))
        self.assertEqual(plan.rollback_steps[0].command, ("sudo", "ufw", "delete", "allow", "8443/tcp"))

    def test_firewall_deny_plan_has_critical_risk_and_delete_rollback(self):
        plan = plan_firewall_deny_tcp(
            "admin.firewall.deny.22",
            22,
            "close exposed ssh listener",
            "open",
        )

        self.assertEqual(plan.kind, AdminChangeKind.FIREWALL_DENY_TCP)
        self.assertEqual(plan.risk_level, RiskLevel.CRITICAL)
        self.assertEqual(plan.approval_level, ApprovalLevel.HUMAN)
        self.assertEqual(plan.steps[0].command, ("sudo", "ufw", "deny", "22/tcp"))
        self.assertEqual(plan.rollback_steps[0].command, ("sudo", "ufw", "delete", "deny", "22/tcp"))

    def test_admin_change_plan_persists_without_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            status = plan_admin_change_status(
                store_path,
                "admin.restart.overseer-api",
                AdminChangeKind.USER_SERVICE_RESTART.value,
                "overseer-api.service",
                "reload updated code",
                "active",
            )
            store = SQLiteStore(store_path)
            loaded = store.load_admin_change_plan("admin.restart.overseer-api")
            store.close()
            state = list_state_status(store_path)

        self.assertEqual(status["approval_level"], ApprovalLevel.SISKO.value)
        self.assertEqual(status["steps"][0]["command"], ["systemctl", "--user", "restart", "overseer-api.service"])
        self.assertFalse(status["can_execute"])
        self.assertEqual(loaded.target, "overseer-api.service")
        self.assertEqual(state["admin_change_plans"][0]["id"], "admin.restart.overseer-api")

    def test_authorizations_required_lists_unapproved_plans(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            plan_admin_change_status(
                store_path,
                "admin.restart.pending",
                AdminChangeKind.USER_SERVICE_RESTART.value,
                "overseer-api.service",
                "reload approved code",
                "active",
            )

            pending = authorizations_required_status(store_path)
            approved = approve_admin_change_status(
                store_path,
                "admin.restart.pending",
                "sisko",
                "2026-07-18T16:30:00+00:00",
            )
            after = authorizations_required_status(store_path)

        self.assertEqual(pending["pending_count"], 1)
        self.assertEqual(pending["pending"][0]["next_step"], "Sisko approval required for exact command list, risks, rollback, and verification")
        self.assertTrue(approved["approved"])
        self.assertEqual(approved["approved_by"], "sisko")
        self.assertEqual(after["pending_count"], 0)

    def test_cancel_admin_change_removes_plan_from_authorization_queue(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            plan_admin_change_status(
                store_path,
                "admin.block.placeholder",
                AdminChangeKind.BLOCK_IP.value,
                "192.0.2.10",
                "placeholder example",
                "no observed traffic",
            )

            pending = authorizations_required_status(store_path)
            canceled = cancel_admin_change_status(
                store_path,
                "admin.block.placeholder",
                "odo",
                "reserved documentation address; no observed hostile traffic",
            )
            after = authorizations_required_status(store_path)
            state = list_state_status(store_path)

        self.assertEqual(pending["pending_count"], 1)
        self.assertTrue(canceled["canceled"])
        self.assertEqual(canceled["cancellation_reason"], "reserved documentation address; no observed hostile traffic")
        self.assertEqual(after["pending_count"], 0)
        self.assertTrue(state["admin_change_plans"][0]["canceled"])

    def test_approved_user_service_restart_executes_and_persists_result(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            plan_admin_change_status(
                store_path,
                "admin.restart.exec",
                AdminChangeKind.USER_SERVICE_RESTART.value,
                "overseer-api.service",
                "reload approved code",
                "active",
            )
            approve_admin_change_status(
                store_path,
                "admin.restart.exec",
                "sisko",
                "2026-07-18T16:45:00+00:00",
            )
            store = SQLiteStore(store_path)
            plan = store.load_admin_change_plan("admin.restart.exec")
            result = execute_admin_change_plan(
                plan,
                runner=lambda step: AdminCommandResult(
                    title=step.title,
                    command=step.command,
                    exit_code=0,
                    stdout="ok",
                ),
            )
            store.save_admin_execution(result)
            store.save_audit_event(audit_event_from_admin_execution(plan, result))
            loaded = store.load_admin_execution(result.id)
            store.close()
            state = list_state_status(store_path)

        self.assertEqual(result.status, AdminExecutionStatus.COMPLETED)
        self.assertEqual(loaded.plan_id, "admin.restart.exec")
        self.assertEqual(state["audit_events"][0]["event_type"], AuditEventType.EXECUTED.value)
        self.assertEqual(state["audit_events"][0]["evidence_ids"], [result.id])
        self.assertEqual(state["admin_executions"][0]["status"], AdminExecutionStatus.COMPLETED.value)

    def test_unapproved_admin_change_execution_is_blocked(self):
        plan = plan_user_service_restart(
            "admin.restart.blocked",
            "overseer-api.service",
            "reload approved code",
            "active",
        )

        result = execute_admin_change_plan(plan)

        self.assertEqual(result.status, AdminExecutionStatus.BLOCKED)
        self.assertEqual(result.command_results, ())

    def test_non_restart_admin_change_execution_is_blocked(self):
        plan = approve_admin_change_plan(
            plan_apt_install("admin.install.blocked", ("nmap",), "enable approved audit"),
            "operator",
        )

        result = execute_admin_change_plan(plan)
        capability = admin_execution_capability_for(plan.kind)

        self.assertEqual(result.status, AdminExecutionStatus.BLOCKED)
        self.assertEqual(capability.status, AdminAdapterStatus.DISABLED)
        self.assertIn("live adapter unavailable for apt_install", result.summary)


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

    def test_discover_physical_status_persists_to_explicit_store(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "devices"
            root.mkdir()
            store_path = Path(directory) / "overseer.sqlite3"
            (root / "usb-Serial_Device-if00-port0").touch()

            status = discover_physical_status((str(root),), store_path=store_path)
            store = SQLiteStore(store_path)

            self.assertEqual(status["store"], str(store_path))
            self.assertEqual(len(store.list_physical_identities()), 1)
            self.assertEqual(
                store.load_physical_identity("serial.usb-serial-device-if00-port0").kind,
                PhysicalAssetKind.SERIAL_PORT,
            )
            store.close()


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
                "health_targets": [
                    {
                        "id": "health.config",
                        "resource_id": "svc.config",
                        "name": "Configured Service Health",
                        "probe_type": "json",
                        "target": "http://127.0.0.1:8794/health",
                        "expected_content_type": "application/json",
                    }
                ],
            }
        )

        self.assertIsInstance(config, OverseerConfig)
        self.assertEqual(config.resources[0].owner_domain, OwnerDomain.DAX)
        self.assertEqual(config.resources[0].ports(), frozenset({8795}))
        self.assertEqual(config.usage_limits[0].remaining, 50)
        self.assertEqual(config.health_targets[0].probe_type, ProbeType.JSON)

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

    def test_rejects_health_target_for_unknown_resource(self):
        with self.assertRaises(ValueError):
            config_from_mapping(
                {
                    "health_targets": [
                        {
                            "id": "health.unknown",
                            "resource_id": "svc.missing",
                            "name": "Missing Service Health",
                            "probe_type": "json",
                            "target": "http://127.0.0.1:8794/health",
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
                    "health_targets": [
                        {
                            "id": "health.seeded",
                            "resource_id": "svc.seeded",
                            "name": "Seeded Health",
                            "probe_type": "json",
                            "target": "http://127.0.0.1:8794/health",
                        }
                    ],
                }
            )

            result = seed_store_from_config(config, store)

            self.assertEqual(result.resource_count, 1)
            self.assertEqual(result.usage_limit_count, 1)
            self.assertEqual(result.health_target_count, 1)
            self.assertEqual(store.load_resource("svc.seeded").owner_domain, OwnerDomain.JULIAN)
            self.assertEqual(store.load_usage_limit("limit.seeded").remaining, 10)
            self.assertEqual(store.load_health_target("health.seeded").resource_id, "svc.seeded")
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
                        "health_targets": [
                            {
                                "id": "health.runtime",
                                "resource_id": "svc.runtime",
                                "name": "Runtime Health",
                                "probe_type": "json",
                                "target": "http://127.0.0.1:8794/health",
                            }
                        ],
                    }
                ),
                store,
            )

            tick = OverseerRuntime(store).run(once=True)

            self.assertEqual(tick.resources, 1)
            self.assertEqual(tick.usage_limits, 1)
            self.assertEqual(tick.health_targets, 1)
            self.assertEqual(tick.health_evidence, 0)
            self.assertEqual(tick.runtime_heartbeats, 1)
            self.assertEqual(tick.health_probes, 0)
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
            self.assertEqual(status["health_targets"], 0)
            self.assertEqual(status["health_evidence"], 0)
            self.assertEqual(status["physical_identities"], 0)
            self.assertEqual(status["runtime_heartbeats"], 1)
            self.assertEqual(status["health_probes"], 0)
            self.assertEqual(status["host_inspections"], 0)

    def test_persistence_security_status_reports_owner_only_store(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            SQLiteStore(store_path).close()
            store_path.chmod(0o600)

            status = persistence_security_status(store_path)

        self.assertFalse(status["mutation_performed"])
        self.assertEqual(status["status"], "ok")
        self.assertEqual(status["recommended_mode"], "0600")
        self.assertEqual(status["warning_count"], 0)
        self.assertEqual(status["items"][0]["octal_mode"], "0o600")

    def test_persistence_security_status_flags_group_or_other_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            SQLiteStore(store_path).close()
            store_path.chmod(0o644)

            status = persistence_security_status(store_path)

        self.assertEqual(status["status"], "warning")
        self.assertEqual(status["warning_count"], 1)
        self.assertTrue(status["items"][0]["group_or_other_permissions"])
        self.assertIn("group or other users have file permissions", status["items"][0]["risks"])

    def test_persistence_security_status_does_not_create_missing_store(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "missing.sqlite3"

            status = persistence_security_status(store_path)

            self.assertFalse(store_path.exists())

        self.assertEqual(status["status"], "missing")
        self.assertFalse(status["database_exists"])

    def test_runtime_can_probe_configured_health_targets_when_enabled(self):
        with tempfile.TemporaryDirectory() as directory, LocalHttpServer() as server:
            store = SQLiteStore(Path(directory) / "overseer.sqlite3")
            seed_store_from_config(
                config_from_mapping(
                    {
                        "resources": [
                            {
                                "id": "svc.runtime.probe",
                                "name": "Runtime Probe Service",
                                "type": "service",
                                "owner_domain": "julian",
                                "risk_level": "low",
                            }
                        ],
                        "health_targets": [
                            {
                                "id": "health.runtime.probe",
                                "resource_id": "svc.runtime.probe",
                                "name": "Runtime Probe Health",
                                "probe_type": "json",
                                "target": server.url,
                                "expected_content_type": "application/json",
                            }
                        ],
                    }
                ),
                store,
            )

            tick = OverseerRuntime(store, probe_health_targets=True).run(once=True)

            self.assertEqual(tick.health_probes, 1)
            self.assertEqual(tick.health_evidence, 1)
            self.assertEqual(store.list_health_evidence()[0].observed_status, HealthStatus.HEALTHY)
            store.close()

    def test_runtime_can_capture_host_inspection_when_enabled(self):
        class FakeHostInspectionAdapter:
            def inspect(self):
                return HostInspectionAdapter(
                    command_runner=lambda command, timeout_seconds: HostCommandObservation(
                        name=command[0],
                        command=tuple(command),
                        exit_code=0,
                        stdout=(
                            "host-runtime"
                            if tuple(command) == ("hostname",)
                            else "LISTEN 0 5 127.0.0.1:8766 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:22 0.0.0.0:*"
                            if tuple(command) == ("ss", "-ltnp")
                            else "ok"
                        ),
                    ),
                    file_reader=lambda path: "ID=debian\n",
                ).inspect("2026-07-18T17:00:00+00:00")

        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteStore(Path(directory) / "overseer.sqlite3")

            tick = OverseerRuntime(
                store,
                inspect_host=True,
                host_inspection_adapter=FakeHostInspectionAdapter(),
            ).run(once=True)

            self.assertEqual(tick.host_inspections, 1)
            self.assertEqual(tick.host_security_high_findings, 1)
            self.assertEqual(tick.host_security_warning_findings, 0)
            self.assertEqual(store.list_host_snapshots()[0].hostname, "host-runtime")
            store.close()

    def test_runtime_prunes_health_evidence_per_target(self):
        with tempfile.TemporaryDirectory() as directory, LocalHttpServer() as server:
            store = SQLiteStore(Path(directory) / "overseer.sqlite3")
            seed_store_from_config(
                config_from_mapping(
                    {
                        "resources": [
                            {
                                "id": "svc.runtime.prune",
                                "name": "Runtime Prune Service",
                                "type": "service",
                                "owner_domain": "julian",
                                "risk_level": "low",
                            }
                        ],
                        "health_targets": [
                            {
                                "id": "health.runtime.prune",
                                "resource_id": "svc.runtime.prune",
                                "name": "Runtime Prune Health",
                                "probe_type": "json",
                                "target": server.url,
                                "expected_content_type": "application/json",
                            }
                        ],
                    }
                ),
                store,
            )
            runtime = OverseerRuntime(
                store,
                probe_health_targets=True,
                health_evidence_retention_per_target=2,
            )

            runtime.tick()
            runtime.tick()
            runtime.tick()

            self.assertEqual(len(store.list_health_evidence()), 2)
            store.close()

    def test_runtime_tick_persists_service_heartbeat(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)

            tick = OverseerRuntime(store, service_name="test-overseer").run(once=True)
            heartbeat = store.load_runtime_heartbeat("test-overseer")

            self.assertEqual(tick.runtime_heartbeats, 1)
            self.assertEqual(heartbeat.service_name, "test-overseer")
            self.assertEqual(heartbeat.tick_count, 1)
            store.close()

    def test_service_status_reads_stored_heartbeat(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_runtime_heartbeat(
                RuntimeHeartbeat(
                    id="overseer",
                    service_name="overseer",
                    started_at="2026-07-18T13:00:00+00:00",
                    last_tick_at="2026-07-18T13:00:30+00:00",
                    tick_count=2,
                )
            )
            store.close()

            status = service_status(store_path)

            self.assertEqual(status["service_name"], "overseer")
            self.assertEqual(status["tick_count"], 2)

    def test_request_claim_status_queues_against_active_stored_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="proxy.cli",
                    name="CLI Proxy",
                    type=ResourceType.VIRTUAL_ASSET,
                    owner_domain=OwnerDomain.DAX,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.close()

            first = request_claim_status(
                store_path,
                "claim.cli.first",
                "proxy.cli",
                ClaimType.LEASE.value,
                "thread-a",
                OwnerDomain.DAX.value,
                "use proxy",
                "bind proxy",
                RiskLevel.LOW.value,
            )
            approval = approve_claim_status(store_path, first["approval_id"], "sisko")
            activated = activate_claim_status(store_path, first["claim"], approval["approval_id"])
            second = request_claim_status(
                store_path,
                "claim.cli.second",
                "proxy.cli",
                ClaimType.LEASE.value,
                "thread-b",
                OwnerDomain.DAX.value,
                "use proxy too",
                "bind proxy",
                RiskLevel.LOW.value,
            )

            self.assertEqual(first["claim_status"], ClaimStatus.REQUESTED.value)
            self.assertEqual(approval["approval_status"], ApprovalStatus.APPROVED.value)
            self.assertEqual(activated["claim_status"], ClaimStatus.ACTIVE.value)
            self.assertEqual(second["claim_status"], ClaimStatus.QUEUED.value)
            self.assertEqual(second["blocking_claim_ids"], ["claim.cli.first"])

    def test_claim_review_status_flags_expired_active_lease(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="proxy.review.cli",
                    name="Review CLI Proxy",
                    type=ResourceType.VIRTUAL_ASSET,
                    owner_domain=OwnerDomain.DAX,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.save_claim(
                Claim(
                    id="claim.review.expired",
                    resource_id="proxy.review.cli",
                    claim_type=ClaimType.LEASE,
                    owner_thread="thread-a",
                    owner_role=OwnerDomain.DAX,
                    intent="use proxy",
                    requested_action="bind proxy",
                    risk_level=RiskLevel.LOW,
                    status=ClaimStatus.ACTIVE,
                    expires_at="2026-07-18T20:00:00+00:00",
                )
            )
            store.close()

            review = claim_review_status(store_path, "2026-07-18T20:10:00+00:00")
            command = command_summary_status(store_path, now="2026-07-18T20:10:00+00:00")

            self.assertEqual(review["expired_active_like"], 1)
            self.assertEqual(review["missing_release_condition"], 1)
            self.assertEqual(review["operator_review_required"], 1)
            self.assertTrue(review["items"][0]["expired"])
            self.assertEqual(command["claims"]["expired_active_like"], 1)
            self.assertEqual(command["claims"]["missing_release_condition"], 1)

    def test_activate_claim_status_requires_approved_request(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="proxy.approval.cli",
                    name="Approval CLI Proxy",
                    type=ResourceType.VIRTUAL_ASSET,
                    owner_domain=OwnerDomain.DAX,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.close()

            requested = request_claim_status(
                store_path,
                "claim.cli.approval",
                "proxy.approval.cli",
                ClaimType.LEASE.value,
                "thread-a",
                OwnerDomain.DAX.value,
                "use proxy",
                "bind proxy",
                RiskLevel.LOW.value,
            )

            with self.assertRaises(ValueError):
                activate_claim_status(store_path, requested["claim"], requested["approval_id"])

    def test_list_state_status_reports_claim_approval_and_audit_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="proxy.state.cli",
                    name="State CLI Proxy",
                    type=ResourceType.VIRTUAL_ASSET,
                    owner_domain=OwnerDomain.DAX,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.close()
            requested = request_claim_status(
                store_path,
                "claim.cli.state",
                "proxy.state.cli",
                ClaimType.LEASE.value,
                "thread-a",
                OwnerDomain.DAX.value,
                "use proxy",
                "bind proxy",
                RiskLevel.LOW.value,
            )
            approve_claim_status(store_path, requested["approval_id"], "sisko")

            status = list_state_status(store_path)

            self.assertEqual(status["resources"][0]["id"], "proxy.state.cli")
            self.assertEqual(status["claims"][0]["status"], ClaimStatus.REQUESTED.value)
            self.assertEqual(status["approvals"][0]["status"], ApprovalStatus.APPROVED.value)
            self.assertEqual(status["audit_events"][0]["subject_id"], "claim.cli.state")
            self.assertEqual(status["runtime_heartbeats"], [])

    def test_export_state_redacted_status_removes_sensitive_operational_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="svc.export",
                    name="Export Service",
                    type=ResourceType.SERVICE,
                    owner_domain=OwnerDomain.JULIAN,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.save_health_target(
                HealthTarget(
                    id="health.export",
                    resource_id="svc.export",
                    name="Export Health",
                    probe_type=ProbeType.JSON,
                    target="http://127.0.0.1:8766/private-status",
                )
            )
            store.save_health_evidence(
                HealthEvidence(
                    id="evidence.export",
                    resource_id="svc.export",
                    target="http://127.0.0.1:8766/private-status",
                    probe_type=ProbeType.JSON,
                    observed_status=HealthStatus.FAILED,
                    owner_domain=OwnerDomain.JULIAN,
                    observed_error="token appeared in upstream error text",
                )
            )
            plan_admin_change_status(
                store_path,
                "admin.export",
                AdminChangeKind.USER_SERVICE_RESTART.value,
                "private-service.target",
                "restart path includes local deployment details",
                "active",
            )
            store.close()

            status = export_state_redacted_status(store_path)

        self.assertEqual(status["store"], "[REDACTED]")
        self.assertEqual(status["health_targets"][0]["target"], "[REDACTED]")
        self.assertEqual(status["health_evidence"][0]["target"], "[REDACTED]")
        self.assertEqual(status["health_evidence"][0]["error"], "[REDACTED]")
        self.assertEqual(status["admin_change_plans"][0]["target"], "[REDACTED]")
        self.assertFalse(status["export"]["mutation_performed"])
        self.assertIn("$.store", status["export"]["redacted_paths"])
        self.assertIn("$.health_evidence[0].error", status["export"]["redacted_paths"])

    def test_list_state_status_reports_health_targets_and_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_health_target(
                HealthTarget(
                    id="health.state",
                    resource_id="svc.state",
                    name="State Health",
                    probe_type=ProbeType.JSON,
                    target="http://127.0.0.1:8787/health",
                )
            )
            store.save_health_evidence(
                HealthEvidence(
                    id="evidence.state",
                    resource_id="svc.state",
                    target="http://127.0.0.1:8787/health",
                    probe_type=ProbeType.JSON,
                    observed_status=HealthStatus.HEALTHY,
                    owner_domain=OwnerDomain.JULIAN,
                )
            )
            store.close()

            status = list_state_status(store_path)

            self.assertEqual(status["health_targets"][0]["id"], "health.state")
            self.assertEqual(status["health_evidence"][0]["status"], HealthStatus.HEALTHY.value)

    def test_release_claim_status_clears_stored_resource_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="gateway.cli",
                    name="CLI Gateway",
                    type=ResourceType.VIRTUAL_ASSET,
                    owner_domain=OwnerDomain.DAX,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.close()

            requested = request_claim_status(
                store_path,
                "claim.cli.gateway",
                "gateway.cli",
                ClaimType.LEASE.value,
                "thread-a",
                OwnerDomain.DAX.value,
                "use gateway",
                "bind gateway",
                RiskLevel.LOW.value,
            )
            approval = approve_claim_status(store_path, requested["approval_id"], "sisko")
            activate_claim_status(store_path, requested["claim"], approval["approval_id"])
            released = release_claim_status(
                store_path,
                requested["claim"],
                released_by="dax",
                reason="gateway health verified after work",
                evidence_ids=("health.gateway.ok",),
                released_at="2026-07-18T21:00:00+00:00",
            )
            store = SQLiteStore(store_path)

            self.assertEqual(released["claim_status"], ClaimStatus.RELEASED.value)
            self.assertTrue(released["release_evidence_complete"])
            self.assertEqual(released["audit_event"]["summary"], "gateway health verified after work")
            self.assertEqual(released["audit_event"]["occurred_at"], "2026-07-18T21:00:00+00:00")
            release_event = next(event for event in store.list_audit_events() if event.id == "audit.claim.cli.gateway.released")
            self.assertEqual(release_event.evidence_ids, ("health.gateway.ok",))
            self.assertIsNone(store.load_resource("gateway.cli").current_claim_id)
            store.close()


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
            self.assertIsNone(store.load_resource(resource.id).current_claim_id)
            store.close()


if __name__ == "__main__":
    unittest.main()
