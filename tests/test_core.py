import contextlib
import io
import os
import tempfile
import threading
import unittest
import json
import subprocess
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import overseer.api as overseer_api
import overseer.admin as overseer_admin
import overseer.cli as overseer_cli
import overseer.documents as overseer_documents
import overseer.knowledge as overseer_knowledge
from overseer import (
    ApprovalLevel,
    ApprovalRequest,
    ApprovalStatus,
    AuditEvent,
    AuditEventType,
    Claim,
    ClaimStatus,
    ClaimType,
    CodexProjectThread,
    CodexProjectThreadAdapter,
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
    AdminCommandStep,
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
    git_status_status,
    summarize_health_targets,
    HealthStatus,
    HealthEvidence,
    HealthTarget,
    HostCommandObservation,
    HostFindingSeverity,
    HostInspectionAdapter,
    HostInspectionSnapshot,
    HttpHealthProbeAdapter,
    LocalCommandHealthProbeAdapter,
    LocalLogHealthProbeAdapter,
    ManualHealthProbeAdapter,
    McpHttpHealthProbeAdapter,
    LocalProcessHealthProbeAdapter,
    RoutedHealthProbeAdapter,
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
    HostSecuritySourceReview,
    PathPhysicalDiscoveryAdapter,
    AptPackageInspectionAdapter,
    StoragePhysicalDiscoveryAdapter,
    ListenerVirtualDiscoveryAdapter,
    PolicyProfile,
    PolicyCheckStatus,
    ProbeResult,
    ProbeType,
    PhysicalAssetKind,
    PhysicalIdentity,
    PhysicalIdentitySource,
    ProtectiveAction,
    SecurityIncident,
    SecuritySignal,
    SecuritySignalType,
    SecurityStatus,
    SQLiteStore,
    CURRENT_SCHEMA_VERSION,
    ScheduledWorkStatus,
    UsageContinuationRequest,
    UsageContinuationDispatch,
    UsageLimit,
    CrewMessage,
    CrewMessageStatus,
    assess_freshness,
    approval_from_decision,
    assess_maintenance_readiness,
    audit_event_from_decision,
    build_ids_review_package,
    can_close_maintenance,
    config_from_mapping,
    codex_project_thread_resource,
    needs_operator_approval,
    physical_identity_conflicts,
    parse_apt_upgradable,
    parse_systemd_service_rows,
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
    plan_apt_update,
    plan_apt_upgrade,
    plan_block_ip,
    plan_docker_compose_update,
    plan_flatpak_install,
    plan_firewalld_deny_tcp,
    plan_firewalld_source_scoped_deny_tcp,
    plan_firewall_allow_tcp,
    plan_firewall_deny_tcp,
    plan_npm_global_install,
    plan_user_service_restart,
    policy_customization_helper_status,
    policy_profile_from_answers_status,
    policy_profile_from_mapping,
    SourceReviewDisposition,
)
from overseer.api import make_api_handler, run_api_server
from overseer.client import OverseerApiClient
from overseer.host import run_read_only_command
from overseer.remote_testing import (
    enqueue_remote_test_job_status,
    request_remote_testing_lease_status,
)
from overseer.ui import OPERATOR_CONSOLE_HTML
from overseer.cli import demo_status
from overseer.cli import discover_codex_project_threads_status
from overseer.cli import discover_physical_status
from overseer.cli import discover_storage_status
from overseer.cli import discover_user_services_status
from overseer.cli import discover_virtual_listeners_status
from overseer.cli import persisted_demo_status
from overseer.cli import activate_claim_status
from overseer.cli import active_policy_profile_status
from overseer.cli import admin_adapter_capabilities_status
from overseer.cli import admin_adapter_enablement_plan_status
from overseer.cli import admin_executions_status
from overseer.cli import admin_execution_readiness_status
from overseer.cli import admin_policy_status
from overseer.cli import admin_history_archive_plan_status
from overseer.cli import admin_history_archives_status
from overseer.cli import admin_history_review_status
from overseer.cli import admin_history_restore_readiness_status
from overseer.cli import admin_summary_status
from overseer.cli import archive_admin_history_status
from overseer.cli import build_policy_profile_status
from overseer.cli import approve_admin_change_status
from overseer.cli import approve_admin_adapter_enablement_status
from overseer.cli import approve_admin_history_archive_status
from overseer.cli import approve_admin_history_restore_status
from overseer.cli import approve_admin_policy_warning_status
from overseer.cli import approve_claim_cleanup_status
from overseer.cli import approve_claim_status
from overseer.cli import approve_daemon_migration_status
from overseer.cli import approvals_summary_status
from overseer.cli import alerts_summary_status
from overseer.cli import audit_station_status
from overseer.cli import audit_summary_status
from overseer.cli import assess_host_security_status
from overseer.cli import authorizations_required_status
from overseer.cli import cancel_admin_change_status
from overseer.cli import claim_cleanup_plan_status
from overseer.cli import claim_review_status
from overseer.cli import command_summary_status
from overseer.cli import daemon_migration_plan_status
from overseer.cli import execute_admin_change_status
from overseer.cli import execute_claim_cleanup_status
from overseer.cli import export_state_redacted_status
from overseer.cli import export_host_security_ids_review_prompt_status
from overseer.cli import health_efficiency_summary_status
from overseer.cli import health_summary_status
from overseer.cli import host_security_findings_status
from overseer.cli import host_security_listener_review_queue_status
from overseer.cli import host_security_source_review_queue_status
from overseer.cli import host_security_sources_status
from overseer.cli import create_host_security_source_review_status
from overseer.cli import host_security_source_reviews_status
from overseer.cli import host_security_triage_status
from overseer.cli import inspect_host_status
from overseer.cli import inspect_packages_status
from overseer.cli import list_state_status
from overseer.cli import main as cli_main
from overseer.cli import maintenance_summary_status
from overseer.cli import operator_dashboard_status
from overseer.cli import physical_summary_status
from overseer.cli import persistence_security_status
from overseer.cli import plan_host_security_listener_queue_remediations_status
from overseer.cli import plan_package_updates_status
from overseer.cli import prepare_host_security_ids_review_package_status
from overseer.cli import host_security_ids_review_packages_status
from overseer.cli import host_security_ids_review_summary_status
from overseer.cli import record_host_security_ids_review_result_status
from overseer.cli import plan_host_security_source_block_status
from overseer.cli import plan_host_security_remediation_status
from overseer.cli import plan_admin_change_status
from overseer.cli import probe_config_status
from overseer.cli import probe_health_status
from overseer.cli import probe_stored_health_status
from overseer.cli import record_health_target_status
from overseer.cli import record_resource_status
from overseer.cli import release_claim_status
from overseer.cli import request_admin_adapter_enablement_status
from overseer.cli import request_admin_history_archive_status
from overseer.cli import request_admin_history_restore_status
from overseer.cli import request_admin_policy_warning_status
from overseer.cli import request_claim_cleanup_status
from overseer.cli import request_claim_status
from overseer.cli import request_daemon_migration_status
from overseer.cli import record_usage_limit_status
from overseer.cli import crew_messages_status, dispatch_crew_messages_status, record_crew_message_status
from overseer.cli import _advance_admin_plan_after_dispatch
from overseer.cli import request_usage_continuation_status
from overseer.cli import dispatch_host_security_ids_review_package_status
from overseer.cli import dispatch_usage_continuations_status
from overseer.cli import run_obrien_package_maintenance_cycle_status
from overseer.cli import run_status
from overseer.cli import runtime_status
from overseer.cli import security_summary_status
from overseer.cli import submit_host_security_ids_review_package_status
from overseer.cli import service_status
from overseer.cli import unarchive_admin_history_status
from overseer.cli import seed_config_status
from overseer.cli import usage_summary_status
from overseer.cli import usage_continuation_plan_status
from overseer.cli import virtual_summary_status
from overseer import parse_tcp_listeners


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


class _McpHealthHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        self.rfile.read(length)
        if self.path != "/mcp/":
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": "test-mcp", "version": "0"},
                },
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


class _FakeObsidianHandler(BaseHTTPRequestHandler):
    calls = []

    def do_GET(self):
        self.__class__.calls.append(("GET", self.path, self.headers.get("authorization"), ""))
        if self.path.startswith("/search?"):
            self._json([{"path": "Overseer/Runbooks/REST.md", "score": 1, "matches": []}])
            return
        if self.headers.get("authorization") != "Bearer test-token":
            self.send_response(401)
            self.end_headers()
            return
        if self.path == "/":
            self._json(
                {
                    "status": "OK",
                    "service": "Obsidian Local REST API",
                    "authenticated": True,
                    "versions": {"obsidian": "1.12.7", "self": "4.1.7"},
                    "manifest": {"id": "obsidian-local-rest-api", "name": "Local REST API with MCP", "version": "4.1.7"},
                }
            )
            return
        if self.path == "/vault/Overseer/":
            self._json({"files": ["Inbox/operator-note.md", "Runbooks/REST.md"]})
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        self.__class__.calls.append(("POST", self.path, self.headers.get("authorization"), body))
        if self.headers.get("authorization") != "Bearer test-token":
            self.send_response(401)
            self.end_headers()
            return
        if self.path.startswith("/search/simple/"):
            self._json([{"filename": "Overseer/Runbooks/REST.md", "score": 1, "matches": [{"match": "Overseer"}]}])
            return
        if self.path == "/vault/Overseer/Inbox/operator-note.md" or self.path.startswith("/vault/Overseer/Knowledge/"):
            self.send_response(204)
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()

    def do_PUT(self):
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        self.__class__.calls.append(("PUT", self.path, self.headers.get("authorization"), body))
        if self.headers.get("authorization") != "Bearer test-token":
            self.send_response(401)
            self.end_headers()
            return
        if self.path == "/vault/Overseer/Inbox/operator-note.md" or self.path.startswith("/vault/Overseer/Knowledge/"):
            self.send_response(204)
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()

    def _json(self, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


class _FakeCodexProjectRunner:
    def __init__(self) -> None:
        self.commands = []
        self.inputs = []

    def __call__(self, command, input=None, text=True, capture_output=True):
        self.commands.append(tuple(command))
        self.inputs.append(input)
        if tuple(command[:3]) == ("/usr/bin/tmux", "has-session", "-t"):
            return subprocess.CompletedProcess(command, 1, "", "missing")
        return subprocess.CompletedProcess(command, 0, "resumed", "")


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


class LocalMcpHttpServer:
    def __enter__(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _McpHealthHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.url = f"http://{host}:{port}/mcp"
        return self

    def __exit__(self, exc_type, exc, tb):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class LocalFakeObsidianServer:
    def __enter__(self):
        _FakeObsidianHandler.calls = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeObsidianHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.url = f"http://{host}:{port}"
        return self

    def __exit__(self, exc_type, exc, tb):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    @property
    def calls(self):
        return _FakeObsidianHandler.calls


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

    def get_text(self, path, headers=None):
        request = Request(f"{self.url}{path}", headers=self._headers(headers))
        with urlopen(request, timeout=5) as response:
            return response.read().decode("utf-8"), response.headers.get("content-type")

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
        self.assertIsNotNone(operation.approval_request)
        self.assertEqual(operation.approval_request.id, "approval.operation.maint.gateway.patch")
        self.assertEqual(operation.approval_request.evidence_required, ("health.before",))
        self.assertIsNotNone(operation.scheduled_work)
        self.assertEqual(operation.scheduled_work.status, ScheduledWorkStatus.READY)
        self.assertEqual(operation.scheduled_work.scheduled_for, "2026-07-18T12:00:00-04:00")
        self.assertEqual(operation.result.mode, ExecutionMode.DRY_RUN)
        self.assertFalse(operation.result.changed_host_state())

    def test_plans_overlapping_maintenance_as_waiting_dry_run(self):
        planner = OperationPlanner()
        active = MaintenancePlan(
            id="maint.active",
            resource_id="gateway.protected",
            kind=MaintenanceKind.PATCH,
            requested_state="1.2.2",
            risk_level=RiskLevel.MEDIUM,
            window=MaintenanceWindow(
                id="window.active",
                starts_at="2026-07-18T12:00:00-04:00",
                ends_at="2026-07-18T12:45:00-04:00",
            ),
            interruption_policy=InterruptionPolicy.EXCLUSIVE_WINDOW_REQUIRED,
            precheck_ids=("health.before.active",),
            rollback_plan="restore active gateway config",
        )
        requested = MaintenancePlan(
            id="maint.requested",
            resource_id="gateway.protected",
            kind=MaintenanceKind.PATCH,
            requested_state="1.2.3",
            risk_level=RiskLevel.MEDIUM,
            window=MaintenanceWindow(
                id="window.requested",
                starts_at="2026-07-18T12:15:00-04:00",
                ends_at="2026-07-18T12:30:00-04:00",
            ),
            interruption_policy=InterruptionPolicy.EXCLUSIVE_WINDOW_REQUIRED,
            precheck_ids=("health.before.requested",),
            rollback_plan="restore requested gateway config",
        )

        operation = planner.plan_maintenance(requested, (active,))

        self.assertEqual(operation.result.mode, ExecutionMode.DRY_RUN)
        self.assertIsNotNone(operation.scheduled_work)
        self.assertEqual(operation.scheduled_work.status, ScheduledWorkStatus.WAITING)
        self.assertEqual(operation.scheduled_work.blocking_ids, ("maint.active",))

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
        self.assertIsNotNone(operation.approval_request)
        self.assertEqual(operation.approval_request.owner_domain, OwnerDomain.DAX)
        self.assertEqual(operation.approval_request.evidence_required, ("vm.intrusion",))
        self.assertEqual(operation.request.action, "security:quarantine")
        self.assertEqual(operation.result.mode, ExecutionMode.DRY_RUN)

    def test_plans_usage_limited_work_until_reset(self):
        planner = OperationPlanner()
        work = planner.plan_usage_limited_work(
            UsageLimit(
                id="limit.planner.ai",
                resource_id="svc.ai",
                kind=LimitKind.TOKENS,
                capacity=100,
                remaining=0,
                resets_at="2026-07-18T16:00:00-04:00",
                window="hourly",
            ),
            LimitedWorkRequest(
                id="work.planner.ai",
                resource_id="svc.ai",
                owner_thread="thread-planner",
                requested_units=10,
                intent="continue planned work",
            ),
        )

        self.assertEqual(work.status, ScheduledWorkStatus.WAITING)
        self.assertEqual(work.scheduled_for, "2026-07-18T16:00:00-04:00")


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

    def test_mcp_http_health_probe_adapter_initializes_streamable_http_server(self):
        with LocalMcpHttpServer() as server:
            target = HealthTarget(
                id="local-mcp",
                resource_id="svc.local.mcp",
                name="Local MCP",
                probe_type=ProbeType.MCP,
                target=server.url,
                expected_content_type="application/json",
            )

            evidence = McpHttpHealthProbeAdapter(timeout_seconds=2).probe(target)

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

    def test_probe_health_status_reports_allowed_command_target(self):
        status = probe_health_status(
            "svc.command.file",
            "Command File",
            "command:test -e /tmp",
            ProbeType.COMMAND.value,
        )

        self.assertEqual(status["status"], HealthStatus.HEALTHY.value)
        self.assertEqual(status["probe_type"], ProbeType.COMMAND.value)

    def test_probe_health_status_reports_log_target_without_raw_content(self):
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "service.log"
            log_path.write_text("token=SECRET\nservice ready\n", encoding="utf-8")

            status = probe_health_status(
                "svc.log.file",
                "Log File",
                f"log:{log_path}?contains=service%20ready",
                ProbeType.LOG.value,
            )

        self.assertEqual(status["status"], HealthStatus.HEALTHY.value)
        self.assertEqual(status["probe_type"], ProbeType.LOG.value)
        self.assertEqual(status["error"], "")

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

    def test_local_process_probe_adapter_classifies_active_systemd_unit(self):
        def runner(command, timeout_seconds):
            return HostCommandObservation(
                name="systemctl",
                command=tuple(command),
                exit_code=0,
                stdout="active\n",
            )

        target = HealthTarget(
            id="health.overseer.api",
            resource_id="svc.overseer.api",
            name="Overseer API",
            probe_type=ProbeType.PROCESS,
            target="systemd:user:overseer-api.service",
        )

        evidence = LocalProcessHealthProbeAdapter(command_runner=runner).probe(target)

        self.assertEqual(evidence.observed_status, HealthStatus.HEALTHY)
        self.assertFalse(evidence.recovery_required)

    def test_local_process_probe_adapter_preserves_failed_process_error(self):
        def runner(command, timeout_seconds):
            return HostCommandObservation(
                name="systemctl",
                command=tuple(command),
                exit_code=3,
                stdout="inactive\n",
            )

        target = HealthTarget(
            id="health.overseer.api",
            resource_id="svc.overseer.api",
            name="Overseer API",
            probe_type=ProbeType.PROCESS,
            target="systemd:user:overseer-api.service",
        )

        evidence = LocalProcessHealthProbeAdapter(command_runner=runner).probe(target)

        self.assertEqual(evidence.observed_status, HealthStatus.FAILED)
        self.assertTrue(evidence.recovery_required)
        self.assertEqual(evidence.observed_error, "inactive")

    def test_local_command_probe_adapter_runs_allowed_read_only_command(self):
        commands = []

        def runner(command, timeout_seconds):
            commands.append(tuple(command))
            return HostCommandObservation(
                name="stat",
                command=tuple(command),
                exit_code=0,
                stdout="regular file\n",
            )

        target = HealthTarget(
            id="health.command.file",
            resource_id="svc.command.file",
            name="Command File",
            probe_type=ProbeType.COMMAND,
            target="command:stat -c %F /tmp/example",
        )

        evidence = LocalCommandHealthProbeAdapter(command_runner=runner).probe(target)

        self.assertEqual(commands, [("stat", "-c", "%F", "/tmp/example")])
        self.assertEqual(evidence.observed_status, HealthStatus.HEALTHY)
        self.assertFalse(evidence.recovery_required)

    def test_local_command_probe_adapter_blocks_unsupported_command(self):
        def runner(command, timeout_seconds):
            raise AssertionError("unsupported command should not execute")

        target = HealthTarget(
            id="health.command.unsafe",
            resource_id="svc.command.unsafe",
            name="Unsafe Command",
            probe_type=ProbeType.COMMAND,
            target="command:rm -rf /tmp/example",
        )

        evidence = LocalCommandHealthProbeAdapter(command_runner=runner).probe(target)

        self.assertEqual(evidence.observed_status, HealthStatus.FAILED)
        self.assertTrue(evidence.recovery_required)
        self.assertIn("unsupported command probe target", evidence.observed_error)

    def test_local_log_probe_adapter_does_not_persist_raw_log_content(self):
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "service.log"
            log_path.write_text("api-key=SECRET\nservice ready\n", encoding="utf-8")
            target = HealthTarget(
                id="health.log.ready",
                resource_id="svc.log.ready",
                name="Ready Log",
                probe_type=ProbeType.LOG,
                target=f"log:{log_path}?contains=service%20ready",
            )

            evidence = LocalLogHealthProbeAdapter().probe(target)

        self.assertEqual(evidence.observed_status, HealthStatus.HEALTHY)
        self.assertFalse(evidence.recovery_required)
        self.assertNotIn("SECRET", evidence.observed_error)

    def test_local_log_probe_adapter_fails_when_blocked_marker_is_present(self):
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "service.log"
            log_path.write_text("startup ok\ntraceback detected\n", encoding="utf-8")
            target = HealthTarget(
                id="health.log.blocked",
                resource_id="svc.log.blocked",
                name="Blocked Log",
                probe_type=ProbeType.LOG,
                target=f"log:{log_path}?absent=traceback",
            )

            evidence = LocalLogHealthProbeAdapter().probe(target)

        self.assertEqual(evidence.observed_status, HealthStatus.FAILED)
        self.assertTrue(evidence.recovery_required)
        self.assertEqual(evidence.observed_error, "blocked log marker found")

    def test_manual_health_probe_adapter_records_explicit_healthy_status(self):
        target = HealthTarget(
            id="health.manual.ready",
            resource_id="svc.manual.ready",
            name="Manual Ready",
            probe_type=ProbeType.MANUAL,
            target="manual:healthy",
        )

        evidence = ManualHealthProbeAdapter().probe(target)

        self.assertEqual(evidence.observed_status, HealthStatus.HEALTHY)
        self.assertFalse(evidence.recovery_required)
        self.assertEqual(evidence.observed_error, "")

    def test_manual_health_probe_adapter_records_failed_status_with_error(self):
        target = HealthTarget(
            id="health.manual.failed",
            resource_id="svc.manual.failed",
            name="Manual Failed",
            probe_type=ProbeType.MANUAL,
            target="manual:failed?error=operator%20observed%20crash",
        )

        evidence = ManualHealthProbeAdapter().probe(target)

        self.assertEqual(evidence.observed_status, HealthStatus.FAILED)
        self.assertTrue(evidence.recovery_required)
        self.assertEqual(evidence.observed_error, "operator observed crash")

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

    def test_probe_health_status_routes_process_probe_and_persists_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            status = probe_health_status(
                "svc.current-process",
                "Current Process",
                f"pid:{os.getpid()}",
                ProbeType.PROCESS.value,
                timeout_seconds=2,
                store_path=store_path,
            )
            store = SQLiteStore(store_path)

            self.assertEqual(status["status"], HealthStatus.HEALTHY.value)
            self.assertEqual(store.load_health_evidence(status["id"]).observed_status, HealthStatus.HEALTHY)
            store.close()

    def test_probe_stored_health_status_probes_persisted_process_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_health_target(
                HealthTarget(
                    id="health.stored.process",
                    resource_id="svc.stored.process",
                    name="Stored Process",
                    probe_type=ProbeType.PROCESS,
                    target=f"pid:{os.getpid()}",
                )
            )
            store.close()

            status = probe_stored_health_status(store_path, timeout_seconds=2, health_evidence_retention_per_target=1)
            store = SQLiteStore(store_path)

            self.assertEqual(status["targets"], 1)
            self.assertEqual(status["healthy"], 1)
            self.assertEqual(status["evidence"][0]["status"], HealthStatus.HEALTHY.value)
            self.assertEqual(store.list_health_evidence()[0].observed_status, HealthStatus.HEALTHY)
            store.close()


class PackageInspectionTests(unittest.TestCase):
    def test_parse_apt_upgradable_extracts_versions(self):
        updates = parse_apt_upgradable(
            "\n".join(
                (
                    "Listing...",
                    "openssl/oldstable-security 3.0.15-1 amd64 [upgradable from: 3.0.14-1]",
                    "python3/oldstable 3.11.2-1 amd64 [upgradable from: 3.11.1-1]",
                )
            )
        )

        self.assertEqual([update.name for update in updates], ["openssl", "python3"])
        self.assertEqual(updates[0].repository, "oldstable-security")
        self.assertEqual(updates[0].candidate_version, "3.0.15-1")
        self.assertEqual(updates[0].installed_version, "3.0.14-1")

    def test_inspect_packages_status_reports_read_only_apt_updates(self):
        commands = []

        def runner(command):
            commands.append(tuple(command))
            return subprocess.CompletedProcess(
                command,
                0,
                "Listing...\nopenssl/oldstable-security 3.0.15-1 amd64 [upgradable from: 3.0.14-1]\n",
                "",
            )

        status = inspect_packages_status(
            "2026-07-19T14:45:00+00:00",
            AptPackageInspectionAdapter(command_runner=runner),
        )

        self.assertEqual(commands, [("apt", "list", "--upgradable")])
        self.assertEqual(status["status"], "ok")
        self.assertEqual(status["upgradable"], 1)
        self.assertEqual(status["items"][0]["name"], "openssl")

    def test_inspect_packages_status_preserves_failed_stderr(self):
        def runner(command):
            return subprocess.CompletedProcess(command, 100, "", "apt lock unavailable")

        status = inspect_packages_status(
            "2026-07-19T14:46:00+00:00",
            AptPackageInspectionAdapter(command_runner=runner),
        )

        self.assertEqual(status["status"], "failed")
        self.assertEqual(status["upgradable"], 0)
        self.assertEqual(status["stderr"], "apt lock unavailable")

    def test_plan_package_updates_stages_approval_gated_plans(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            def runner(command):
                return subprocess.CompletedProcess(
                    command,
                    0,
                    "Listing...\nopenssl/oldstable-security 3.0.15-1 amd64 [upgradable from: 3.0.14-1]\n",
                    "",
                )

            status = plan_package_updates_status(
                store_path,
                "2026-07-19T14:45:00+00:00",
                adapter=AptPackageInspectionAdapter(command_runner=runner),
            )
            summary = admin_summary_status(store_path)

            self.assertTrue(status["mutation_performed"])
            self.assertFalse(status["host_mutation_performed"])
            self.assertEqual(status["plans"], 2)
            self.assertEqual(status["selected_packages"], ("openssl",))
            self.assertEqual(status["items"][1]["kind"], AdminChangeKind.APT_UPGRADE.value)
            self.assertIn("openssl", status["items"][1]["target"])
            self.assertEqual(summary["plans"], 2)

    def test_plan_package_updates_reports_failed_inspection_without_plans(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            def runner(command):
                return subprocess.CompletedProcess(command, 100, "", "apt lock unavailable")

            status = plan_package_updates_status(
                store_path,
                "2026-07-19T14:46:00+00:00",
                adapter=AptPackageInspectionAdapter(command_runner=runner),
            )

            self.assertFalse(status["mutation_performed"])
            self.assertEqual(status["plans"], 0)
            self.assertEqual(status["inspection"]["status"], "failed")

    def test_obrien_package_maintenance_cycle_refreshes_stages_and_executes_with_enabled_adapters(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            commands = []

            def inspect_runner(command):
                return subprocess.CompletedProcess(
                    command,
                    0,
                    "Listing...\nopenssl/oldstable-security 3.0.15-1 amd64 [upgradable from: 3.0.14-1]\n",
                    "",
                )

            def command_runner(step):
                commands.append(step.command)
                return AdminCommandResult(step.title, step.command, 0, stdout="ok")

            status = run_obrien_package_maintenance_cycle_status(
                store_path,
                "2026-07-25T08:00:00+00:00",
                adapter=AptPackageInspectionAdapter(command_runner=inspect_runner),
                runner=command_runner,
            )
            summary = admin_executions_status(store_path)

        self.assertEqual(status["completed_executions"], 2)
        self.assertEqual(status["failed_executions"], 0)
        self.assertTrue(status["host_mutation_performed"])
        self.assertIn(("sudo", "apt-get", "update"), commands)
        self.assertIn(("sudo", "apt-get", "install", "--only-upgrade", "-y", "openssl"), commands)
        self.assertEqual({item["status"] for item in summary["executions"]}, {AdminExecutionStatus.COMPLETED.value})

    def test_obrien_package_maintenance_cycle_can_leave_live_execution_blocked_without_adapter_auto_enable(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            def inspect_runner(command):
                return subprocess.CompletedProcess(
                    command,
                    0,
                    "Listing...\nopenssl/oldstable-security 3.0.15-1 amd64 [upgradable from: 3.0.14-1]\n",
                    "",
                )

            status = run_obrien_package_maintenance_cycle_status(
                store_path,
                "2026-07-25T08:05:00+00:00",
                adapter=AptPackageInspectionAdapter(command_runner=inspect_runner),
                runner=lambda step: self.fail(f"commands should stay blocked without adapter enablement: {step.command}"),
                auto_enable_adapters=False,
            )

        self.assertEqual(status["completed_executions"], 0)
        self.assertGreaterEqual(status["blocked_executions"], 1)
        self.assertFalse(status["host_mutation_performed"])
        self.assertIn("blocked", status["next_step"])


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

    def test_record_health_target_status_persists_target_for_known_resource(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="svc.registered",
                    name="Registered Service",
                    type=ResourceType.SERVICE,
                    owner_domain=OwnerDomain.JULIAN,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.close()

            status = record_health_target_status(
                store_path,
                "health.registered.ready",
                "svc.registered",
                "Registered Ready",
                ProbeType.COMMAND.value,
                "command:test -e /tmp",
                latency_warn_ms=250,
            )

            store = SQLiteStore(store_path)
            target = store.load_health_target("health.registered.ready")
            store.close()

        self.assertTrue(status["mutation_performed"])
        self.assertFalse(status["host_mutation_performed"])
        self.assertEqual(status["probe_type"], ProbeType.COMMAND.value)
        self.assertEqual(status["latency_warn_ms"], 250)
        self.assertEqual(target.resource_id, "svc.registered")
        self.assertEqual(target.target, "command:test -e /tmp")

    def test_record_health_target_status_rejects_unknown_resource(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            with self.assertRaises(ValueError):
                record_health_target_status(
                    store_path,
                    "health.missing",
                    "svc.missing",
                    "Missing",
                    ProbeType.JSON.value,
                    "http://127.0.0.1:1/health",
                )

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
        upgrade = next(item for item in status["items"] if item["kind"] == AdminChangeKind.APT_UPGRADE.value)
        compose = next(item for item in status["items"] if item["kind"] == AdminChangeKind.DOCKER_COMPOSE_UPDATE.value)

        self.assertIsNone(status["store"])
        self.assertEqual(status["enabled"], 1)
        self.assertEqual(
            status["disabled"],
            sum(1 for item in status["items"] if item["status"] == AdminAdapterStatus.DISABLED.value),
        )
        self.assertEqual(restart["status"], AdminAdapterStatus.ENABLED.value)
        self.assertFalse(restart["authorization_required_before_enable"])
        self.assertEqual(package["status"], AdminAdapterStatus.DISABLED.value)
        self.assertTrue(package["approval_plan_required"])
        self.assertEqual(upgrade["adapter_name"], "apt-package-upgrade")
        self.assertEqual(compose["status"], AdminAdapterStatus.DISABLED.value)
        self.assertTrue(compose["authorization_required_before_enable"])

    def test_admin_adapter_capabilities_use_approved_store_enablement(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            requested = request_admin_adapter_enablement_status(
                store_path,
                AdminChangeKind.APT_INSTALL.value,
                "sisko",
                "2026-07-18T20:30:00+00:00",
            )
            approve_admin_adapter_enablement_status(
                store_path,
                requested["approval_id"],
                "sisko",
                "2026-07-18T20:35:00+00:00",
            )

            status = admin_adapter_capabilities_status(store_path)

        package = next(item for item in status["items"] if item["kind"] == AdminChangeKind.APT_INSTALL.value)
        self.assertEqual(status["store"], str(store_path))
        self.assertEqual(status["enabled"], 2)
        self.assertEqual(
            status["disabled"],
            sum(1 for item in status["items"] if item["status"] == AdminAdapterStatus.DISABLED.value),
        )
        self.assertEqual(package["status"], AdminAdapterStatus.ENABLED.value)
        self.assertIn("approved live", package["summary"])

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

    def test_approved_adapter_enablement_allows_mocked_live_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            requested = request_admin_adapter_enablement_status(
                store_path,
                AdminChangeKind.APT_INSTALL.value,
                "sisko",
                "2026-07-18T20:40:00+00:00",
            )
            approve_admin_adapter_enablement_status(
                store_path,
                requested["approval_id"],
                "sisko",
                "2026-07-18T20:45:00+00:00",
            )
            plan_admin_change_status(
                store_path,
                "admin.install.mocked",
                AdminChangeKind.APT_INSTALL.value,
                "nmap",
                "enable approved local audit",
                "not installed",
                packages=("nmap",),
            )
            approve_admin_change_status(
                store_path,
                "admin.install.mocked",
                "operator",
                "2026-07-18T20:50:00+00:00",
            )

            status = execute_admin_change_status(
                store_path,
                "admin.install.mocked",
                runner=lambda step: AdminCommandResult(
                    title=step.title,
                    command=step.command,
                    exit_code=0,
                    stdout="mocked",
                ),
            )

        self.assertEqual(status["status"], AdminExecutionStatus.COMPLETED.value)
        self.assertEqual(len(status["command_results"]), 2)
        self.assertEqual(len(status["verification_results"]), 1)

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

    def test_admin_execution_readiness_uses_approved_adapter_enablement(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            requested = request_admin_adapter_enablement_status(
                store_path,
                AdminChangeKind.BLOCK_IP.value,
                "sisko",
                "2026-07-18T21:00:00+00:00",
            )
            approve_admin_adapter_enablement_status(
                store_path,
                requested["approval_id"],
                "sisko",
                "2026-07-18T21:05:00+00:00",
            )
            block_plan = plan_admin_change_status(
                store_path,
                "admin.block.enabled-readiness",
                AdminChangeKind.BLOCK_IP.value,
                "8.8.4.4",
                "block reviewed hostile source",
                "not blocked",
            )
            ids_package = prepare_host_security_ids_review_package_status(
                store_path,
                block_plan["id"],
                package_id="ids-review.admin.block.enabled-readiness",
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

        item = next(item for item in status["items"] if item["id"] == "admin.block.enabled-readiness")
        self.assertEqual(status["ready_for_overseer_execution"], 1)
        self.assertEqual(status["manual_execution_required"], 0)
        self.assertEqual(status["adapter_enabled"], 1)
        self.assertEqual(item["readiness_state"], "ready_for_overseer_execution")
        self.assertTrue(item["live_execution_supported"])
        self.assertEqual(item["adapter_status"], AdminAdapterStatus.ENABLED.value)

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
            archive_request = request_admin_history_archive_status(
                store_path,
                "sisko",
                "2026-07-18T22:08:00+00:00",
                plan_id="admin.restart.completed",
            )
            pending_archive_authorizations = authorizations_required_status(store_path)
            archive_approval = approve_admin_history_archive_status(
                store_path,
                archive_request["approval_id"],
                "sisko",
                "2026-07-18T22:09:00+00:00",
            )
            archived = archive_admin_history_status(
                store_path,
                "sisko",
                archive_request["approval_id"],
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
        self.assertEqual(status["assets_by_source"][PhysicalIdentitySource.OPERATOR_DECLARED.value], 3)
        self.assertEqual(status["assets_by_source"][PhysicalIdentitySource.DISCOVERED.value], 0)
        serial = next(item for item in status["items"] if item["stable_id"] == "serial.rs485-a")
        self.assertEqual(serial["observed_paths"], ["/dev/serial/by-id/rs485-a"])
        self.assertEqual(serial["source"], PhysicalIdentitySource.OPERATOR_DECLARED.value)

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
            compact_status = operator_dashboard_status(store_path, include_summaries=False)

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
        self.assertIn("role_focus", compact_status)
        self.assertNotIn("summaries", compact_status)


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

    def test_api_records_resource(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            with LocalOverseerApiServer(store_path, auth_token="local-secret") as server:
                status = server.post(
                    "/resources",
                    {
                        "resource_id": "gateway.api",
                        "name": "API Gateway",
                        "resource_type": "virtual_asset",
                        "owner_domain": "dax",
                        "risk_level": "high",
                        "identifiers": {"kind": "gateway", "ports": [8795]},
                        "exclusive_groups": ["protected-gateway"],
                    },
                )
                state = server.get("/state")

            self.assertTrue(status["mutation_performed"])
            self.assertFalse(status["host_mutation_performed"])
            self.assertEqual(status["resource"]["id"], "gateway.api")
            self.assertEqual(state["resources"][0]["identifiers"]["kind"], "gateway")

    def test_api_rejects_resource_identifiers_that_are_not_objects(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            with LocalOverseerApiServer(store_path) as server:
                with self.assertRaises(HTTPError) as error:
                    server.post(
                        "/resources",
                        {
                            "resource_id": "bad.identifiers",
                            "name": "Bad",
                            "resource_type": "service",
                            "owner_domain": "julian",
                            "risk_level": "low",
                            "identifiers": ["not", "an", "object"],
                        },
                    )
                body = json.loads(error.exception.read().decode("utf-8"))

            self.assertEqual(error.exception.code, 400)
            self.assertEqual(body["error"], "identifiers must be a JSON object")

    def test_documents_client_uses_local_secret_without_exposing_token(self):
        with tempfile.TemporaryDirectory() as directory, LocalFakeObsidianServer() as obsidian:
            env_file = Path(directory) / "obsidian.env"
            env_file.write_text(
                f"OBSIDIAN_BASE_URL={obsidian.url}\nOBSIDIAN_API_KEY=test-token\nOBSIDIAN_OMNISEARCH_URL={obsidian.url}\n",
                encoding="utf-8",
            )

            status = overseer_documents.documents_config_status(str(env_file))
            notes = overseer_documents.documents_list_notes_status(str(env_file), "Overseer")
            search = overseer_documents.documents_search_status(str(env_file), "Overseer", 20)
            write = overseer_documents.documents_write_note_status(
                str(env_file),
                "Overseer/Inbox/operator-note.md",
                "## Operator note\n",
                "append",
            )

        self.assertTrue(status["available"])
        self.assertTrue(status["authenticated"])
        self.assertEqual(notes["files"], ["Inbox/operator-note.md", "Runbooks/REST.md"])
        self.assertTrue(status["omnisearch"]["available"])
        self.assertEqual(search["results"][0]["filename"], "Overseer/Runbooks/REST.md")
        self.assertTrue(write["mutation_performed"])
        self.assertNotIn("test-token", json.dumps(status))

    def test_documents_client_rejects_writes_outside_allowed_folders(self):
        with tempfile.TemporaryDirectory() as directory, LocalFakeObsidianServer() as obsidian:
            env_file = Path(directory) / "obsidian.env"
            env_file.write_text(
                f"OBSIDIAN_BASE_URL={obsidian.url}\nOBSIDIAN_API_KEY=test-token\n",
                encoding="utf-8",
            )

            with self.assertRaises(ValueError) as error:
                overseer_documents.documents_write_note_status(
                    str(env_file),
                    "Private/export.md",
                    "secret",
                    "append",
                )

        self.assertEqual(str(error.exception), "path is outside allowed Documents write folders")

    def test_knowledge_capture_builds_dry_run_candidates(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_crew_message(
                CrewMessage(
                    id="crew.odo.review-source",
                    owner_domain=OwnerDomain.ODO,
                    subject="Review source",
                    message="Check suspicious source traffic.",
                    priority=RiskLevel.HIGH,
                    requested_by="operator",
                    created_at="2026-07-20T12:00:00+00:00",
                    updated_at="2026-07-20T12:00:00+00:00",
                )
            )
            store.save_audit_event(
                AuditEvent(
                    id="audit.odo.review-source",
                    event_type=AuditEventType.ALERT,
                    owner_domain=OwnerDomain.ODO,
                    subject_id="source.192-0-2-10",
                    summary="Suspicious source was observed.",
                    risk_level=RiskLevel.HIGH,
                    occurred_at="2026-07-20T12:01:00+00:00",
                )
            )
            store.close()

            status = overseer_knowledge.knowledge_capture_status(store_path, kinds=("crew", "audit"), limit=10, dry_run=True)

        self.assertEqual(status["candidate_count"], 2)
        self.assertEqual(status["captured"], 0)
        self.assertTrue(status["dry_run"])
        self.assertEqual(status["items"][0]["path"], "Overseer/Knowledge/Events/odo/audit.odo.review-source.md")
        self.assertEqual(status["items"][1]["path"], "Overseer/Knowledge/Crew/odo/crew.odo.review-source.md")

    def test_knowledge_capture_writes_to_documents_without_exposing_token(self):
        with tempfile.TemporaryDirectory() as directory, LocalFakeObsidianServer() as obsidian:
            env_file = Path(directory) / "obsidian.env"
            env_file.write_text(
                f"OBSIDIAN_BASE_URL={obsidian.url}\nOBSIDIAN_API_KEY=test-token\n",
                encoding="utf-8",
            )
            store_path = Path(directory) / "overseer.sqlite3"
            record_crew_message_status(
                store_path,
                OwnerDomain.EZRI.value,
                "Capture runbook",
                "Create a note for the latest runbook decision.",
                RiskLevel.LOW.value,
                message_id="crew.ezri.capture-runbook",
                created_at="2026-07-20T12:00:00+00:00",
            )

            status = overseer_knowledge.knowledge_capture_status(
                store_path,
                str(env_file),
                kinds=("crew",),
                limit=5,
                dry_run=False,
            )

        self.assertEqual(status["captured"], 1)
        self.assertEqual(status["failed"], 0)
        self.assertTrue(status["mutation_performed"])
        self.assertNotIn("test-token", json.dumps(status))
        self.assertTrue(any(call[0] == "PUT" and call[1].startswith("/vault/Overseer/Knowledge/Crew/ezri/") for call in obsidian.calls))

    def test_documents_cli_status_and_search_use_env_file(self):
        with tempfile.TemporaryDirectory() as directory, LocalFakeObsidianServer() as obsidian:
            env_file = Path(directory) / "obsidian.env"
            env_file.write_text(
                f"OBSIDIAN_BASE_URL={obsidian.url}\nOBSIDIAN_API_KEY=test-token\n",
                encoding="utf-8",
            )
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = cli_main(["documents-status", "--env-file", str(env_file)])
            status = json.loads(stdout.getvalue())

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                search_exit = cli_main(
                    [
                        "documents-search",
                        "--env-file",
                        str(env_file),
                        "--query",
                        "Overseer",
                        "--context-length",
                        "20",
                    ]
                )
            search = json.loads(stdout.getvalue())

        self.assertEqual(exit_code, 0)
        self.assertEqual(search_exit, 0)
        self.assertTrue(status["available"])
        self.assertEqual(search["count"], 1)

    def test_documents_cli_write_uses_content_file(self):
        with tempfile.TemporaryDirectory() as directory, LocalFakeObsidianServer() as obsidian:
            env_file = Path(directory) / "obsidian.env"
            content_file = Path(directory) / "note.md"
            env_file.write_text(
                f"OBSIDIAN_BASE_URL={obsidian.url}\nOBSIDIAN_API_KEY=test-token\n",
                encoding="utf-8",
            )
            content_file.write_text("## Operator note\n", encoding="utf-8")
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = cli_main(
                    [
                        "documents-write-note",
                        "--env-file",
                        str(env_file),
                        "--path",
                        "Overseer/Inbox/operator-note.md",
                        "--content-file",
                        str(content_file),
                    ]
                )
            status = json.loads(stdout.getvalue())

        self.assertEqual(exit_code, 0)
        self.assertEqual(status["path"], "Overseer/Inbox/operator-note.md")
        self.assertTrue(status["mutation_performed"])

    def test_knowledge_capture_cli_supports_dry_run(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            record_crew_message_status(
                store_path,
                OwnerDomain.DAX.value,
                "Document checkout",
                "Capture the latest virtual asset checkout.",
                RiskLevel.MEDIUM.value,
                message_id="crew.dax.document-checkout",
                created_at="2026-07-20T12:00:00+00:00",
            )
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = cli_main(
                    [
                        "capture-knowledge-events",
                        "--store",
                        str(store_path),
                        "--kind",
                        "crew",
                        "--limit",
                        "3",
                        "--dry-run",
                    ]
                )
            status = json.loads(stdout.getvalue())

        self.assertEqual(exit_code, 0)
        self.assertEqual(status["candidate_count"], 1)
        self.assertEqual(status["items"][0]["path"], "Overseer/Knowledge/Crew/dax/crew.dax.document-checkout.md")

    def test_api_exposes_documents_routes_behind_overseer_auth(self):
        with tempfile.TemporaryDirectory() as directory, LocalFakeObsidianServer() as obsidian:
            env_file = Path(directory) / "obsidian.env"
            env_file.write_text(
                f"OBSIDIAN_BASE_URL={obsidian.url}\nOBSIDIAN_API_KEY=test-token\n",
                encoding="utf-8",
            )
            store_path = Path(directory) / "overseer.sqlite3"

            with patch.object(overseer_api, "documents_config_status", lambda: overseer_documents.documents_config_status(str(env_file))):
                with patch.object(
                    overseer_api,
                    "documents_list_notes_status",
                    lambda folder="": overseer_documents.documents_list_notes_status(str(env_file), folder),
                ):
                    with patch.object(
                        overseer_api,
                        "documents_search_status",
                        lambda query="", context_length=100: overseer_documents.documents_search_status(str(env_file), query, context_length),
                    ):
                        with LocalOverseerApiServer(store_path, auth_token="local-secret") as server:
                            status = server.get("/documents/status")
                            notes = server.get("/documents/notes?folder=Overseer")
                            search = server.post("/documents/search", {"query": "Overseer"})

            self.assertTrue(status["available"])
            self.assertEqual(notes["count"], 2)
            self.assertEqual(search["count"], 1)

    def test_git_status_reports_branch_remote_links_and_working_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            repo_path = Path(directory) / "repo"
            repo_path.mkdir()
            subprocess.run(("git", "init", "-b", "main"), cwd=repo_path, check=True, capture_output=True, text=True)
            subprocess.run(("git", "config", "user.email", "test@example.invalid"), cwd=repo_path, check=True)
            subprocess.run(("git", "config", "user.name", "Overseer Test"), cwd=repo_path, check=True)
            (repo_path / "README.md").write_text("# Test\n", encoding="utf-8")
            subprocess.run(("git", "add", "README.md"), cwd=repo_path, check=True)
            subprocess.run(("git", "commit", "-m", "Initialize test repo"), cwd=repo_path, check=True, capture_output=True, text=True)
            subprocess.run(
                ("git", "remote", "add", "origin", "git@github.com:example/overseer-test.git"),
                cwd=repo_path,
                check=True,
            )
            (repo_path / "README.md").write_text("# Test\n\nChanged\n", encoding="utf-8")
            (repo_path / "notes.md").write_text("draft\n", encoding="utf-8")

            status = git_status_status(repo_path)

        self.assertEqual(status["branch"], "main")
        self.assertTrue(status["dirty"])
        self.assertEqual(status["changed"], 2)
        self.assertEqual(status["unstaged"], 1)
        self.assertEqual(status["untracked"], 1)
        self.assertEqual(status["remote"]["owner"], "example")
        self.assertEqual(status["remote"]["repo"], "overseer-test")
        self.assertEqual(status["links"]["repository"], "https://github.com/example/overseer-test")
        self.assertIn("/tree/main", status["links"]["branch"])
        self.assertIn("/commit/", status["links"]["commit"])
        self.assertEqual(status["files"], status["status_lines"])
        self.assertEqual(len(status["files"]), 2)
        self.assertEqual(status["account"]["repository_count"], 1)
        self.assertEqual(status["account"]["dirty_count"], 1)
        self.assertEqual(status["account"]["repositories"][0]["relative_path"], "repo")
        self.assertTrue(status["account"]["repositories"][0]["is_current"])

    def test_api_exposes_knowledge_capture_routes_behind_overseer_auth(self):
        with tempfile.TemporaryDirectory() as directory, LocalFakeObsidianServer() as obsidian:
            env_file = Path(directory) / "obsidian.env"
            env_file.write_text(
                f"OBSIDIAN_BASE_URL={obsidian.url}\nOBSIDIAN_API_KEY=test-token\n",
                encoding="utf-8",
            )
            store_path = Path(directory) / "overseer.sqlite3"
            record_crew_message_status(
                store_path,
                OwnerDomain.EZRI.value,
                "Capture API route",
                "Capture via the API route.",
                RiskLevel.LOW.value,
                message_id="crew.ezri.capture-api-route",
                created_at="2026-07-20T12:00:00+00:00",
            )

            def capture_with_env(path, kinds=(), limit=50, dry_run=False):
                return overseer_knowledge.knowledge_capture_status(path, str(env_file), kinds, limit, dry_run)

            with patch.object(overseer_api, "knowledge_capture_status", capture_with_env):
                with LocalOverseerApiServer(store_path, auth_token="local-secret") as server:
                    plan = server.get("/documents/knowledge-capture-plan?kind=crew&limit=5")
                    captured = server.post(
                        "/documents/knowledge-capture",
                        {"kinds": ["crew"], "limit": 5, "dry_run": False},
                    )

        self.assertEqual(plan["candidate_count"], 1)
        self.assertTrue(plan["dry_run"])
        self.assertEqual(captured["captured"], 1)
        self.assertTrue(any(call[0] == "PUT" and call[1].startswith("/vault/Overseer/Knowledge/Crew/ezri/") for call in obsidian.calls))

    def test_api_and_client_expose_git_status_for_ezri(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            payload = {
                "branch": "main",
                "short_head": "abc1234",
                "dirty": False,
                "changed": 0,
                "remote": {"web_url": "https://github.com/example/overseer-test"},
                "links": {"repository": "https://github.com/example/overseer-test"},
                "status_lines": [],
            }

            with patch.object(overseer_api, "git_status_status", lambda repo_path=None: payload):
                with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                    direct = server.get("/git/status")
                    client = OverseerApiClient(server.url, auth_token="client-secret")
                    via_client = client.git_status()

        self.assertEqual(direct["branch"], "main")
        self.assertEqual(via_client["remote"]["web_url"], "https://github.com/example/overseer-test")

    def test_loopback_api_serves_operator_console_without_token(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            with LocalOverseerApiServer(store_path, auth_token="local-secret") as server:
                html, content_type = server.get_text("/ui")
                favicon_request = Request(f"{server.url}/favicon.ico")
                with urlopen(favicon_request, timeout=5) as favicon_response:
                    favicon_status = favicon_response.status
                auth_check = server.get("/auth-check")
                with self.assertRaises(HTTPError) as error:
                    urlopen(f"{server.url}/operator-dashboard", timeout=5)

            self.assertIn("text/html", content_type)
            self.assertEqual(favicon_status, 204)
            self.assertTrue(auth_check["authorized"])
            self.assertIn("<title>Overseer</title>", html)
            self.assertIn("Station operations", html)
            self.assertIn("Overseer API token", html)
            self.assertIn("enter Overseer API token", html)
            self.assertIn("runtime: \"/runtime-status\"", html)
            self.assertIn("Runtime Heartbeat", html)
            self.assertIn("Host Inspection Freshness", html)
            self.assertIn("freshnessTone", html)
            self.assertIn('policyHelper: "/admin/policy-customization-helper"', html)
            self.assertIn("crewStation(name)", html)
            self.assertIn("aside::before", html)
            self.assertIn("--lcars-amber", html)
            self.assertIn("function stateTone(value)", html)
            self.assertIn(".pill.pending", html)
            self.assertIn("/operator-dashboard", html)
            self.assertIn("crewMessages: \"/crew/messages\"", html)
            self.assertIn("Crew Queue", html)
            self.assertIn("Dispatch Blocks", html)
            self.assertIn("Recent Crew Dispatches", html)
            self.assertIn("Open Queue", html)
            self.assertIn("Dispatch History", html)
            self.assertIn("Blocked Reasons", html)
            self.assertIn("mini-metrics", html)
            self.assertIn(".field.span-4 { grid-column: span 4; }", html)
            self.assertIn(".field.span-8, .field.span-9, .field.span-12 { grid-column: span 6; }", html)
            self.assertIn("data-action=\"send-crew-message\"", html)
            self.assertIn("data-action=\"dispatch-crew-messages\"", html)
            self.assertIn("/crew/dispatch", html)
            self.assertIn("MCP API quota scheduling", html)
            self.assertIn("limit.mcp.api.calls.daily", html)
            self.assertIn("body[data-station=\"ezri\"]", html)
            self.assertIn("document.body.dataset.station = view", html)
            self.assertIn("function stationIntro", html)
            self.assertIn('apiBase = protectedGatewayPath ? "/Overseer" : ""', html)
            self.assertIn("tokenStore = protectedGatewayPath ? sessionStorage : localStorage", html)
            self.assertIn('auth: "/auth-check"', html)
            self.assertIn('requiredEndpointKeys = new Set(["auth"])', html)
            self.assertIn("authPayload = await getJson(endpoints.auth)", html)
            self.assertIn("filter(([key]) => !requiredEndpointKeys.has(key))", html)
            self.assertIn("mapEndpointEntries(endpointEntries, 4)", html)
            self.assertIn("Loaded with panel errors", html)
            self.assertIn("data-view-target", html)
            self.assertIn("data-fill", html)
            self.assertIn("function authorizationDecisionBoard", html)
            self.assertIn("Approval Decisions", html)
            self.assertIn("Request Changes", html)
            self.assertIn("function domainView", html)
            self.assertIn("data-action=\"register-resource\"", html)
            self.assertIn("/resources", html)
            self.assertIn("data-view=\"claims\"", html)
            self.assertIn("data-view=\"ezri\"", html)
            self.assertIn("<button data-view=\"ezri\">Documents</button>", html)
            self.assertIn("<section id=\"ezri\"", html)
            self.assertIn("function renderEzri()", html)
            self.assertIn('stationIntro("Ezri", "Knowledge Base"', html)
            self.assertIn('gitStatus: "/git/status"', html)
            self.assertIn("Git Runtime", html)
            self.assertIn("Account Repositories", html)
            self.assertIn("Current Repo Links", html)
            self.assertIn("Current Working Tree", html)
            self.assertIn("Dirty Repos", html)
            self.assertIn("Workflows", html)
            self.assertIn("Approve a pending admin request", html)
            self.assertIn("View VM leases and virtual claims", html)
            self.assertIn("View logs from an unhealthy service", html)
            self.assertIn("Check an exhausted limit refresh", html)
            self.assertIn("Adjust service schedule", html)
            self.assertIn("Overseer/Runbooks/operator-workflows.md", html)
            self.assertIn("function ezriWorkflowRows()", html)
            self.assertIn("function workflowFill(row)", html)
            self.assertIn("Search and List", html)
            self.assertIn("Current Folder", html)
            self.assertIn("Capture Queue", html)
            self.assertIn("data-action=\"documents-capture-knowledge\"", html)
            self.assertIn("Documentation support", html)
            self.assertNotIn("Knowledge Base Candidates", html)
            self.assertNotIn("cyanheads/obsidian-mcp-server", html)
            self.assertIn("claimCleanup: \"/claims/cleanup-plan\"", html)
            self.assertIn("data-action=\"request-claim\"", html)
            self.assertIn("data-action=\"approve-claim\"", html)
            self.assertIn("data-action=\"activate-claim\"", html)
            self.assertIn("data-action=\"release-claim\"", html)
            self.assertIn("data-action=\"plan-admin-change\"", html)
            self.assertIn("data-action=\"approve-admin-change\"", html)
            self.assertIn("data-action=\"execute-admin-change\"", html)
            self.assertIn("data-action=\"cancel-admin-change\"", html)
            self.assertIn("Adapter Enablement", html)
            self.assertIn("data-action=\"request-admin-adapter-enablement\"", html)
            self.assertIn("data-action=\"approve-admin-adapter-enablement\"", html)
            self.assertIn("/admin/adapter-enablement-requests", html)
            self.assertIn("Policy Customization Helper", html)
            self.assertIn("data-action=\"build-policy-profile\"", html)
            self.assertIn("/admin/policy-customization-helper/profile", html)
            self.assertIn("Policy Warning Acceptance", html)
            self.assertIn("data-action=\"request-policy-warning\"", html)
            self.assertIn("data-action=\"approve-policy-warning\"", html)
            self.assertIn("/admin/policy-warning-requests", html)
            self.assertIn("data-action=\"discover-storage\"", html)
            self.assertIn("healthSummary: \"/health-summary\"", html)
            self.assertIn("data-action=\"register-health-target\"", html)
            self.assertIn("/health-targets", html)
            self.assertIn("data-action=\"discover-listeners\"", html)
            self.assertIn("data-action=\"run-health-probes\"", html)
            self.assertEqual(error.exception.code, 401)

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

    def test_loopback_api_discovers_virtual_listeners(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            original = overseer_api.discover_virtual_listeners_status

            def fake_discover(store_path):
                store = SQLiteStore(store_path)
                try:
                    store.save_resource(
                        Resource(
                            id="listener.tcp.127-0-0-1.8766",
                            name="TCP 127.0.0.1:8766",
                            type=ResourceType.VIRTUAL_ASSET,
                            owner_domain=OwnerDomain.DAX,
                            risk_level=RiskLevel.LOW,
                            identifiers={"kind": "proxy", "host": "127.0.0.1", "ports": [8766]},
                            exclusive_groups=frozenset({"tcp.8766"}),
                        )
                    )
                finally:
                    store.close()
                return {"store": str(store_path), "count": 1, "assets": []}

            try:
                overseer_api.discover_virtual_listeners_status = fake_discover
                with LocalOverseerApiServer(store_path) as server:
                    discovered = server.post("/virtual/discover-listeners", {})
                    summary = server.get("/virtual-summary")
            finally:
                overseer_api.discover_virtual_listeners_status = original

            self.assertEqual(discovered["count"], 1)
            self.assertEqual(summary["assets"], 1)
            self.assertEqual(summary["items"][0]["id"], "listener.tcp.127-0-0-1.8766")

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

    def test_api_records_health_target(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="svc.api.health-target",
                    name="API Health Target Service",
                    type=ResourceType.SERVICE,
                    owner_domain=OwnerDomain.JULIAN,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="local-secret") as server:
                status = server.post(
                    "/health-targets",
                    {
                        "target_id": "health.api.ready",
                        "resource_id": "svc.api.health-target",
                        "name": "API Ready",
                        "probe_type": "process",
                        "target": f"pid:{os.getpid()}",
                    },
                )

            self.assertTrue(status["mutation_performed"])
            self.assertFalse(status["host_mutation_performed"])
            self.assertEqual(status["target_id"], "health.api.ready")

    def test_api_rejects_health_target_for_unknown_resource(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            with LocalOverseerApiServer(store_path) as server:
                with self.assertRaises(HTTPError) as error:
                    server.post(
                        "/health-targets",
                        {
                            "target_id": "health.api.missing",
                            "resource_id": "svc.api.missing",
                            "name": "Missing",
                            "probe_type": "json",
                            "target": "http://127.0.0.1:1/health",
                        },
                    )
                body = json.loads(error.exception.read().decode("utf-8"))

            self.assertEqual(error.exception.code, 400)
            self.assertEqual(body["error"], "unknown resource: svc.api.missing")


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

    def test_client_uses_documents_routes(self):
        with tempfile.TemporaryDirectory() as directory, LocalFakeObsidianServer() as obsidian:
            env_file = Path(directory) / "obsidian.env"
            env_file.write_text(
                f"OBSIDIAN_BASE_URL={obsidian.url}\nOBSIDIAN_API_KEY=test-token\n",
                encoding="utf-8",
            )
            store_path = Path(directory) / "overseer.sqlite3"

            with patch.object(overseer_api, "documents_config_status", lambda: overseer_documents.documents_config_status(str(env_file))):
                with patch.object(
                    overseer_api,
                    "documents_list_notes_status",
                    lambda folder="": overseer_documents.documents_list_notes_status(str(env_file), folder),
                ):
                    with patch.object(
                        overseer_api,
                        "documents_search_status",
                        lambda query="", context_length=100: overseer_documents.documents_search_status(str(env_file), query, context_length),
                    ):
                        with patch.object(
                            overseer_api,
                            "documents_write_note_status",
                            lambda path="", content="", mode="append": overseer_documents.documents_write_note_status(
                                str(env_file),
                                path,
                                content,
                                mode,
                            ),
                        ):
                            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                                client = OverseerApiClient(server.url, auth_token="client-secret")
                                status = client.documents_status()
                                notes = client.documents_notes("Overseer")
                                search = client.documents_search("Overseer", context_length=20)
                                write = client.documents_write_note(
                                    "Overseer/Inbox/operator-note.md",
                                    "## Operator note\n",
                                )

            self.assertTrue(status["available"])
            self.assertEqual(notes["count"], 2)
            self.assertEqual(search["count"], 1)
            self.assertTrue(write["mutation_performed"])

    def test_client_uses_knowledge_capture_routes(self):
        with tempfile.TemporaryDirectory() as directory, LocalFakeObsidianServer() as obsidian:
            env_file = Path(directory) / "obsidian.env"
            env_file.write_text(
                f"OBSIDIAN_BASE_URL={obsidian.url}\nOBSIDIAN_API_KEY=test-token\n",
                encoding="utf-8",
            )
            store_path = Path(directory) / "overseer.sqlite3"
            record_crew_message_status(
                store_path,
                OwnerDomain.EZRI.value,
                "Capture client route",
                "Capture via the client helper.",
                RiskLevel.LOW.value,
                message_id="crew.ezri.capture-client-route",
                created_at="2026-07-20T12:00:00+00:00",
            )

            def capture_with_env(path, kinds=(), limit=50, dry_run=False):
                return overseer_knowledge.knowledge_capture_status(path, str(env_file), kinds, limit, dry_run)

            with patch.object(overseer_api, "knowledge_capture_status", capture_with_env):
                with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                    client = OverseerApiClient(server.url, auth_token="client-secret")
                    plan = client.documents_knowledge_capture_plan(kinds=("crew",), limit=5)
                    captured = client.documents_capture_knowledge(kinds=("crew",), limit=5)

        self.assertEqual(plan["candidate_count"], 1)
        self.assertTrue(plan["dry_run"])
        self.assertEqual(captured["captured"], 1)
        self.assertTrue(any(call[0] == "PUT" and call[1].startswith("/vault/Overseer/Knowledge/Crew/ezri/") for call in obsidian.calls))

    def test_client_records_resource(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                status = client.record_resource(
                    "svc.client.registered",
                    "Client Registered Service",
                    "service",
                    "julian",
                    "low",
                    identifiers={"kind": "api-test"},
                )

            self.assertEqual(status["resource"]["id"], "svc.client.registered")
            self.assertEqual(status["resource"]["identifiers"]["kind"], "api-test")
            self.assertTrue(status["mutation_performed"])

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

    def test_client_requests_and_approves_daemon_migration(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_runtime_heartbeat(
                RuntimeHeartbeat(
                    id="overseer",
                    service_name="overseer",
                    started_at="2026-07-18T16:00:00+00:00",
                    last_tick_at="2026-07-18T16:01:00+00:00",
                    tick_count=7,
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                plan = client.daemon_migration_plan()
                requested = client.request_daemon_migration("sisko", requested_at="2026-07-18T16:05:00+00:00")
                pending = client.authorizations_required()
                approved = client.approve_daemon_migration(
                    requested["approval_id"],
                    "sisko",
                    approved_at="2026-07-18T16:10:00+00:00",
                )
                after = client.authorizations_required()

            self.assertEqual(plan["mode"], "read_only_daemon_migration_plan")
            self.assertFalse(plan["mutation_performed"])
            self.assertEqual(plan["current_runtime_evidence"]["tick_count"], 7)
            self.assertTrue(requested["mutation_performed"])
            self.assertEqual(requested["approval_status"], ApprovalStatus.PENDING.value)
            self.assertEqual(pending["pending_daemon_migration_approval_count"], 1)
            self.assertEqual(pending["daemon_migration_approvals"][0]["service_name"], "overseer")
            self.assertEqual(approved["approval_status"], ApprovalStatus.APPROVED.value)
            self.assertTrue(approved["daemon_migration_approval"])
            self.assertEqual(after["pending_daemon_migration_approval_count"], 0)

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

    def test_client_reads_filtered_approvals_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_approval(
                ApprovalRequest(
                    id="approval.client.pending",
                    subject_id="claim.client.pending",
                    approval_level=ApprovalLevel.SISKO,
                    requester_thread="thread-client",
                    owner_domain=OwnerDomain.DAX,
                    reason="client pending approval",
                )
            )
            store.save_approval(
                ApprovalRequest(
                    id="approval.client.approved",
                    subject_id="claim.client.approved",
                    approval_level=ApprovalLevel.HUMAN,
                    requester_thread="thread-client",
                    owner_domain=OwnerDomain.SISKO,
                    reason="client approved approval",
                    status=ApprovalStatus.APPROVED,
                    decided_by="sisko",
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                status = client.approvals_summary(status=ApprovalStatus.PENDING.value, owner=OwnerDomain.DAX.value)

            self.assertEqual(status["approval_count"], 1)
            self.assertEqual(status["pending_count"], 1)
            self.assertEqual(status["approvals"][0]["id"], "approval.client.pending")
            self.assertEqual(status["filters"]["status"], ApprovalStatus.PENDING.value)

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

    def test_client_requests_usage_continuation_and_reads_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_usage_limit(
                UsageLimit(
                    id="limit.client.ai",
                    resource_id="svc.client.ai",
                    kind=LimitKind.TOKENS,
                    capacity=1000,
                    remaining=0,
                    resets_at="2026-07-18T19:00:00+00:00",
                    window="hourly",
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                request_status = client.request_usage_continuation(
                    "work.client.ai",
                    "limit.client.ai",
                    "svc.client.ai",
                    "thread-client",
                    100,
                    "continue client work",
                )
                plan = client.usage_continuation_plan()

            self.assertFalse(request_status["host_mutation_performed"])
            self.assertEqual(request_status["schedule"]["status"], ScheduledWorkStatus.WAITING.value)
            self.assertEqual(plan["continuation_requests"], 1)
            self.assertEqual(plan["waiting"], 1)

    def test_client_records_usage_limit_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                status = client.record_usage_limit(
                    "limit.client.ai",
                    "svc.client.ai",
                    LimitKind.TOKENS.value,
                    1000,
                    900,
                    "hourly",
                    resets_at="2026-07-18T19:00:00+00:00",
                    observed_at="2026-07-18T18:00:00+00:00",
                    confidence=0.8,
                )
                summary = client.usage_summary()

            self.assertTrue(status["mutation_performed"])
            self.assertEqual(status["limit"]["remaining"], 900)
            self.assertEqual(summary["limits"], 1)
            self.assertEqual(summary["items"][0]["confidence"], 0.8)

    def test_client_dispatches_ready_usage_continuation(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_usage_limit(
                UsageLimit(
                    id="limit.client.github",
                    resource_id="svc.client.github",
                    kind=LimitKind.REQUESTS,
                    capacity=5000,
                    remaining=5000,
                    resets_at="2026-07-18T19:00:00+00:00",
                    window="hourly",
                )
            )
            store.save_usage_continuation_request(
                UsageContinuationRequest(
                    id="work.client.github",
                    limit_id="limit.client.github",
                    resource_id="svc.client.github",
                    owner_thread="thread-client",
                    requested_units=100,
                    intent="continue client work",
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                dispatch = client.dispatch_usage_continuations(
                    dispatched_by="quark",
                    dispatched_at="2026-07-18T10:00:00+00:00",
                )
                plan = client.usage_continuation_plan()

            self.assertFalse(dispatch["host_mutation_performed"])
            self.assertEqual(dispatch["dispatched"], 1)
            self.assertEqual(dispatch["dispatches"][0]["request_id"], "work.client.github")
            self.assertEqual(plan["dispatches"], 1)
            self.assertEqual(plan["undispatched_ready"], 0)

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

    def test_client_discovers_path_physical_identities(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            root = Path(directory) / "serial"
            root.mkdir()
            (root / "usb-client-a").write_text("", encoding="utf-8")

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                discovered = client.discover_physical((str(root),))
                summary = client.physical_summary()

            self.assertEqual(discovered["count"], 1)
            self.assertEqual(discovered["assets"][0]["stable_id"], "serial.usb-client-a")
            self.assertEqual(summary["assets"], 1)
            self.assertEqual(summary["items"][0]["kind"], PhysicalAssetKind.SERIAL_PORT.value)

    def test_client_discovers_storage_physical_identities(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            root = Path(directory) / "block"
            device = root / "sdc" / "device"
            device.mkdir(parents=True)
            (root / "sdc" / "removable").write_text("1\n", encoding="utf-8")
            (root / "sdc" / "ro").write_text("0\n", encoding="utf-8")
            (device / "serial").write_text("CLIENT-STORAGE\n", encoding="utf-8")

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                discovered = client.discover_storage(str(root))
                summary = client.physical_summary()

            self.assertEqual(discovered["count"], 1)
            self.assertEqual(discovered["assets"][0]["stable_id"], "storage.client-storage")
            self.assertEqual(summary["assets"], 1)
            self.assertEqual(summary["items"][0]["kind"], PhysicalAssetKind.STORAGE_ARRAY.value)

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
                status = client.operator_dashboard(include_summaries=True)

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

    def test_client_reads_package_status(self):
        original = overseer_api.inspect_packages_status
        overseer_api.inspect_packages_status = lambda: {
            "status": "ok",
            "upgradable": 1,
            "items": [{"name": "openssl"}],
        }
        try:
            with tempfile.TemporaryDirectory() as directory:
                store_path = Path(directory) / "overseer.sqlite3"

                with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                    client = OverseerApiClient(server.url, auth_token="client-secret")
                    status = client.package_status()
        finally:
            overseer_api.inspect_packages_status = original

        self.assertEqual(status["status"], "ok")
        self.assertEqual(status["upgradable"], 1)
        self.assertEqual(status["items"][0]["name"], "openssl")

    def test_client_plans_package_updates(self):
        original = overseer_api.plan_package_updates_status
        overseer_api.plan_package_updates_status = lambda store_path, **kwargs: {
            "store": str(store_path),
            "plans": 2,
            "selected_packages": tuple(kwargs["packages"]),
            "mutation_performed": True,
        }
        try:
            with tempfile.TemporaryDirectory() as directory:
                store_path = Path(directory) / "overseer.sqlite3"

                with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                    client = OverseerApiClient(server.url, auth_token="client-secret")
                    status = client.plan_package_updates(("openssl",), captured_at="2026-07-19T14:45:00+00:00")
        finally:
            overseer_api.plan_package_updates_status = original

        self.assertEqual(status["plans"], 2)
        self.assertEqual(status["selected_packages"], ["openssl"])

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

    def test_client_discovers_user_services(self):
        original = overseer_api.discover_user_services_status
        overseer_api.discover_user_services_status = lambda store_path: {
            "store": str(store_path),
            "count": 1,
            "items": [{"id": "svc.systemd-user.overseer-api", "unit": "overseer-api.service"}],
        }
        try:
            with tempfile.TemporaryDirectory() as directory:
                store_path = Path(directory) / "overseer.sqlite3"

                with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                    client = OverseerApiClient(server.url, auth_token="client-secret")
                    status = client.discover_user_services()
        finally:
            overseer_api.discover_user_services_status = original

        self.assertEqual(status["count"], 1)
        self.assertEqual(status["items"][0]["unit"], "overseer-api.service")

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

    def test_client_reads_host_security_listener_review_queue(self):
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
                status = client.host_security_listener_review_queue()

            self.assertEqual(status["listener_count"], 1)
            self.assertEqual(status["needs_exposure_review"], 1)
            self.assertEqual(status["items"][0]["listener"], "0.0.0.0:22")
            self.assertEqual(status["items"][0]["queue_status"], "needs_exposure_review")

    def test_client_plans_host_security_listener_queue_remediations(self):
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
                status = client.plan_host_security_listener_queue_remediations({"requested_by": "odo"})

            self.assertEqual(status["candidate_ports"], 1)
            self.assertEqual(status["staged_count"], 1)
            self.assertEqual(status["staged"][0]["target"], "tcp/22")
            self.assertFalse(status["host_mutation_performed"])

    def test_client_reads_host_security_source_review_queue(self):
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
                status = client.host_security_source_review_queue()

            self.assertEqual(status["connection_count"], 1)
            self.assertEqual(status["needs_review"], 1)
            self.assertEqual(status["items"][0]["remote_address"], "8.8.8.8")
            self.assertEqual(status["items"][0]["queue_status"], "needs_review")

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

    def test_client_dispatch_ids_review_records_missing_codex_project(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            missing_registry = Path(directory) / "missing-codex-projects.csv"

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                block_plan = client.plan_admin_change(
                    {
                        "plan_id": "admin.host-security.block-source.api",
                        "kind": AdminChangeKind.BLOCK_IP.value,
                        "target": "192.0.2.10",
                        "reason": "stage hostile source block",
                        "current_state": "pending IDS review",
                    }
                )
                ids_package = client.prepare_host_security_ids_review_package({"plan_id": block_plan["id"]})
                dispatched = client.dispatch_host_security_ids_review_package(
                    {
                        "package_id": ids_package["id"],
                        "dispatched_by": "odo",
                        "codex_projects_registry": str(missing_registry),
                    }
                )
                summary = client.host_security_ids_review_summary()
                pending = client.authorizations_required()
                prompt_exists = Path(dispatched["prompt_path"]).exists()

            self.assertEqual(dispatched["status"], IDSReviewPackageStatus.PREPARED.value)
            self.assertEqual(dispatched["dispatch_status"], "not_found")
            self.assertTrue(prompt_exists)
            self.assertEqual(summary["packages"][0]["next_step"], "repair Intrusion Detection codex-project dispatch before approval")
            self.assertEqual(
                pending["pending"][0]["ids_review_next_step"],
                "repair Intrusion Detection codex-project dispatch before approval",
            )

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
            self.assertEqual(status["steps"][0]["command"][0:3], ["sudo", "firewall-cmd", "--permanent"])
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

    def test_client_reads_policy_customization_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                status = client.policy_customization_helper()

            self.assertEqual(status["profile"]["name"], "best-practice")
            self.assertIn("questions", status)
            self.assertIn("next_step", status)

    def test_client_reads_active_policy_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store_path = root / "overseer.sqlite3"
            (root / "policy-profile.json").write_text(
                json.dumps({"profile": {"name": "client-active", "block_warnings_until_accepted": False}}),
                encoding="utf-8",
            )

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                status = client.active_policy_profile()

            self.assertEqual(status["profile"]["name"], "client-active")
            self.assertEqual(status["source"], "store_sibling_file")
            self.assertTrue(status["active"])

    def test_operator_console_loads_active_policy_profile(self):
        self.assertIn('activePolicy: "/admin/active-policy-profile"', OPERATOR_CONSOLE_HTML)
        self.assertIn("Active Policy Profile", OPERATOR_CONSOLE_HTML)
        self.assertIn('packageStatus: "/maintenance/package-status"', OPERATOR_CONSOLE_HTML)
        self.assertIn("Package Status", OPERATOR_CONSOLE_HTML)
        self.assertIn('postJson("/services/discover-user"', OPERATOR_CONSOLE_HTML)
        self.assertIn("Discover Services", OPERATOR_CONSOLE_HTML)
        self.assertIn('postJson("/physical/discover"', OPERATOR_CONSOLE_HTML)
        self.assertIn("Discover Devices", OPERATOR_CONSOLE_HTML)
        self.assertIn('postJson("/maintenance/package-update-plans"', OPERATOR_CONSOLE_HTML)
        self.assertIn("Plan Updates", OPERATOR_CONSOLE_HTML)
        self.assertIn('postJson("/codex-projects/discover-threads"', OPERATOR_CONSOLE_HTML)
        self.assertIn("Discover Codex Threads", OPERATOR_CONSOLE_HTML)
        self.assertIn('postJson("/usage-limits"', OPERATOR_CONSOLE_HTML)
        self.assertIn('postJson("/usage/continuation-requests"', OPERATOR_CONSOLE_HTML)
        self.assertIn('postJson("/usage/continuation-dispatches"', OPERATOR_CONSOLE_HTML)
        self.assertIn('data-action="record-usage-limit"', OPERATOR_CONSOLE_HTML)
        self.assertIn('data-action="request-usage-continuation"', OPERATOR_CONSOLE_HTML)
        self.assertIn('data-action="dispatch-usage-continuations"', OPERATOR_CONSOLE_HTML)
        self.assertIn('postJson("/host/inspect"', OPERATOR_CONSOLE_HTML)
        self.assertIn('postJson("/host/security/advance"', OPERATOR_CONSOLE_HTML)
        self.assertIn('postJson("/host/security/remediations/plans"', OPERATOR_CONSOLE_HTML)
        self.assertIn('postJson("/host/security/source-reviews"', OPERATOR_CONSOLE_HTML)
        self.assertIn('postJson("/host/security/source-reviews/block-plans"', OPERATOR_CONSOLE_HTML)
        self.assertIn('postJson("/host/security/ids-review-packages"', OPERATOR_CONSOLE_HTML)
        self.assertIn('postJson("/host/security/ids-review-packages/results"', OPERATOR_CONSOLE_HTML)
        self.assertIn('data-action="inspect-host"', OPERATOR_CONSOLE_HTML)
        self.assertIn('data-action="advance-odo-security"', OPERATOR_CONSOLE_HTML)
        self.assertIn('data-action="record-source-review"', OPERATOR_CONSOLE_HTML)
        self.assertIn('data-action="prepare-ids-review-package"', OPERATOR_CONSOLE_HTML)
        self.assertIn("approve-and-execute-admin-change", OPERATOR_CONSOLE_HTML)
        self.assertIn("Plain-English Review", OPERATOR_CONSOLE_HTML)
        self.assertIn("Odo Security Team", OPERATOR_CONSOLE_HTML)
        self.assertIn("Odo IDS", OPERATOR_CONSOLE_HTML)
        self.assertIn("Odo Firewall", OPERATOR_CONSOLE_HTML)
        self.assertIn("odo_ids", OPERATOR_CONSOLE_HTML)
        self.assertIn("odo_firewall", OPERATOR_CONSOLE_HTML)
        self.assertIn('adminArchivePlan: "/admin/history-archive-plan"', OPERATOR_CONSOLE_HTML)
        self.assertIn('adminArchives: "/admin/history-archives"', OPERATOR_CONSOLE_HTML)
        self.assertIn('postJson("/admin/history-archive-requests"', OPERATOR_CONSOLE_HTML)
        self.assertIn('postJson("/admin/history-archive-requests/approve"', OPERATOR_CONSOLE_HTML)
        self.assertIn('postJson("/admin/history-archive"', OPERATOR_CONSOLE_HTML)
        self.assertIn('postJson("/admin/history-restore-requests"', OPERATOR_CONSOLE_HTML)
        self.assertIn('postJson("/admin/history-restore-requests/approve"', OPERATOR_CONSOLE_HTML)
        self.assertIn('postJson("/admin/history-unarchive"', OPERATOR_CONSOLE_HTML)
        self.assertIn('data-action="request-admin-archive"', OPERATOR_CONSOLE_HTML)
        self.assertIn('data-action="unarchive-admin-history"', OPERATOR_CONSOLE_HTML)

    def test_client_builds_policy_profile_from_answers(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                status = client.build_policy_profile(
                    {
                        "name": "client-profile",
                        "warnings-block": False,
                    }
                )

            self.assertEqual(status["profile"]["name"], "client-profile")
            self.assertFalse(status["profile"]["block_warnings_until_accepted"])

    def test_client_runs_stored_health_probes(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_health_target(
                HealthTarget(
                    id="health.client.process",
                    resource_id="svc.client.process",
                    name="Client Process",
                    probe_type=ProbeType.PROCESS,
                    target=f"pid:{os.getpid()}",
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                status = client.run_health_probes(timeout_seconds=2, retention_per_target=1)

            self.assertEqual(status["targets"], 1)
            self.assertEqual(status["healthy"], 1)
            self.assertEqual(status["evidence"][0]["status"], HealthStatus.HEALTHY.value)

    def test_probe_stored_health_status_probes_persisted_manual_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_health_target(
                HealthTarget(
                    id="health.manual.stored",
                    resource_id="svc.manual.stored",
                    name="Stored Manual",
                    probe_type=ProbeType.MANUAL,
                    target="manual:degraded?error=operator%20reported%20slow",
                )
            )
            store.close()

            status = probe_stored_health_status(store_path)

        self.assertEqual(status["targets"], 1)
        self.assertEqual(status["unhealthy"], 1)
        self.assertEqual(status["evidence"][0]["status"], HealthStatus.DEGRADED.value)
        self.assertEqual(status["evidence"][0]["error"], "operator reported slow")

    def test_client_records_health_target(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="svc.client.health-target",
                    name="Client Health Target Service",
                    type=ResourceType.SERVICE,
                    owner_domain=OwnerDomain.JULIAN,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                status = client.record_health_target(
                    "health.client.ready",
                    "svc.client.health-target",
                    "Client Ready",
                    "process",
                    f"pid:{os.getpid()}",
                )

            self.assertEqual(status["target_id"], "health.client.ready")
            self.assertEqual(status["owner_domain"], OwnerDomain.JULIAN.value)
            self.assertTrue(status["mutation_performed"])

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

    def test_client_reads_claim_cleanup_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="gateway.cleanup.client",
                    name="Client Cleanup Gateway",
                    type=ResourceType.VIRTUAL_ASSET,
                    owner_domain=OwnerDomain.DAX,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.save_claim(
                Claim(
                    id="claim.cleanup.client.expired",
                    resource_id="gateway.cleanup.client",
                    claim_type=ClaimType.LEASE,
                    owner_thread="thread-client",
                    owner_role=OwnerDomain.DAX,
                    intent="use gateway",
                    requested_action="bind gateway",
                    risk_level=RiskLevel.LOW,
                    status=ClaimStatus.ACTIVE,
                    expires_at="2026-07-18T20:00:00+00:00",
                    release_condition="operator verified work stopped",
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                plan = client.claim_cleanup_plan("2026-07-18T20:30:00+00:00")
                state = client.state()

            self.assertFalse(plan["mutation_performed"])
            self.assertEqual(plan["cleanup_candidates"], 1)
            self.assertEqual(plan["expired_active_like"], 1)
            self.assertEqual(plan["items"][0]["cleanup_action"], "review_expired_active_claim")
            self.assertEqual(state["claims"][0]["status"], ClaimStatus.ACTIVE.value)

    def test_client_requests_and_approves_claim_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="gateway.cleanup.approval.client",
                    name="Client Cleanup Approval Gateway",
                    type=ResourceType.VIRTUAL_ASSET,
                    owner_domain=OwnerDomain.DAX,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.save_claim(
                Claim(
                    id="claim.cleanup.approval.client",
                    resource_id="gateway.cleanup.approval.client",
                    claim_type=ClaimType.LEASE,
                    owner_thread="thread-client",
                    owner_role=OwnerDomain.DAX,
                    intent="use gateway",
                    requested_action="bind gateway",
                    risk_level=RiskLevel.LOW,
                    status=ClaimStatus.ACTIVE,
                    expires_at="2026-07-18T20:00:00+00:00",
                    release_condition="operator verified work stopped",
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                requested = client.request_claim_cleanup(
                    "claim.cleanup.approval.client",
                    "sisko",
                    requested_at="2026-07-18T20:30:00+00:00",
                    now="2026-07-18T20:30:00+00:00",
                )
                pending = client.authorizations_required()
                approved = client.approve_claim_cleanup(
                    requested["approval_id"],
                    "sisko",
                    approved_at="2026-07-18T20:35:00+00:00",
                    now="2026-07-18T20:35:00+00:00",
                )
                after = client.authorizations_required()
                state = client.state()

            self.assertTrue(requested["mutation_performed"])
            self.assertEqual(requested["approval_status"], ApprovalStatus.PENDING.value)
            self.assertEqual(requested["cleanup_action"], "review_expired_active_claim")
            self.assertEqual(pending["pending_claim_cleanup_approval_count"], 1)
            self.assertEqual(pending["claim_cleanup_approvals"][0]["claim_id"], "claim.cleanup.approval.client")
            self.assertEqual(approved["approval_status"], ApprovalStatus.APPROVED.value)
            self.assertTrue(approved["claim_cleanup_approval"])
            self.assertEqual(after["pending_claim_cleanup_approval_count"], 0)
            self.assertEqual(state["claims"][0]["status"], ClaimStatus.ACTIVE.value)

    def test_client_executes_approved_claim_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="gateway.cleanup.execute.client",
                    name="Client Cleanup Execute Gateway",
                    type=ResourceType.VIRTUAL_ASSET,
                    owner_domain=OwnerDomain.DAX,
                    risk_level=RiskLevel.LOW,
                    state=ResourceState.CHECKED_OUT,
                    current_claim_id="claim.cleanup.execute.client",
                )
            )
            store.save_claim(
                Claim(
                    id="claim.cleanup.execute.client",
                    resource_id="gateway.cleanup.execute.client",
                    claim_type=ClaimType.LEASE,
                    owner_thread="thread-client",
                    owner_role=OwnerDomain.DAX,
                    intent="use gateway",
                    requested_action="bind gateway",
                    risk_level=RiskLevel.LOW,
                    status=ClaimStatus.ACTIVE,
                    expires_at="2026-07-18T20:00:00+00:00",
                    release_condition="operator verified work stopped",
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                requested = client.request_claim_cleanup(
                    "claim.cleanup.execute.client",
                    "sisko",
                    now="2026-07-18T20:30:00+00:00",
                )
                client.approve_claim_cleanup(
                    requested["approval_id"],
                    "sisko",
                    now="2026-07-18T20:35:00+00:00",
                )
                executed = client.execute_claim_cleanup(
                    requested["approval_id"],
                    "sisko",
                    executed_at="2026-07-18T20:40:00+00:00",
                    now="2026-07-18T20:40:00+00:00",
                )
                state = client.state()

            self.assertTrue(executed["mutation_performed"])
            self.assertEqual(executed["claim_status_before"], ClaimStatus.ACTIVE.value)
            self.assertEqual(executed["claim_status_after"], ClaimStatus.EXPIRED.value)
            self.assertEqual(state["claims"][0]["status"], ClaimStatus.EXPIRED.value)
            self.assertEqual(state["resources"][0]["state"], ResourceState.AVAILABLE.value)
            self.assertIsNone(state["resources"][0]["current_claim_id"])

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

    def test_client_reads_admin_policies(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                client.plan_admin_change(
                    {
                        "plan_id": "admin.restart.policy",
                        "kind": AdminChangeKind.USER_SERVICE_RESTART.value,
                        "target": "overseer-api.service",
                        "reason": "reload policy code",
                        "current_state": "active",
                    }
                )
                policies = client.admin_policies("admin.restart.policy")

            self.assertEqual(policies["plans"], 1)
            self.assertEqual(policies["block"], 1)
            self.assertEqual(policies["items"][0]["subject_id"], "admin.restart.policy")
            self.assertEqual(policies["items"][0]["checks"][0]["id"], "admin.plan.state")

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

    def test_client_requests_and_approves_admin_policy_warning(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            (Path(directory) / "policy-profile.json").write_text(
                json.dumps({"profile": {"name": "api-warning-profile", "warn_on_apt_upgrade_rollback": True}}),
                encoding="utf-8",
            )

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                adapter_request = client.request_admin_adapter_enablement(
                    {
                        "kind": AdminChangeKind.APT_UPGRADE.value,
                        "requested_by": "sisko",
                    }
                )
                client.approve_admin_adapter_enablement(
                    {
                        "approval_id": adapter_request["approval_id"],
                        "approved_by": "sisko",
                    }
                )
                client.plan_admin_change(
                    {
                        "plan_id": "admin.apt.upgrade.policy-api",
                        "kind": AdminChangeKind.APT_UPGRADE.value,
                        "target": "sqlite3",
                        "packages": ["sqlite3"],
                        "reason": "apply approved package patch",
                        "current_state": "sqlite3 upgrade available",
                    }
                )
                client.approve_admin_change(
                    {
                        "plan_id": "admin.apt.upgrade.policy-api",
                        "approved_by": "operator",
                    }
                )
                requested = client.request_admin_policy_warning(
                    {
                        "plan_id": "admin.apt.upgrade.policy-api",
                        "check_id": "admin.rollback",
                        "requested_by": "sisko",
                    }
                )
                pending = client.authorizations_required()
                approved = client.approve_admin_policy_warning(
                    {
                        "approval_id": requested["approval_id"],
                        "approved_by": "operator",
                    }
                )
                policies = client.admin_policies("admin.apt.upgrade.policy-api")
                checks = {check["id"]: check for check in policies["items"][0]["checks"]}

            self.assertEqual(requested["approval_status"], ApprovalStatus.PENDING.value)
            self.assertEqual(pending["pending_policy_warning_approval_count"], 1)
            self.assertTrue(approved["policy_warning_approval"])
            self.assertEqual(policies["items"][0]["status"], PolicyCheckStatus.PASS.value)
            self.assertEqual(checks["admin.rollback"]["status"], PolicyCheckStatus.PASS.value)

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
            archive_request = request_admin_history_archive_status(
                store_path,
                "sisko",
                "2026-07-18T22:38:00+00:00",
                plan_id=completed["id"],
            )
            approve_admin_history_archive_status(
                store_path,
                archive_request["approval_id"],
                "sisko",
                "2026-07-18T22:39:00+00:00",
            )
            archive_admin_history_status(
                store_path,
                "sisko",
                archive_request["approval_id"],
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

    def test_client_requests_approves_and_executes_admin_history_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            completed = plan_admin_change_status(
                store_path,
                "admin.restart.client.archive",
                AdminChangeKind.USER_SERVICE_RESTART.value,
                "overseer-api.service",
                "reload approved code",
                "active",
            )
            approve_admin_change_status(store_path, completed["id"], "sisko")
            store = SQLiteStore(store_path)
            store.save_admin_execution(
                AdminExecutionResult(
                    id="admin.exec.admin.restart.client.archive.completed",
                    plan_id=completed["id"],
                    status=AdminExecutionStatus.COMPLETED,
                    summary="admin change completed and verified",
                    command_results=(),
                )
            )
            store.close()

            with LocalOverseerApiServer(store_path, auth_token="client-secret") as server:
                client = OverseerApiClient(server.url, auth_token="client-secret")
                requested = client.request_admin_history_archive(
                    {
                        "plan_id": completed["id"],
                        "requested_by": "sisko",
                        "requested_at": "2026-07-18T22:31:00+00:00",
                    }
                )
                pending = client.authorizations_required()
                approved = client.approve_admin_history_archive(
                    {
                        "approval_id": requested["approval_id"],
                        "approved_by": "sisko",
                        "approved_at": "2026-07-18T22:32:00+00:00",
                    }
                )
                archived = client.archive_admin_history(
                    {
                        "plan_id": completed["id"],
                        "approval_id": requested["approval_id"],
                        "archived_by": "sisko",
                        "archived_at": "2026-07-18T22:33:00+00:00",
                    }
                )
                after = client.authorizations_required()

            self.assertEqual(requested["approval_status"], ApprovalStatus.PENDING.value)
            self.assertEqual(pending["pending_archive_approval_count"], 1)
            self.assertTrue(approved["archive_approval"])
            self.assertEqual(approved["approval_status"], ApprovalStatus.APPROVED.value)
            self.assertEqual(archived["archived"], 1)
            self.assertEqual(archived["approval_id"], requested["approval_id"])
            self.assertEqual(after["pending_archive_approval_count"], 0)

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
                archive_request_error = None
                try:
                    client.request_admin_history_archive(
                        {
                            "requested_by": "sisko",
                            "requested_at": "2026-07-18T22:14:00+00:00",
                        }
                    )
                except HTTPError as error:
                    archive_request_error = error
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
            self.assertIsNotNone(archive_request_error)
            self.assertEqual(archive_request_error.code, 400)
            self.assertIsNotNone(unarchive_error)
            self.assertEqual(unarchive_error.code, 400)
            self.assertIn("is not archived", unarchive_error.read().decode("utf-8"))
            self.assertEqual(summary["executions_by_status"][AdminExecutionStatus.BLOCKED.value], 1)
            self.assertEqual(executions["executions"][0]["plan_id"], "admin.restart.blocked")
            self.assertEqual(state["audit_events"][0]["event_type"], AuditEventType.BLOCKED.value)
            self.assertEqual(state["audit_events"][0]["subject_id"], "admin.restart.blocked")


class HostInspectionTests(unittest.TestCase):
    def test_parse_systemd_service_rows_extracts_running_user_services(self):
        rows = parse_systemd_service_rows(
            "\n".join(
                (
                    "UNIT LOAD ACTIVE SUB DESCRIPTION",
                    "overseer-api.service loaded active running Overseer localhost API",
                    "sample.service loaded active running lowercase service description",
                    "dbus.service loaded active running D-Bus User Message Bus",
                    "LOAD   = Reflects whether the unit definition was properly loaded.",
                )
            )
        )

        self.assertEqual([row["unit"] for row in rows], ["overseer-api.service", "sample.service", "dbus.service"])
        self.assertEqual(rows[0]["description"], "Overseer localhost API")
        self.assertEqual(rows[1]["description"], "lowercase service description")

    def test_discover_user_services_status_persists_service_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            snapshot = HostInspectionSnapshot(
                id="host.test.services",
                captured_at="2026-07-19T15:00:00+00:00",
                hostname="test-host",
                os_release={"ID": "debian", "PRETTY_NAME": "Debian Test"},
                observations=(
                    HostCommandObservation(
                        name="systemctl",
                        command=("systemctl", "--user", "list-units", "--type=service", "--state=running", "--no-pager"),
                        exit_code=0,
                        stdout="overseer-api.service loaded active running Overseer localhost API\n",
                    ),
                ),
            )

            status = discover_user_services_status(store_path, snapshot=snapshot)
            store = SQLiteStore(store_path)
            resource = store.load_resource("svc.systemd-user.overseer-api")
            target = store.load_health_target("health.systemd-user.overseer-api")
            snapshots = store.list_host_snapshots()
            store.close()

        self.assertEqual(status["count"], 1)
        self.assertEqual(status["health_targets"], 1)
        self.assertEqual(status["items"][0]["unit"], "overseer-api.service")
        self.assertEqual(resource.owner_domain, OwnerDomain.JULIAN)
        self.assertEqual(resource.identifiers["description"], "Overseer localhost API")
        self.assertEqual(target.resource_id, "svc.systemd-user.overseer-api")
        self.assertEqual(target.target, "systemd:user:overseer-api.service")
        self.assertEqual(snapshots[0].id, "host.test.services")

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
                ("firewall-cmd", "--state"): "running\n",
                ("firewall-cmd", "--get-active-zones"): "public\n  interfaces: enp3s0\n",
                ("firewall-cmd", "--zone=public", "--list-all"): "public (active)\n  services: ssh\n",
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
        self.assertEqual(snapshot.observation("firewalld-state").stdout, "running")
        self.assertEqual(snapshot.observation("firewalld-public-zone").command, ("firewall-cmd", "--zone=public", "--list-all"))
        self.assertIn(("df", "-h", "--output=source,size,used,avail,pcent,target"), commands)

    def test_read_only_command_timeout_is_recorded_as_observation(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(("firewall-cmd", "--state"), 5.0)):
            observation = run_read_only_command(("firewall-cmd", "--state"), 5.0)

        self.assertEqual(observation.name, "firewall-cmd")
        self.assertEqual(observation.exit_code, 124)
        self.assertIn("timed out", observation.stderr)

    def test_host_inspection_can_skip_firewall_commands_for_daemon_runtime(self):
        commands = []

        def runner(command, timeout_seconds):
            commands.append(tuple(command))
            return HostCommandObservation(
                name=command[0],
                command=tuple(command),
                exit_code=0,
                stdout="workstation" if tuple(command) == ("hostname",) else "ok",
            )

        snapshot = HostInspectionAdapter(
            command_runner=runner,
            file_reader=lambda path: "ID=debian\n",
            collect_firewall_commands=False,
        ).inspect("2026-07-18T16:00:00+00:00")

        self.assertNotIn(("firewall-cmd", "--state"), commands)
        with self.assertRaises(KeyError):
            snapshot.observation("firewalld-state")

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
            newer_snapshot = replace(
                snapshot,
                id="host.host-a.2026-07-18t17-00-00-000000-00-00",
                captured_at="2026-07-18T17:00:00+00:00",
            )
            store.save_host_snapshot(newer_snapshot)
            loaded = store.load_host_snapshot(snapshot.id)
            latest = store.load_latest_host_snapshot()
            store.close()

            state = list_state_status(store_path)

        self.assertEqual(loaded.hostname, "host-a")
        self.assertEqual(latest.id, newer_snapshot.id)
        self.assertEqual(state["host_snapshots"][0]["id"], snapshot.id)
        self.assertEqual(state["host_snapshots"][0]["observation_count"], 8)

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

    def test_host_security_listener_review_queue_reconciles_findings_and_plans(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            snapshot = HostInspectionAdapter(
                command_runner=lambda command, timeout_seconds: HostCommandObservation(
                    name=command[0],
                    command=tuple(command),
                    exit_code=0,
                    stdout=(
                        "host-listener-queue"
                        if tuple(command) == ("hostname",)
                        else "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                        "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
                        "LISTEN 0 128 0.0.0.0:80 0.0.0.0:*\n"
                        "LISTEN 0 128 10.50.0.100:9443 0.0.0.0:*\n"
                        if tuple(command) == ("ss", "-ltnp")
                        else "ok"
                    ),
                ),
                file_reader=lambda path: "ID=debian\n",
            ).inspect("2026-07-18T16:16:00+00:00")
            store = SQLiteStore(store_path)
            store.save_host_snapshot(snapshot)
            staged = plan_firewall_deny_tcp(
                "admin.host-security.deny-tcp.22",
                22,
                "stage ssh exposure review",
                "ssh exposed",
            )
            approved = approve_admin_change_plan(
                plan_firewall_deny_tcp(
                    "admin.host-security.deny-tcp.80",
                    80,
                    "stage http exposure review",
                    "http exposed",
                ),
                "sisko",
            )
            store.save_admin_change_plan(staged)
            store.save_admin_change_plan(approved)
            store.close()

            queue = host_security_listener_review_queue_status(store_path)

        by_listener = {item["listener"]: item for item in queue["items"]}
        self.assertEqual(queue["listener_count"], 3)
        self.assertEqual(queue["needs_exposure_review"], 1)
        self.assertEqual(queue["plan_staged"], 1)
        self.assertEqual(queue["approved_for_execution"], 1)
        self.assertEqual(queue["plan_canceled"], 0)
        self.assertEqual(by_listener["0.0.0.0:22"]["queue_status"], "plan_staged")
        self.assertEqual(by_listener["0.0.0.0:22"]["plan_id"], "admin.host-security.deny-tcp.22")
        self.assertEqual(by_listener["0.0.0.0:80"]["queue_status"], "approved_for_execution")
        self.assertEqual(by_listener["10.50.0.100:9443"]["queue_status"], "needs_exposure_review")
        self.assertIn("read-only listener queue", queue["approval_boundary"])

    def test_plan_host_security_listener_queue_remediations_groups_unplanned_ports(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            snapshot = HostInspectionAdapter(
                command_runner=lambda command, timeout_seconds: HostCommandObservation(
                    name=command[0],
                    command=tuple(command),
                    exit_code=0,
                    stdout=(
                        "host-listener-plan"
                        if tuple(command) == ("hostname",)
                        else "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                        "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
                        "LISTEN 0 128 [::]:22 [::]:*\n"
                        "LISTEN 0 128 0.0.0.0:80 0.0.0.0:*\n"
                        if tuple(command) == ("ss", "-ltnp")
                        else "ok"
                    ),
                ),
                file_reader=lambda path: "ID=debian\n",
            ).inspect("2026-07-18T16:17:00+00:00")
            store = SQLiteStore(store_path)
            store.save_host_snapshot(snapshot)
            store.save_admin_change_plan(
                plan_firewall_deny_tcp(
                    "admin.host-security.deny-tcp.80",
                    80,
                    "existing http exposure plan",
                    "http exposed",
                )
            )
            store.close()

            status = plan_host_security_listener_queue_remediations_status(store_path, requested_by="odo")
            queue = host_security_listener_review_queue_status(store_path)
            store = SQLiteStore(store_path)
            plans = [plan for plan in store.list_admin_change_plans() if plan.kind == AdminChangeKind.FIREWALL_DENY_TCP]
            store.close()

        self.assertEqual(status["candidate_ports"], 1)
        self.assertEqual(status["staged_count"], 1)
        self.assertEqual(status["skipped_count"], 0)
        self.assertEqual(status["staged"][0]["target"], "tcp/22")
        self.assertEqual(set(status["staged"][0]["listeners"]), {"0.0.0.0:22", "[::]:22"})
        self.assertFalse(status["host_mutation_performed"])
        self.assertEqual(len(plans), 2)
        self.assertEqual(queue["plan_staged"], 3)
        self.assertIn("plans staged only", status["approval_boundary"])

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
        self.assertIn("review_brief", auth_missing_package["pending"][0])
        self.assertIn("Block traffic from source", auth_missing_package["pending"][0]["review_brief"]["change"])
        self.assertIn("deny_effect", auth_missing_package["pending"][0]["review_brief"])
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
        self.assertEqual(ids_review_summary["latest_audit_events"][0]["owner_domain"], OwnerDomain.ODO_IDS.value)
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

    def test_host_security_source_review_queue_reconciles_current_sources_and_reviews(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            snapshot = HostInspectionAdapter(
                command_runner=lambda command, timeout_seconds: HostCommandObservation(
                    name=command[0],
                    command=tuple(command),
                    exit_code=0,
                    stdout=(
                        "host-review-queue"
                        if tuple(command) == ("hostname",)
                        else "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                        "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
                        if tuple(command) == ("ss", "-ltnp")
                        else "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                        "ESTAB 0 0 192.168.1.20:22 8.8.8.8:53122\n"
                        "ESTAB 0 0 192.168.1.20:22 1.1.1.1:53123\n"
                        "ESTAB 0 0 192.168.1.20:22 192.0.2.10:54000\n"
                        if tuple(command) == ("ss", "-tnp")
                        else "ok"
                    ),
                ),
                file_reader=lambda path: "ID=debian\n",
            ).inspect("2026-07-18T16:12:00+00:00")
            store = SQLiteStore(store_path)
            store.save_host_snapshot(snapshot)
            store.close()

            create_host_security_source_review_status(
                store_path,
                "8.8.8.8",
                disposition=SourceReviewDisposition.HOSTILE.value,
                rationale="confirmed hostile connection pattern",
                reviewed_by="odo",
                reviewed_at="2026-07-18T16:13:00+00:00",
            )
            create_host_security_source_review_status(
                store_path,
                "192.0.2.10",
                disposition=SourceReviewDisposition.BENIGN.value,
                rationale="documentation-range test evidence",
                reviewed_by="odo",
                reviewed_at="2026-07-18T16:14:00+00:00",
            )
            refreshed_snapshot = HostInspectionAdapter(
                command_runner=lambda command, timeout_seconds: HostCommandObservation(
                    name=command[0],
                    command=tuple(command),
                    exit_code=0,
                    stdout=(
                        "host-review-queue"
                        if tuple(command) == ("hostname",)
                        else "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                        "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
                        if tuple(command) == ("ss", "-ltnp")
                        else "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                        "ESTAB 0 0 192.168.1.20:22 8.8.8.8:53124\n"
                        "ESTAB 0 0 192.168.1.20:22 1.1.1.1:53125\n"
                        "ESTAB 0 0 192.168.1.20:22 192.0.2.10:54001\n"
                        if tuple(command) == ("ss", "-tnp")
                        else "ok"
                    ),
                ),
                file_reader=lambda path: "ID=debian\n",
            ).inspect("2026-07-18T16:15:00+00:00")
            store = SQLiteStore(store_path)
            store.save_host_snapshot(refreshed_snapshot)
            store.close()

            queue = host_security_source_review_queue_status(store_path)

        by_remote = {item["remote_address"]: item for item in queue["items"]}
        self.assertEqual(queue["connection_count"], 3)
        self.assertEqual(queue["review_count"], 2)
        self.assertEqual(queue["needs_review"], 1)
        self.assertEqual(queue["ready_for_block_plan"], 1)
        self.assertEqual(queue["reviewed_no_action"], 1)
        self.assertEqual(queue["not_blockable"], 0)
        self.assertEqual(by_remote["8.8.8.8"]["queue_status"], "ready_for_block_plan")
        self.assertTrue(by_remote["8.8.8.8"]["can_stage_block_plan"])
        self.assertEqual(by_remote["1.1.1.1"]["queue_status"], "needs_review")
        self.assertEqual(by_remote["192.0.2.10"]["queue_status"], "reviewed_no_action")
        self.assertIn("read-only queue", queue["approval_boundary"])

    def test_dispatch_ids_review_package_uses_codex_projects_adapter(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            registry_path = Path(directory) / "codex-projects.csv"
            registry_path.write_text(
                "conversation_id,label,project,command,launcher,created_at,updated_at,source,notes\n"
                "019f09da-25c8-72b2-9730-9a0a17b9e177,Intrusion Detection,"
                "/home/god/Documents/Codex Workspace/Intrusion Detection,"
                "codex-intrusion-detection-019f09da,"
                "/home/god/.local/bin/codex-intrusion-detection-019f09da,"
                "2026-06-27T16:11:59+00:00,2026-06-28T17:17:28+00:00,registry+codex-state,\n",
                encoding="utf-8",
            )
            fake_runner = _FakeCodexProjectRunner()
            adapter = CodexProjectThreadAdapter(registry_path=registry_path, runner=fake_runner)
            plan = plan_admin_change_status(
                store_path,
                "admin.host-security.block-source.192-0-2-10",
                AdminChangeKind.BLOCK_IP.value,
                "192.0.2.10",
                "stage hostile source block",
                "source review pending IDS review",
            )
            package = prepare_host_security_ids_review_package_status(store_path, plan["id"])

            dispatched = dispatch_host_security_ids_review_package_status(
                store_path,
                package["id"],
                "odo",
                "2026-07-19T05:10:00+00:00",
                adapter=adapter,
            )
            auth_status = authorizations_required_status(store_path)
            summary = host_security_ids_review_summary_status(store_path)
            prompt_exists = Path(dispatched["prompt_path"]).exists()

        self.assertEqual(dispatched["status"], IDSReviewPackageStatus.SUBMITTED.value)
        self.assertEqual(dispatched["dispatch_status"], "prompt_dispatched")
        self.assertEqual(dispatched["dispatch_result"]["status"], "prompt_dispatched")
        self.assertEqual(dispatched["resume_result"]["status"], "resumed")
        self.assertEqual(dispatched["dispatch_thread"], "codex-intrusion-detection-019f09da")
        self.assertEqual(dispatched["dispatch_conversation_id"], "019f09da-25c8-72b2-9730-9a0a17b9e177")
        self.assertTrue(prompt_exists)
        self.assertEqual(
            auth_status["pending"][0]["ids_review_next_step"],
            "await Intrusion Detection advisory result before approval",
        )
        self.assertEqual(summary["submitted_without_result"], 1)
        self.assertEqual(
            fake_runner.commands[0],
            ("/usr/bin/tmux", "has-session", "-t", "codex-intrusion-detection-019f09da"),
        )
        self.assertEqual(fake_runner.commands[2], ("/usr/bin/tmux", "load-buffer", "-b", "overseer-dispatch", "-"))
        self.assertIn("Evaluate this proposed Overseer security change before enforcement.", fake_runner.inputs[2])
        self.assertEqual(
            fake_runner.commands[3],
            ("/usr/bin/tmux", "paste-buffer", "-b", "overseer-dispatch", "-t", "codex-intrusion-detection-019f09da"),
        )
        self.assertEqual(fake_runner.commands[4], ("/usr/bin/tmux", "send-keys", "-t", "codex-intrusion-detection-019f09da", "Enter"))
        self.assertEqual(fake_runner.commands[1][0:4], ("/usr/bin/tmux", "new-session", "-d", "-s"))

    def test_ids_review_summary_excludes_canceled_plan_packages_from_active_gate_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            plan = plan_admin_change_status(
                store_path,
                "admin.host-security.firewalld-deny-tcp.8088",
                AdminChangeKind.FIREWALL_DENY_TCP.value,
                "tcp/8088",
                "stage listener deny after Odo review",
                "listener evidence requires IDS review",
                port=8088,
            )
            package = prepare_host_security_ids_review_package_status(store_path, plan["id"])
            submit_host_security_ids_review_package_status(
                store_path,
                package["id"],
                "odo",
                prompt_path="/tmp/ids-review.prompt.md",
            )
            record_host_security_ids_review_result_status(
                store_path,
                package["id"],
                IDSReviewPackageStatus.REVISION_REQUIRED.value,
                "revise the package before enforcement",
                "odo",
            )

            before_cancel = host_security_ids_review_summary_status(store_path)
            cancel_admin_change_status(
                store_path,
                plan["id"],
                "sisko",
                "cancel superseded firewall deny plan",
            )
            after_cancel = host_security_ids_review_summary_status(store_path)

        self.assertEqual(before_cancel["package_count"], 1)
        self.assertEqual(before_cancel["gate_blocked"], 1)
        self.assertEqual(before_cancel["revision_required"], 1)
        self.assertEqual(after_cancel["package_count"], 0)
        self.assertEqual(after_cancel["total_package_count"], 1)
        self.assertEqual(after_cancel["inactive_plan_package_count"], 1)
        self.assertEqual(after_cancel["gate_blocked"], 0)
        self.assertEqual(after_cancel["revision_required"], 0)
        self.assertTrue(after_cancel["packages"][0]["plan_canceled"])
        self.assertEqual(
            after_cancel["packages"][0]["next_step"],
            "linked admin plan is canceled; package retained for audit history",
        )

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

    def test_host_security_remediation_uses_detected_firewalld_backend(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            def runner(command, timeout_seconds):
                stdout = "ok"
                stderr = ""
                exit_code = 0
                if tuple(command) == ("hostname",):
                    stdout = "host-firewalld"
                elif tuple(command) == ("ss", "-ltnp"):
                    stdout = "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"
                elif tuple(command) == ("firewall-cmd", "--state"):
                    stdout = ""
                    stderr = "Authorization failed."
                    exit_code = 253
                elif tuple(command) == ("firewall-cmd", "--get-active-zones"):
                    stdout = "public (default)\n  interfaces: enp3s0"
                return HostCommandObservation(
                    name=command[0],
                    command=tuple(command),
                    exit_code=exit_code,
                    stdout=stdout,
                    stderr=stderr,
                )

            snapshot = HostInspectionAdapter(
                command_runner=runner,
                file_reader=lambda path: "ID=debian\n",
            ).inspect("2026-07-18T16:05:00+00:00")
            store = SQLiteStore(store_path)
            store.save_host_snapshot(snapshot)
            store.close()

            status = plan_host_security_remediation_status(store_path, "0.0.0.0:22")
            loaded = SQLiteStore(store_path)
            plan = loaded.load_admin_change_plan("admin.host-security.deny-tcp.22")
            loaded.close()

        self.assertEqual(status["firewall_backend"], "firewalld")
        self.assertEqual(plan.steps[0].command[0:3], ("sudo", "firewall-cmd", "--permanent"))
        self.assertIn("--add-rich-rule=", plan.steps[0].command[4])
        self.assertEqual(plan.steps[1].command, ("sudo", "firewall-cmd", "--reload"))

    def test_host_security_remediation_uses_firewalld_when_probe_times_out_and_ufw_absent(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            def runner(command, timeout_seconds):
                stdout = "ok"
                stderr = ""
                exit_code = 0
                if tuple(command) == ("hostname",):
                    stdout = "host-firewalld"
                elif tuple(command) == ("ss", "-ltnp"):
                    stdout = "LISTEN 0 128 0.0.0.0:9443 0.0.0.0:*"
                elif tuple(command) in {
                    ("firewall-cmd", "--state"),
                    ("firewall-cmd", "--get-active-zones"),
                    ("firewall-cmd", "--zone=public", "--list-all"),
                }:
                    stdout = ""
                    stderr = "command timed out after 5.0 seconds"
                    exit_code = 124
                return HostCommandObservation(
                    name=command[0],
                    command=tuple(command),
                    exit_code=exit_code,
                    stdout=stdout,
                    stderr=stderr,
                )

            snapshot = HostInspectionAdapter(
                command_runner=runner,
                file_reader=lambda path: "ID=debian\n",
            ).inspect("2026-07-18T16:05:00+00:00")
            store = SQLiteStore(store_path)
            store.save_host_snapshot(snapshot)
            store.close()

            def fake_which(command):
                if command == "firewall-cmd":
                    return "/usr/bin/firewall-cmd"
                if command == "ufw":
                    return None
                return None

            with patch("overseer.cli.shutil.which", side_effect=fake_which):
                status = plan_host_security_remediation_status(store_path, "0.0.0.0:9443")
            loaded = SQLiteStore(store_path)
            plan = loaded.load_admin_change_plan("admin.host-security.deny-tcp.9443")
            loaded.close()

        self.assertEqual(status["firewall_backend"], "firewalld")
        self.assertEqual(plan.steps[0].command[0:3], ("sudo", "firewall-cmd", "--permanent"))

    def test_firewalld_source_scoped_plan_preserves_sources_before_fallback_reject(self):
        plan = plan_firewalld_source_scoped_deny_tcp(
            "admin.firewalld.source-scoped.9443",
            9443,
            ("10.70.0.10/32", "10.70.0.11/32"),
            "preserve protected gateway clients",
            "gateway exposed",
        )

        self.assertEqual(plan.kind, AdminChangeKind.FIREWALL_DENY_TCP)
        self.assertIn("10.70.0.10/32", plan.proposed_state)
        self.assertIn("priority=\"-200\"", plan.steps[0].command[4])
        self.assertIn("source address=\"10.70.0.10/32\"", plan.steps[0].command[4])
        reject_rules = " ".join(
            step.command[4]
            for step in plan.steps
            if len(step.command) > 4 and "--add-rich-rule" in step.command[4]
        )
        self.assertIn("family=\"ipv4\" priority=\"-100\"", reject_rules)
        self.assertIn("family=\"ipv6\" priority=\"-100\"", reject_rules)
        self.assertIn("overseer-deny6-9443", reject_rules)
        self.assertEqual(plan.steps[-2].command, ("sudo", "firewall-cmd", "--check-config"))
        self.assertEqual(plan.steps[-1].command, ("sudo", "firewall-cmd", "--reload"))
        self.assertEqual(plan.rollback_steps[-2].command, ("sudo", "firewall-cmd", "--check-config"))
        self.assertEqual(plan.rollback_steps[-1].command, ("sudo", "firewall-cmd", "--reload"))

    def test_odo_advance_collects_firewall_backend_before_ids_review(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            def runner(command, timeout_seconds):
                stdout = "ok"
                if tuple(command) == ("hostname",):
                    stdout = "host-firewalld"
                elif tuple(command) == ("ss", "-ltnp"):
                    stdout = "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"
                elif tuple(command) == ("firewall-cmd", "--state"):
                    stdout = "running"
                elif tuple(command) == ("firewall-cmd", "--get-active-zones"):
                    stdout = "public\n  interfaces: enp3s0"
                return HostCommandObservation(
                    name=command[0],
                    command=tuple(command),
                    exit_code=0,
                    stdout=stdout,
                )

            class FirewalldInspectionAdapter:
                def __init__(self, collect_firewall_commands=True, **kwargs):
                    self.collect_firewall_commands = collect_firewall_commands

                def inspect(self, captured_at=None):
                    return HostInspectionAdapter(
                        command_runner=runner,
                        file_reader=lambda path: "ID=debian\n",
                        collect_firewall_commands=self.collect_firewall_commands,
                    ).inspect(captured_at or "2026-07-18T16:05:00+00:00")

            def fake_dispatch(store_path_arg, package_id, **kwargs):
                store = SQLiteStore(store_path_arg)
                try:
                    package = store.load_host_security_ids_review_package(package_id)
                    return overseer_cli.host_security_ids_review_package_status(package)
                finally:
                    store.close()

            with patch("overseer.cli.HostInspectionAdapter", FirewalldInspectionAdapter):
                with patch("overseer.cli.dispatch_host_security_ids_review_package_status", side_effect=fake_dispatch):
                    status = overseer_cli.advance_odo_security_status(store_path)

            loaded = SQLiteStore(store_path)
            plan = loaded.load_admin_change_plan("admin.host-security.deny-tcp.22")
            package = loaded.load_host_security_ids_review_package("ids-review.admin.host-security.deny-tcp.22")
            loaded.close()

        self.assertEqual(status["remediation"]["firewall_backend"], "firewalld")
        self.assertEqual(plan.steps[0].command[0:3], ("sudo", "firewall-cmd", "--permanent"))
        self.assertIn("firewall-cmd", package.firewall_rule_drafts[0])
        self.assertNotIn("ufw", package.prompt)

    def test_odo_revision_restages_ssh_as_source_scoped_from_active_peer(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            plan = overseer_cli.plan_admin_change_status(
                store_path,
                "admin.host-security.deny-tcp.22",
                AdminChangeKind.FIREWALL_DENY_TCP.value,
                "tcp/22",
                "stage approval-gated firewall deny for exposed listener queue tcp/22; requested_by=odo",
                "listeners=0.0.0.0:22, [::]:22",
                port=22,
                use_firewalld=True,
            )
            package = overseer_cli.prepare_host_security_ids_review_package_status(store_path, plan["id"])
            overseer_cli.submit_host_security_ids_review_package_status(store_path, package["id"], "odo")
            overseer_cli.record_host_security_ids_review_result_status(
                store_path,
                package["id"],
                "revision_required",
                "Revision required: replace broad deny with source-scoped policy that preserves intended clients.",
                "intrusion-detection-advisor",
            )

            completed = subprocess.CompletedProcess(
                ("ss",),
                0,
                stdout="0 0 192.168.68.100:22 192.168.68.115:54939\n",
                stderr="",
            )
            with patch("overseer.cli.subprocess.run", return_value=completed):
                restaged = overseer_cli._restage_admin_plan_after_ids_revision(store_path, plan["id"])

            loaded = SQLiteStore(store_path)
            revised = loaded.load_admin_change_plan("admin.host-security.deny-tcp.22")
            loaded.close()

        self.assertEqual(restaged["firewall_backend"], "firewalld")
        self.assertFalse(revised.approved)
        self.assertIn("192.168.68.115/32", revised.proposed_state)
        self.assertIn("source address=\"192.168.68.115/32\"", revised.steps[0].command[4])
        reject_rules = " ".join(
            step.command[4]
            for step in revised.steps
            if len(step.command) > 4 and "--add-rich-rule" in step.command[4]
        )
        self.assertIn("family=\"ipv4\" priority=\"-100\"", reject_rules)
        self.assertIn("family=\"ipv6\" priority=\"-100\"", reject_rules)

    def test_odo_advance_restages_revision_required_firewall_plan_before_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            def runner(command, timeout_seconds):
                stdout = "ok"
                if tuple(command) == ("hostname",):
                    stdout = "host-firewalld"
                elif tuple(command) == ("ss", "-ltnp"):
                    stdout = "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"
                elif tuple(command) == ("firewall-cmd", "--state"):
                    stdout = "running"
                elif tuple(command) == ("firewall-cmd", "--get-active-zones"):
                    stdout = "public\n  interfaces: enp3s0"
                return HostCommandObservation(
                    name=command[0],
                    command=tuple(command),
                    exit_code=0,
                    stdout=stdout,
                )

            class FirewalldInspectionAdapter:
                def __init__(self, collect_firewall_commands=True, **kwargs):
                    self.collect_firewall_commands = collect_firewall_commands

                def inspect(self, captured_at=None):
                    return HostInspectionAdapter(
                        command_runner=runner,
                        file_reader=lambda path: "ID=debian\n",
                        collect_firewall_commands=self.collect_firewall_commands,
                    ).inspect(captured_at or "2026-07-18T16:05:00+00:00")

            stale = overseer_cli.plan_admin_change_status(
                store_path,
                "admin.host-security.deny-tcp.22",
                AdminChangeKind.FIREWALL_DENY_TCP.value,
                "tcp/22",
                "stage approval-gated firewall deny for exposed listener queue tcp/22; requested_by=odo",
                "listener exposed",
                port=22,
            )
            package = overseer_cli.prepare_host_security_ids_review_package_status(store_path, stale["id"])
            overseer_cli.submit_host_security_ids_review_package_status(store_path, package["id"], "odo")
            loaded = SQLiteStore(store_path)
            loaded.save_admin_change_plan(
                replace(
                    loaded.load_admin_change_plan("admin.host-security.deny-tcp.22"),
                    approved=True,
                    approved_by="human",
                    approved_at="2026-07-18T16:06:00+00:00",
                )
            )
            loaded.close()
            overseer_cli.record_host_security_ids_review_result_status(
                store_path,
                package["id"],
                "revision_required",
                "replace UFW draft with firewalld draft",
                "intrusion-detection-advisor",
            )

            def fake_dispatch(store_path_arg, package_id, **kwargs):
                store = SQLiteStore(store_path_arg)
                try:
                    package = store.load_host_security_ids_review_package(package_id)
                    return overseer_cli.host_security_ids_review_package_status(package)
                finally:
                    store.close()

            with patch("overseer.cli.HostInspectionAdapter", FirewalldInspectionAdapter):
                with patch("overseer.cli.dispatch_host_security_ids_review_package_status", side_effect=fake_dispatch):
                    status = overseer_cli.advance_odo_security_status(store_path)

            loaded = SQLiteStore(store_path)
            plan = loaded.load_admin_change_plan("admin.host-security.deny-tcp.22")
            package = loaded.load_host_security_ids_review_package("ids-review.admin.host-security.deny-tcp.22")
            loaded.close()

        self.assertEqual(status["remediation"]["firewall_backend"], "firewalld")
        self.assertFalse(plan.approved)
        self.assertIsNone(plan.approved_by)
        self.assertIsNone(plan.approved_at)
        self.assertEqual(plan.steps[0].command[0:3], ("sudo", "firewall-cmd", "--permanent"))
        self.assertIn("firewall-cmd", package.firewall_rule_drafts[0])
        self.assertNotIn("ufw", package.prompt)

    def test_odo_advance_does_not_auto_execute_explicit_firewall_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            plan = overseer_cli.plan_admin_change_status(
                store_path,
                "admin.host-security.deny-tcp.22",
                AdminChangeKind.FIREWALL_DENY_TCP.value,
                "tcp/22",
                "stage approval-gated firewall deny for exposed listener queue tcp/22; requested_by=odo",
                "listener exposed",
                port=22,
                use_firewalld=True,
            )
            package = overseer_cli.prepare_host_security_ids_review_package_status(store_path, plan["id"])
            overseer_cli.submit_host_security_ids_review_package_status(store_path, package["id"], "odo")
            overseer_cli.record_host_security_ids_review_result_status(
                store_path,
                package["id"],
                "accepted",
                "accepted firewalld review",
                "intrusion-detection-advisor",
            )
            enablement = overseer_cli.request_admin_adapter_enablement_status(
                store_path,
                AdminChangeKind.FIREWALL_DENY_TCP.value,
                "odo",
            )
            overseer_cli.approve_admin_adapter_enablement_status(store_path, enablement["approval_id"], "human")
            loaded = SQLiteStore(store_path)
            loaded.save_admin_change_plan(
                replace(
                    loaded.load_admin_change_plan("admin.host-security.deny-tcp.22"),
                    approved=True,
                    approved_by="human",
                    approved_at="2026-07-18T16:06:00+00:00",
                )
            )
            loaded.close()

            status = overseer_cli._advance_admin_plan_after_dispatch(
                store_path,
                "admin.host-security.deny-tcp.22",
                "2026-07-18T16:07:00+00:00",
            )

        self.assertEqual(status["readiness_state"], "ready_for_overseer_execution")
        self.assertIn("sisko_message", status)
        self.assertNotIn("execution", status)

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

    def test_package_update_plan_runs_without_explicit_approval_and_consistency_check(self):
        plan = plan_apt_update(
            "admin.apt.update",
            "refresh package metadata before maintenance",
            "package index stale",
        )

        self.assertEqual(plan.kind, AdminChangeKind.APT_UPDATE)
        self.assertEqual(plan.approval_level, ApprovalLevel.NONE)
        self.assertEqual(plan.risk_level, RiskLevel.LOW)
        self.assertFalse(plan.requires_explicit_approval())
        self.assertTrue(plan.can_execute())
        self.assertEqual(plan.steps[0].command, ("sudo", "apt-get", "update"))
        self.assertEqual(plan.verification_steps[0].command, ("sudo", "apt-get", "check"))

    def test_package_upgrade_plan_uses_sisko_approval_and_preview(self):
        plan = plan_apt_upgrade(
            "admin.apt.upgrade.sqlite",
            ("sqlite3",),
            "apply approved package patch",
            "sqlite3 upgrade available",
        )

        self.assertEqual(plan.kind, AdminChangeKind.APT_UPGRADE)
        self.assertEqual(plan.approval_level, ApprovalLevel.SISKO)
        self.assertEqual(plan.risk_level, RiskLevel.HIGH)
        self.assertEqual(plan.target, "sqlite3")
        self.assertEqual(plan.steps[0].command, ("sudo", "apt-get", "install", "--only-upgrade", "--dry-run", "sqlite3"))
        self.assertEqual(plan.steps[1].command, ("sudo", "apt-get", "install", "--only-upgrade", "-y", "sqlite3"))
        self.assertEqual(plan.rollback_steps[1].command, ("sudo", "apt-get", "-f", "install", "-y"))
        self.assertEqual(plan.verification_steps[0].command, ("dpkg-query", "-W", "sqlite3"))

    def test_plan_admin_change_cli_accepts_package_argument(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = cli_main(
                    [
                        "plan-admin-change",
                        "--store",
                        str(store_path),
                        "--plan-id",
                        "admin.apt.upgrade.cli",
                        "--kind",
                        AdminChangeKind.APT_UPGRADE.value,
                        "--target",
                        "sqlite3",
                        "--package",
                        "sqlite3",
                        "--reason",
                        "apply approved package patch",
                    ]
                )
            status = json.loads(stdout.getvalue())

        self.assertEqual(exit_code, 0)
        self.assertEqual(status["steps"][0]["command"], ["sudo", "apt-get", "install", "--only-upgrade", "--dry-run", "sqlite3"])
        self.assertEqual(status["steps"][1]["command"], ["sudo", "apt-get", "install", "--only-upgrade", "-y", "sqlite3"])

    def test_firewall_plan_has_critical_risk_and_delete_rollback(self):
        plan = plan_firewall_allow_tcp(
            "admin.firewall.8443",
            8443,
            "publish approved local service",
            "closed",
        )

        self.assertEqual(plan.risk_level, RiskLevel.CRITICAL)
        self.assertEqual(plan.owner_domain, OwnerDomain.ODO_FIREWALL)
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
        self.assertEqual(plan.owner_domain, OwnerDomain.ODO_FIREWALL)
        self.assertEqual(plan.risk_level, RiskLevel.CRITICAL)
        self.assertEqual(plan.approval_level, ApprovalLevel.HUMAN)
        self.assertEqual(plan.steps[0].command, ("sudo", "ufw", "deny", "22/tcp"))
        self.assertEqual(plan.rollback_steps[0].command, ("sudo", "ufw", "delete", "deny", "22/tcp"))

    def test_firewalld_deny_plan_has_matching_rollback_and_logging(self):
        plan = plan_firewalld_deny_tcp(
            "admin.firewalld.deny.22",
            22,
            "close exposed ssh listener",
            "open",
        )

        self.assertEqual(plan.kind, AdminChangeKind.FIREWALL_DENY_TCP)
        self.assertEqual(plan.risk_level, RiskLevel.CRITICAL)
        self.assertEqual(plan.approval_level, ApprovalLevel.HUMAN)
        self.assertEqual(plan.steps[0].command[0:3], ("sudo", "firewall-cmd", "--permanent"))
        self.assertIn('port="22"', plan.steps[0].command[4])
        self.assertIn('log prefix="overseer-deny-22 ', plan.steps[0].command[4])
        self.assertEqual(plan.steps[1].command, ("sudo", "firewall-cmd", "--reload"))
        self.assertIn("--remove-rich-rule=", plan.rollback_steps[0].command[4])
        self.assertEqual(plan.verification_steps[0].command, ("sudo", "firewall-cmd", "--zone=public", "--list-all"))

    def test_ids_review_prompt_shell_quotes_firewalld_rich_rules(self):
        plan = plan_firewalld_deny_tcp(
            "admin.firewalld.deny.22",
            22,
            "close exposed ssh listener",
            "open",
        )

        package = build_ids_review_package(plan)

        self.assertIn("'--add-rich-rule=rule port port=\"22\"", package.prompt)
        self.assertIn("'--remove-rich-rule=rule port port=\"22\"", package.prompt)
        self.assertIn("overseer-deny-22 ", package.prompt)

    def test_ids_review_package_accepts_source_review_for_firewall_listener(self):
        plan = plan_firewalld_source_scoped_deny_tcp(
            "admin.firewalld.source-scoped.22",
            22,
            ("192.168.68.115/32",),
            "preserve the current management client",
            "listeners=0.0.0.0:22; intended_sources=192.168.68.115/32",
        )
        source_review = HostSecuritySourceReview(
            id="source-review.ssh.management",
            source_connection_id="admin.firewalld.source-scoped.22:192.168.68.115",
            snapshot_id="snapshot.ssh",
            listener="tcp/22",
            remote_address="192.168.68.115",
            remote_port="observed",
            source_scope="lan",
            evidence="observed established SSH peer during Odo source-scoped restage",
            disposition=SourceReviewDisposition.EXPECTED,
            rationale="current management peer preserved for lockout avoidance",
            reviewed_by="odo",
            reviewed_at="2026-07-27T03:45:00+00:00",
            created_at="2026-07-27T03:45:00+00:00",
        )

        package = build_ids_review_package(plan, source_review)

        self.assertEqual(package.source_review_id, "source-review.ssh.management")
        self.assertIn("source_review=source-review.ssh.management", package.prompt)
        self.assertIn("allow only intended sources 192.168.68.115/32", package.intended_traffic)

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

    def test_apt_install_rejects_provider_prefixed_packages(self):
        with self.assertRaisesRegex(ValueError, "provider-specific admin adapter"):
            plan_apt_install(
                "admin.install.bad-provider",
                ("npm:obsidian-mcp-server",),
                "install documents bridge",
            )

    def test_stale_provider_prefixed_apt_plan_blocks_before_commands(self):
        plan = approve_admin_change_plan(
            replace(
                plan_apt_install("admin.install.bad-provider", ("nmap",), "enable approved audit"),
                target="npm:obsidian-mcp-server",
                steps=(
                    AdminCommandStep(
                        "Install packages",
                        ("sudo", "apt-get", "install", "-y", "npm:obsidian-mcp-server"),
                        "invalid stale provider-prefixed package plan",
                    ),
                ),
            ),
            "operator",
        )

        result = execute_admin_change_plan(
            plan,
            enabled_adapter_kinds=(AdminChangeKind.APT_INSTALL,),
            runner=lambda step: self.fail(f"runner should not be called for {step.command}"),
        )

        self.assertEqual(result.status, AdminExecutionStatus.BLOCKED)
        self.assertIn("unsupported package provider 'npm'", result.summary)

    def test_provider_specific_install_plans_use_provider_commands(self):
        flatpak_plan = plan_flatpak_install(
            "admin.flatpak.install.obsidian",
            "md.obsidian.Obsidian",
            "install documents editor",
        )
        npm_plan = plan_npm_global_install(
            "admin.npm.install.documents",
            "obsidian-mcp-server",
            "install documents MCP bridge",
        )

        self.assertEqual(flatpak_plan.kind, AdminChangeKind.FLATPAK_INSTALL)
        self.assertEqual(flatpak_plan.steps[0].command, ("flatpak", "install", "-y", "flathub", "md.obsidian.Obsidian"))
        self.assertEqual(flatpak_plan.verification_steps[0].command, ("flatpak", "info", "md.obsidian.Obsidian"))
        self.assertEqual(npm_plan.kind, AdminChangeKind.NPM_GLOBAL_INSTALL)
        self.assertEqual(npm_plan.steps[0].command, ("npm", "install", "-g", "obsidian-mcp-server"))
        self.assertEqual(npm_plan.rollback_steps[0].command, ("npm", "uninstall", "-g", "obsidian-mcp-server"))

    def test_provider_specific_install_executes_only_with_enabled_adapter(self):
        plan = approve_admin_change_plan(
            plan_npm_global_install(
                "admin.npm.install.documents",
                "obsidian-mcp-server",
                "install documents MCP bridge",
            ),
            "sisko",
        )

        blocked = execute_admin_change_plan(plan)
        executed = execute_admin_change_plan(
            plan,
            enabled_adapter_kinds=(AdminChangeKind.NPM_GLOBAL_INSTALL,),
            runner=lambda step: AdminCommandResult(
                title=step.title,
                command=step.command,
                exit_code=0,
                stdout="ok",
            ),
        )
        capability = admin_execution_capability_for(plan.kind, (AdminChangeKind.NPM_GLOBAL_INSTALL,))

        self.assertEqual(blocked.status, AdminExecutionStatus.BLOCKED)
        self.assertEqual(capability.status, AdminAdapterStatus.ENABLED)
        self.assertEqual(executed.status, AdminExecutionStatus.COMPLETED)
        self.assertEqual(executed.command_results[0].command, ("npm", "install", "-g", "obsidian-mcp-server"))

    def test_firewall_plan_executes_through_local_fixture_after_ids_and_approval_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            state.mkdir()
            store_path = state / "overseer.sqlite3"
            plan = overseer_cli.plan_admin_change_status(
                store_path,
                "admin.firewall.fixture",
                AdminChangeKind.FIREWALL_DENY_TCP.value,
                "tcp/9443",
                "exercise approved Odo firewall fixture",
                "listener exposed",
                port=9443,
            )
            package = overseer_cli.prepare_host_security_ids_review_package_status(store_path, plan["id"])
            submitted = overseer_cli.submit_host_security_ids_review_package_status(
                store_path,
                package["id"],
                "odo",
            )
            accepted = overseer_cli.record_host_security_ids_review_result_status(
                store_path,
                package["id"],
                "accepted",
                "accepted for local fixture execution only",
                "odo",
            )
            enablement = overseer_cli.request_admin_adapter_enablement_status(
                store_path,
                AdminChangeKind.FIREWALL_DENY_TCP.value,
                "odo",
            )
            overseer_cli.approve_admin_adapter_enablement_status(store_path, enablement["approval_id"], "human")
            approval = overseer_cli.approve_admin_change_status(store_path, plan["id"], "human")
            executed = overseer_cli.execute_firewall_change_status(store_path, plan["id"], "odo", "local_fixture")
            manifest_exists = (root / executed["manifest_path"]).exists()
            state_payload = overseer_cli.list_state_status(store_path)

        self.assertEqual(submitted["status"], IDSReviewPackageStatus.SUBMITTED.value)
        self.assertTrue(accepted["satisfies_pre_execution_review_gate"])
        self.assertTrue(approval["approved"])
        self.assertEqual(executed["status"], AdminExecutionStatus.COMPLETED.value)
        self.assertEqual(executed["mode"], "local_fixture")
        self.assertFalse(executed["host_mutation_performed"])
        self.assertFalse(executed["firewall_mutation_performed"])
        self.assertTrue(manifest_exists)
        self.assertIn("host firewall not modified", executed["command_results"][0]["stdout"])
        self.assertEqual(state_payload["admin_executions"][0]["status"], AdminExecutionStatus.COMPLETED.value)

    def test_firewall_live_mode_records_blocked_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            plan = overseer_cli.plan_admin_change_status(
                store_path,
                "admin.firewall.live.blocked",
                AdminChangeKind.BLOCK_IP.value,
                "192.0.2.10",
                "exercise live firewall mode block",
                "reviewed source",
            )
            blocked = overseer_cli.execute_firewall_change_status(store_path, plan["id"], "odo", "live", backend_override="ufw")

        self.assertEqual(blocked["status"], AdminExecutionStatus.BLOCKED.value)
        self.assertIn("admin policy", blocked["summary"])
        self.assertEqual(blocked["firewall_backend"]["name"], "ufw")
        self.assertFalse(blocked["host_mutation_performed"])
        self.assertFalse(blocked["firewall_mutation_performed"])

    def test_firewall_live_mode_uses_fake_runner_after_all_gates(self):
        executed_commands = []

        def fake_live_runner(step):
            executed_commands.append(step.command)
            return AdminCommandResult(step.title, step.command, 0, "fake live runner accepted command")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            state.mkdir()
            store_path = state / "overseer.sqlite3"
            plan = overseer_cli.plan_admin_change_status(
                store_path,
                "admin.firewall.live.fake",
                AdminChangeKind.FIREWALL_DENY_TCP.value,
                "tcp/9443",
                "exercise approved live Odo firewall runner with fake command execution",
                "listener exposed",
                port=9443,
            )
            package = overseer_cli.prepare_host_security_ids_review_package_status(store_path, plan["id"])
            overseer_cli.submit_host_security_ids_review_package_status(store_path, package["id"], "odo")
            overseer_cli.record_host_security_ids_review_result_status(
                store_path,
                package["id"],
                "accepted",
                "accepted for fake live runner execution path only",
                "odo",
            )
            enablement = overseer_cli.request_admin_adapter_enablement_status(
                store_path,
                AdminChangeKind.FIREWALL_DENY_TCP.value,
                "odo",
            )
            overseer_cli.approve_admin_adapter_enablement_status(store_path, enablement["approval_id"], "human")
            overseer_cli.approve_admin_change_status(store_path, plan["id"], "human")
            executed = overseer_cli.execute_firewall_change_status(
                store_path,
                plan["id"],
                "odo",
                "live",
                live_runner=fake_live_runner,
                backend_override="ufw",
            )
            manifest_exists = (root / executed["manifest_path"]).exists()

        self.assertEqual(executed["status"], AdminExecutionStatus.COMPLETED.value)
        self.assertEqual(executed["mode"], "live")
        self.assertEqual(executed["firewall_backend"]["name"], "ufw")
        self.assertTrue(executed["host_mutation_performed"])
        self.assertTrue(executed["firewall_mutation_performed"])
        self.assertTrue(manifest_exists)
        self.assertEqual(len(executed_commands), 2)
        self.assertIn("fake live runner accepted command", executed["command_results"][0]["stdout"])

    def test_firewall_live_mode_blocks_backend_incompatible_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            plan = overseer_cli.plan_admin_change_status(
                store_path,
                "admin.firewall.live.backend.blocked",
                AdminChangeKind.FIREWALL_DENY_TCP.value,
                "tcp/9443",
                "exercise incompatible backend gate",
                "listener exposed",
                port=9443,
                use_firewalld=True,
            )
            blocked = overseer_cli.execute_firewall_change_status(store_path, plan["id"], "odo", "live", backend_override="ufw")

        self.assertEqual(blocked["status"], AdminExecutionStatus.BLOCKED.value)
        self.assertIn("incompatible", blocked["summary"])
        self.assertFalse(blocked["host_mutation_performed"])
        self.assertFalse(blocked["firewall_mutation_performed"])

    def test_docker_compose_update_plan_is_human_gated_with_backups(self):
        plan = plan_docker_compose_update(
            "admin.compose.penpot.update",
            "/srv/penpot/docker-compose.yaml",
            "remediate vulnerable active container images",
            "penpot 2.16 images running",
            project_directory="/srv/penpot",
            env=("PENPOT_VERSION=2.17.0",),
            rollback_env=("PENPOT_VERSION=2.16",),
            extra_compose_files=("/srv/penpot/local-secrets/admin-overrides/support.yaml",),
            scan_images=("penpotapp/frontend:2.17.0",),
            health_url="http://127.0.0.1:9001/",
        )

        self.assertEqual(plan.kind, AdminChangeKind.DOCKER_COMPOSE_UPDATE)
        self.assertEqual(plan.owner_domain, OwnerDomain.OBRIEN)
        self.assertEqual(plan.approval_level, ApprovalLevel.HUMAN)
        self.assertEqual(plan.risk_level, RiskLevel.HIGH)
        self.assertIn("Backup Postgres volume", [step.title for step in plan.steps])
        self.assertIn("Backup asset volume", [step.title for step in plan.steps])
        self.assertIn("Backup Compose override 1", [step.title for step in plan.steps])
        self.assertIn(
            (
                "sudo",
                "env",
                "PENPOT_VERSION=2.17.0",
                "docker",
                "compose",
                "-f",
                "/srv/penpot/docker-compose.yaml",
                "-f",
                "/srv/penpot/local-secrets/admin-overrides/support.yaml",
                "pull",
            ),
            [step.command for step in plan.steps],
        )
        self.assertIn(
            ("trivy", "image", "--severity", "CRITICAL,HIGH", "--exit-code", "1", "penpotapp/frontend:2.17.0"),
            [step.command for step in plan.steps],
        )
        self.assertLess(
            [step.title for step in plan.steps].index("Scan updated image penpotapp/frontend:2.17.0"),
            [step.title for step in plan.steps].index("Recreate Compose services"),
        )
        self.assertEqual(
            plan.rollback_steps[0].command,
            ("sudo", "env", "PENPOT_VERSION=2.16", "docker", "compose", "-f", "/srv/penpot/docker-compose.yaml", "up", "-d"),
        )
        self.assertEqual(plan.verification_steps[-1].command, ("curl", "-fsS", "http://127.0.0.1:9001/"))

    def test_docker_compose_update_executes_only_with_enabled_adapter(self):
        plan = approve_admin_change_plan(
            plan_docker_compose_update(
                "admin.compose.penpot.exec",
                "/srv/penpot/docker-compose.yaml",
                "apply approved image update",
                "staged",
                project_directory="/srv/penpot",
            ),
            "human",
        )

        blocked = execute_admin_change_plan(plan)
        executed = execute_admin_change_plan(
            plan,
            enabled_adapter_kinds=(AdminChangeKind.DOCKER_COMPOSE_UPDATE,),
            runner=lambda step: AdminCommandResult(
                title=step.title,
                command=step.command,
                exit_code=0,
                stdout="ok",
            ),
        )
        capability = admin_execution_capability_for(plan.kind, (AdminChangeKind.DOCKER_COMPOSE_UPDATE,))

        self.assertEqual(blocked.status, AdminExecutionStatus.BLOCKED)
        self.assertIn("live adapter unavailable for docker_compose_update", blocked.summary)
        self.assertEqual(capability.status, AdminAdapterStatus.ENABLED)
        self.assertEqual(executed.status, AdminExecutionStatus.COMPLETED)
        self.assertEqual(executed.command_results[-1].command, ("sudo", "docker", "compose", "-f", "/srv/penpot/docker-compose.yaml", "up", "-d"))

    def test_admin_execution_stops_before_later_mutations_after_failed_step(self):
        plan = approve_admin_change_plan(
            plan_docker_compose_update(
                "admin.compose.penpot.scan-gate",
                "/srv/penpot/docker-compose.yaml",
                "block recreate when replacement image scan fails",
                "staged",
                project_directory="/srv/penpot",
                scan_images=("penpotapp/frontend:2.17.0",),
            ),
            "human",
        )
        calls = []

        def runner(step):
            calls.append(step.title)
            return AdminCommandResult(
                title=step.title,
                command=step.command,
                exit_code=1 if step.title.startswith("Scan updated image") else 0,
                stdout="",
            )

        result = execute_admin_change_plan(
            plan,
            enabled_adapter_kinds=(AdminChangeKind.DOCKER_COMPOSE_UPDATE,),
            runner=runner,
        )

        self.assertEqual(result.status, AdminExecutionStatus.FAILED)
        self.assertIn("Scan updated image penpotapp/frontend:2.17.0", result.summary)
        self.assertNotIn("Recreate Compose services", calls)
        self.assertEqual(calls[-1], "Rollback Compose services")
        self.assertEqual([item.title for item in result.command_results][-1], "Scan updated image penpotapp/frontend:2.17.0")

    def test_approved_package_update_executes_only_with_enabled_adapter(self):
        plan = approve_admin_change_plan(
            plan_apt_update("admin.apt.update.exec", "refresh approved package metadata"),
            "sisko",
        )

        blocked = execute_admin_change_plan(plan)
        executed = execute_admin_change_plan(
            plan,
            enabled_adapter_kinds=(AdminChangeKind.APT_UPDATE,),
            runner=lambda step: AdminCommandResult(
                title=step.title,
                command=step.command,
                exit_code=0,
                stdout="ok",
            ),
        )
        capability = admin_execution_capability_for(plan.kind, (AdminChangeKind.APT_UPDATE,))

        self.assertEqual(blocked.status, AdminExecutionStatus.BLOCKED)
        self.assertEqual(capability.status, AdminAdapterStatus.ENABLED)
        self.assertEqual(executed.status, AdminExecutionStatus.COMPLETED)
        self.assertEqual(executed.command_results[0].command, ("sudo", "apt-get", "update"))

    def test_apt_admin_command_runs_noninteractively(self):
        step = AdminCommandStep(
            "Upgrade packages",
            ("sudo", "apt-get", "install", "--only-upgrade", "-y", "sqlite3"),
            "apply approved upgrade",
        )

        with patch.object(overseer_admin.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess(step.command, 0, "ok\n", "")
            result = overseer_admin.run_admin_command_step(step)

        kwargs = run.call_args.kwargs
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(kwargs["env"]["DEBIAN_FRONTEND"], "noninteractive")
        self.assertEqual(kwargs["env"]["DEBIAN_PRIORITY"], "critical")
        self.assertEqual(kwargs["env"]["APT_LISTCHANGES_FRONTEND"], "none")

    def test_non_apt_admin_command_uses_default_environment(self):
        step = AdminCommandStep(
            "Verify user service status",
            ("systemctl", "--user", "status", "overseer-api.service", "--no-pager"),
            "confirm service state",
        )

        with patch.object(overseer_admin.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess(step.command, 0, "active\n", "")
            result = overseer_admin.run_admin_command_step(step)

        self.assertEqual(result.stdout, "active")
        self.assertIsNone(run.call_args.kwargs["env"])

    def test_admin_policy_status_blocks_unapproved_disabled_adapter_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            plan_admin_change_status(
                store_path,
                "admin.apt.upgrade.pending",
                AdminChangeKind.APT_UPGRADE.value,
                "sqlite3",
                "apply approved patch",
                "upgrade available",
                packages=("sqlite3",),
            )

            status = admin_policy_status(store_path)
            item = status["items"][0]
            checks = {check["id"]: check for check in item["checks"]}

        self.assertEqual(status["block"], 1)
        self.assertEqual(item["status"], PolicyCheckStatus.BLOCK.value)
        self.assertEqual(checks["admin.plan.approval"]["status"], PolicyCheckStatus.BLOCK.value)
        self.assertEqual(checks["admin.adapter.enabled"]["status"], PolicyCheckStatus.BLOCK.value)
        self.assertEqual(checks["admin.rollback"]["status"], PolicyCheckStatus.PASS.value)

    def test_admin_policy_status_warns_when_upgrade_is_approved_and_adapter_enabled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store_path = root / "overseer.sqlite3"
            (root / "policy-profile.json").write_text(
                json.dumps({"profile": {"name": "warning-observing", "warn_on_apt_upgrade_rollback": True}}),
                encoding="utf-8",
            )
            plan_admin_change_status(
                store_path,
                "admin.apt.upgrade.ready",
                AdminChangeKind.APT_UPGRADE.value,
                "sqlite3",
                "apply approved patch",
                "upgrade available",
                packages=("sqlite3",),
            )
            requested = request_admin_adapter_enablement_status(
                store_path,
                AdminChangeKind.APT_UPGRADE.value,
                "sisko",
                "2026-07-19T05:30:00+00:00",
            )
            approve_admin_adapter_enablement_status(
                store_path,
                requested["approval_id"],
                "sisko",
                "2026-07-19T05:31:00+00:00",
            )
            approve_admin_change_status(
                store_path,
                "admin.apt.upgrade.ready",
                "operator",
                "2026-07-19T05:32:00+00:00",
            )

            status = admin_policy_status(store_path, "admin.apt.upgrade.ready")
            item = status["items"][0]
            checks = {check["id"]: check for check in item["checks"]}

        self.assertEqual(status["warn"], 1)
        self.assertEqual(item["status"], PolicyCheckStatus.WARN.value)
        self.assertFalse(item["can_proceed"])
        self.assertEqual(checks["admin.plan.approval"]["status"], PolicyCheckStatus.PASS.value)
        self.assertEqual(checks["admin.adapter.enabled"]["status"], PolicyCheckStatus.PASS.value)
        self.assertEqual(checks["admin.rollback"]["status"], PolicyCheckStatus.WARN.value)

    def test_active_policy_profile_status_reports_best_practice_when_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            status = active_policy_profile_status(store_path)

        self.assertEqual(status["profile"]["name"], "best-practice")
        self.assertEqual(status["source"], "best_practice_default")
        self.assertFalse(status["customized"])
        self.assertTrue(status["path"].endswith("policy-profile.json"))
        self.assertIn("build-policy-profile", status["next_step"])

    def test_active_policy_profile_status_reports_store_sibling_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store_path = root / "overseer.sqlite3"
            profile_path = root / "policy-profile.json"
            profile_path.write_text(
                json.dumps(
                    {
                        "name": "store-profile",
                        "block_warnings_until_accepted": False,
                    }
                ),
                encoding="utf-8",
            )

            status = active_policy_profile_status(store_path)

        self.assertEqual(status["profile"]["name"], "store-profile")
        self.assertEqual(status["source"], "store_sibling_file")
        self.assertEqual(status["path"], str(profile_path))
        self.assertTrue(status["customized"])

    def test_admin_policy_status_uses_store_sibling_policy_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store_path = root / "overseer.sqlite3"
            (root / "policy-profile.json").write_text(
                json.dumps(
                    {
                        "name": "store-warning-observing",
                        "warn_on_apt_upgrade_rollback": True,
                        "block_warnings_until_accepted": False,
                    }
                ),
                encoding="utf-8",
            )
            plan_admin_change_status(
                store_path,
                "admin.apt.upgrade.active-profile",
                AdminChangeKind.APT_UPGRADE.value,
                "sqlite3",
                "apply approved patch",
                "upgrade available",
                packages=("sqlite3",),
            )
            requested = request_admin_adapter_enablement_status(store_path, AdminChangeKind.APT_UPGRADE.value, "sisko")
            approve_admin_adapter_enablement_status(store_path, requested["approval_id"], "sisko")
            approve_admin_change_status(store_path, "admin.apt.upgrade.active-profile", "operator")

            status = admin_policy_status(store_path, "admin.apt.upgrade.active-profile")
            item = status["items"][0]

        self.assertEqual(status["policy_profile"], "store-warning-observing")
        self.assertEqual(status["policy_profile_source"], "store_sibling_file")
        self.assertEqual(item["status"], PolicyCheckStatus.WARN.value)
        self.assertTrue(item["can_proceed"])

    def test_execute_admin_change_status_blocks_policy_warnings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store_path = root / "overseer.sqlite3"
            (root / "policy-profile.json").write_text(
                json.dumps({"profile": {"name": "warning-blocking", "warn_on_apt_upgrade_rollback": True}}),
                encoding="utf-8",
            )
            plan_admin_change_status(
                store_path,
                "admin.apt.upgrade.warn-blocked",
                AdminChangeKind.APT_UPGRADE.value,
                "sqlite3",
                "apply approved patch",
                "upgrade available",
                packages=("sqlite3",),
            )
            requested = request_admin_adapter_enablement_status(
                store_path,
                AdminChangeKind.APT_UPGRADE.value,
                "sisko",
            )
            approve_admin_adapter_enablement_status(store_path, requested["approval_id"], "sisko")
            approve_admin_change_status(store_path, "admin.apt.upgrade.warn-blocked", "operator")

            result = execute_admin_change_status(
                store_path,
                "admin.apt.upgrade.warn-blocked",
                runner=lambda step: self.fail("policy warnings must block command execution"),
            )

        self.assertEqual(result["status"], AdminExecutionStatus.BLOCKED.value)
        self.assertEqual(result["policy"]["status"], PolicyCheckStatus.WARN.value)
        self.assertIn("admin policy warn", result["summary"])

    def test_execute_admin_change_status_uses_store_sibling_policy_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store_path = root / "overseer.sqlite3"
            (root / "policy-profile.json").write_text(
                json.dumps({"profile": {"name": "store-execution-profile", "block_warnings_until_accepted": False}}),
                encoding="utf-8",
            )
            plan_admin_change_status(
                store_path,
                "admin.apt.upgrade.active-profile-exec",
                AdminChangeKind.APT_UPGRADE.value,
                "sqlite3",
                "apply approved patch",
                "upgrade available",
                packages=("sqlite3",),
            )
            requested = request_admin_adapter_enablement_status(store_path, AdminChangeKind.APT_UPGRADE.value, "sisko")
            approve_admin_adapter_enablement_status(store_path, requested["approval_id"], "sisko")
            approve_admin_change_status(store_path, "admin.apt.upgrade.active-profile-exec", "operator")

            result = execute_admin_change_status(
                store_path,
                "admin.apt.upgrade.active-profile-exec",
                runner=lambda step: AdminCommandResult(
                    title=step.title,
                    command=step.command,
                    exit_code=0,
                    stdout="ok",
                ),
            )

        self.assertEqual(result["status"], AdminExecutionStatus.COMPLETED.value)
        self.assertEqual(result["policy_profile"], "store-execution-profile")
        self.assertEqual(result["policy_profile_source"], "store_sibling_file")

    def test_execute_admin_change_status_runs_rollback_when_upgrade_verification_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            plan_admin_change_status(
                store_path,
                "admin.apt.upgrade.rollback",
                AdminChangeKind.APT_UPGRADE.value,
                "sqlite3",
                "apply package patch",
                "sqlite3 upgrade available",
                packages=("sqlite3",),
            )
            requested = request_admin_adapter_enablement_status(store_path, AdminChangeKind.APT_UPGRADE.value, "sisko")
            approve_admin_adapter_enablement_status(store_path, requested["approval_id"], "sisko")
            approve_admin_change_status(store_path, "admin.apt.upgrade.rollback", "sisko")

            def runner(step):
                if step.title == "Verify package upgrade":
                    return AdminCommandResult(step.title, step.command, 1, stderr="package query failed")
                return AdminCommandResult(step.title, step.command, 0, stdout="ok")

            result = execute_admin_change_status(store_path, "admin.apt.upgrade.rollback", runner=runner)
            executions = admin_executions_status(store_path)

        self.assertEqual(result["status"], AdminExecutionStatus.FAILED.value)
        self.assertIn("rollback steps attempted", result["summary"])
        self.assertEqual(result["rollback_results"][0]["command"], ["sudo", "apt-get", "check"])
        self.assertEqual(result["rollback_results"][1]["command"], ["sudo", "apt-get", "-f", "install", "-y"])
        self.assertEqual(executions["executions"][0]["rollback_results"][1]["title"], "Attempt package recovery")

    def test_obrien_advancement_uses_sisko_approval_for_package_upgrade(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            plan_admin_change_status(
                store_path,
                "admin.apt.upgrade.sisko-auto",
                AdminChangeKind.APT_UPGRADE.value,
                "sqlite3",
                "apply package patch",
                "sqlite3 upgrade available",
                packages=("sqlite3",),
            )
            requested = request_admin_adapter_enablement_status(store_path, AdminChangeKind.APT_UPGRADE.value, "sisko")
            approve_admin_adapter_enablement_status(store_path, requested["approval_id"], "sisko")

            with patch("overseer.cli.execute_admin_change_status") as execute:
                execute.return_value = {"status": AdminExecutionStatus.COMPLETED.value}
                status = overseer_cli._advance_obrien_package_plan(
                    store_path,
                    "admin.apt.upgrade.sisko-auto",
                    "2026-07-20T20:30:00+00:00",
                )

            store = SQLiteStore(store_path)
            try:
                plan = store.load_admin_change_plan("admin.apt.upgrade.sisko-auto")
            finally:
                store.close()

        self.assertEqual(status["readiness_state"], "sisko_approved")
        self.assertEqual(status["approval"]["approval_level"], ApprovalLevel.SISKO.value)
        self.assertEqual(status["execution"]["status"], AdminExecutionStatus.COMPLETED.value)
        self.assertTrue(plan.approved)
        self.assertEqual(plan.approved_by, "sisko")

    def test_admin_policy_warning_approval_allows_residual_warning(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            (Path(directory) / "policy-profile.json").write_text(
                json.dumps({"profile": {"name": "warning-observing", "warn_on_apt_upgrade_rollback": True}}),
                encoding="utf-8",
            )
            plan_admin_change_status(
                store_path,
                "admin.apt.upgrade.warning-accepted",
                AdminChangeKind.APT_UPGRADE.value,
                "libslirp0",
                "apply approved package patch",
                "upgrade available",
                packages=("libslirp0",),
            )
            requested_adapter = request_admin_adapter_enablement_status(
                store_path,
                AdminChangeKind.APT_UPGRADE.value,
                "sisko",
            )
            approve_admin_adapter_enablement_status(store_path, requested_adapter["approval_id"], "sisko")
            approve_admin_change_status(store_path, "admin.apt.upgrade.warning-accepted", "operator")

            warning_request = request_admin_policy_warning_status(
                store_path,
                "admin.apt.upgrade.warning-accepted",
                "admin.rollback",
                "sisko",
            )
            pending = authorizations_required_status(store_path)
            approved_warning = approve_admin_policy_warning_status(
                store_path,
                warning_request["approval_id"],
                "operator",
            )
            status = admin_policy_status(store_path, "admin.apt.upgrade.warning-accepted")
            checks = {check["id"]: check for check in status["items"][0]["checks"]}
            after = authorizations_required_status(store_path)

        self.assertEqual(warning_request["approval_status"], ApprovalStatus.PENDING.value)
        self.assertEqual(pending["pending_policy_warning_approval_count"], 1)
        self.assertTrue(approved_warning["policy_warning_approval"])
        self.assertEqual(status["pass"], 1)
        self.assertEqual(checks["admin.rollback"]["status"], PolicyCheckStatus.PASS.value)
        self.assertIn("accepted residual warning", checks["admin.rollback"]["summary"])
        self.assertEqual(after["pending_policy_warning_approval_count"], 0)

    def test_admin_policy_status_warns_on_residual_compose_scan_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            plan = plan_admin_change_status(
                store_path,
                "admin.compose.penpot.residual-scan",
                AdminChangeKind.DOCKER_COMPOSE_UPDATE.value,
                "/srv/penpot/docker-compose.yaml",
                "reduce Penpot image vulnerability exposure",
                "Penpot app images have higher current critical/high findings",
                compose_project_directory="/srv/penpot",
                compose_extra_file=("/srv/penpot/local-secrets/admin-overrides/app-2.17.yaml",),
                compose_residual_scan_finding=("penpotapp/exporter:2.17 keeps critical findings after reducing total exposure",),
                health_url="http://127.0.0.1:9001/",
            )

            approve_admin_change_status(store_path, plan["id"], "human")
            requested_adapter = request_admin_adapter_enablement_status(
                store_path,
                AdminChangeKind.DOCKER_COMPOSE_UPDATE.value,
                "sisko",
            )
            approve_admin_adapter_enablement_status(store_path, requested_adapter["approval_id"], "sisko")
            status = admin_policy_status(store_path, plan["id"])
            checks = {check["id"]: check for check in status["items"][0]["checks"]}
            warning_request = request_admin_policy_warning_status(
                store_path,
                plan["id"],
                "admin.scan.residual-findings",
                "sisko",
            )

        self.assertEqual(plan["residual_scan_findings"], ["penpotapp/exporter:2.17 keeps critical findings after reducing total exposure"])
        self.assertEqual(status["warn"], 1)
        self.assertEqual(checks["admin.scan.residual-findings"]["status"], PolicyCheckStatus.WARN.value)
        self.assertEqual(warning_request["check_id"], "admin.scan.residual-findings")

    def test_residual_compose_scan_findings_keep_non_failing_scan_evidence(self):
        plan = plan_docker_compose_update(
            "admin.compose.penpot.residual",
            "/srv/penpot/docker-compose.yaml",
            "reduce image findings while preserving residual evidence",
            "current image family has more findings",
            project_directory="/srv/penpot",
            scan_images=("penpotapp/backend:2.17",),
            residual_scan_findings=("penpotapp/backend:2.17 retains high findings",),
            health_url="http://127.0.0.1:9001/",
        )

        self.assertIn(
            ("trivy", "image", "--severity", "CRITICAL,HIGH", "--exit-code", "0", "penpotapp/backend:2.17"),
            [step.command for step in plan.steps],
        )
        self.assertEqual(plan.residual_scan_findings, ("penpotapp/backend:2.17 retains high findings",))

    def test_policy_customization_helper_reports_best_practice_questions(self):
        status = policy_customization_helper_status()
        question_ids = {question["id"] for question in status["questions"]}

        self.assertEqual(status["profile"]["name"], "best-practice")
        self.assertEqual(status["profile"]["minimum_approval_by_risk"]["medium"], ApprovalLevel.SISKO.value)
        self.assertIn("risk-medium-approval", question_ids)
        self.assertIn("warnings-block", question_ids)

    def test_policy_profile_from_mapping_customizes_warning_execution_gate(self):
        profile = policy_profile_from_mapping(
            {
                "name": "lab-relaxed",
                "block_warnings_until_accepted": False,
                "minimum_approval_by_risk": {"medium": "role"},
            }
        )

        self.assertEqual(profile.name, "lab-relaxed")
        self.assertFalse(profile.block_warnings_until_accepted)
        self.assertEqual(profile.minimum_approval_by_risk[RiskLevel.MEDIUM], ApprovalLevel.ROLE)

    def test_policy_profile_from_answers_builds_custom_profile(self):
        status = policy_profile_from_answers_status(
            {
                "name": "lab-profile",
                "description": "Local lab profile",
                "risk-medium-approval": ApprovalLevel.ROLE.value,
                "warnings-block": False,
            }
        )

        self.assertEqual(status["profile"]["name"], "lab-profile")
        self.assertEqual(status["profile"]["description"], "Local lab profile")
        self.assertEqual(status["profile"]["minimum_approval_by_risk"]["medium"], ApprovalLevel.ROLE.value)
        self.assertFalse(status["profile"]["block_warnings_until_accepted"])

    def test_build_policy_profile_status_writes_profile_from_answers_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            answers_path = root / "answers.json"
            output_path = root / "policy-profile.json"
            answers_path.write_text(
                json.dumps(
                    {
                        "name": "file-profile",
                        "risk-critical-approval": ApprovalLevel.HUMAN.value,
                        "apt-upgrade-warning": False,
                    }
                ),
                encoding="utf-8",
            )

            status = build_policy_profile_status(answers_path, output_path)
            written = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(status["output_path"], str(output_path))
        self.assertEqual(written["name"], "file-profile")
        self.assertFalse(written["warn_on_apt_upgrade_rollback"])

    def test_execute_admin_change_status_can_use_policy_profile_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store_path = root / "overseer.sqlite3"
            profile_path = root / "policy-profile.json"
            profile_path.write_text(
                json.dumps(
                    {
                        "profile": {
                            "name": "warning-observing",
                            "block_warnings_until_accepted": False,
                        }
                    }
                ),
                encoding="utf-8",
            )
            plan_admin_change_status(
                store_path,
                "admin.apt.upgrade.profile",
                AdminChangeKind.APT_UPGRADE.value,
                "sqlite3",
                "apply approved patch",
                "upgrade available",
                packages=("sqlite3",),
            )
            requested = request_admin_adapter_enablement_status(store_path, AdminChangeKind.APT_UPGRADE.value, "sisko")
            approve_admin_adapter_enablement_status(store_path, requested["approval_id"], "sisko")
            approve_admin_change_status(store_path, "admin.apt.upgrade.profile", "operator")

            result = execute_admin_change_status(
                store_path,
                "admin.apt.upgrade.profile",
                runner=lambda step: AdminCommandResult(
                    title=step.title,
                    command=step.command,
                    exit_code=0,
                    stdout="ok",
                ),
                policy_profile_path=profile_path,
            )

        self.assertEqual(result["status"], AdminExecutionStatus.COMPLETED.value)


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
            self.assertEqual(identities[0].source, PhysicalIdentitySource.DISCOVERED)
            self.assertIsNotNone(identities[0].last_observed_at)
            self.assertTrue(identities[0].is_complete_for_exclusive_checkout())

    def test_path_physical_discovery_enriches_usb_sysfs_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "serial"
            dev = base / "dev"
            sysfs_tty = base / "sys" / "class" / "tty"
            root.mkdir()
            dev.mkdir()
            tty_path = dev / "ttyUSB0"
            tty_path.touch()
            (root / "usb-FTDI_RS485_A-if00-port0").symlink_to(tty_path)
            device = sysfs_tty / "ttyUSB0" / "device"
            device.mkdir(parents=True)
            (device / "idVendor").write_text("0403\n", encoding="utf-8")
            (device / "idProduct").write_text("6001\n", encoding="utf-8")
            (device / "serial").write_text("FT1234\n", encoding="utf-8")

            identities = PathPhysicalDiscoveryAdapter((root,), sysfs_tty_root=sysfs_tty).discover()

            self.assertEqual(len(identities), 1)
            self.assertEqual(identities[0].vendor_id, "0403")
            self.assertEqual(identities[0].product_id, "6001")
            self.assertEqual(identities[0].serial_number, "FT1234")
            self.assertIn("usb", identities[0].capabilities)

    def test_discover_physical_status_reports_temp_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "usb-Serial_Device-if00-port0").touch()

            status = discover_physical_status((str(root),))

            self.assertEqual(status["count"], 1)
            self.assertEqual(status["assets"][0]["kind"], PhysicalAssetKind.SERIAL_PORT.value)
            self.assertEqual(status["assets"][0]["source"], PhysicalIdentitySource.DISCOVERED.value)
            self.assertIn("vendor_id", status["assets"][0])

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
            self.assertEqual(
                store.load_physical_identity("serial.usb-serial-device-if00-port0").source,
                PhysicalIdentitySource.DISCOVERED,
            )
            store.close()

    def test_storage_physical_discovery_reads_sysfs_block_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "block"
            device = root / "sdb" / "device"
            device.mkdir(parents=True)
            (root / "sdb" / "removable").write_text("1\n", encoding="utf-8")
            (root / "sdb" / "ro").write_text("0\n", encoding="utf-8")
            (root / "sdb" / "size").write_text("2048\n", encoding="utf-8")
            (device / "model").write_text("Backup Stick\n", encoding="utf-8")
            (device / "serial").write_text("USB123\n", encoding="utf-8")
            (device / "idVendor").write_text("abcd\n", encoding="utf-8")
            (device / "idProduct").write_text("1234\n", encoding="utf-8")
            (root / "loop0").mkdir()

            identities = StoragePhysicalDiscoveryAdapter(root).discover()

        self.assertEqual(len(identities), 1)
        self.assertEqual(identities[0].kind, PhysicalAssetKind.STORAGE_ARRAY)
        self.assertEqual(identities[0].stable_id, "storage.backup-stick-usb123")
        self.assertEqual(identities[0].vendor_id, "abcd")
        self.assertEqual(identities[0].product_id, "1234")
        self.assertEqual(identities[0].serial_number, "USB123")
        self.assertEqual(identities[0].storage_profile, "removable_read_write")
        self.assertIn("block_storage", identities[0].capabilities)
        self.assertIn("removable", identities[0].capabilities)
        self.assertIn("usb", identities[0].capabilities)
        self.assertTrue(identities[0].has_storage_risk())

    def test_discover_storage_status_persists_to_explicit_store(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "block"
            device = root / "sda" / "device"
            device.mkdir(parents=True)
            (root / "sda" / "removable").write_text("0\n", encoding="utf-8")
            (root / "sda" / "ro").write_text("1\n", encoding="utf-8")
            (device / "model").write_text("Readonly Array\n", encoding="utf-8")
            store_path = Path(directory) / "overseer.sqlite3"

            status = discover_storage_status(root, store_path)
            store = SQLiteStore(store_path)
            loaded = store.load_physical_identity("storage.sda")

        self.assertEqual(status["count"], 1)
        self.assertEqual(status["assets"][0]["kind"], PhysicalAssetKind.STORAGE_ARRAY.value)
        self.assertEqual(status["assets"][0]["storage_profile"], "read_only")
        self.assertFalse(status["assets"][0]["storage_risk"])
        self.assertEqual(loaded.kind, PhysicalAssetKind.STORAGE_ARRAY)
        self.assertEqual(loaded.source, PhysicalIdentitySource.DISCOVERED)
        store.close()


class VirtualDiscoveryTests(unittest.TestCase):
    def test_parse_tcp_listeners_extracts_unique_listen_sockets(self):
        listeners = parse_tcp_listeners(
            "\n".join(
                (
                    "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process",
                    'LISTEN 0 4096 127.0.0.1:8766 0.0.0.0:* users:(("python3",pid=100,fd=3))',
                    'LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=101,fd=4))',
                    'LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=101,fd=4))',
                )
            )
        )

        self.assertEqual(len(listeners), 2)
        self.assertEqual(listeners[0].address, "127.0.0.1")
        self.assertEqual(listeners[0].port, 8766)
        self.assertEqual(listeners[1].address, "0.0.0.0")
        self.assertEqual(listeners[1].port, 22)

    def test_listener_virtual_discovery_maps_snapshot_to_resources(self):
        snapshot = HostInspectionSnapshot(
            id="host.test",
            captured_at="2026-07-19T09:00:00+00:00",
            hostname="test-host",
            os_release={},
            observations=(
                HostCommandObservation(
                    name="ss",
                    command=("ss", "-ltnp"),
                    exit_code=0,
                    stdout='LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=101,fd=4))',
                ),
            ),
        )

        resources = ListenerVirtualDiscoveryAdapter().discover(snapshot)

        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0].id, "listener.tcp.0-0-0-0.22")
        self.assertEqual(resources[0].type, ResourceType.VIRTUAL_ASSET)
        self.assertEqual(resources[0].owner_domain, OwnerDomain.DAX)
        self.assertEqual(resources[0].risk_level, RiskLevel.HIGH)
        self.assertEqual(resources[0].identifiers["kind"], "gateway")
        self.assertEqual(resources[0].identifiers["bind_scope"], "all_interfaces")
        self.assertEqual(resources[0].ports(), frozenset({22}))
        self.assertIn("tcp.22", resources[0].exclusive_groups)
        self.assertIn("tcp.0-0-0-0.22", resources[0].exclusive_groups)

    def test_discover_virtual_listeners_status_persists_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            snapshot = HostInspectionSnapshot(
                id="host.persist",
                captured_at="2026-07-19T09:00:00+00:00",
                hostname="test-host",
                os_release={},
                observations=(
                    HostCommandObservation(
                        name="ss",
                        command=("ss", "-ltnp"),
                        exit_code=0,
                        stdout="LISTEN 0 4096 127.0.0.1:8766 0.0.0.0:*",
                    ),
                ),
            )
            status = discover_virtual_listeners_status(store_path, snapshot=snapshot)
            summary = virtual_summary_status(store_path)

        self.assertEqual(status["store"], str(store_path))
        self.assertEqual(status["count"], 1)
        self.assertEqual(status["assets"][0]["protocol"], "tcp")
        self.assertEqual(status["assets"][0]["bind_scope"], "loopback")
        self.assertEqual(summary["assets"], status["count"])


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


class UsageContinuationRequestTests(unittest.TestCase):
    class _Completed:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    class _FakeRunner:
        def __init__(self):
            self.commands = []

        def __call__(self, command, text=True, capture_output=True):
            self.commands.append(command)
            if command[:2] == ["/tmp/tmux", "has-session"]:
                return UsageContinuationRequestTests._Completed(returncode=1, stderr="no session")
            return UsageContinuationRequestTests._Completed(returncode=0, stdout="started")

    def test_codex_project_thread_adapter_resumes_registry_thread_detached(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = Path(directory) / "codex-projects.csv"
            registry.write_text(
                "conversation_id,label,project,command,launcher,created_at,updated_at,source,notes\n"
                "019f7140-debb-7c40-a056-d29be0630f01,Overseer,"
                "/workspace/Overseer,codex-overseer-019f7140,/bin/codex-overseer-019f7140,"
                "2026-07-17T18:05:04+00:00,2026-07-18T19:57:08+00:00,registry,\n",
                encoding="utf-8",
            )
            runner = self._FakeRunner()
            adapter = CodexProjectThreadAdapter(
                registry,
                tmux_path="/tmp/tmux",
                codex_memory_session_path="/tmp/codex-memory-session",
                runner=runner,
            )

            result = adapter.resume("codex-overseer-019f7140")

            self.assertEqual(result.status, "resumed")
            self.assertEqual(result.conversation_id, "019f7140-debb-7c40-a056-d29be0630f01")
            self.assertEqual(runner.commands[0], ["/tmp/tmux", "has-session", "-t", "codex-overseer-019f7140"])
            self.assertEqual(runner.commands[1][0:6], ["/tmp/tmux", "new-session", "-d", "-s", "codex-overseer-019f7140", "-c"])
            self.assertIn("/tmp/codex-memory-session", runner.commands[1])

    def test_maps_codex_project_thread_to_usage_limited_resource(self):
        thread = CodexProjectThread(
            conversation_id="019f7140-debb-7c40-a056-d29be0630f01",
            label="Overseer",
            project="/workspace/Overseer",
            command="codex-overseer-019f7140",
            launcher="/bin/codex-overseer-019f7140",
        )

        resource = codex_project_thread_resource(thread)

        self.assertEqual(resource.id, "thread.codex.codex-overseer-019f7140")
        self.assertEqual(resource.type, ResourceType.USAGE_LIMITED_SERVICE)
        self.assertEqual(resource.owner_domain, OwnerDomain.QUARK)
        self.assertEqual(resource.identifiers["conversation_id"], thread.conversation_id)

    def test_discovers_codex_project_threads_as_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            registry = Path(directory) / "codex-projects.csv"
            registry.write_text(
                "conversation_id,label,project,command,launcher,created_at,updated_at,source,notes\n"
                "019f7140-debb-7c40-a056-d29be0630f01,Overseer,"
                "/workspace/Overseer,codex-overseer-019f7140,/bin/codex-overseer-019f7140,"
                "2026-07-17T18:05:04+00:00,2026-07-18T19:57:08+00:00,registry,\n",
                encoding="utf-8",
            )

            status = discover_codex_project_threads_status(store_path, registry)
            store = SQLiteStore(store_path)
            resource = store.load_resource("thread.codex.codex-overseer-019f7140")
            store.close()

            self.assertTrue(status["mutation_performed"])
            self.assertFalse(status["host_mutation_performed"])
            self.assertEqual(status["threads"], 1)
            self.assertEqual(status["items"][0]["resource_id"], resource.id)
            self.assertEqual(resource.identifiers["project"], "/workspace/Overseer")

    def test_api_client_discovers_codex_project_threads(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            registry = Path(directory) / "codex-projects.csv"
            registry.write_text(
                "conversation_id,label,project,command,launcher,created_at,updated_at,source,notes\n"
                "019f7140-debb-7c40-a056-d29be0630f01,Overseer,"
                "/workspace/Overseer,codex-overseer-019f7140,/bin/codex-overseer-019f7140,"
                "2026-07-17T18:05:04+00:00,2026-07-18T19:57:08+00:00,registry,\n",
                encoding="utf-8",
            )
            with LocalOverseerApiServer(store_path, auth_token="secret") as harness:
                client = OverseerApiClient(harness.url, auth_token="secret")

                status = client.discover_codex_project_threads(str(registry))

            self.assertEqual(status["threads"], 1)
            self.assertEqual(status["items"][0]["command"], "codex-overseer-019f7140")

    def test_api_client_records_and_filters_crew_messages(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            with LocalOverseerApiServer(store_path, auth_token="secret") as harness:
                client = OverseerApiClient(harness.url, auth_token="secret")

                recorded = client.record_crew_message(
                    OwnerDomain.ODO.value,
                    "Investigate source",
                    "Review a suspicious source before planning a block.",
                    priority=RiskLevel.CRITICAL.value,
                    message_id="crew.odo.investigate-source",
                )
                summary = client.crew_messages(owner_domain=OwnerDomain.ODO.value)

            self.assertEqual(recorded["message"]["owner_domain"], OwnerDomain.ODO.value)
            self.assertEqual(summary["messages"], 1)
            self.assertEqual(summary["items"][0]["id"], "crew.odo.investigate-source")

    def test_dispatches_odo_ids_subordinate_message(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            record_crew_message_status(
                store_path,
                OwnerDomain.ODO_IDS.value,
                "Review firewall advisory",
                "Odo directed IDS to review the exact staged firewall package.",
                RiskLevel.HIGH.value,
                message_id="crew.odo-ids.review-firewall",
                related_plan_id="admin.host-security.deny-tcp.22",
            )

            with patch(
                "overseer.cli._ensure_ids_review_package_for_plan",
                return_value={
                    "id": "ids-review.admin.host-security.deny-tcp.22",
                    "status": "submitted",
                    "host_mutation_performed": False,
                },
            ) as ensure_package:
                status = dispatch_crew_messages_status(
                    store_path,
                    owner_domain=OwnerDomain.ODO_IDS.value,
                    dispatched_at="2026-07-27T02:30:00+00:00",
                )
            summary = crew_messages_status(store_path, owner_domain=OwnerDomain.ODO_IDS.value)

        self.assertEqual(status["processed"], 1)
        self.assertEqual(status["acknowledged"], 1)
        self.assertFalse(status["host_mutation_performed"])
        ensure_package.assert_called_once()
        self.assertEqual(summary["by_owner_domain"][OwnerDomain.ODO_IDS.value]["dispatches"], 1)

    def test_dispatches_odo_firewall_subordinate_message(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            record_crew_message_status(
                store_path,
                OwnerDomain.ODO_FIREWALL.value,
                "Advance firewall plan",
                "Odo directed firewall management to advance this exact plan.",
                RiskLevel.HIGH.value,
                message_id="crew.odo-firewall.advance-plan",
                related_plan_id="admin.host-security.deny-tcp.22",
            )

            with patch(
                "overseer.cli._advance_admin_plan_after_dispatch",
                return_value={
                    "plan_id": "admin.host-security.deny-tcp.22",
                    "readiness_state": "ids_review_blocked",
                    "host_mutation_performed": False,
                },
            ) as advance_plan:
                status = dispatch_crew_messages_status(
                    store_path,
                    owner_domain=OwnerDomain.ODO_FIREWALL.value,
                    dispatched_at="2026-07-27T02:31:00+00:00",
                )
            summary = crew_messages_status(store_path, owner_domain=OwnerDomain.ODO_FIREWALL.value)

        self.assertEqual(status["processed"], 1)
        self.assertEqual(status["acknowledged"], 1)
        self.assertFalse(status["host_mutation_performed"])
        advance_plan.assert_called_once()
        self.assertEqual(summary["by_owner_domain"][OwnerDomain.ODO_FIREWALL.value]["dispatches"], 1)

    def test_records_usage_limit_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            status = record_usage_limit_status(
                store_path,
                "limit.github.requests",
                "svc.github",
                LimitKind.REQUESTS.value,
                5000,
                4000,
                "hourly",
                resets_at="2026-07-18T11:00:00-04:00",
                observed_at="2026-07-18T10:30:00-04:00",
                confidence=0.9,
            )
            summary = usage_summary_status(store_path)

            self.assertTrue(status["mutation_performed"])
            self.assertFalse(status["host_mutation_performed"])
            self.assertEqual(status["limit"]["remaining"], 4000)
            self.assertEqual(summary["limits"], 1)
            self.assertEqual(summary["items"][0]["confidence"], 0.9)

    def test_records_crew_message_and_audits_request(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            status = record_crew_message_status(
                store_path,
                OwnerDomain.QUARK.value,
                "MCP API quota scheduling",
                "Queue work until the API-keyed MCP service call limit resets.",
                RiskLevel.HIGH.value,
                requested_by="operator",
                message_id="crew.quark.mcp-api-quota",
                created_at="2026-07-19T12:00:00+00:00",
                related_limit_id="limit.mcp.api.calls.daily",
            )
            summary = crew_messages_status(store_path, owner_domain=OwnerDomain.QUARK.value)

            self.assertTrue(status["mutation_performed"])
            self.assertFalse(status["host_mutation_performed"])
            self.assertEqual(status["message"]["id"], "crew.quark.mcp-api-quota")
            self.assertEqual(status["message"]["related_limit_id"], "limit.mcp.api.calls.daily")
            self.assertEqual(status["audit_event"]["event_type"], AuditEventType.REQUESTED.value)
            self.assertEqual(summary["messages"], 1)
            self.assertEqual(summary["summary"]["open"], 1)
            self.assertEqual(summary["by_status"]["open"], 1)
            self.assertEqual(summary["by_owner_domain"]["quark"]["open"], 1)
            self.assertEqual(summary["items"][0]["subject"], "MCP API quota scheduling")

    def test_dispatches_quark_message_to_usage_continuation_request(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_usage_limit(
                UsageLimit(
                    id="limit.mcp.api.calls.daily",
                    resource_id="svc.mcp.api-keyed",
                    kind=LimitKind.DAILY_QUOTA,
                    capacity=1000,
                    remaining=0,
                    resets_at="2026-07-20T00:00:00+00:00",
                    window="daily",
                )
            )
            store.close()
            record_crew_message_status(
                store_path,
                OwnerDomain.QUARK.value,
                "MCP API quota scheduling",
                "Continue API-keyed MCP work when quota resets.",
                RiskLevel.MEDIUM.value,
                requested_by="thread.mcp",
                message_id="crew.quark.dispatch-quota",
                related_limit_id="limit.mcp.api.calls.daily",
            )

            status = dispatch_crew_messages_status(
                store_path,
                owner_domain=OwnerDomain.QUARK.value,
                dispatched_at="2026-07-19T13:00:00+00:00",
            )
            summary = crew_messages_status(store_path, owner_domain=OwnerDomain.QUARK.value)
            plan = usage_continuation_plan_status(store_path)

            self.assertEqual(status["processed"], 1)
            self.assertEqual(status["acknowledged"], 1)
            self.assertEqual(summary["items"][0]["status"], "acknowledged")
            self.assertEqual(summary["summary"]["acknowledged"], 1)
            self.assertEqual(summary["by_owner_domain"]["quark"]["dispatches"], 1)
            self.assertEqual(summary["recent_dispatches"][0]["message_id"], "crew.quark.dispatch-quota")
            self.assertEqual(summary["recent_dispatches"][0]["event_type"], AuditEventType.EXECUTED.value)
            self.assertIn("quark dispatch", summary["recent_dispatches"][0]["reason"])
            self.assertEqual(plan["continuation_requests"], 1)
            self.assertEqual(plan["items"][0]["id"], "work.crew.quark.dispatch-quota")

    def test_dispatches_quark_remote_testing_message_without_usage_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store_path = root / "state" / "overseer.sqlite3"
            store_path.parent.mkdir()
            request_remote_testing_lease_status(
                root,
                "lease.roadex",
                "Roadex",
                "coordinate Tank through Quark",
                job_types=("roadex.project_creation_flow",),
            )
            enqueue_remote_test_job_status(
                root,
                "lease.roadex",
                "roadex.project_creation_flow",
                params={
                    "allow_mutation": True,
                    "require_explicit_user_approval": True,
                },
                mutates=True,
            )
            record_crew_message_status(
                store_path,
                OwnerDomain.QUARK.value,
                "Dispatch Tank Roadex job",
                "Have Tank claim the approved leased job.",
                RiskLevel.HIGH.value,
                requested_by="Roadex",
                message_id="crew.quark.remote-testing",
                related_resource_id="remote-testing.tank-msi",
            )

            status = dispatch_crew_messages_status(
                store_path,
                message_id="crew.quark.remote-testing",
                dispatched_at="2026-07-26T18:00:00+00:00",
            )

            self.assertEqual(status["processed"], 1)
            self.assertEqual(status["acknowledged"], 1)
            self.assertEqual(status["blocked"], 0)
            self.assertEqual(status["items"][0]["status"], "dispatched")
            self.assertIn("Tank pickup", status["items"][0]["reason"])

    def test_crew_message_summary_reports_blocked_dispatch_history(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            record_crew_message_status(
                store_path,
                OwnerDomain.QUARK.value,
                "Missing limit",
                "Continue work after a limit that has not been registered.",
                RiskLevel.MEDIUM.value,
                requested_by="thread.missing-limit",
                message_id="crew.quark.missing-limit",
                related_limit_id="limit.missing",
            )

            status = dispatch_crew_messages_status(
                store_path,
                owner_domain=OwnerDomain.QUARK.value,
                dispatched_at="2026-07-19T13:02:00+00:00",
            )
            summary = crew_messages_status(store_path)

            self.assertEqual(status["processed"], 1)
            self.assertEqual(status["blocked"], 1)
            self.assertEqual(summary["summary"]["open"], 1)
            self.assertEqual(summary["summary"]["blocked_dispatches"], 1)
            self.assertEqual(summary["by_owner_domain"]["quark"]["blocked_dispatches"], 1)
            self.assertEqual(summary["recent_dispatches"][0]["event_type"], AuditEventType.BLOCKED.value)
            self.assertIn("limit.missing", summary["recent_dispatches"][0]["reason"])

    def test_dispatches_sisko_exact_plan_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            plan_admin_change_status(
                store_path,
                "admin.restart.dispatch-test",
                AdminChangeKind.USER_SERVICE_RESTART.value,
                "overseer-api.service",
                "restart service after operator request",
                "active",
            )
            record_crew_message_status(
                store_path,
                OwnerDomain.SISKO.value,
                "Approve plan",
                "Approved for Sisko dispatch.",
                RiskLevel.MEDIUM.value,
                message_id="crew.sisko.approve-restart",
                related_plan_id="admin.restart.dispatch-test",
            )

            status = dispatch_crew_messages_status(
                store_path,
                owner_domain=OwnerDomain.SISKO.value,
                dispatched_at="2026-07-19T13:05:00+00:00",
            )
            readiness = admin_execution_readiness_status(store_path)

            self.assertEqual(status["processed"], 1)
            self.assertEqual(status["items"][0]["status"], "dispatched")
            approved = next(item for item in readiness["items"] if item["id"] == "admin.restart.dispatch-test")
            self.assertTrue(approved["approved"])

    def test_dispatching_odo_stages_exact_sisko_and_ids_review_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            snapshot = HostInspectionAdapter(
                command_runner=lambda command, timeout_seconds: HostCommandObservation(
                    name=command[0],
                    command=tuple(command),
                    exit_code=0,
                    stdout=(
                        "odo-dispatch-host"
                        if tuple(command) == ("hostname",)
                        else "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                        "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
                        if tuple(command) == ("ss", "-ltnp")
                        else "ok"
                    ),
                ),
                file_reader=lambda path: "ID=debian\n",
            ).inspect("2026-07-19T13:06:00+00:00")
            store = SQLiteStore(store_path)
            store.save_host_snapshot(snapshot)
            store.close()
            record_crew_message_status(
                store_path,
                OwnerDomain.ODO.value,
                "Resolve exposure findings",
                "I reviewed the high and warning exposure findings. Odo is approved to stage remediation for Sisko.",
                RiskLevel.HIGH.value,
                message_id="crew.odo.resolve-exposure",
                requested_by="operator",
            )

            with patch("overseer.cli.inspect_host_status", return_value={"id": snapshot.id}):
                status = dispatch_crew_messages_status(
                    store_path,
                    owner_domain=OwnerDomain.ODO.value,
                    dispatched_at="2026-07-19T13:07:00+00:00",
                )
            readiness = admin_execution_readiness_status(store_path)
            messages = crew_messages_status(store_path, owner_domain=OwnerDomain.SISKO.value, status=CrewMessageStatus.OPEN.value)
            ids_packages = host_security_ids_review_packages_status(store_path)

        self.assertEqual(status["processed"], 1)
        self.assertEqual(status["items"][0]["status"], "dispatched")
        staged = next(item for item in readiness["items"] if item["id"] == "admin.host-security.deny-tcp.22")
        self.assertEqual(staged["readiness_state"], "ids_review_blocked")
        self.assertEqual(ids_packages["package_count"], 1)
        self.assertEqual(ids_packages["packages"][0]["plan_id"], "admin.host-security.deny-tcp.22")
        self.assertEqual(ids_packages["packages"][0]["status"], "submitted")
        self.assertEqual(ids_packages["packages"][0]["dispatch_status"], "prompt_dispatched")
        self.assertTrue(ids_packages["packages"][0]["prompt_path"])
        self.assertEqual(messages["open"], 1)
        self.assertEqual(messages["items"][0]["related_plan_id"], "admin.host-security.deny-tcp.22")
        self.assertIn("IDS review", messages["items"][0]["subject"])

    def test_odo_advancement_executes_no_approval_ready_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            plan = replace(
                plan_user_service_restart(
                    "admin.odo.low-risk-restart",
                    "overseer-api.service",
                    "low-risk restart selected by policy",
                    "active",
                ),
                owner_domain=OwnerDomain.ODO,
                risk_level=RiskLevel.LOW,
                approval_level=ApprovalLevel.NONE,
            )
            store = SQLiteStore(store_path)
            store.save_admin_change_plan(plan)
            store.close()

            with patch(
                "overseer.cli.execute_admin_change_status",
                return_value={
                    "id": "admin.exec.admin.odo.low-risk-restart.completed",
                    "plan_id": "admin.odo.low-risk-restart",
                    "status": AdminExecutionStatus.COMPLETED.value,
                },
            ) as execute:
                status = _advance_admin_plan_after_dispatch(
                    store_path,
                    "admin.odo.low-risk-restart",
                    "2026-07-19T13:08:00+00:00",
                )
            store = SQLiteStore(store_path)
            approved = store.load_admin_change_plan("admin.odo.low-risk-restart")
            store.close()

        self.assertEqual(status["readiness_state"], "ready_for_overseer_execution")
        self.assertEqual(status["execution"]["status"], AdminExecutionStatus.COMPLETED.value)
        self.assertTrue(status["execution"]["host_mutation_performed"])
        self.assertTrue(approved.approved)
        self.assertEqual(approved.approved_by, "odo-auto")
        execute.assert_called_once_with(store_path, "admin.odo.low-risk-restart")

    def test_rejects_invalid_usage_limit_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            with self.assertRaises(ValueError):
                record_usage_limit_status(
                    store_path,
                    "limit.bad",
                    "svc.bad",
                    LimitKind.REQUESTS.value,
                    10,
                    11,
                    "hourly",
                )

    def test_persists_usage_continuation_request_and_plans_waiting_work(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_usage_limit(
                UsageLimit(
                    id="limit.ai.tokens",
                    resource_id="svc.ai",
                    kind=LimitKind.TOKENS,
                    capacity=100000,
                    remaining=1000,
                    resets_at="2026-07-18T12:00:00-04:00",
                    window="daily",
                )
            )
            store.close()

            request_status = request_usage_continuation_status(
                store_path,
                "work.large-eval",
                "limit.ai.tokens",
                "svc.ai",
                "thread-b",
                5000,
                "run eval after quota renewal",
                requested_by="quark",
                requested_at="2026-07-18T10:30:00-04:00",
            )
            plan = usage_continuation_plan_status(store_path)

            self.assertTrue(request_status["mutation_performed"])
            self.assertFalse(request_status["host_mutation_performed"])
            self.assertEqual(request_status["schedule"]["status"], ScheduledWorkStatus.WAITING.value)
            self.assertEqual(plan["continuation_requests"], 1)
            self.assertEqual(plan["waiting"], 1)
            self.assertFalse(plan["mutation_performed"])
            self.assertEqual(plan["schedules"][0]["scheduled_for"], "2026-07-18T12:00:00-04:00")

    def test_rejects_usage_continuation_for_mismatched_resource(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_usage_limit(
                UsageLimit(
                    id="limit.github.requests",
                    resource_id="svc.github",
                    kind=LimitKind.REQUESTS,
                    capacity=5000,
                    remaining=5000,
                    resets_at="2026-07-18T11:00:00-04:00",
                    window="hourly",
                )
            )
            store.close()

            with self.assertRaises(ValueError):
                request_usage_continuation_status(
                    store_path,
                    "work.bad-resource",
                    "limit.github.requests",
                    "svc.ai",
                    "thread-b",
                    1,
                    "use wrong service",
                )

    def test_store_round_trips_usage_continuation_request(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            request = UsageContinuationRequest(
                id="work.sync",
                limit_id="limit.github.requests",
                resource_id="svc.github",
                owner_thread="thread-a",
                requested_units=10,
                intent="sync issues",
            )
            store = SQLiteStore(store_path)
            store.save_usage_continuation_request(request)

            loaded = store.load_usage_continuation_request("work.sync")
            store.close()

            self.assertEqual(loaded, request)

    def test_dispatches_ready_usage_continuation_once(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_usage_limit(
                UsageLimit(
                    id="limit.github.requests",
                    resource_id="svc.github",
                    kind=LimitKind.REQUESTS,
                    capacity=5000,
                    remaining=100,
                    resets_at="2026-07-18T11:00:00-04:00",
                    window="hourly",
                )
            )
            store.save_usage_continuation_request(
                UsageContinuationRequest(
                    id="work.sync",
                    limit_id="limit.github.requests",
                    resource_id="svc.github",
                    owner_thread="thread-a",
                    requested_units=10,
                    intent="sync issues",
                )
            )
            store.close()

            first = dispatch_usage_continuations_status(
                store_path,
                dispatched_by="quark",
                dispatched_at="2026-07-18T10:00:00-04:00",
            )
            second = dispatch_usage_continuations_status(store_path, dispatched_by="quark")
            plan = usage_continuation_plan_status(store_path)

            self.assertTrue(first["mutation_performed"])
            self.assertFalse(first["host_mutation_performed"])
            self.assertEqual(first["dispatched"], 1)
            self.assertEqual(first["dispatches"][0]["request_id"], "work.sync")
            self.assertEqual(first["dispatches"][0]["owner_thread"], "thread-a")
            self.assertEqual(second["dispatched"], 0)
            self.assertEqual(second["skipped_items"][0]["status"], "already_dispatched")
            self.assertEqual(plan["dispatches"], 1)
            self.assertEqual(plan["undispatched_ready"], 0)

    def test_dispatch_resumes_ready_codex_project_thread(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            registry = Path(directory) / "codex-projects.csv"
            registry.write_text(
                "conversation_id,label,project,command,launcher,created_at,updated_at,source,notes\n"
                "019f7140-debb-7c40-a056-d29be0630f01,Overseer,"
                "/workspace/Overseer,codex-overseer-019f7140,/bin/codex-overseer-019f7140,"
                "2026-07-17T18:05:04+00:00,2026-07-18T19:57:08+00:00,registry,\n",
                encoding="utf-8",
            )
            runner = self._FakeRunner()
            adapter = CodexProjectThreadAdapter(
                registry,
                tmux_path="/tmp/tmux",
                codex_memory_session_path="/tmp/codex-memory-session",
                runner=runner,
            )
            store = SQLiteStore(store_path)
            store.save_usage_limit(
                UsageLimit(
                    id="limit.github.requests",
                    resource_id="svc.github",
                    kind=LimitKind.REQUESTS,
                    capacity=5000,
                    remaining=100,
                    resets_at="2026-07-18T11:00:00-04:00",
                    window="hourly",
                )
            )
            store.save_usage_continuation_request(
                UsageContinuationRequest(
                    id="work.sync",
                    limit_id="limit.github.requests",
                    resource_id="svc.github",
                    owner_thread="codex-overseer-019f7140",
                    requested_units=10,
                    intent="sync issues",
                )
            )
            store.close()

            status = dispatch_usage_continuations_status(
                store_path,
                resume_codex_projects=True,
                thread_adapter=adapter,
            )
            plan = usage_continuation_plan_status(store_path)

            self.assertTrue(status["host_mutation_performed"])
            self.assertEqual(status["resume_results"][0]["status"], "resumed")
            self.assertEqual(status["dispatches"][0]["resume_status"], "resumed")
            self.assertEqual(status["dispatches"][0]["resume_command"], "codex-overseer-019f7140")
            self.assertEqual(plan["dispatch_items"][0]["resume_conversation_id"], "019f7140-debb-7c40-a056-d29be0630f01")

    def test_dispatch_skips_waiting_usage_continuation(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_usage_limit(
                UsageLimit(
                    id="limit.ai.tokens",
                    resource_id="svc.ai",
                    kind=LimitKind.TOKENS,
                    capacity=100000,
                    remaining=1000,
                    resets_at="2026-07-18T12:00:00-04:00",
                    window="daily",
                )
            )
            store.save_usage_continuation_request(
                UsageContinuationRequest(
                    id="work.large-eval",
                    limit_id="limit.ai.tokens",
                    resource_id="svc.ai",
                    owner_thread="thread-b",
                    requested_units=5000,
                    intent="run eval after quota renewal",
                )
            )
            store.close()

            status = dispatch_usage_continuations_status(store_path)

            self.assertFalse(status["mutation_performed"])
            self.assertEqual(status["dispatched"], 0)
            self.assertEqual(status["skipped_items"][0]["status"], ScheduledWorkStatus.WAITING.value)

    def test_store_round_trips_usage_continuation_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            dispatch = UsageContinuationDispatch(
                id="usage.dispatch.work-sync",
                request_id="work.sync",
                limit_id="limit.github.requests",
                resource_id="svc.github",
                owner_thread="thread-a",
                status="dispatched",
                reason="sufficient capacity is available",
                dispatched_by="quark",
                dispatched_at="2026-07-18T10:00:00-04:00",
            )
            store = SQLiteStore(store_path)
            store.save_usage_continuation_dispatch(dispatch)

            loaded = store.load_usage_continuation_dispatch("usage.dispatch.work-sync")
            store.close()

            self.assertEqual(loaded, dispatch)


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
                "physical_identities": [
                    {
                        "kind": "serial_port",
                        "stable_id": "serial.config.rs485",
                        "observed_paths": ["/dev/serial/by-id/config-rs485"],
                        "capabilities": ["rs485"],
                        "exclusive_groups": ["rs485-bus"],
                    }
                ],
            }
        )

        self.assertIsInstance(config, OverseerConfig)
        self.assertEqual(config.resources[0].owner_domain, OwnerDomain.DAX)
        self.assertEqual(config.resources[0].ports(), frozenset({8795}))
        self.assertEqual(config.usage_limits[0].remaining, 50)
        self.assertEqual(config.health_targets[0].probe_type, ProbeType.JSON)
        self.assertEqual(config.physical_identities[0].stable_id, "serial.config.rs485")
        self.assertIn("rs485", config.physical_identities[0].capabilities)
        self.assertEqual(config.physical_identities[0].source, PhysicalIdentitySource.OPERATOR_DECLARED)

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

    def test_rejects_conflicting_physical_identities(self):
        with self.assertRaises(ValueError):
            config_from_mapping(
                {
                    "physical_identities": [
                        {
                            "kind": "serial_port",
                            "stable_id": "serial.left",
                            "observed_paths": ["/dev/ttyUSB0"],
                        },
                        {
                            "kind": "serial_port",
                            "stable_id": "serial.right",
                            "observed_paths": ["/dev/ttyUSB0"],
                        },
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

    def test_record_resource_status_persists_structured_resource(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            status = record_resource_status(
                store_path,
                "vm.local.android",
                "Local Android VM",
                ResourceType.VIRTUAL_ASSET.value,
                OwnerDomain.DAX.value,
                RiskLevel.MEDIUM.value,
                identifiers={"kind": "vm", "ports": [5555]},
                dependencies=("svc.systemd-user.protected-service-gateway",),
                exclusive_groups=("android-emulator",),
                notes="registered by test",
            )

            store = SQLiteStore(store_path)
            resource = store.load_resource("vm.local.android")
            store.close()

        self.assertTrue(status["mutation_performed"])
        self.assertFalse(status["host_mutation_performed"])
        self.assertEqual(status["resource"]["id"], "vm.local.android")
        self.assertEqual(status["resource"]["identifiers"]["ports"], [5555])
        self.assertEqual(resource.owner_domain, OwnerDomain.DAX)
        self.assertEqual(resource.exclusive_groups, frozenset({"android-emulator"}))

    def test_cli_records_bsbbs_port_resource_and_claim_with_append_options(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            resource_stdout = io.StringIO()
            claim_stdout = io.StringIO()

            with contextlib.redirect_stdout(resource_stdout):
                resource_exit = cli_main(
                    [
                        "record-resource",
                        "--store",
                        str(store_path),
                        "--resource-id",
                        "port.bsbbs.8796",
                        "--name",
                        "BSBBS localhost port 8796",
                        "--resource-type",
                        ResourceType.VIRTUAL_ASSET.value,
                        "--owner-domain",
                        OwnerDomain.DAX.value,
                        "--risk-level",
                        RiskLevel.MEDIUM.value,
                        "--identifier-json",
                        '{"host":"127.0.0.1","port":8796,"service":"bsbbs"}',
                        "--exclusive-group",
                        "protected-gateway-ports",
                    ]
                )
            with contextlib.redirect_stdout(claim_stdout):
                claim_exit = cli_main(
                    [
                        "request-claim",
                        "--store",
                        str(store_path),
                        "--claim-id",
                        "claim.bsbbs.port.8796",
                        "--resource-id",
                        "port.bsbbs.8796",
                        "--claim-type",
                        ClaimType.LEASE.value,
                        "--owner-thread",
                        "BSBBS",
                        "--owner-role",
                        OwnerDomain.DAX.value,
                        "--intent",
                        "reserve BSBBS localhost backend port",
                        "--requested-action",
                        "bind 127.0.0.1:8796 for BSBBS protected gateway rollout",
                        "--risk-level",
                        RiskLevel.MEDIUM.value,
                        "--port",
                        "8796",
                    ]
                )
            resource_status = json.loads(resource_stdout.getvalue())
            claim_status = json.loads(claim_stdout.getvalue())

        self.assertEqual(resource_exit, 0)
        self.assertEqual(claim_exit, 0)
        self.assertEqual(resource_status["resource"]["exclusive_groups"], ["protected-gateway-ports"])
        self.assertEqual(resource_status["resource"]["identifiers"]["port"], 8796)
        self.assertEqual(claim_status["claim"], "claim.bsbbs.port.8796")

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
                        "physical_identities": [
                            {
                                "kind": "serial_port",
                                "stable_id": "serial.cli.config",
                                "observed_paths": ["/dev/serial/by-id/cli-config"],
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
            self.assertEqual(status["physical_identities"], 1)


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
    def test_records_bootstrap_schema_migration_once(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            migrations = store.list_schema_migrations()
            store.close()

            reopened = SQLiteStore(store_path)
            reopened_migrations = reopened.list_schema_migrations()
            reopened.close()

        self.assertEqual(len(migrations), 1)
        self.assertEqual(migrations[0].version, CURRENT_SCHEMA_VERSION)
        self.assertEqual(migrations[0].description, "bootstrap JSON payload store")
        self.assertEqual(reopened_migrations, migrations)

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

    def test_persists_crew_messages(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteStore(Path(directory) / "overseer.sqlite3")
            store.save_crew_message(
                CrewMessage(
                    id="crew.julian.mcp-health",
                    owner_domain=OwnerDomain.JULIAN,
                    subject="MCP health",
                    message="Review MCP service errors.",
                    priority=RiskLevel.MEDIUM,
                    requested_by="operator",
                    created_at="2026-07-19T12:00:00+00:00",
                    updated_at="2026-07-19T12:00:00+00:00",
                )
            )
            store.close()

            reopened = SQLiteStore(Path(directory) / "overseer.sqlite3")
            messages = reopened.list_crew_messages()
            reopened.close()

            self.assertEqual(len(messages), 1)
            self.assertEqual(messages[0].owner_domain, OwnerDomain.JULIAN)
            self.assertEqual(messages[0].subject, "MCP health")

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
                    "physical_identities": [
                        {
                            "kind": "storage_array",
                            "stable_id": "storage.seeded",
                            "storage_profile": "read_only",
                        }
                    ],
                }
            )

            result = seed_store_from_config(config, store)

            self.assertEqual(result.resource_count, 1)
            self.assertEqual(result.usage_limit_count, 1)
            self.assertEqual(result.health_target_count, 1)
            self.assertEqual(result.physical_identity_count, 1)
            self.assertEqual(store.load_resource("svc.seeded").owner_domain, OwnerDomain.JULIAN)
            self.assertEqual(store.load_usage_limit("limit.seeded").remaining, 10)
            self.assertEqual(store.load_health_target("health.seeded").resource_id, "svc.seeded")
            self.assertEqual(store.load_physical_identity("storage.seeded").storage_profile, "read_only")
            self.assertEqual(
                store.load_physical_identity("storage.seeded").source,
                PhysicalIdentitySource.OPERATOR_DECLARED,
            )
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

    def test_run_status_routes_process_health_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="svc.run.process",
                    name="Run Process",
                    type=ResourceType.SERVICE,
                    owner_domain=OwnerDomain.JULIAN,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.save_health_target(
                HealthTarget(
                    id="health.run.process",
                    resource_id="svc.run.process",
                    name="Run Process Health",
                    probe_type=ProbeType.PROCESS,
                    target=f"pid:{os.getpid()}",
                )
            )
            store.close()

            status = run_status(store_path, once=True, probe_health_targets=True)
            store = SQLiteStore(store_path)
            evidence = store.list_health_evidence()
            store.close()

        self.assertEqual(status["health_probes"], 1)
        self.assertEqual(status["health_evidence"], 1)
        self.assertEqual(evidence[0].observed_status, HealthStatus.HEALTHY)

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
        self.assertTrue(status["schema"]["migration_ledger_present"])
        self.assertEqual(status["schema"]["applied_schema_version"], CURRENT_SCHEMA_VERSION)

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
        self.assertFalse(status["schema"]["migration_ledger_present"])
        self.assertEqual(status["schema"]["current_schema_version"], CURRENT_SCHEMA_VERSION)

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

    def test_runtime_default_probe_adapter_routes_process_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteStore(Path(directory) / "overseer.sqlite3")
            seed_store_from_config(
                config_from_mapping(
                    {
                        "resources": [
                            {
                                "id": "svc.runtime.process",
                                "name": "Runtime Process",
                                "type": "service",
                                "owner_domain": "julian",
                                "risk_level": "low",
                            }
                        ],
                        "health_targets": [
                            {
                                "id": "health.runtime.process",
                                "resource_id": "svc.runtime.process",
                                "name": "Runtime Process",
                                "probe_type": "process",
                                "target": f"pid:{os.getpid()}",
                            }
                        ],
                    }
                ),
                store,
            )

            tick = OverseerRuntime(store, probe_health_targets=True).run(once=True)

            self.assertEqual(tick.health_probes, 1)
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
            self.assertEqual(tick.host_security_remediation_plans_staged, 0)
            self.assertEqual(tick.host_security_ids_reviews_prepared, 0)
            self.assertEqual(tick.host_security_sisko_requests, 0)
            self.assertEqual(tick.host_security_auto_executions, 0)
            self.assertEqual(store.list_host_snapshots()[0].hostname, "host-runtime")
            store.close()

    def test_runtime_advances_host_security_after_inspection_when_configured(self):
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
                            else "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"
                            if tuple(command) == ("ss", "-ltnp")
                            else "ok"
                        ),
                    ),
                    file_reader=lambda path: "ID=debian\n",
                ).inspect("2026-07-18T17:01:00+00:00")

        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteStore(Path(directory) / "overseer.sqlite3")
            calls = []

            def fake_advancer(store_path: str, snapshot_id: str) -> dict[str, object]:
                calls.append((store_path, snapshot_id))
                return {
                    "staged_count": 2,
                    "ids_reviews_prepared": 2,
                    "sisko_requests": 2,
                    "executions": 0,
                }

            tick = OverseerRuntime(
                store,
                inspect_host=True,
                host_inspection_adapter=FakeHostInspectionAdapter(),
                host_security_advancer=fake_advancer,
            ).run(once=True)

            self.assertEqual(tick.host_inspections, 1)
            self.assertEqual(tick.host_security_high_findings, 1)
            self.assertEqual(tick.host_security_remediation_plans_staged, 2)
            self.assertEqual(tick.host_security_ids_reviews_prepared, 2)
            self.assertEqual(tick.host_security_sisko_requests, 2)
            self.assertEqual(tick.host_security_auto_executions, 0)
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][1], store.list_host_snapshots()[0].id)
            store.close()

    def test_station_audit_routes_unknowns_to_odo_and_counts_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            with (
                patch(
                    "overseer.cli.discover_physical_status",
                    return_value={
                        "count": 1,
                        "assets": [
                            {
                                "stable_id": "storage.unknown",
                                "kind": "storage_array",
                                "complete_for_checkout": True,
                                "storage_risk": True,
                            }
                        ],
                    },
                ),
                patch("overseer.cli.discover_storage_status", return_value={"count": 0, "assets": []}),
                patch(
                    "overseer.cli.discover_virtual_listeners_status",
                    return_value={
                        "count": 1,
                        "assets": [
                            {
                                "id": "listener.tcp.any.8080",
                                "kind": "gateway",
                                "bind_scope": "all_interfaces",
                                "ports": [8080],
                                "process_hint": "LISTEN 0 128 0.0.0.0:8080",
                            }
                        ],
                    },
                ),
                patch("overseer.cli.discover_user_services_status", return_value={"count": 1, "health_targets": 1, "items": []}),
                patch("overseer.cli.plan_package_updates_status", return_value={"plans": 2, "items": [], "host_mutation_performed": False}),
                patch("overseer.cli.discover_codex_project_threads_status", return_value={"threads": 1, "resources": 1}),
                patch("overseer.cli.knowledge_capture_status", return_value={"captured": 1, "failed": 0, "host_mutation_performed": False}),
            ):
                status = audit_station_status(
                    store_path,
                    audited_at="2026-07-20T17:30:00+00:00",
                )
            messages = crew_messages_status(store_path, owner_domain=OwnerDomain.ODO.value, status=CrewMessageStatus.OPEN.value)

        self.assertEqual(status["actions"], 7)
        self.assertEqual(status["odo_referrals"], 2)
        self.assertEqual(status["sisko_requests"], 2)
        self.assertFalse(status["host_mutation_performed"])
        self.assertEqual(messages["open"], 2)
        self.assertEqual(
            {item["related_resource_id"] for item in messages["items"]},
            {"storage.unknown", "listener.tcp.any.8080"},
        )

    def test_runtime_runs_station_audit_on_configured_interval(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteStore(Path(directory) / "overseer.sqlite3")
            calls = []

            def fake_auditor(store_path: str, snapshot_id: str | None) -> dict[str, object]:
                calls.append((store_path, snapshot_id))
                return {"actions": 7, "odo_referrals": 3, "sisko_requests": 1}

            runtime = OverseerRuntime(
                store,
                audit_station=True,
                station_auditor=fake_auditor,
                station_audit_interval_ticks=2,
            )
            first = runtime.run(once=True)
            second = runtime.run(once=True)
            third = runtime.run(once=True)
            fourth = runtime.run(once=True)

            self.assertEqual(first.station_audits, 0)
            self.assertEqual(second.station_audits, 1)
            self.assertEqual(second.station_audit_actions, 7)
            self.assertEqual(second.station_audit_odo_referrals, 3)
            self.assertEqual(second.station_audit_sisko_requests, 1)
            self.assertEqual(third.station_audits, 0)
            self.assertEqual(fourth.station_audits, 1)
            self.assertEqual(len(calls), 2)
            store.close()

    def test_runtime_dispatches_crew_messages_when_enabled(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteStore(Path(directory) / "overseer.sqlite3")

            def fake_dispatcher(store_path: str) -> dict[str, object]:
                return {"acknowledged": 2, "blocked": 1}

            tick = OverseerRuntime(
                store,
                dispatch_crew_messages=True,
                crew_dispatcher=fake_dispatcher,
            ).run(once=True)

            self.assertEqual(tick.crew_messages_dispatched, 2)
            self.assertEqual(tick.crew_messages_blocked, 1)
            store.close()

    def test_runtime_dispatches_usage_continuations_when_enabled(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteStore(Path(directory) / "overseer.sqlite3")

            def fake_dispatcher(store_path: str) -> dict[str, object]:
                return {"dispatched": 3, "skipped": 2}

            tick = OverseerRuntime(
                store,
                dispatch_usage_continuations=True,
                usage_continuation_dispatcher=fake_dispatcher,
            ).run(once=True)

            self.assertEqual(tick.usage_continuations_dispatched, 3)
            self.assertEqual(tick.usage_continuations_skipped, 2)
            store.close()

    def test_runtime_captures_knowledge_events_when_enabled(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteStore(Path(directory) / "overseer.sqlite3")

            def fake_capture(store_path: str) -> dict[str, object]:
                return {"captured": 4, "failed": 1}

            tick = OverseerRuntime(
                store,
                capture_knowledge_events=True,
                knowledge_capture_dispatcher=fake_capture,
            ).run(once=True)

            self.assertEqual(tick.knowledge_events_captured, 4)
            self.assertEqual(tick.knowledge_events_failed, 1)
            store.close()

    def test_run_status_dispatches_open_crew_messages_when_enabled(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            record_crew_message_status(
                store_path,
                OwnerDomain.DAX.value,
                "Virtual inventory",
                "Refresh virtual inventory for checkout.",
                RiskLevel.LOW.value,
                message_id="crew.dax.runtime-dispatch",
            )

            status = run_status(store_path, once=True, dispatch_crew_messages=True)
            messages = crew_messages_status(store_path, owner_domain=OwnerDomain.DAX.value)

            self.assertEqual(status["crew_messages_dispatched"], 1)
            self.assertEqual(status["crew_messages_blocked"], 0)
            self.assertEqual(messages["items"][0]["status"], "acknowledged")

    def test_run_status_dispatches_ready_usage_continuations_when_enabled(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_usage_limit(
                UsageLimit(
                    id="limit.runtime.quota",
                    resource_id="svc.runtime.quota",
                    kind=LimitKind.DAILY_QUOTA,
                    capacity=100,
                    remaining=10,
                    resets_at="2026-07-20T00:00:00+00:00",
                    window="daily",
                )
            )
            store.close()
            request_usage_continuation_status(
                store_path,
                "work.runtime.quota",
                "limit.runtime.quota",
                "svc.runtime.quota",
                "thread.runtime.quota",
                5,
                "continue after quota is ready",
            )

            status = run_status(store_path, once=True, dispatch_usage_continuations=True)
            plan = usage_continuation_plan_status(store_path)

            self.assertEqual(status["usage_continuations_dispatched"], 1)
            self.assertEqual(status["usage_continuations_skipped"], 0)
            self.assertEqual(plan["dispatches"], 1)
            self.assertEqual(plan["dispatch_items"][0]["request_id"], "work.runtime.quota")

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

    def test_daemon_migration_plan_and_approval_are_approval_only(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_runtime_heartbeat(
                RuntimeHeartbeat(
                    id="overseer",
                    service_name="overseer",
                    started_at="2026-07-18T13:00:00+00:00",
                    last_tick_at="2026-07-18T13:02:00+00:00",
                    tick_count=3,
                )
            )
            store.close()

            plan = daemon_migration_plan_status(store_path)
            requested = request_daemon_migration_status(
                store_path,
                "overseer",
                "sisko",
                "2026-07-18T13:05:00+00:00",
            )
            pending = authorizations_required_status(store_path)
            summary = admin_summary_status(store_path)
            approved = approve_daemon_migration_status(
                store_path,
                requested["approval_id"],
                "sisko",
                "2026-07-18T13:10:00+00:00",
            )
            after = authorizations_required_status(store_path)
            runtime = runtime_status(store_path)

        self.assertEqual(plan["mode"], "read_only_daemon_migration_plan")
        self.assertFalse(plan["mutation_performed"])
        self.assertEqual(plan["approval_level"], ApprovalLevel.HUMAN.value)
        self.assertIn("systemctl", plan["commands_in_scope"][0])
        self.assertEqual(plan["current_runtime_evidence"]["tick_count"], 3)
        self.assertTrue(requested["mutation_performed"])
        self.assertEqual(requested["approval_status"], ApprovalStatus.PENDING.value)
        self.assertEqual(requested["audit_event"]["event_type"], AuditEventType.REQUESTED.value)
        self.assertEqual(pending["pending_daemon_migration_approval_count"], 1)
        self.assertEqual(
            pending["daemon_migration_approvals"][0]["next_step"],
            "approve-daemon-migration before changing user service enablement or runtime command",
        )
        self.assertEqual(summary["daemon_migration_approvals"]["pending"], 1)
        self.assertEqual(approved["approval_status"], ApprovalStatus.APPROVED.value)
        self.assertTrue(approved["daemon_migration_approval"])
        self.assertEqual(after["pending_daemon_migration_approval_count"], 0)
        self.assertEqual(runtime["service"]["tick_count"], 3)

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

    def test_claim_cleanup_plan_status_identifies_expired_and_stale_claims(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="proxy.cleanup.cli",
                    name="Cleanup CLI Proxy",
                    type=ResourceType.VIRTUAL_ASSET,
                    owner_domain=OwnerDomain.DAX,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.save_claim(
                Claim(
                    id="claim.cleanup.expired",
                    resource_id="proxy.cleanup.cli",
                    claim_type=ClaimType.LEASE,
                    owner_thread="thread-a",
                    owner_role=OwnerDomain.DAX,
                    intent="use proxy",
                    requested_action="bind proxy",
                    risk_level=RiskLevel.LOW,
                    status=ClaimStatus.ACTIVE,
                    expires_at="2026-07-18T20:00:00+00:00",
                    release_condition="operator verified work stopped",
                )
            )
            store.save_claim(
                Claim(
                    id="claim.cleanup.released-blocker",
                    resource_id="proxy.cleanup.cli",
                    claim_type=ClaimType.LEASE,
                    owner_thread="thread-b",
                    owner_role=OwnerDomain.DAX,
                    intent="previous proxy use",
                    requested_action="bind proxy",
                    risk_level=RiskLevel.LOW,
                    status=ClaimStatus.RELEASED,
                )
            )
            store.save_claim(
                Claim(
                    id="claim.cleanup.stale-queue",
                    resource_id="proxy.cleanup.cli",
                    claim_type=ClaimType.LEASE,
                    owner_thread="thread-c",
                    owner_role=OwnerDomain.DAX,
                    intent="queued proxy use",
                    requested_action="bind proxy",
                    risk_level=RiskLevel.LOW,
                    status=ClaimStatus.QUEUED,
                ),
                ConflictDecision(
                    outcome=ConflictOutcome.QUEUE,
                    reason="resource was claimed",
                    blocking_claim_ids=("claim.cleanup.released-blocker",),
                ),
            )
            store.close()

            plan = claim_cleanup_plan_status(store_path, "2026-07-18T20:10:00+00:00")
            state = list_state_status(store_path)

            self.assertFalse(plan["mutation_performed"])
            self.assertEqual(plan["cleanup_candidates"], 2)
            self.assertEqual(plan["expired_active_like"], 1)
            self.assertEqual(plan["stale_queued"], 1)
            self.assertEqual(
                [item["cleanup_action"] for item in plan["items"]],
                ["review_expired_active_claim", "re_evaluate_stale_queue"],
            )
            self.assertEqual(plan["items"][1]["blocking_claim_ids"], ["claim.cleanup.released-blocker"])
            self.assertEqual(plan["items"][1]["active_blocking_claim_ids"], [])
            self.assertEqual(
                {claim["id"]: claim["status"] for claim in state["claims"]},
                {
                    "claim.cleanup.expired": ClaimStatus.ACTIVE.value,
                    "claim.cleanup.released-blocker": ClaimStatus.RELEASED.value,
                    "claim.cleanup.stale-queue": ClaimStatus.QUEUED.value,
                },
            )

    def test_claim_cleanup_request_requires_candidate_and_preserves_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="proxy.cleanup.approval.cli",
                    name="Cleanup Approval CLI Proxy",
                    type=ResourceType.VIRTUAL_ASSET,
                    owner_domain=OwnerDomain.DAX,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.save_claim(
                Claim(
                    id="claim.cleanup.approval.cli",
                    resource_id="proxy.cleanup.approval.cli",
                    claim_type=ClaimType.LEASE,
                    owner_thread="thread-a",
                    owner_role=OwnerDomain.DAX,
                    intent="use proxy",
                    requested_action="bind proxy",
                    risk_level=RiskLevel.LOW,
                    status=ClaimStatus.ACTIVE,
                    expires_at="2026-07-18T20:00:00+00:00",
                    release_condition="operator verified work stopped",
                )
            )
            store.save_claim(
                Claim(
                    id="claim.cleanup.not-candidate",
                    resource_id="proxy.cleanup.approval.cli",
                    claim_type=ClaimType.LEASE,
                    owner_thread="thread-b",
                    owner_role=OwnerDomain.DAX,
                    intent="use proxy later",
                    requested_action="bind proxy",
                    risk_level=RiskLevel.LOW,
                    status=ClaimStatus.RELEASED,
                )
            )
            store.close()

            requested = request_claim_cleanup_status(
                store_path,
                "claim.cleanup.approval.cli",
                "sisko",
                "2026-07-18T20:30:00+00:00",
                "2026-07-18T20:30:00+00:00",
            )
            pending = authorizations_required_status(store_path)
            summary = admin_summary_status(store_path)
            approved = approve_claim_cleanup_status(
                store_path,
                requested["approval_id"],
                "sisko",
                "2026-07-18T20:35:00+00:00",
                "2026-07-18T20:35:00+00:00",
            )
            after = authorizations_required_status(store_path)
            state = list_state_status(store_path)

            with self.assertRaises(ValueError):
                request_claim_cleanup_status(store_path, "claim.cleanup.not-candidate", "sisko")

        self.assertTrue(requested["mutation_performed"])
        self.assertEqual(requested["approval_level"], ApprovalLevel.SISKO.value)
        self.assertEqual(requested["audit_event"]["event_type"], AuditEventType.REQUESTED.value)
        self.assertEqual(pending["pending_count"], 1)
        self.assertEqual(pending["pending_claim_cleanup_approval_count"], 1)
        self.assertEqual(
            pending["claim_cleanup_approvals"][0]["next_step"],
            "approve-claim-cleanup before cleanup mutation can be implemented or executed",
        )
        self.assertEqual(summary["claim_cleanup_approvals"]["pending"], 1)
        self.assertEqual(approved["approval_status"], ApprovalStatus.APPROVED.value)
        self.assertTrue(approved["claim_cleanup_approval"])
        self.assertEqual(after["pending_claim_cleanup_approval_count"], 0)
        self.assertEqual(
            {claim["id"]: claim["status"] for claim in state["claims"]},
            {
                "claim.cleanup.approval.cli": ClaimStatus.ACTIVE.value,
                "claim.cleanup.not-candidate": ClaimStatus.RELEASED.value,
            },
        )

    def test_execute_claim_cleanup_re_evaluates_stale_queue_after_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="proxy.cleanup.execute.cli",
                    name="Cleanup Execute CLI Proxy",
                    type=ResourceType.VIRTUAL_ASSET,
                    owner_domain=OwnerDomain.DAX,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.save_claim(
                Claim(
                    id="claim.cleanup.execute.released-blocker",
                    resource_id="proxy.cleanup.execute.cli",
                    claim_type=ClaimType.LEASE,
                    owner_thread="thread-a",
                    owner_role=OwnerDomain.DAX,
                    intent="previous proxy use",
                    requested_action="bind proxy",
                    risk_level=RiskLevel.LOW,
                    status=ClaimStatus.RELEASED,
                )
            )
            store.save_claim(
                Claim(
                    id="claim.cleanup.execute.stale-queue",
                    resource_id="proxy.cleanup.execute.cli",
                    claim_type=ClaimType.LEASE,
                    owner_thread="thread-b",
                    owner_role=OwnerDomain.DAX,
                    intent="queued proxy use",
                    requested_action="bind proxy",
                    risk_level=RiskLevel.LOW,
                    status=ClaimStatus.QUEUED,
                ),
                ConflictDecision(
                    outcome=ConflictOutcome.QUEUE,
                    reason="resource was claimed",
                    blocking_claim_ids=("claim.cleanup.execute.released-blocker",),
                ),
            )
            store.close()

            requested = request_claim_cleanup_status(
                store_path,
                "claim.cleanup.execute.stale-queue",
                "sisko",
                now="2026-07-18T20:30:00+00:00",
            )
            with self.assertRaises(ValueError):
                execute_claim_cleanup_status(store_path, requested["approval_id"], "sisko")
            approve_claim_cleanup_status(
                store_path,
                requested["approval_id"],
                "sisko",
                now="2026-07-18T20:35:00+00:00",
            )
            executed = execute_claim_cleanup_status(
                store_path,
                requested["approval_id"],
                "sisko",
                "2026-07-18T20:40:00+00:00",
                "2026-07-18T20:40:00+00:00",
            )
            state = list_state_status(store_path)

        self.assertTrue(executed["mutation_performed"])
        self.assertEqual(executed["cleanup_action"], "re_evaluate_stale_queue")
        self.assertEqual(executed["claim_status_before"], ClaimStatus.QUEUED.value)
        self.assertEqual(executed["claim_status_after"], ClaimStatus.REQUESTED.value)
        self.assertEqual(
            {claim["id"]: claim["status"] for claim in state["claims"]},
            {
                "claim.cleanup.execute.released-blocker": ClaimStatus.RELEASED.value,
                "claim.cleanup.execute.stale-queue": ClaimStatus.REQUESTED.value,
            },
        )
        self.assertIn(
            ("audit.approval.claim.cleanup.claim.cleanup.execute.stale-queue.executed", AuditEventType.EXECUTED.value),
            {(event["id"], event["event_type"]) for event in state["audit_events"]},
        )

    def test_execute_claim_cleanup_handles_missing_release_evidence_and_blocked_claims(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_resource(
                Resource(
                    id="proxy.cleanup.execute.more.cli",
                    name="Cleanup Execute More CLI Proxy",
                    type=ResourceType.VIRTUAL_ASSET,
                    owner_domain=OwnerDomain.DAX,
                    risk_level=RiskLevel.LOW,
                    state=ResourceState.CHECKED_OUT,
                    current_claim_id="claim.cleanup.execute.missing-release",
                )
            )
            store.save_claim(
                Claim(
                    id="claim.cleanup.execute.missing-release",
                    resource_id="proxy.cleanup.execute.more.cli",
                    claim_type=ClaimType.LEASE,
                    owner_thread="thread-a",
                    owner_role=OwnerDomain.DAX,
                    intent="use proxy",
                    requested_action="bind proxy",
                    risk_level=RiskLevel.LOW,
                    status=ClaimStatus.ACTIVE,
                )
            )
            store.save_claim(
                Claim(
                    id="claim.cleanup.execute.blocked",
                    resource_id="proxy.cleanup.execute.more.cli",
                    claim_type=ClaimType.LEASE,
                    owner_thread="thread-b",
                    owner_role=OwnerDomain.DAX,
                    intent="blocked proxy use",
                    requested_action="bind proxy",
                    risk_level=RiskLevel.LOW,
                    status=ClaimStatus.BLOCKED,
                )
            )
            store.close()

            missing_requested = request_claim_cleanup_status(
                store_path,
                "claim.cleanup.execute.missing-release",
                "sisko",
                now="2026-07-18T20:30:00+00:00",
            )
            approve_claim_cleanup_status(
                store_path,
                missing_requested["approval_id"],
                "sisko",
                now="2026-07-18T20:35:00+00:00",
            )
            missing_executed = execute_claim_cleanup_status(
                store_path,
                missing_requested["approval_id"],
                "sisko",
                now="2026-07-18T20:40:00+00:00",
            )
            blocked_requested = request_claim_cleanup_status(
                store_path,
                "claim.cleanup.execute.blocked",
                "dax",
                now="2026-07-18T20:45:00+00:00",
            )
            approve_claim_cleanup_status(
                store_path,
                blocked_requested["approval_id"],
                "dax",
                now="2026-07-18T20:50:00+00:00",
            )
            blocked_executed = execute_claim_cleanup_status(
                store_path,
                blocked_requested["approval_id"],
                "dax",
                now="2026-07-18T20:55:00+00:00",
            )
            state = list_state_status(store_path)

        claims = {claim["id"]: claim for claim in state["claims"]}
        resources = {resource["id"]: resource for resource in state["resources"]}
        self.assertEqual(missing_executed["cleanup_action"], "add_release_condition_or_evidence")
        self.assertEqual(missing_executed["claim_status_after"], ClaimStatus.RELEASING.value)
        self.assertEqual(claims["claim.cleanup.execute.missing-release"]["status"], ClaimStatus.RELEASING.value)
        self.assertEqual(resources["proxy.cleanup.execute.more.cli"]["current_claim_id"], "claim.cleanup.execute.missing-release")
        self.assertEqual(resources["proxy.cleanup.execute.more.cli"]["state"], ResourceState.CHECKED_OUT.value)
        self.assertEqual(blocked_executed["cleanup_action"], "review_blocked_claim")
        self.assertEqual(blocked_executed["claim_status_after"], ClaimStatus.REVOKED.value)
        self.assertEqual(claims["claim.cleanup.execute.blocked"]["status"], ClaimStatus.REVOKED.value)

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
            self.assertEqual(status["resources"][0]["name"], "State CLI Proxy")
            self.assertEqual(status["resources"][0]["identifiers"], {})
            self.assertEqual(status["schema_migrations"][0]["version"], CURRENT_SCHEMA_VERSION)
            self.assertEqual(status["claims"][0]["status"], ClaimStatus.REQUESTED.value)
            self.assertEqual(status["approvals"][0]["status"], ApprovalStatus.APPROVED.value)
            self.assertEqual(status["audit_events"][0]["subject_id"], "claim.cli.state")
            self.assertEqual(status["runtime_heartbeats"], [])

    def test_approvals_summary_status_filters_stored_approvals(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_approval(
                ApprovalRequest(
                    id="approval.summary.pending",
                    subject_id="claim.summary.pending",
                    approval_level=ApprovalLevel.SISKO,
                    requester_thread="thread-summary",
                    owner_domain=OwnerDomain.DAX,
                    reason="pending summary approval",
                )
            )
            store.save_approval(
                ApprovalRequest(
                    id="approval.summary.approved",
                    subject_id="admin.summary.approved",
                    approval_level=ApprovalLevel.HUMAN,
                    requester_thread="thread-summary",
                    owner_domain=OwnerDomain.SISKO,
                    reason="approved summary approval",
                    status=ApprovalStatus.APPROVED,
                    decided_by="sisko",
                )
            )
            store.close()

            pending = approvals_summary_status(
                store_path,
                status=ApprovalStatus.PENDING.value,
                owner=OwnerDomain.DAX.value,
                approval_level=ApprovalLevel.SISKO.value,
                subject_prefix="claim.",
            )
            all_items = approvals_summary_status(store_path)

        self.assertEqual(pending["approval_count"], 1)
        self.assertEqual(pending["pending_count"], 1)
        self.assertEqual(pending["approved_count"], 0)
        self.assertEqual(pending["approvals"][0]["id"], "approval.summary.pending")
        self.assertEqual(pending["by_status"][ApprovalStatus.PENDING.value], 1)
        self.assertEqual(pending["filters"]["subject_prefix"], "claim.")
        self.assertEqual(all_items["approval_count"], 2)
        self.assertEqual(all_items["approved_count"], 1)

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

    def test_list_state_status_reports_usage_limits_and_continuations(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            store.save_usage_limit(
                UsageLimit(
                    id="limit.state.ai",
                    resource_id="svc.state.ai",
                    kind=LimitKind.TOKENS,
                    capacity=1000,
                    remaining=0,
                    resets_at="2026-07-18T20:00:00+00:00",
                    window="hourly",
                )
            )
            store.save_usage_continuation_request(
                UsageContinuationRequest(
                    id="work.state.ai",
                    limit_id="limit.state.ai",
                    resource_id="svc.state.ai",
                    owner_thread="thread-state",
                    requested_units=100,
                    intent="continue state export work",
                )
            )
            store.close()

            status = list_state_status(store_path)

            self.assertEqual(status["usage_limits"][0]["id"], "limit.state.ai")
            self.assertEqual(status["usage_continuation_requests"][0]["id"], "work.state.ai")

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
