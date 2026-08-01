"""Loopback HTTP API for local Overseer coordination."""

from __future__ import annotations

import json
import os
import secrets
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .codex_usage import CodexUsageTracker
from .cli import (
    DEFAULT_AGENT_REGISTRY,
    activate_claim_status,
    active_policy_profile_status,
    agent_dispatches_status,
    agent_failover_executions_status,
    agent_instances_status,
    agent_providers_status,
    agent_sessions_status,
    agent_usage_status,
    admin_adapter_capabilities_status,
    admin_adapter_enablement_plan_status,
    admin_executions_status,
    admin_execution_readiness_status,
    admin_history_archive_plan_status,
    admin_history_archives_status,
    admin_history_review_status,
    admin_policy_status,
    admin_history_restore_readiness_status,
    admin_summary_status,
    archive_admin_history_status,
    assess_host_security_status,
    advance_odo_security_status,
    approve_admin_change_status,
    approve_admin_adapter_enablement_status,
    approve_admin_history_archive_status,
    approve_admin_history_restore_status,
    approve_admin_policy_warning_status,
    approve_claim_status,
    approve_claim_cleanup_status,
    approve_daemon_migration_status,
    approvals_summary_status,
    alerts_summary_status,
    audit_summary_status,
    authorizations_required_status,
    cancel_admin_change_status,
    claim_cleanup_plan_status,
    claim_review_status,
    command_summary_status,
    create_host_security_source_review_status,
    crew_messages_status,
    checkpoint_agent_status,
    evaluate_agent_failover_status,
    execute_agent_failover_status,
    discover_agent_sessions_status,
    dispatch_agent_goal_status,
    dispatch_crew_messages_status,
    decide_crew_message_status,
    dispatch_usage_continuations_status,
    dispatch_host_security_ids_review_package_status,
    daemon_migration_plan_status,
    discover_physical_status,
    discover_user_services_status,
    discover_storage_status,
    discover_virtual_listeners_status,
    execute_admin_change_status,
    execute_firewall_change_status,
    execute_claim_cleanup_status,
    export_host_security_ids_review_prompt_status,
    export_state_redacted_status,
    health_efficiency_summary_status,
    health_summary_status,
    skiller_effectiveness_status,
    skiller_guidance_adherence_status,
    host_security_findings_status,
    host_security_ids_review_packages_status,
    host_security_ids_review_summary_status,
    host_security_listener_review_queue_status,
    host_security_source_review_queue_status,
    host_security_sources_status,
    host_security_source_reviews_status,
    host_security_triage_status,
    inspect_firmware_preflight_status,
    inspect_firmware_status,
    inspect_host_status,
    inspect_packages_status,
    issue_key_broker_token_status,
    handoff_agent_status,
    key_broker_status,
    list_state_status,
    maintenance_summary_status,
    operator_dashboard_status,
    plan_host_security_listener_queue_remediations_status,
    plan_firewall_policy_diff_enforcement_status,
    plan_host_security_source_block_status,
    plan_host_security_remediation_status,
    physical_summary_status,
    plan_admin_change_status,
    plan_firmware_updates_status,
    plan_package_updates_status,
    policy_customization_helper_cli_status,
    probe_stored_health_status,
    record_resource_status,
    record_crew_message_status,
    reconcile_crew_reviews_status,
    resubmit_crew_message_status,
    record_health_target_status,
    record_key_provider_status,
    record_host_security_ids_review_result_status,
    release_claim_status,
    request_admin_adapter_enablement_status,
    request_admin_history_archive_status,
    request_admin_history_restore_status,
    request_admin_policy_warning_status,
    request_daemon_migration_status,
    request_usage_continuation_status,
    prepare_host_security_ids_review_package_status,
    persistence_security_status,
    record_usage_limit_status,
    request_claim_status,
    request_claim_cleanup_status,
    request_key_broker_token_status,
    recover_agent_status,
    recover_agent_failover_execution_status,
    run_obrien_package_maintenance_cycle_status,
    service_status,
    runtime_status,
    security_summary_status,
    usage_continuation_plan_status,
    usage_summary_status,
    submit_host_security_ids_review_package_status,
    unarchive_admin_history_status,
    approve_key_broker_request_status,
    revoke_key_broker_token_status,
    virtual_summary_status,
)
from .agent_manager import AgentAuthorizationError, AgentManagerError
from .storage_adapter import verify_storage_authorization_status, verify_storage_root_authorization_status
from .storage_control import list_authorizations, stage_authorization_api, approve_authorization_api, materialize_authorization_api, revoke_authorization_api
from .agent_registry import AgentAdapterUnavailableError
from .documents import (
    documents_config_status,
    documents_list_notes_status,
    documents_search_status,
    documents_write_note_status,
)
from .compliance_evidence import compliance_evidence_status
from .advisories import advisory_status, refresh_advisories_status
from .backup_ops import (
    approve_backup_execution_request_status,
    approve_backup_cleanup_request_status,
    approve_restore_execution_request_status,
    backup_operations_status,
    execute_backup_execution_request_status,
    execute_backup_cleanup_request_status,
    execute_restore_execution_request_status,
    record_backup_job_status,
    record_restore_test_status,
    stage_backup_execution_request_status,
    stage_backup_cleanup_request_status,
    stage_restore_execution_request_status,
)
from .documentation_evidence import documentation_evidence_status
from .git import git_status_status
from .image_scanning import (
    approve_image_scan_request_status,
    execute_image_scan_request_status,
    image_scan_status,
    stage_image_scan_request_status,
)
from .identity_evidence import identity_evidence_status
from .identity_ops import (
    approve_identity_rotation_request_status,
    execute_identity_rotation_request_status,
    identity_rotation_execution_readiness_status,
    identity_rotation_requests_status,
    stage_identity_rotation_request_status,
)
from .incident_lifecycle import incident_lifecycle_status
from .knowledge import knowledge_capture_status
from .maintenance_schedule import maintenance_schedules_status, record_maintenance_schedule_status
from .metric_history import capture_metric_history_status, metric_history_status
from .observability_trends import observability_trends_status
from .ops import (
    list_operation_records_status,
    operation_workflow_catalog_status,
    operations_gap_coverage_status,
    record_operation_status,
    stage_operation_workflow_status,
    transition_operation_record_status,
)
from .performance_history import performance_history_status
from .remote_testing import (
    collect_remote_test_results_status,
    enqueue_remote_test_job_status,
    issue_remote_testing_token_status,
    record_remote_testing_account_status,
    record_remote_testing_profile_status,
    remote_testing_status,
    request_remote_testing_lease_status,
    revoke_remote_testing_token_status,
    validate_remote_testing_token,
)
from .service_evidence import execute_journal_access_request_status, service_evidence_status, stage_journal_access_request_status
from .security_evidence import security_evidence_status
from .software_evidence import software_evidence_status
from .storage_evidence import capture_storage_growth_snapshot_status, storage_evidence_status
from .usage_evidence import usage_evidence_status
from .virtual_evidence import virtual_evidence_status
from .virtual_ops import (
    approve_virtual_destroy_request_status,
    approve_virtual_restore_request_status,
    approve_virtual_snapshot_request_status,
    execute_virtual_destroy_request_status,
    execute_virtual_lifecycle_status,
    execute_virtual_target_setup_status,
    execute_virtual_restore_request_status,
    execute_virtual_snapshot_request_status,
    record_virtual_target_setup_result_status,
    record_virtual_runtime_status,
    stage_virtual_destroy_request_status,
    stage_virtual_restore_request_status,
    stage_virtual_snapshot_request_status,
    stage_virtual_target_setup_batch_status,
    virtual_operations_status,
)
from .ui import OPERATOR_CONSOLE_HTML


DEFAULT_CODEX_USAGE_DB = Path("/home/god/.local/share/overseer/codex-usage-mcp/state.sqlite3")


def codex_usage_health_status(db_path: str | Path | None = None) -> dict[str, Any]:
    """Return Julian's read-only view of the latest Codex usage evidence."""

    selected = Path(
        db_path
        or os.environ.get("OVERSEER_CODEX_USAGE_DB")
        or DEFAULT_CODEX_USAGE_DB
    ).expanduser()
    if not selected.is_file():
        return {
            "available": False,
            "observed_at": None,
            "posture": "unknown",
            "minimum_remaining_percent": None,
            "recommendation": "Codex usage has not produced a local snapshot yet.",
            "rate_limits": [],
            "account_usage": {},
            "next_step": "Verify the codex-usage MCP service and refresh usage.",
        }
    try:
        tracker = CodexUsageTracker(selected)
        snapshot = tracker.latest(refresh=False)
        heuristics = tracker.heuristics(refresh=False)
    except (OSError, ValueError, RuntimeError) as error:
        return {
            "available": False,
            "observed_at": None,
            "posture": "unknown",
            "minimum_remaining_percent": None,
            "recommendation": "Codex usage evidence could not be read.",
            "rate_limits": [],
            "account_usage": {},
            "error": type(error).__name__,
            "next_step": "Check the codex-usage MCP service and its local snapshot database.",
        }
    return {
        "available": True,
        "observed_at": snapshot.get("observed_at"),
        "posture": heuristics.get("posture"),
        "minimum_remaining_percent": heuristics.get("minimum_remaining_percent"),
        "recommendation": heuristics.get("recommendation"),
        "confidence": heuristics.get("confidence"),
        "rate_limits": snapshot.get("rate_limits") or [],
        "account_usage": snapshot.get("account_usage") or {},
        "window_forecasts": heuristics.get("window_forecasts") or [],
        "warnings": heuristics.get("warnings") or [],
        "next_step": "Refresh through the Codex Usage MCP when newer evidence is required.",
    }

LOOPBACK_HOSTS = {"127.0.0.1", "localhost"}
PROTECTED_GATEWAY_PREFIX = "/Overseer"


def _strip_protected_gateway_prefix(path: str) -> str:
    if path == PROTECTED_GATEWAY_PREFIX:
        return "/"
    if path.startswith(f"{PROTECTED_GATEWAY_PREFIX}/"):
        stripped = path.removeprefix(PROTECTED_GATEWAY_PREFIX)
        return stripped or "/"
    return path


def _project_path_for_store(store_path: str) -> Path:
    store_parent = Path(store_path).resolve().parent
    if store_parent.name == "state":
        return store_parent.parent
    return Path.cwd()


def make_api_handler(store_path: str, auth_token: str | None = None):
    class OverseerApiHandler(BaseHTTPRequestHandler):
        server_version = "OverseerApi/0.1"

        def do_GET(self) -> None:
            route = urlsplit(self.path)
            raw_path = route.path
            path = _strip_protected_gateway_prefix(route.path)
            query = parse_qs(route.query)
            if path == "/health":
                self._write_json({"ok": True, "service": "overseer-api"})
                return
            if path == "/favicon.ico":
                self._write_empty(HTTPStatus.NO_CONTENT)
                return
            if path in {"/", "/ui"}:
                self._write_html(OPERATOR_CONSOLE_HTML)
                return
            auth_context = self._authorize_request("GET", raw_path, path)
            if not auth_context.get("authorized"):
                self._write_auth_error(auth_context)
                return
            if path.startswith("/storage/control/") and auth_context.get("auth_type") != "admin_token":
                self._write_json({"error":"unauthorized","reason":"admin_token_required"},HTTPStatus.FORBIDDEN)
                return
            if path == "/auth-check":
                self._write_json(
                    {
                        "ok": True,
                        "service": "overseer-api",
                        "authorized": True,
                        "auth_type": auth_context.get("auth_type"),
                        "account_id": auth_context.get("account_id"),
                        "token_id": auth_context.get("token_id"),
                    }
                )
                return
            if path == "/storage/control/authorizations":
                self._handle(lambda: list_authorizations(store_path, _query_first(query, "kind")))
                return
            if path == "/agent-providers":
                self._handle(agent_providers_status)
                return
            if path == "/agent-instances":
                self._handle(lambda: agent_instances_status(store_path))
                return
            if path == "/agent-sessions":
                self._handle(
                    lambda: agent_sessions_status(
                        store_path,
                        _query_first(query, "provider_id"),
                        _query_first(query, "instance_id"),
                    )
                )
                return
            if path == "/agent-dispatches":
                self._handle(
                    lambda: agent_dispatches_status(
                        store_path,
                        _query_first(query, "instance_id"),
                    )
                )
                return
            if path == "/agent-failover-executions":
                self._handle(
                    lambda: agent_failover_executions_status(
                        store_path, _query_first(query, "instance_id")
                    )
                )
                return
            if path == "/agent-usage":
                self._handle(lambda: agent_usage_status(store_path))
                return
            if path == "/service-status":
                self._handle(lambda: service_status(store_path))
                return
            if path == "/runtime-status":
                self._handle(lambda: runtime_status(store_path))
                return
            if path == "/runtime/daemon-migration-plan":
                self._handle(lambda: daemon_migration_plan_status(store_path, _query_first(query, "service_name") or "overseer"))
                return
            if path == "/persistence/security":
                self._handle(lambda: persistence_security_status(store_path))
                return
            if path == "/command-summary":
                self._handle(lambda: command_summary_status(store_path))
                return
            if path == "/operator-dashboard":
                include_summaries = _query_first(query, "include_summaries") in {"1", "true", "yes"}
                self._handle(lambda: operator_dashboard_status(store_path, include_summaries=include_summaries))
                return
            if path == "/incidents/lifecycle":
                self._handle(lambda: incident_lifecycle_status(store_path))
                return
            if path == "/operations/gap-coverage":
                self._handle(lambda: operations_gap_coverage_status(store_path))
                return
            if path == "/operations/records":
                self._handle(
                    lambda: list_operation_records_status(
                        store_path,
                        _query_first(query, "kind"),
                        _query_first(query, "owner_domain"),
                        _query_first(query, "status"),
                    )
                )
                return
            if path == "/operations/workflows":
                self._handle(lambda: operation_workflow_catalog_status(store_path))
                return
            if path == "/maintenance-summary":
                self._handle(lambda: maintenance_summary_status(store_path))
                return
            if path == "/maintenance/package-status":
                self._handle(lambda: inspect_packages_status())
                return
            if path == "/maintenance/firmware-status":
                self._handle(lambda: inspect_firmware_status())
                return
            if path == "/maintenance/firmware-preflight":
                self._handle(lambda: inspect_firmware_preflight_status())
                return
            if path == "/maintenance/software-evidence":
                self._handle(lambda: software_evidence_status(store_path))
                return
            if path == "/maintenance/advisories":
                self._handle(lambda: advisory_status(store_path))
                return
            if path == "/maintenance/schedules":
                self._handle(lambda: maintenance_schedules_status(store_path))
                return
            if path == "/health-summary":
                self._handle(lambda: health_summary_status(store_path))
                return
            if path == "/health/service-evidence":
                self._handle(lambda: service_evidence_status(store_path, _query_first(query, "resource_id")))
                return
            if path == "/health/codex-usage":
                self._handle(codex_usage_health_status)
                return
            if path == "/health/skiller-effectiveness":
                self._handle(skiller_effectiveness_status)
                return
            if path == "/health/skiller-guidance-adherence":
                self._handle(skiller_guidance_adherence_status)
                return
            if path == "/observability/trends":
                self._handle(lambda: observability_trends_status(store_path))
                return
            if path == "/observability/metric-history":
                self._handle(lambda: metric_history_status(_project_path_for_store(store_path)))
                return
            if path == "/observability/performance-history":
                self._handle(lambda: performance_history_status(_project_path_for_store(store_path), limit=int(_query_first(query, "limit") or "50")))
                return
            if path == "/health-efficiency":
                self._handle(lambda: health_efficiency_summary_status(store_path))
                return
            if path == "/usage-summary":
                self._handle(lambda: usage_summary_status(store_path))
                return
            if path == "/usage/evidence":
                self._handle(lambda: usage_evidence_status(store_path))
                return
            if path == "/usage/remote-testing":
                self._handle(lambda: remote_testing_status(_project_path_for_store(store_path)))
                return
            if path == "/crew/messages":
                self._handle(lambda: crew_messages_status(store_path, _query_first(query, "owner_domain"), _query_first(query, "status")))
                return
            if path == "/documents/status":
                self._handle(lambda: documents_config_status())
                return
            if path == "/documents/evidence":
                self._handle(lambda: documentation_evidence_status(_project_path_for_store(store_path)))
                return
            if path == "/git/status":
                self._handle(lambda: git_status_status(_project_path_for_store(store_path)))
                return
            if path == "/documents/notes":
                self._handle(lambda: documents_list_notes_status(folder=_query_first(query, "folder") or ""))
                return
            if path == "/documents/knowledge-capture-plan":
                self._handle(
                    lambda: knowledge_capture_status(
                        store_path,
                        kinds=_query_values(query, "kind"),
                        limit=int(_query_first(query, "limit") or "50"),
                        dry_run=True,
                    )
                )
                return
            if path == "/usage/continuation-plan":
                self._handle(lambda: usage_continuation_plan_status(store_path))
                return
            if path == "/physical-summary":
                self._handle(lambda: physical_summary_status(store_path))
                return
            if path == "/storage/evidence":
                self._handle(lambda: storage_evidence_status(_project_path_for_store(store_path)))
                return
            if path == "/storage/backup-operations":
                self._handle(lambda: backup_operations_status(_project_path_for_store(store_path)))
                return
            if path == "/virtual-summary":
                self._handle(lambda: virtual_summary_status(store_path))
                return
            if path == "/virtual/evidence":
                self._handle(lambda: virtual_evidence_status(store_path))
                return
            if path == "/virtual/operations":
                self._handle(lambda: virtual_operations_status(_project_path_for_store(store_path)))
                return
            if path == "/virtual/image-scans":
                self._handle(lambda: image_scan_status(_project_path_for_store(store_path)))
                return
            if path == "/alerts-summary":
                self._handle(lambda: alerts_summary_status(store_path))
                return
            if path == "/audit-summary":
                self._handle(lambda: audit_summary_status(store_path, _query_first(query, "event_type"), _query_first(query, "owner"), _query_first(query, "subject_prefix")))
                return
            if path == "/approvals-summary":
                self._handle(
                    lambda: approvals_summary_status(
                        store_path,
                        _query_first(query, "status"),
                        _query_first(query, "owner"),
                        _query_first(query, "approval_level"),
                        _query_first(query, "subject_prefix"),
                    )
                )
                return
            if path == "/security-summary":
                self._handle(lambda: security_summary_status(store_path))
                return
            if path == "/security/evidence":
                self._handle(lambda: security_evidence_status(store_path))
                return
            if path == "/security/key-broker":
                self._handle(lambda: key_broker_status(store_path, _project_path_for_store(store_path)))
                return
            if path == "/identity/evidence":
                self._handle(lambda: identity_evidence_status(_project_path_for_store(store_path)))
                return
            if path == "/identity/rotation-requests":
                self._handle(lambda: identity_rotation_requests_status(_project_path_for_store(store_path)))
                return
            if path == "/identity/rotation-readiness":
                self._handle(lambda: identity_rotation_execution_readiness_status(_project_path_for_store(store_path), _query_first(query, "request_id")))
                return
            if path == "/host/security":
                self._handle(lambda: assess_host_security_status(store_path))
                return
            if path == "/host/security/findings":
                self._handle(lambda: host_security_findings_status(store_path))
                return
            if path == "/host/security/triage":
                self._handle(lambda: host_security_triage_status(store_path))
                return
            if path == "/host/security/listener-review-queue":
                self._handle(lambda: host_security_listener_review_queue_status(store_path))
                return
            if path == "/host/security/sources":
                self._handle(lambda: host_security_sources_status(store_path))
                return
            if path == "/host/security/source-review-queue":
                self._handle(lambda: host_security_source_review_queue_status(store_path))
                return
            if path == "/host/security/source-reviews":
                self._handle(lambda: host_security_source_reviews_status(store_path))
                return
            if path == "/host/security/ids-review-packages":
                self._handle(lambda: host_security_ids_review_packages_status(store_path))
                return
            if path == "/host/security/ids-review-summary":
                self._handle(lambda: host_security_ids_review_summary_status(store_path))
                return
            if path == "/admin/authorizations-required":
                self._handle(lambda: authorizations_required_status(store_path))
                return
            if path == "/admin/adapter-capabilities":
                self._handle(lambda: admin_adapter_capabilities_status(store_path))
                return
            if path == "/admin/adapter-enablement-plan":
                self._handle(lambda: admin_adapter_enablement_plan_status(_query_first(query, "kind")))
                return
            if path == "/admin/executions":
                self._handle(lambda: admin_executions_status(store_path))
                return
            if path == "/admin/execution-readiness":
                self._handle(lambda: admin_execution_readiness_status(store_path))
                return
            if path == "/admin/policies":
                self._handle(lambda: admin_policy_status(store_path, _query_first(query, "plan_id")))
                return
            if path == "/compliance/evidence":
                self._handle(lambda: compliance_evidence_status(store_path, _project_path_for_store(store_path)))
                return
            if path == "/admin/active-policy-profile":
                self._handle(lambda: active_policy_profile_status(store_path))
                return
            if path == "/admin/policy-customization-helper":
                self._handle(lambda: policy_customization_helper_cli_status())
                return
            if path == "/admin/history-review":
                self._handle(lambda: admin_history_review_status(store_path))
                return
            if path == "/admin/history-archive-plan":
                self._handle(lambda: admin_history_archive_plan_status(store_path))
                return
            if path == "/admin/history-archives":
                self._handle(lambda: admin_history_archives_status(store_path, _query_first(query, "plan_id")))
                return
            if path == "/admin/history-restore-readiness":
                self._handle(lambda: admin_history_restore_readiness_status(store_path, _query_first(query, "plan_id")))
                return
            if path == "/admin/summary":
                self._handle(lambda: admin_summary_status(store_path))
                return
            if path == "/state":
                self._handle(lambda: list_state_status(store_path))
                return
            if path == "/state/redacted":
                self._handle(lambda: export_state_redacted_status(store_path))
                return
            if path == "/claims/review":
                self._handle(lambda: claim_review_status(store_path, _query_first(query, "now")))
                return
            if path == "/claims/cleanup-plan":
                self._handle(lambda: claim_cleanup_plan_status(store_path, _query_first(query, "now")))
                return
            self._write_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

        def do_POST(self) -> None:
            route = urlsplit(self.path)
            raw_path = route.path
            path = _strip_protected_gateway_prefix(route.path)
            if path == "/usage/remote-testing/authorize":
                header = self.headers.get("authorization", "")
                prefix = "Bearer "
                if auth_token is None or not header.startswith(prefix) or not secrets.compare_digest(header[len(prefix) :], auth_token):
                    self._write_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
                    return
                self._handle_json(
                    lambda payload: validate_remote_testing_token(
                        _project_path_for_store(store_path),
                        str(payload.get("token", "")),
                        str(payload.get("method", "")),
                        str(payload.get("raw_path", "")),
                        str(payload.get("normalized_path", "")),
                    )
                    or {"authorized": False, "auth_type": "unknown", "reason": "invalid_token"}
                )
                return
            auth_context = self._authorize_request("POST", raw_path, path)
            if not auth_context.get("authorized"):
                self._write_auth_error(auth_context)
                return
            if path.startswith("/storage/control/") and auth_context.get("auth_type") != "admin_token":
                self._write_json({"error":"unauthorized","reason":"admin_token_required"},HTTPStatus.FORBIDDEN)
                return
            if path == "/storage/authorizations/verify":
                self._handle_json(lambda payload: verify_storage_authorization_status(store_path, payload))
                return
            if path == "/storage/roots/verify":
                self._handle_json(lambda payload: verify_storage_root_authorization_status(store_path, payload))
                return
            if path == "/storage/control/stage":
                self._handle_json(lambda p: stage_authorization_api(store_path,p))
                return
            if path == "/storage/control/materialize":
                self._handle_json(lambda p: materialize_authorization_api(store_path,p))
                return
            if path == "/storage/control/approve":
                self._handle_json(lambda p: approve_authorization_api(store_path,p))
                return
            if path == "/storage/control/revoke":
                self._handle_json(lambda p: revoke_authorization_api(store_path,p))
                return
            if (
                path.startswith("/usage/remote-testing/")
                or path.startswith("/security/key-broker/")
            ) and auth_context.get("auth_type") != "admin_token":
                self._write_json({"error": "control routes require admin authorization"}, HTTPStatus.FORBIDDEN)
                return
            if path == "/agent-sessions/discover":
                self._handle_json(
                    lambda payload: discover_agent_sessions_status(
                        store_path,
                        **_agent_session_discovery_args(payload),
                    )
                )
                return
            if path == "/agent-dispatches":
                self._handle_json(
                    lambda payload: dispatch_agent_goal_status(
                        store_path,
                        **_agent_dispatch_args(payload),
                    )
                )
                return
            if path == "/agent-checkpoints":
                self._handle_json(
                    lambda payload: checkpoint_agent_status(
                        store_path,
                        **_agent_checkpoint_args(payload),
                    )
                )
                return
            if path == "/agent-recovery":
                self._handle_json(
                    lambda payload: recover_agent_status(
                        store_path,
                        **_agent_recovery_args(payload),
                    )
                )
                return
            if path == "/agent-handoffs":
                self._handle_json(
                    lambda payload: handoff_agent_status(
                        store_path,
                        **_agent_handoff_args(payload),
                    )
                )
                return
            if path == "/agent-failover":
                self._handle_json(
                    lambda payload: execute_agent_failover_status(
                        store_path,
                        **_agent_failover_execution_args(payload),
                    )
                )
                return
            if path == "/agent-failover/evaluate":
                self._handle_json(
                    lambda payload: evaluate_agent_failover_status(
                        store_path,
                        **_agent_failover_evaluation_args(payload),
                    )
                )
                return
            if path == "/agent-failover/recover":
                self._handle_json(
                    lambda payload: recover_agent_failover_execution_status(
                        store_path,
                        **_agent_failover_recovery_args(payload),
                    )
                )
                return
            if path == "/claims/request":
                self._handle_json(lambda payload: request_claim_status(store_path, **_request_claim_args(payload)))
                return
            if path == "/resources":
                self._handle_json(lambda payload: record_resource_status(store_path, **_resource_args(payload)))
                return
            if path == "/claims/approve":
                self._handle_json(lambda payload: approve_claim_status(store_path, **_approve_claim_args(payload)))
                return
            if path == "/claims/activate":
                self._handle_json(lambda payload: activate_claim_status(store_path, **_activate_claim_args(payload)))
                return
            if path == "/claims/release":
                self._handle_json(lambda payload: release_claim_status(store_path, **_release_claim_args(payload)))
                return
            if path == "/claims/cleanup-requests":
                self._handle_json(lambda payload: request_claim_cleanup_status(store_path, **_claim_cleanup_request_args(payload)))
                return
            if path == "/claims/cleanup-requests/approve":
                self._handle_json(lambda payload: approve_claim_cleanup_status(store_path, **_approve_claim_cleanup_args(payload)))
                return
            if path == "/claims/cleanup-requests/execute":
                self._handle_json(lambda payload: execute_claim_cleanup_status(store_path, **_execute_claim_cleanup_args(payload)))
                return
            if path == "/host/inspect":
                self._handle(lambda: inspect_host_status(store_path))
                return
            if path == "/operations/records":
                self._handle_json(lambda payload: record_operation_status(store_path, **_operation_record_args(payload)))
                return
            if path == "/operations/records/transition":
                self._handle_json(lambda payload: transition_operation_record_status(store_path, **_operation_transition_args(payload)))
                return
            if path == "/operations/workflows/stage":
                self._handle_json(lambda payload: stage_operation_workflow_status(store_path, **_operation_workflow_stage_args(payload)))
                return
            if path == "/services/discover-user":
                self._handle(lambda: discover_user_services_status(store_path))
                return
            if path == "/physical/discover":
                self._handle_json(lambda payload: discover_physical_status(**_physical_discovery_args(store_path, payload)))
                return
            if path == "/health/probes/run":
                self._handle_json(lambda payload: probe_stored_health_status(store_path, **_stored_health_probe_args(payload)))
                return
            if path == "/health-targets":
                self._handle_json(lambda payload: record_health_target_status(store_path, **_health_target_args(payload)))
                return
            if path == "/health/journal-access-requests":
                self._handle_json(lambda payload: stage_journal_access_request_status(store_path, **_journal_access_request_args(payload)))
                return
            if path == "/health/journal-access-requests/execute":
                self._handle_json(lambda payload: execute_journal_access_request_status(store_path, _project_path_for_store(store_path), **_journal_access_execution_args(payload)))
                return
            if path == "/observability/metric-history/capture":
                self._handle_json(lambda payload: capture_metric_history_status(store_path, _project_path_for_store(store_path), **_metric_history_capture_args(payload)))
                return
            if path == "/physical/discover-storage":
                self._handle_json(lambda payload: discover_storage_status(**_physical_storage_discovery_args(store_path, payload)))
                return
            if path == "/storage/backup-jobs":
                self._handle_json(lambda payload: record_backup_job_status(_project_path_for_store(store_path), **_backup_job_args(payload)))
                return
            if path == "/storage/restore-tests":
                self._handle_json(lambda payload: record_restore_test_status(_project_path_for_store(store_path), **_restore_test_args(payload)))
                return
            if path == "/storage/backup-execution-requests":
                self._handle_json(lambda payload: stage_backup_execution_request_status(_project_path_for_store(store_path), **_backup_execution_request_args(payload)))
                return
            if path == "/storage/backup-execution-requests/approve":
                self._handle_json(lambda payload: approve_backup_execution_request_status(_project_path_for_store(store_path), **_backup_execution_approval_args(payload)))
                return
            if path == "/storage/backup-execution-requests/execute":
                self._handle_json(lambda payload: execute_backup_execution_request_status(_project_path_for_store(store_path), **_backup_execution_execute_args(payload)))
                return
            if path == "/storage/growth-snapshots/capture":
                self._handle_json(lambda payload: capture_storage_growth_snapshot_status(_project_path_for_store(store_path), **_storage_growth_capture_args(payload)))
                return
            if path == "/storage/restore-execution-requests":
                self._handle_json(lambda payload: stage_restore_execution_request_status(_project_path_for_store(store_path), **_restore_execution_request_args(payload)))
                return
            if path == "/storage/restore-execution-requests/approve":
                self._handle_json(lambda payload: approve_restore_execution_request_status(_project_path_for_store(store_path), **_restore_execution_approval_args(payload)))
                return
            if path == "/storage/restore-execution-requests/execute":
                self._handle_json(lambda payload: execute_restore_execution_request_status(_project_path_for_store(store_path), **_restore_execution_execute_args(payload)))
                return
            if path == "/storage/cleanup-requests":
                self._handle_json(lambda payload: stage_backup_cleanup_request_status(_project_path_for_store(store_path), **_backup_cleanup_request_args(payload)))
                return
            if path == "/storage/cleanup-requests/approve":
                self._handle_json(lambda payload: approve_backup_cleanup_request_status(_project_path_for_store(store_path), **_backup_cleanup_approval_args(payload)))
                return
            if path == "/storage/cleanup-requests/execute":
                self._handle_json(lambda payload: execute_backup_cleanup_request_status(_project_path_for_store(store_path), **_backup_cleanup_execution_args(payload)))
                return
            if path == "/virtual/discover-listeners":
                self._handle(lambda: discover_virtual_listeners_status(store_path))
                return
            if path == "/virtual/target-setup-requests":
                self._handle_json(lambda payload: stage_virtual_target_setup_batch_status(_project_path_for_store(store_path), **_virtual_target_setup_args(payload)))
                return
            if path == "/virtual/target-setup-requests/result":
                self._handle_json(lambda payload: record_virtual_target_setup_result_status(_project_path_for_store(store_path), **_virtual_target_setup_result_args(payload)))
                return
            if path == "/virtual/target-setup-requests/execute":
                self._handle_json(lambda payload: execute_virtual_target_setup_status(_project_path_for_store(store_path), **_virtual_target_setup_execute_args(payload)))
                return
            if path == "/virtual/runtime-records":
                self._handle_json(lambda payload: record_virtual_runtime_status(_project_path_for_store(store_path), **_virtual_runtime_record_args(payload)))
                return
            if path == "/virtual/lifecycle/execute":
                self._handle_json(lambda payload: execute_virtual_lifecycle_status(_project_path_for_store(store_path), **_virtual_lifecycle_execution_args(payload)))
                return
            if path == "/virtual/snapshot-requests":
                self._handle_json(lambda payload: stage_virtual_snapshot_request_status(_project_path_for_store(store_path), **_virtual_snapshot_request_args(payload)))
                return
            if path == "/virtual/snapshot-requests/approve":
                self._handle_json(lambda payload: approve_virtual_snapshot_request_status(_project_path_for_store(store_path), **_virtual_approval_args(payload)))
                return
            if path == "/virtual/snapshot-requests/execute":
                self._handle_json(lambda payload: execute_virtual_snapshot_request_status(_project_path_for_store(store_path), **_virtual_execution_args(payload)))
                return
            if path == "/virtual/restore-requests":
                self._handle_json(lambda payload: stage_virtual_restore_request_status(_project_path_for_store(store_path), **_virtual_restore_request_args(payload)))
                return
            if path == "/virtual/restore-requests/approve":
                self._handle_json(lambda payload: approve_virtual_restore_request_status(_project_path_for_store(store_path), **_virtual_approval_args(payload)))
                return
            if path == "/virtual/restore-requests/execute":
                self._handle_json(lambda payload: execute_virtual_restore_request_status(_project_path_for_store(store_path), **_virtual_execution_args(payload)))
                return
            if path == "/virtual/destroy-requests":
                self._handle_json(lambda payload: stage_virtual_destroy_request_status(_project_path_for_store(store_path), **_virtual_destroy_request_args(payload)))
                return
            if path == "/virtual/destroy-requests/approve":
                self._handle_json(lambda payload: approve_virtual_destroy_request_status(_project_path_for_store(store_path), **_virtual_approval_args(payload)))
                return
            if path == "/virtual/destroy-requests/execute":
                self._handle_json(lambda payload: execute_virtual_destroy_request_status(_project_path_for_store(store_path), **_virtual_execution_args(payload)))
                return
            if path == "/virtual/image-scans":
                self._handle_json(lambda payload: stage_image_scan_request_status(_project_path_for_store(store_path), **_image_scan_request_args(payload)))
                return
            if path == "/virtual/image-scans/approve":
                self._handle_json(lambda payload: approve_image_scan_request_status(_project_path_for_store(store_path), **_image_scan_approval_args(payload)))
                return
            if path == "/virtual/image-scans/execute":
                self._handle_json(lambda payload: execute_image_scan_request_status(_project_path_for_store(store_path), **_image_scan_execution_args(payload)))
                return
            if path == "/host/security/remediations/plans":
                self._handle_json(lambda payload: plan_host_security_remediation_status(store_path, **_host_security_remediation_args(payload)))
                return
            if path == "/host/security/listener-review-queue/remediation-plans":
                self._handle_json(lambda payload: plan_host_security_listener_queue_remediations_status(store_path, **_host_security_listener_queue_remediations_args(payload)))
                return
            if path == "/host/security/advance":
                self._handle_json(lambda payload: advance_odo_security_status(store_path, **_advance_odo_security_args(payload)))
                return
            if path == "/host/security/source-reviews/block-plans":
                self._handle_json(lambda payload: plan_host_security_source_block_status(store_path, **_host_security_source_block_args(payload)))
                return
            if path == "/host/security/firewall-policy/enforcement-plans":
                self._handle_json(lambda payload: plan_firewall_policy_diff_enforcement_status(store_path, **_firewall_policy_enforcement_args(payload)))
                return
            if path == "/host/security/firewall-executions/execute":
                self._handle_json(lambda payload: execute_firewall_change_status(store_path, **_firewall_execution_args(payload)))
                return
            if path == "/identity/rotation-requests":
                self._handle_json(lambda payload: stage_identity_rotation_request_status(_project_path_for_store(store_path), **_identity_rotation_request_args(payload)))
                return
            if path == "/identity/rotation-requests/approve":
                self._handle_json(lambda payload: approve_identity_rotation_request_status(_project_path_for_store(store_path), **_identity_rotation_approval_args(payload)))
                return
            if path == "/identity/rotation-requests/execute":
                self._handle_json(lambda payload: execute_identity_rotation_request_status(_project_path_for_store(store_path), **_identity_rotation_execution_args(payload)))
                return
            if path == "/host/security/source-reviews":
                self._handle_json(lambda payload: create_host_security_source_review_status(store_path, **_host_security_source_review_args(payload)))
                return
            if path == "/host/security/ids-review-packages":
                self._handle_json(lambda payload: prepare_host_security_ids_review_package_status(store_path, **_host_security_ids_review_package_args(payload)))
                return
            if path == "/host/security/ids-review-packages/submit":
                self._handle_json(lambda payload: submit_host_security_ids_review_package_status(store_path, **_submit_host_security_ids_review_package_args(payload)))
                return
            if path == "/host/security/ids-review-packages/prompts":
                self._handle_json(lambda payload: export_host_security_ids_review_prompt_status(store_path, **_export_host_security_ids_review_prompt_args(payload)))
                return
            if path == "/host/security/ids-review-packages/dispatch":
                self._handle_json(lambda payload: dispatch_host_security_ids_review_package_status(store_path, **_dispatch_host_security_ids_review_package_args(payload)))
                return
            if path == "/host/security/ids-review-packages/results":
                self._handle_json(lambda payload: record_host_security_ids_review_result_status(store_path, **_host_security_ids_review_result_args(payload)))
                return
            if path == "/admin/plans":
                self._handle_json(lambda payload: plan_admin_change_status(store_path, **_admin_plan_args(payload)))
                return
            if path == "/maintenance/package-update-plans":
                self._handle_json(lambda payload: plan_package_updates_status(store_path, **_package_update_plan_args(payload)))
                return
            if path == "/maintenance/firmware-update-plans":
                self._handle_json(lambda payload: plan_firmware_updates_status(store_path, **_firmware_update_plan_args(payload)))
                return
            if path == "/maintenance/package-maintenance-cycle":
                self._handle_json(lambda payload: run_obrien_package_maintenance_cycle_status(store_path, **_package_maintenance_cycle_args(payload)))
                return
            if path == "/maintenance/advisories/refresh":
                self._handle_json(lambda payload: refresh_advisories_status(store_path, **_advisory_refresh_args(payload)))
                return
            if path == "/maintenance/schedules":
                self._handle_json(lambda payload: record_maintenance_schedule_status(store_path, **_maintenance_schedule_args(payload)))
                return
            if path == "/admin/approve":
                self._handle_json(lambda payload: approve_admin_change_status(store_path, **_approve_admin_plan_args(payload)))
                return
            if path == "/admin/cancel":
                self._handle_json(lambda payload: cancel_admin_change_status(store_path, **_cancel_admin_plan_args(payload)))
                return
            if path == "/admin/execute":
                self._handle_admin_execute()
                return
            if path == "/admin/history-archive":
                self._handle_json(lambda payload: archive_admin_history_status(store_path, **_archive_admin_history_args(payload)))
                return
            if path == "/admin/history-archive-requests":
                self._handle_json(lambda payload: request_admin_history_archive_status(store_path, **_admin_history_archive_request_args(payload)))
                return
            if path == "/admin/history-archive-requests/approve":
                self._handle_json(lambda payload: approve_admin_history_archive_status(store_path, **_approve_admin_history_archive_args(payload)))
                return
            if path == "/admin/history-restore-requests":
                self._handle_json(lambda payload: request_admin_history_restore_status(store_path, **_admin_history_restore_request_args(payload)))
                return
            if path == "/admin/history-restore-requests/approve":
                self._handle_json(lambda payload: approve_admin_history_restore_status(store_path, **_approve_admin_history_restore_args(payload)))
                return
            if path == "/admin/adapter-enablement-requests":
                self._handle_json(lambda payload: request_admin_adapter_enablement_status(store_path, **_admin_adapter_enablement_request_args(payload)))
                return
            if path == "/admin/adapter-enablement-requests/approve":
                self._handle_json(lambda payload: approve_admin_adapter_enablement_status(store_path, **_approve_admin_adapter_enablement_args(payload)))
                return
            if path == "/admin/policy-warning-requests":
                self._handle_json(lambda payload: request_admin_policy_warning_status(store_path, **_admin_policy_warning_request_args(payload)))
                return
            if path == "/admin/policy-warning-requests/approve":
                self._handle_json(lambda payload: approve_admin_policy_warning_status(store_path, **_approve_admin_policy_warning_args(payload)))
                return
            if path == "/admin/policy-customization-helper/profile":
                self._handle_json(lambda payload: _build_policy_profile_api_status(payload))
                return
            if path == "/runtime/daemon-migration-requests":
                self._handle_json(lambda payload: request_daemon_migration_status(store_path, **_daemon_migration_request_args(payload)))
                return
            if path == "/runtime/daemon-migration-requests/approve":
                self._handle_json(lambda payload: approve_daemon_migration_status(store_path, **_approve_daemon_migration_args(payload)))
                return
            if path == "/usage/continuation-requests":
                self._handle_json(lambda payload: request_usage_continuation_status(store_path, **_usage_continuation_request_args(payload)))
                return
            if path == "/usage/remote-testing/profiles":
                self._handle_json(lambda payload: record_remote_testing_profile_status(_project_path_for_store(store_path), **_remote_testing_profile_args(payload)))
                return
            if path == "/usage/remote-testing/accounts":
                self._handle_json(lambda payload: record_remote_testing_account_status(_project_path_for_store(store_path), **_remote_testing_account_args(payload)))
                return
            if path == "/usage/remote-testing/auth-tokens":
                self._handle_json(lambda payload: issue_remote_testing_token_status(_project_path_for_store(store_path), **_remote_testing_token_args(payload)))
                return
            if path == "/usage/remote-testing/auth-tokens/revoke":
                self._handle_json(lambda payload: revoke_remote_testing_token_status(_project_path_for_store(store_path), **_remote_testing_revoke_args(payload)))
                return
            if path == "/usage/remote-testing/leases":
                self._handle_json(lambda payload: request_remote_testing_lease_status(_project_path_for_store(store_path), **_remote_testing_lease_args(payload)))
                return
            if path == "/usage/remote-testing/jobs":
                self._handle_json(lambda payload: enqueue_remote_test_job_status(_project_path_for_store(store_path), **_remote_testing_job_args(payload)))
                return
            if path == "/usage/remote-testing/results":
                self._handle_json(lambda payload: collect_remote_test_results_status(_project_path_for_store(store_path), **_remote_testing_results_args(payload)))
                return
            if path == "/security/key-broker/providers":
                self._handle_json(lambda payload: record_key_provider_status(store_path, **_key_provider_args(payload)))
                return
            if path == "/security/key-broker/requests":
                self._handle_json(lambda payload: request_key_broker_token_status(store_path, **_key_broker_request_args(payload)))
                return
            if path == "/security/key-broker/requests/approve":
                self._handle_json(lambda payload: approve_key_broker_request_status(store_path, **_key_broker_approval_args(payload)))
                return
            if path == "/security/key-broker/tokens":
                self._handle_json(lambda payload: issue_key_broker_token_status(store_path, _project_path_for_store(store_path), **_key_broker_issue_args(payload)))
                return
            if path == "/security/key-broker/tokens/revoke":
                self._handle_json(lambda payload: revoke_key_broker_token_status(store_path, **_key_broker_revoke_args(payload)))
                return
            if path == "/usage-limits":
                self._handle_json(lambda payload: record_usage_limit_status(store_path, **_usage_limit_args(payload)))
                return
            if path == "/crew/messages":
                self._handle_json(lambda payload: record_crew_message_status(store_path, **_crew_message_args(payload)))
                return
            if path == "/crew/dispatch":
                self._handle_json(lambda payload: dispatch_crew_messages_status(store_path, **_crew_dispatch_args(payload)))
                return
            if path == "/crew/messages/decide":
                self._handle_json(lambda payload: decide_crew_message_status(store_path, **_crew_decision_args(payload)))
                return
            if path == "/crew/messages/resubmit":
                self._handle_json(lambda payload: resubmit_crew_message_status(store_path, **_crew_resubmit_args(payload)))
                return
            if path == "/crew/reconcile":
                self._handle_json(lambda payload: reconcile_crew_reviews_status(store_path, **_crew_reconcile_args(payload)))
                return
            if path == "/documents/search":
                self._handle_json(lambda payload: documents_search_status(**_documents_search_args(payload)))
                return
            if path == "/documents/notes":
                self._handle_json(lambda payload: documents_write_note_status(**_documents_write_args(payload)))
                return
            if path == "/documents/knowledge-capture":
                self._handle_json(lambda payload: knowledge_capture_status(store_path, **_knowledge_capture_args(payload)))
                return
            if path == "/usage/continuation-dispatches":
                self._handle_json(lambda payload: dispatch_usage_continuations_status(store_path, **_usage_continuation_dispatch_args(payload)))
                return
            if path == "/codex-projects/discover-threads":
                self._handle_json(
                    lambda payload: _legacy_codex_discovery_status(
                        store_path,
                        payload,
                    ),
                    response_headers={
                        "Deprecation": "true",
                        "Link": '</agent-sessions/discover>; rel="successor-version"',
                    },
                )
                return
            if path == "/admin/history-unarchive":
                self._handle_json(lambda payload: unarchive_admin_history_status(store_path, **_unarchive_admin_history_args(payload)))
                return
            self._write_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

        def log_message(self, format: str, *args: object) -> None:
            return

        def _authorize_request(self, method: str, raw_path: str, normalized_path: str) -> dict[str, object]:
            if auth_token is None:
                return {"authorized": True, "auth_type": "none"}
            header = self.headers.get("authorization", "")
            prefix = "Bearer "
            if not header.startswith(prefix):
                return {"authorized": False, "auth_type": "missing", "reason": "missing_bearer"}
            presented = header[len(prefix) :]
            if secrets.compare_digest(presented, auth_token):
                return {"authorized": True, "auth_type": "admin_token"}
            context = validate_remote_testing_token(
                _project_path_for_store(store_path),
                presented,
                method,
                raw_path,
                normalized_path,
            )
            if context is not None:
                return context
            return {"authorized": False, "auth_type": "unknown", "reason": "invalid_token"}

        def _write_auth_error(self, auth_context: dict[str, object]) -> None:
            status = HTTPStatus.FORBIDDEN if auth_context.get("auth_type") == "remote_testing_token" else HTTPStatus.UNAUTHORIZED
            self._write_json({"error": "unauthorized", "reason": auth_context.get("reason")}, status)

        def _is_authorized(self) -> bool:
            if auth_token is None:
                return True
            header = self.headers.get("authorization", "")
            prefix = "Bearer "
            if not header.startswith(prefix):
                return False
            return secrets.compare_digest(header[len(prefix) :], auth_token)

        def _handle(self, handler) -> None:
            try:
                self._write_json(handler())
            except KeyError as error:
                self._write_json({"error": f"missing record: {error.args[0]}"}, HTTPStatus.NOT_FOUND)
            except ValueError as error:
                self._write_json({"error": str(error)}, HTTPStatus.BAD_REQUEST)
            except AgentAuthorizationError as error:
                self._write_json({"error": str(error)}, HTTPStatus.FORBIDDEN)
            except (AgentManagerError, AgentAdapterUnavailableError) as error:
                self._write_json({"error": str(error)}, HTTPStatus.CONFLICT)

        def _handle_json(
            self,
            handler,
            response_headers: dict[str, str] | None = None,
        ) -> None:
            try:
                payload = self._read_json()
                self._write_json(handler(payload), headers=response_headers)
            except KeyError as error:
                self._write_json(
                    {"error": f"missing field: {error.args[0]}"},
                    HTTPStatus.BAD_REQUEST,
                    headers=response_headers,
                )
            except ValueError as error:
                self._write_json(
                    {"error": str(error)},
                    HTTPStatus.BAD_REQUEST,
                    headers=response_headers,
                )
            except AgentAuthorizationError as error:
                self._write_json(
                    {"error": str(error)},
                    HTTPStatus.FORBIDDEN,
                    headers=response_headers,
                )
            except (AgentManagerError, AgentAdapterUnavailableError) as error:
                self._write_json(
                    {"error": str(error)},
                    HTTPStatus.CONFLICT,
                    headers=response_headers,
                )

        def _handle_admin_execute(self) -> None:
            try:
                payload = self._read_json()
                plan_id = str(payload["plan_id"])
            except KeyError as error:
                self._write_json({"error": f"missing field: {error.args[0]}"}, HTTPStatus.BAD_REQUEST)
                return
            except ValueError as error:
                self._write_json({"error": str(error)}, HTTPStatus.BAD_REQUEST)
                return
            self._handle(lambda: execute_admin_change_status(store_path, plan_id))

        def _read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("content-length", "0"))
            if length == 0:
                return {}
            data = self.rfile.read(length)
            parsed = json.loads(data.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise ValueError("request body must be a JSON object")
            return parsed

        def _write_json(
            self,
            payload: dict[str, Any],
            status: HTTPStatus = HTTPStatus.OK,
            headers: dict[str, str] | None = None,
        ) -> None:
            body = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(int(status))
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            try:
                self.wfile.write(body)
            except BrokenPipeError:
                return

        def _write_html(self, html: str, status: HTTPStatus = HTTPStatus.OK) -> None:
            body = html.encode("utf-8")
            self.send_response(int(status))
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("content-length", str(len(body)))
            self.send_header("cache-control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _write_empty(self, status: HTTPStatus) -> None:
            self.send_response(int(status))
            self.send_header("content-length", "0")
            self.end_headers()

    return OverseerApiHandler


def run_api_server(store_path: str, host: str = "127.0.0.1", port: int = 8766, auth_token: str | None = None) -> None:
    if host not in LOOPBACK_HOSTS:
        raise ValueError("Overseer API may only bind to 127.0.0.1 or localhost")
    server = ThreadingHTTPServer((host, port), make_api_handler(store_path, auth_token))
    try:
        server.serve_forever()
    finally:
        server.server_close()


def load_auth_token(token_file: str | None) -> str | None:
    if token_file is None:
        return None
    token = Path(token_file).read_text(encoding="utf-8").strip()
    if not token:
        raise ValueError("auth token file is empty")
    return token


def _request_claim_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "claim_id": str(payload["claim_id"]),
        "resource_id": str(payload["resource_id"]),
        "claim_type": str(payload["claim_type"]),
        "owner_thread": str(payload["owner_thread"]),
        "owner_role": str(payload["owner_role"]),
        "intent": str(payload["intent"]),
        "requested_action": str(payload["requested_action"]),
        "risk_level": str(payload["risk_level"]),
        "ports": tuple(int(port) for port in payload.get("ports", ())),
        "starts_at": str(payload["starts_at"]) if payload.get("starts_at") else None,
        "expires_at": str(payload["expires_at"]) if payload.get("expires_at") else None,
        "release_condition": str(payload["release_condition"]) if payload.get("release_condition") else None,
    }


def _resource_args(payload: dict[str, Any]) -> dict[str, Any]:
    identifiers = payload.get("identifiers", {})
    if not isinstance(identifiers, dict):
        raise ValueError("identifiers must be a JSON object")
    return {
        "resource_id": str(payload["resource_id"]),
        "name": str(payload["name"]),
        "resource_type": str(payload["resource_type"]),
        "owner_domain": str(payload["owner_domain"]),
        "risk_level": str(payload["risk_level"]),
        "state": str(payload.get("state", "available")),
        "identifiers": identifiers,
        "dependencies": tuple(str(item) for item in payload.get("dependencies", ())),
        "exclusive_groups": tuple(str(item) for item in payload.get("exclusive_groups", ())),
        "current_claim_id": str(payload["current_claim_id"]) if payload.get("current_claim_id") else None,
        "last_verified_at": str(payload["last_verified_at"]) if payload.get("last_verified_at") else None,
        "notes": str(payload.get("notes", "")),
    }


def _usage_continuation_request_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "request_id": str(payload["request_id"]),
        "limit_id": str(payload["limit_id"]),
        "resource_id": str(payload["resource_id"]),
        "owner_thread": (
            str(payload["owner_thread"]) if payload.get("owner_thread") else None
        ),
        "requested_units": int(payload["requested_units"]),
        "intent": str(payload["intent"]),
        "risk_level": str(payload.get("risk_level", "low")),
        "earliest_start": str(payload["earliest_start"]) if payload.get("earliest_start") else None,
        "deadline": str(payload["deadline"]) if payload.get("deadline") else None,
        "requested_by": str(payload.get("requested_by", "quark")),
        "requested_at": str(payload["requested_at"]) if payload.get("requested_at") else None,
        "agent_session_id": (
            str(payload["agent_session_id"])
            if payload.get("agent_session_id")
            else None
        ),
        "driver_epoch_id": (
            str(payload["driver_epoch_id"])
            if payload.get("driver_epoch_id")
            else None
        ),
        "provider_id": (
            str(payload["provider_id"]) if payload.get("provider_id") else None
        ),
    }


def _usage_limit_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "limit_id": str(payload["limit_id"]),
        "resource_id": str(payload["resource_id"]),
        "kind": str(payload["kind"]),
        "capacity": int(payload["capacity"]),
        "remaining": int(payload["remaining"]),
        "window": str(payload["window"]),
        "resets_at": str(payload["resets_at"]) if payload.get("resets_at") else None,
        "observed_at": str(payload["observed_at"]) if payload.get("observed_at") else None,
        "confidence": float(payload.get("confidence", 1.0)),
    }


def _crew_message_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "message_id": str(payload["message_id"]) if payload.get("message_id") else None,
        "owner_domain": str(payload["owner_domain"]),
        "subject": str(payload["subject"]),
        "message": str(payload["message"]),
        "priority": str(payload.get("priority", "medium")),
        "requested_by": str(payload.get("requested_by", "operator")),
        "created_at": str(payload["created_at"]) if payload.get("created_at") else None,
        "related_resource_id": str(payload["related_resource_id"]) if payload.get("related_resource_id") else None,
        "related_plan_id": str(payload["related_plan_id"]) if payload.get("related_plan_id") else None,
        "related_limit_id": str(payload["related_limit_id"]) if payload.get("related_limit_id") else None,
        "acceptance_criteria": tuple(str(item) for item in payload.get("acceptance_criteria", [])),
        "request_evidence_ids": tuple(str(item) for item in payload.get("request_evidence_ids", [])),
    }


def _crew_dispatch_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "owner_domain": str(payload["owner_domain"]) if payload.get("owner_domain") else None,
        "message_id": str(payload["message_id"]) if payload.get("message_id") else None,
        "dispatched_by": str(payload.get("dispatched_by", "sisko")),
        "dispatched_at": str(payload["dispatched_at"]) if payload.get("dispatched_at") else None,
    }


def _crew_decision_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "message_id": str(payload["message_id"]),
        "review_status": str(payload["review_status"]),
        "decided_by": str(payload["decided_by"]),
        "reason": str(payload["reason"]),
        "evidence_ids": tuple(str(item) for item in payload.get("evidence_ids", [])),
        "correction_request": str(payload["correction_request"]) if payload.get("correction_request") else None,
        "decided_at": str(payload["decided_at"]) if payload.get("decided_at") else None,
    }


def _crew_resubmit_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "message_id": str(payload["message_id"]),
        "subject": str(payload["subject"]),
        "message": str(payload["message"]),
        "requested_by": str(payload["requested_by"]),
        "new_message_id": str(payload["new_message_id"]) if payload.get("new_message_id") else None,
        "created_at": str(payload["created_at"]) if payload.get("created_at") else None,
        "expected_requesters": tuple(str(item) for item in payload.get("expected_requesters", [])),
        "related_resource_id": str(payload["related_resource_id"]) if payload.get("related_resource_id") else None,
        "related_plan_id": str(payload["related_plan_id"]) if payload.get("related_plan_id") else None,
        "related_limit_id": str(payload["related_limit_id"]) if payload.get("related_limit_id") else None,
        "acceptance_criteria": tuple(str(item) for item in payload.get("acceptance_criteria", [])),
        "request_evidence_ids": tuple(str(item) for item in payload.get("request_evidence_ids", [])),
    }


def _crew_reconcile_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "message_id": str(payload["message_id"]) if payload.get("message_id") else None,
        "reconciled_by": str(payload.get("reconciled_by", "sisko")),
        "reconciled_at": str(payload["reconciled_at"]) if payload.get("reconciled_at") else None,
    }


def _documents_search_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "query": str(payload["query"]),
        "context_length": int(payload.get("context_length", 100)),
    }


def _documents_write_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": str(payload["path"]),
        "content": str(payload["content"]),
        "mode": str(payload.get("mode", "append")),
    }


def _operation_record_args(payload: dict[str, Any]) -> dict[str, Any]:
    metadata = payload.get("metadata") or {}
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be a JSON object")
    return {
        "record_id": str(payload["record_id"]),
        "kind": str(payload["kind"]),
        "owner_domain": str(payload["owner_domain"]),
        "status": str(payload.get("status") or "open"),
        "subject": str(payload["subject"]),
        "summary": str(payload["summary"]),
        "severity": str(payload.get("severity") or "low"),
        "resource_id": str(payload["resource_id"]) if payload.get("resource_id") else None,
        "evidence_ids": tuple(str(item) for item in payload.get("evidence_ids", ())),
        "next_step": str(payload.get("next_step") or ""),
        "metadata": metadata,
    }


def _operation_transition_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_id": str(payload["record_id"]),
        "status": str(payload["status"]),
        "updated_by": str(payload.get("updated_by") or "sisko"),
        "next_step": str(payload["next_step"]) if payload.get("next_step") else None,
        "summary_note": str(payload["summary_note"]) if payload.get("summary_note") else None,
    }


def _operation_workflow_stage_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "template_id": str(payload["template_id"]),
        "record_id": str(payload["record_id"]) if payload.get("record_id") else None,
        "resource_id": str(payload["resource_id"]) if payload.get("resource_id") else None,
        "requested_by": str(payload.get("requested_by") or "sisko"),
    }


def _maintenance_schedule_args(payload: dict[str, Any]) -> dict[str, Any]:
    metadata = payload.get("metadata") or {}
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be a JSON object")
    return {
        "schedule_id": str(payload["schedule_id"]),
        "target": str(payload["target"]),
        "recurrence": str(payload.get("recurrence") or "weekly"),
        "window": str(payload.get("window") or "unscheduled"),
        "timezone": str(payload.get("timezone") or "UTC"),
        "blackout": str(payload.get("blackout") or ""),
        "validation": str(payload.get("validation") or "run health probes and service evidence after maintenance"),
        "rollback": str(payload.get("rollback") or "use related admin plan rollback steps"),
        "status": str(payload.get("status") or "active"),
        "owner_domain": str(payload.get("owner_domain") or "obrien"),
        "risk_level": str(payload.get("risk_level") or "medium"),
        "notes": str(payload.get("notes") or ""),
        "metadata": metadata,
    }


def _advisory_refresh_args(payload: dict[str, Any]) -> dict[str, Any]:
    packages = payload.get("packages")
    if isinstance(packages, str):
        packages = [part.strip() for part in packages.replace("\n", ",").split(",") if part.strip()]
    if packages is not None and not isinstance(packages, list):
        raise ValueError("packages must be a list or comma-separated string")
    return {
        "package_names": [str(item) for item in packages] if packages else None,
        "source": str(payload.get("source") or "nvd"),
        "max_results_per_package": int(payload.get("max_results_per_package") or 5),
        "requested_by": str(payload.get("requested_by") or "obrien"),
        "dry_run": bool(payload.get("dry_run", False)),
    }


def _knowledge_capture_args(payload: dict[str, Any]) -> dict[str, Any]:
    kinds = payload.get("kinds", ())
    if isinstance(kinds, str):
        kinds = (kinds,)
    if not isinstance(kinds, (list, tuple)):
        raise ValueError("kinds must be a list")
    return {
        "kinds": tuple(str(kind) for kind in kinds),
        "limit": int(payload.get("limit", 50)),
        "dry_run": bool(payload.get("dry_run", False)),
    }


def _usage_continuation_dispatch_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "dispatched_by": str(payload.get("dispatched_by", "quark")),
        "dispatched_at": str(payload["dispatched_at"]) if payload.get("dispatched_at") else None,
        "resume_codex_projects": bool(payload.get("resume_codex_projects", False)),
        "codex_projects_registry": str(payload.get("codex_projects_registry", "/home/god/.codex/codex-projects.csv")),
        "resume_agent_sessions": bool(
            payload.get("resume_agent_sessions", False)
        ),
        "agent_registry_path": str(
            payload.get("agent_registry_path", DEFAULT_AGENT_REGISTRY)
        ),
        "local_agent_registry_path": (
            str(payload["local_agent_registry_path"])
            if payload.get("local_agent_registry_path")
            else None
        ),
    }


def _remote_testing_profile_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "profile_id": str(payload.get("profile_id", "remote-testing.tank-msi")),
        "display_name": str(payload.get("display_name", "Tank on MSI remote testing queue")),
        "worker_hint": str(payload.get("worker_hint", "overseer-msi-test-agent")),
        "queue_root": str(payload.get("queue_root", "local-secrets/remote-testing")),
        "base_url": str(payload.get("base_url", "http://127.0.0.1:8766")),
        "ui_path": str(payload.get("ui_path", "/Overseer/ui")),
        "gateway_path": str(payload.get("gateway_path", "/Overseer")),
        "token_source": str(payload.get("token_source", "state/api-token")),
        "recorded_by": str(payload.get("recorded_by", "quark")),
        "remote_host": str(payload.get("remote_host", "god@10.50.0.100")),
    }


def _list_payload(value: Any, default: list[str]) -> list[str]:
    if value is None:
        return default
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, list):
        return [str(item) for item in value]
    raise ValueError("expected a list or comma-separated string")


def _remote_testing_account_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "account_id": str(payload.get("account_id", "tank-msi-gateway-test")),
        "display_name": str(payload.get("display_name", "Tank/MSI gateway test account")),
        "agent_kind": str(payload.get("agent_kind", "windows")),
        "agent_id": str(payload.get("agent_id", "tank-msi")),
        "allowed_projects": tuple(_list_payload(payload.get("allowed_projects"), ["*"])),
        "allowed_service_paths": tuple(_list_payload(payload.get("allowed_service_paths"), ["*"])),
        "allowed_gateway_origins": tuple(_list_payload(payload.get("allowed_gateway_origins"), ["*"])),
        "gateway_principal": str(payload.get("gateway_principal", "owner")),
        "enabled": bool(payload.get("enabled", True)),
        "recorded_by": str(payload.get("recorded_by", "quark")),
    }


def _remote_testing_token_args(payload: dict[str, Any]) -> dict[str, Any]:
    mutation_scope = payload.get("mutation_scope", {})
    if isinstance(mutation_scope, str):
        mutation_scope = json.loads(mutation_scope) if mutation_scope.strip() else {}
    if not isinstance(mutation_scope, dict):
        raise ValueError("mutation_scope must be a JSON object")
    return {
        "account_id": str(payload.get("account_id", "tank-msi-gateway-test")),
        "lease_id": str(payload["lease_id"]) if payload.get("lease_id") else None,
        "job_id": str(payload["job_id"]) if payload.get("job_id") else None,
        "project": str(payload.get("project", "Overseer")),
        "thread_id": str(payload["thread_id"]) if payload.get("thread_id") else None,
        "service_paths": tuple(_list_payload(payload.get("service_paths"), ["/Overseer"])),
        "gateway_origins": tuple(_list_payload(payload.get("gateway_origins"), ["https://roadex.home.arpa:9443"])),
        "allowed_methods": tuple(_list_payload(payload.get("allowed_methods"), ["GET", "HEAD", "OPTIONS"])),
        "allowed_routes": tuple(_list_payload(payload.get("allowed_routes"), ["*"])),
        "ttl_minutes": int(payload.get("ttl_minutes", 30)),
        "mutates": bool(payload.get("mutates", False)),
        "mutation_scope": mutation_scope,
        "issued_by": str(payload.get("issued_by", "quark")),
    }


def _remote_testing_revoke_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "token_id": str(payload["token_id"]),
        "revoked_by": str(payload.get("revoked_by", "quark")),
        "reason": str(payload.get("reason", "test complete")),
    }


def _key_provider_args(payload: dict[str, Any]) -> dict[str, Any]:
    metadata = payload.get("metadata", {})
    if isinstance(metadata, str):
        metadata = json.loads(metadata) if metadata.strip() else {}
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be a JSON object")
    return {
        "provider_id": str(payload["provider_id"]),
        "display_name": str(payload["display_name"]),
        "provider_kind": str(payload["provider_kind"]),
        "secret_ref": str(payload["secret_ref"]),
        "allowed_subjects": tuple(_list_payload(payload.get("allowed_subjects"), ["*"])),
        "allowed_scopes": tuple(_list_payload(payload.get("allowed_scopes"), ["*"])),
        "enabled": bool(payload.get("enabled", True)),
        "metadata": metadata,
    }


def _key_broker_request_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider_id": str(payload["provider_id"]),
        "subject": str(payload["subject"]),
        "requested_scopes": tuple(_list_payload(payload.get("requested_scopes", payload.get("scopes")), [])),
        "requested_by": str(payload["requested_by"]),
        "justification": str(payload["justification"]),
        "ttl_minutes": int(payload.get("ttl_minutes", 15)),
    }


def _key_broker_approval_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "request_id": str(payload["request_id"]),
        "approved_by": str(payload["approved_by"]),
        "approval_id": str(payload["approval_id"]),
        "approved_at": str(payload["approved_at"]) if payload.get("approved_at") else None,
    }


def _key_broker_issue_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "request_id": str(payload["request_id"]),
        "issued_by": str(payload["issued_by"]),
    }


def _key_broker_revoke_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "grant_id": str(payload["grant_id"]),
        "revoked_by": str(payload["revoked_by"]),
        "reason": str(payload.get("reason", "work complete")),
    }


def _remote_testing_lease_args(payload: dict[str, Any]) -> dict[str, Any]:
    job_types = payload.get("job_types", ["ping"])
    if isinstance(job_types, str):
        job_types = [item.strip() for item in job_types.split(",") if item.strip()]
    if not isinstance(job_types, list):
        raise ValueError("job_types must be a list or comma-separated string")
    return {
        "lease_id": str(payload["lease_id"]),
        "project": str(payload.get("project", "Overseer")),
        "purpose": str(payload["purpose"]),
        "requested_by": str(payload.get("requested_by", "quark")),
        "job_types": tuple(str(item) for item in job_types),
        "ttl_minutes": int(payload.get("ttl_minutes", 120)),
        "priority": str(payload.get("priority", "normal")),
        "profile_id": str(payload.get("profile_id", "remote-testing.tank-msi")),
    }


def _remote_testing_job_args(payload: dict[str, Any]) -> dict[str, Any]:
    params = payload.get("params", {})
    if isinstance(params, str):
        params = json.loads(params) if params.strip() else {}
    if not isinstance(params, dict):
        raise ValueError("params must be a JSON object")
    return {
        "lease_id": str(payload["lease_id"]),
        "job_type": str(payload["job_type"]),
        "requested_by": str(payload.get("requested_by", "quark")),
        "project": str(payload.get("project", "Overseer")),
        "params": params,
        "base_url": str(payload.get("base_url", "http://127.0.0.1:8766")),
        "ui_path": str(payload.get("ui_path", "/Overseer/ui")),
        "gateway_path": str(payload.get("gateway_path", "/Overseer")),
        "token_source": str(payload.get("token_source", "state/api-token")),
        "auth_token_id": str(payload["auth_token_id"]) if payload.get("auth_token_id") else None,
        "mutates": bool(payload.get("mutates", False)),
    }


def _remote_testing_results_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "lease_id": str(payload["lease_id"]) if payload.get("lease_id") else None,
        "job_id": str(payload["job_id"]) if payload.get("job_id") else None,
    }


def _codex_project_discovery_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "registry_path": str(payload.get("codex_projects_registry", "/home/god/.codex/codex-projects.csv")),
    }


def _required_agent_string(payload: dict[str, Any], name: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} is required")
    return value


def _agent_session_discovery_args(payload: dict[str, Any]) -> dict[str, Any]:
    _reject_unknown_agent_fields(
        payload,
        {"provider_id", "instance_id", "codex_projects_registry"},
        "agent session discovery",
    )
    return {
        "provider_id": _required_agent_string(payload, "provider_id"),
        "instance_id": _required_agent_string(payload, "instance_id"),
        "codex_projects_registry": (
            str(payload["codex_projects_registry"])
            if payload.get("codex_projects_registry")
            else None
        ),
    }


def _agent_dispatch_args(payload: dict[str, Any]) -> dict[str, Any]:
    _reject_unknown_agent_fields(
        payload,
        {"instance_id", "prompt", "idempotency_key", "requested_by"},
        "agent dispatch",
    )
    return {
        "instance_id": _required_agent_string(payload, "instance_id"),
        "prompt": _required_agent_string(payload, "prompt"),
        "idempotency_key": _required_agent_string(payload, "idempotency_key"),
        "requested_by": (
            str(payload["requested_by"]) if payload.get("requested_by") else None
        ),
    }


def _agent_checkpoint_args(payload: dict[str, Any]) -> dict[str, Any]:
    _reject_unknown_agent_fields(payload, {"instance_id"}, "agent checkpoint")
    return {"instance_id": _required_agent_string(payload, "instance_id")}


def _agent_recovery_args(payload: dict[str, Any]) -> dict[str, Any]:
    _reject_unknown_agent_fields(
        payload, {"session_id", "initiated_by"}, "agent recovery"
    )
    return {
        "session_id": _required_agent_string(payload, "session_id"),
        "initiated_by": _required_agent_string(payload, "initiated_by"),
    }


def _agent_handoff_args(payload: dict[str, Any]) -> dict[str, Any]:
    _reject_unknown_agent_fields(
        payload,
        {"instance_id", "incoming_provider_id", "initiated_by", "approval_id"},
        "agent handoff",
    )
    return {
        "instance_id": _required_agent_string(payload, "instance_id"),
        "incoming_provider_id": _required_agent_string(
            payload, "incoming_provider_id"
        ),
        "initiated_by": _required_agent_string(payload, "initiated_by"),
        "approval_id": _required_agent_string(payload, "approval_id"),
    }


def _reject_unknown_agent_fields(
    payload: dict[str, Any], allowed: set[str], route_name: str
) -> None:
    unknown = set(payload) - allowed
    if unknown:
        raise ValueError(f"unknown {route_name} fields: {sorted(unknown)}")


def _agent_failover_evaluation_args(payload: dict[str, Any]) -> dict[str, Any]:
    unknown = set(payload) - {"instance_id", "policy_id"}
    if unknown:
        raise ValueError(f"unknown failover evaluation fields: {sorted(unknown)}")
    return {
        "instance_id": _required_agent_string(payload, "instance_id"),
        "policy_id": (
            _required_agent_string(payload, "policy_id")
            if payload.get("policy_id") is not None
            else None
        ),
    }


def _agent_failover_execution_args(payload: dict[str, Any]) -> dict[str, Any]:
    unknown = set(payload) - {
        "instance_id", "decision_id", "initiated_by", "approval_id"
    }
    if unknown:
        raise ValueError(f"unknown failover execution fields: {sorted(unknown)}")
    return {
        "instance_id": _required_agent_string(payload, "instance_id"),
        "decision_id": _required_agent_string(payload, "decision_id"),
        "initiated_by": _required_agent_string(payload, "initiated_by"),
        "approval_id": _required_agent_string(payload, "approval_id"),
    }


def _agent_failover_recovery_args(payload: dict[str, Any]) -> dict[str, Any]:
    unknown = set(payload) - {"execution_id", "initiated_by", "approval_id"}
    if unknown:
        raise ValueError(f"unknown failover recovery fields: {sorted(unknown)}")
    return {
        "execution_id": _required_agent_string(payload, "execution_id"),
        "initiated_by": _required_agent_string(payload, "initiated_by"),
        "approval_id": _required_agent_string(payload, "approval_id"),
    }


def _legacy_codex_discovery_status(
    store_path: str,
    payload: dict[str, Any],
) -> dict[str, object]:
    selected_registry = _codex_project_discovery_args(payload)["registry_path"]
    result = discover_agent_sessions_status(
        store_path,
        provider_id="codex",
        instance_id="overseer.default",
        codex_projects_registry=selected_registry,
        legacy_compatibility=True,
    )
    return {
        "store": str(Path(store_path)),
        "registry": selected_registry,
        "threads": result["threads"],
        "resources": result["resources"],
        "items": result["items"],
        "mutation_performed": result["mutation_performed"],
        "host_mutation_performed": result["host_mutation_performed"],
        "next_step": (
            "review imported codex-project thread resources before scheduling "
            "continuation work"
        ),
    }


def _approve_claim_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "approval_id": str(payload["approval_id"]),
        "decided_by": str(payload["decided_by"]),
        "decided_at": str(payload["decided_at"]) if payload.get("decided_at") else None,
    }


def _activate_claim_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "claim_id": str(payload["claim_id"]),
        "approval_id": str(payload["approval_id"]) if payload.get("approval_id") else None,
    }


def _release_claim_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "claim_id": str(payload["claim_id"]),
        "released_by": str(payload["released_by"]) if payload.get("released_by") else None,
        "reason": str(payload["reason"]) if payload.get("reason") else None,
        "evidence_ids": tuple(str(evidence_id) for evidence_id in payload.get("evidence_ids", ())),
        "released_at": str(payload["released_at"]) if payload.get("released_at") else None,
    }


def _claim_cleanup_request_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "claim_id": str(payload["claim_id"]),
        "requested_by": str(payload["requested_by"]),
        "requested_at": str(payload["requested_at"]) if payload.get("requested_at") is not None else None,
        "now": str(payload["now"]) if payload.get("now") is not None else None,
    }


def _physical_storage_discovery_args(store_path: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "sysfs_block_root": str(payload.get("sysfs_block_root", "/sys/class/block")),
        "store_path": store_path,
    }


def _physical_discovery_args(store_path: str, payload: dict[str, Any]) -> dict[str, Any]:
    roots = payload.get("roots", ("/dev/serial/by-id", "/dev/serial/by-path"))
    if isinstance(roots, str):
        roots = (roots,)
    return {
        "roots": tuple(str(root) for root in roots),
        "store_path": store_path,
    }


def _backup_job_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "job_id": str(payload["job_id"]),
        "target": str(payload["target"]),
        "schedule": str(payload.get("schedule") or "manual"),
        "retention": str(payload.get("retention") or "operator-defined"),
        "requested_by": str(payload.get("requested_by") or "kira"),
        "risk_level": str(payload.get("risk_level") or "medium"),
        "status": str(payload.get("status") or "staged"),
        "notes": str(payload.get("notes") or ""),
    }


def _restore_test_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "test_id": str(payload["test_id"]),
        "job_id": str(payload["job_id"]),
        "restore_point": str(payload["restore_point"]),
        "status": str(payload.get("status") or "planned"),
        "validated_by": str(payload.get("validated_by") or "kira"),
        "notes": str(payload.get("notes") or ""),
    }


def _backup_cleanup_request_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": str(payload["path"]),
        "requested_by": str(payload.get("requested_by") or "kira"),
        "reason": str(payload.get("reason") or "review generated storage cleanup candidate"),
    }


def _backup_execution_request_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_path": str(payload["source_path"]),
        "requested_by": str(payload.get("requested_by") or "kira"),
        "reason": str(payload.get("reason") or "stage approved local backup execution"),
        "backup_name": str(payload["backup_name"]) if payload.get("backup_name") else None,
    }


def _backup_execution_approval_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "request_id": str(payload["request_id"]),
        "approved_by": str(payload.get("approved_by") or "kira"),
        "approved_at": str(payload["approved_at"]) if payload.get("approved_at") else None,
    }


def _backup_execution_execute_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "request_id": str(payload["request_id"]),
        "executed_by": str(payload.get("executed_by") or "kira"),
        "executed_at": str(payload["executed_at"]) if payload.get("executed_at") else None,
    }


def _restore_execution_request_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "backup_path": str(payload["backup_path"]),
        "restore_target": str(payload["restore_target"]),
        "requested_by": str(payload.get("requested_by") or "kira"),
        "reason": str(payload.get("reason") or "stage approved local restore execution"),
    }


def _restore_execution_approval_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "request_id": str(payload["request_id"]),
        "approved_by": str(payload.get("approved_by") or "kira"),
        "approved_at": str(payload["approved_at"]) if payload.get("approved_at") else None,
    }


def _restore_execution_execute_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "request_id": str(payload["request_id"]),
        "executed_by": str(payload.get("executed_by") or "kira"),
        "executed_at": str(payload["executed_at"]) if payload.get("executed_at") else None,
    }


def _backup_cleanup_approval_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "request_id": str(payload["request_id"]),
        "approved_by": str(payload.get("approved_by") or "kira"),
        "approved_at": str(payload["approved_at"]) if payload.get("approved_at") else None,
    }


def _backup_cleanup_execution_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "request_id": str(payload["request_id"]),
        "executed_by": str(payload.get("executed_by") or "kira"),
        "executed_at": str(payload["executed_at"]) if payload.get("executed_at") else None,
    }


def _virtual_runtime_record_args(payload: dict[str, Any]) -> dict[str, Any]:
    ports = payload.get("ports") or ()
    if isinstance(ports, str):
        ports = [item.strip() for item in ports.split(",") if item.strip()]
    return {
        "resource_id": str(payload["resource_id"]),
        "kind": str(payload.get("kind") or "vm"),
        "state": str(payload.get("state") or "observed"),
        "adapter": str(payload.get("adapter") or "manual"),
        "ports": tuple(int(port) for port in ports),
        "snapshot_hint": str(payload.get("snapshot_hint") or ""),
        "notes": str(payload.get("notes") or ""),
    }


def _virtual_target_setup_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "requested_by": str(payload.get("requested_by") or "dax"),
        "scope": str(payload.get("scope") or "all"),
        "reason": str(payload.get("reason") or "prepare approved disposable real-provider targets for Dax lifecycle development"),
    }


def _virtual_target_setup_result_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider": str(payload["provider"]),
        "status": str(payload["status"]),
        "executed_by": str(payload.get("executed_by") or "dax"),
        "evidence": str(payload.get("evidence") or ""),
        "next_step": str(payload.get("next_step") or ""),
        "executed_at": str(payload["executed_at"]) if payload.get("executed_at") is not None else None,
    }


def _virtual_target_setup_execute_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider": str(payload["provider"]),
        "executed_by": str(payload.get("executed_by") or "dax"),
        "approved_by": str(payload["approved_by"]),
        "executed_at": str(payload["executed_at"]) if payload.get("executed_at") is not None else None,
    }


def _virtual_snapshot_request_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "resource_id": str(payload["resource_id"]),
        "requested_by": str(payload.get("requested_by") or "dax"),
        "reason": str(payload.get("reason") or "stage virtual snapshot before maintenance"),
        "snapshot_name": str(payload.get("snapshot_name") or ""),
    }


def _virtual_restore_request_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "resource_id": str(payload["resource_id"]),
        "restore_point": str(payload["restore_point"]),
        "requested_by": str(payload.get("requested_by") or "dax"),
        "reason": str(payload.get("reason") or "stage virtual restore after failed change"),
    }


def _virtual_destroy_request_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "resource_id": str(payload["resource_id"]),
        "requested_by": str(payload.get("requested_by") or "dax"),
        "reason": str(payload.get("reason") or "stage virtual destroy after disposable target is no longer needed"),
    }


def _virtual_lifecycle_execution_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "resource_id": str(payload["resource_id"]),
        "action": str(payload["action"]),
        "executed_by": str(payload.get("executed_by") or "dax"),
        "provider": str(payload.get("provider") or ""),
        "executed_at": str(payload["executed_at"]) if payload.get("executed_at") is not None else None,
    }


def _virtual_approval_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "request_id": str(payload["request_id"]),
        "approved_by": str(payload.get("approved_by") or "sisko"),
        "approved_at": str(payload["approved_at"]) if payload.get("approved_at") is not None else None,
    }


def _virtual_execution_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "request_id": str(payload["request_id"]),
        "executed_by": str(payload.get("executed_by") or "dax"),
        "provider": str(payload.get("provider") or "local_fixture"),
        "executed_at": str(payload["executed_at"]) if payload.get("executed_at") is not None else None,
    }


def _image_scan_request_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "image": str(payload["image"]),
        "provider": str(payload.get("provider") or "docker"),
        "scanner": str(payload.get("scanner") or "trivy"),
        "requested_by": str(payload.get("requested_by") or "dax"),
        "reason": str(payload.get("reason") or "scan container image before production use"),
    }


def _image_scan_approval_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "request_id": str(payload["request_id"]),
        "approved_by": str(payload.get("approved_by") or "sisko"),
        "approved_at": str(payload["approved_at"]) if payload.get("approved_at") is not None else None,
    }


def _image_scan_execution_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "request_id": str(payload["request_id"]),
        "executed_by": str(payload.get("executed_by") or "dax"),
        "executed_at": str(payload["executed_at"]) if payload.get("executed_at") is not None else None,
    }


def _stored_health_probe_args(payload: dict[str, Any]) -> dict[str, Any]:
    args: dict[str, Any] = {}
    if "timeout_seconds" in payload:
        args["timeout_seconds"] = float(payload["timeout_seconds"])
    if "retention_per_target" in payload:
        args["health_evidence_retention_per_target"] = int(payload["retention_per_target"])
    return args


def _health_target_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "target_id": str(payload["target_id"]),
        "resource_id": str(payload["resource_id"]),
        "name": str(payload["name"]),
        "probe_type": str(payload["probe_type"]),
        "target": str(payload["target"]),
        "owner_domain": str(payload.get("owner_domain", "julian")),
        "expected_status": int(payload["expected_status"]) if payload.get("expected_status") is not None else None,
        "expected_content_type": str(payload["expected_content_type"]) if payload.get("expected_content_type") else None,
        "latency_warn_ms": int(payload["latency_warn_ms"]) if payload.get("latency_warn_ms") is not None else None,
        "enabled": bool(payload.get("enabled", True)),
        "suspension_reason": str(payload.get("suspension_reason") or ""),
    }


def _journal_access_request_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "resource_id": str(payload["resource_id"]),
        "unit": str(payload.get("unit") or ""),
        "requested_by": str(payload.get("requested_by") or "julian"),
        "reason": str(payload.get("reason") or "system journal access needed for service diagnosis"),
    }


def _journal_access_execution_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_id": str(payload["record_id"]),
        "executed_by": str(payload.get("executed_by") or "julian"),
        "line_limit": int(payload.get("line_limit") or 50),
        "since": str(payload.get("since") or "24 hours ago"),
        "executed_at": str(payload["executed_at"]) if payload.get("executed_at") is not None else None,
    }


def _metric_history_capture_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "snapshot_id": str(payload.get("snapshot_id") or ""),
        "requested_by": str(payload.get("requested_by") or "julian"),
        "notes": str(payload.get("notes") or ""),
        "max_snapshots": int(payload.get("max_snapshots") or 250),
    }


def _storage_growth_capture_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "snapshot_id": str(payload.get("snapshot_id") or ""),
        "requested_by": str(payload.get("requested_by") or "kira"),
        "notes": str(payload.get("notes") or ""),
        "max_snapshots": int(payload.get("max_snapshots") or 250),
    }


def _approve_claim_cleanup_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "approval_id": str(payload["approval_id"]),
        "approved_by": str(payload["approved_by"]),
        "approved_at": str(payload["approved_at"]) if payload.get("approved_at") is not None else None,
        "now": str(payload["now"]) if payload.get("now") is not None else None,
    }


def _execute_claim_cleanup_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "approval_id": str(payload["approval_id"]),
        "executed_by": str(payload["executed_by"]),
        "executed_at": str(payload["executed_at"]) if payload.get("executed_at") is not None else None,
        "now": str(payload["now"]) if payload.get("now") is not None else None,
    }


def _admin_plan_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "plan_id": str(payload["plan_id"]),
        "kind": str(payload["kind"]),
        "target": str(payload["target"]),
        "reason": str(payload["reason"]),
        "current_state": str(payload.get("current_state", "unknown")),
        "packages": tuple(str(package) for package in payload.get("packages", ())),
        "port": int(payload["port"]) if payload.get("port") is not None else None,
        "compose_project_directory": str(payload["compose_project_directory"]) if payload.get("compose_project_directory") else None,
        "compose_env": tuple(str(item) for item in payload.get("compose_env", ())),
        "compose_rollback_env": tuple(str(item) for item in payload.get("compose_rollback_env", ())),
        "compose_extra_file": tuple(str(item) for item in payload.get("compose_extra_file", ())),
        "compose_scan_image": tuple(str(item) for item in payload.get("compose_scan_image", ())),
        "compose_residual_scan_finding": tuple(str(item) for item in payload.get("compose_residual_scan_finding", ())),
        "health_url": str(payload["health_url"]) if payload.get("health_url") else None,
        "backup_label": str(payload["backup_label"]) if payload.get("backup_label") else None,
        "use_firewalld": bool(payload.get("use_firewalld", False)),
        "mount_path": str(payload["mount_path"]) if payload.get("mount_path") else None,
        "credential_file": str(payload["credential_file"]) if payload.get("credential_file") else None,
        "filesystem_type": str(payload.get("filesystem_type", "cifs")),
    }


def _archive_admin_history_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "archived_by": str(payload["archived_by"]),
        "approval_id": str(payload["approval_id"]),
        "archived_at": str(payload["archived_at"]) if payload.get("archived_at") is not None else None,
        "plan_id": str(payload["plan_id"]) if payload.get("plan_id") is not None else None,
    }


def _admin_history_archive_request_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "requested_by": str(payload["requested_by"]),
        "requested_at": str(payload["requested_at"]) if payload.get("requested_at") is not None else None,
        "plan_id": str(payload["plan_id"]) if payload.get("plan_id") is not None else None,
    }


def _approve_admin_history_archive_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "approval_id": str(payload["approval_id"]),
        "approved_by": str(payload["approved_by"]),
        "approved_at": str(payload["approved_at"]) if payload.get("approved_at") is not None else None,
    }


def _unarchive_admin_history_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "plan_id": str(payload["plan_id"]),
        "restored_by": str(payload["restored_by"]),
        "approval_id": str(payload["approval_id"]),
        "restored_at": str(payload["restored_at"]) if payload.get("restored_at") is not None else None,
    }


def _admin_history_restore_request_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "plan_id": str(payload["plan_id"]),
        "requested_by": str(payload["requested_by"]),
        "requested_at": str(payload["requested_at"]) if payload.get("requested_at") is not None else None,
    }


def _approve_admin_history_restore_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "approval_id": str(payload["approval_id"]),
        "approved_by": str(payload["approved_by"]),
        "approved_at": str(payload["approved_at"]) if payload.get("approved_at") is not None else None,
    }


def _admin_adapter_enablement_request_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": str(payload["kind"]),
        "requested_by": str(payload["requested_by"]),
        "requested_at": str(payload["requested_at"]) if payload.get("requested_at") is not None else None,
    }


def _approve_admin_adapter_enablement_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "approval_id": str(payload["approval_id"]),
        "approved_by": str(payload["approved_by"]),
        "approved_at": str(payload["approved_at"]) if payload.get("approved_at") is not None else None,
    }


def _admin_policy_warning_request_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "plan_id": str(payload["plan_id"]),
        "check_id": str(payload["check_id"]),
        "requested_by": str(payload["requested_by"]),
        "requested_at": str(payload["requested_at"]) if payload.get("requested_at") is not None else None,
    }


def _build_policy_profile_api_status(payload: dict[str, Any]) -> dict[str, object]:
    from .policy import policy_profile_from_answers_status

    answers = payload.get("answers", payload)
    if not isinstance(answers, dict):
        raise ValueError("policy answers must be a JSON object")
    return policy_profile_from_answers_status(answers)


def _approve_admin_policy_warning_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "approval_id": str(payload["approval_id"]),
        "approved_by": str(payload["approved_by"]),
        "approved_at": str(payload["approved_at"]) if payload.get("approved_at") is not None else None,
    }


def _daemon_migration_request_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "service_name": str(payload.get("service_name", "overseer")),
        "requested_by": str(payload["requested_by"]),
        "requested_at": str(payload["requested_at"]) if payload.get("requested_at") is not None else None,
    }


def _approve_daemon_migration_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "approval_id": str(payload["approval_id"]),
        "approved_by": str(payload["approved_by"]),
        "approved_at": str(payload["approved_at"]) if payload.get("approved_at") is not None else None,
    }


def _host_security_remediation_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "listener": str(payload["listener"]),
        "plan_id": str(payload["plan_id"]) if payload.get("plan_id") else None,
        "action": str(payload.get("action", "deny_tcp")),
        "reason": str(payload["reason"]) if payload.get("reason") else None,
        "snapshot_id": str(payload["snapshot_id"]) if payload.get("snapshot_id") else None,
    }


def _host_security_listener_queue_remediations_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "snapshot_id": str(payload["snapshot_id"]) if payload.get("snapshot_id") else None,
        "requested_by": str(payload.get("requested_by", "odo")),
        "plan_prefix": str(payload.get("plan_prefix", "admin.host-security.deny-tcp")),
    }


def _advance_odo_security_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "snapshot_id": str(payload["snapshot_id"]) if payload.get("snapshot_id") else None,
        "requested_by": str(payload.get("requested_by", "odo")),
        "advanced_at": str(payload["advanced_at"]) if payload.get("advanced_at") else None,
    }


def _host_security_source_review_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "remote_address": str(payload["remote_address"]),
        "listener": str(payload["listener"]) if payload.get("listener") else None,
        "review_id": str(payload["review_id"]) if payload.get("review_id") else None,
        "disposition": str(payload.get("disposition", "needs_review")),
        "rationale": str(payload.get("rationale", "pending Odo review")),
        "reviewed_by": str(payload["reviewed_by"]) if payload.get("reviewed_by") else None,
        "reviewed_at": str(payload["reviewed_at"]) if payload.get("reviewed_at") else None,
        "created_at": str(payload["created_at"]) if payload.get("created_at") else None,
        "snapshot_id": str(payload["snapshot_id"]) if payload.get("snapshot_id") else None,
    }


def _host_security_source_block_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "review_id": str(payload["review_id"]),
        "plan_id": str(payload["plan_id"]) if payload.get("plan_id") else None,
        "action": str(payload.get("action", "block_ip")),
        "reason": str(payload["reason"]) if payload.get("reason") else None,
    }


def _firewall_policy_enforcement_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "rule_index": int(payload["rule_index"]),
        "plan_id": str(payload["plan_id"]) if payload.get("plan_id") else None,
        "requested_by": str(payload.get("requested_by") or "odo"),
        "reason": str(payload["reason"]) if payload.get("reason") else None,
    }


def _firewall_execution_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "plan_id": str(payload["plan_id"]),
        "executed_by": str(payload.get("executed_by") or "odo"),
        "mode": str(payload.get("mode") or "local_fixture"),
        "executed_at": str(payload["executed_at"]) if payload.get("executed_at") is not None else None,
        "policy_profile_path": str(payload["policy_profile"]) if payload.get("policy_profile") else None,
    }


def _identity_rotation_request_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "subject": str(payload["subject"]),
        "subject_type": str(payload.get("subject_type") or "secret"),
        "requested_by": str(payload.get("requested_by") or "odo"),
        "reason": str(payload.get("reason") or "stage identity or secret rotation review"),
        "urgency": str(payload.get("urgency") or "medium"),
    }


def _identity_rotation_approval_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "request_id": str(payload["request_id"]),
        "approved_by": str(payload.get("approved_by") or "sisko"),
        "approved_at": str(payload["approved_at"]) if payload.get("approved_at") is not None else None,
    }


def _identity_rotation_execution_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "request_id": str(payload["request_id"]),
        "executed_by": str(payload.get("executed_by") or "odo"),
        "mode": str(payload.get("mode") or "local_fixture"),
        "executed_at": str(payload["executed_at"]) if payload.get("executed_at") is not None else None,
    }


def _host_security_ids_review_package_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "plan_id": str(payload["plan_id"]),
        "package_id": str(payload["package_id"]) if payload.get("package_id") else None,
        "source_review_id": str(payload["source_review_id"]) if payload.get("source_review_id") else None,
        "requested_by": str(payload.get("requested_by", "odo")),
        "created_at": str(payload["created_at"]) if payload.get("created_at") else None,
    }


def _submit_host_security_ids_review_package_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "package_id": str(payload["package_id"]),
        "submitted_by": str(payload["submitted_by"]),
        "submitted_at": str(payload["submitted_at"]) if payload.get("submitted_at") else None,
        "prompt_path": str(payload["prompt_path"]) if payload.get("prompt_path") else None,
    }


def _query_first(query: dict[str, list[str]], key: str) -> str | None:
    values = query.get(key)
    return values[0] if values else None


def _query_values(query: dict[str, list[str]], key: str) -> tuple[str, ...]:
    return tuple(query.get(key, ()))


def _export_host_security_ids_review_prompt_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "package_id": str(payload["package_id"]),
        "output_dir": str(payload["output_dir"]) if payload.get("output_dir") else "advisories",
        "filename": str(payload["filename"]) if payload.get("filename") else None,
    }


def _dispatch_host_security_ids_review_package_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "package_id": str(payload["package_id"]),
        "dispatched_by": str(payload["dispatched_by"]),
        "dispatched_at": str(payload["dispatched_at"]) if payload.get("dispatched_at") else None,
        "owner_thread": str(payload["owner_thread"]) if payload.get("owner_thread") else None,
        "output_dir": str(payload["output_dir"]) if payload.get("output_dir") else "advisories",
        "filename": str(payload["filename"]) if payload.get("filename") else None,
        "codex_projects_registry": str(payload["codex_projects_registry"])
        if payload.get("codex_projects_registry")
        else None,
    }


def _host_security_ids_review_result_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "package_id": str(payload["package_id"]),
        "status": str(payload["status"]),
        "advisory_result": str(payload["advisory_result"]),
        "reviewed_by": str(payload["reviewed_by"]),
        "reviewed_at": str(payload["reviewed_at"]) if payload.get("reviewed_at") else None,
    }


def _package_update_plan_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "captured_at": str(payload["captured_at"]) if payload.get("captured_at") else None,
        "packages": tuple(str(package) for package in payload.get("packages", ())),
    }


def _firmware_update_plan_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "captured_at": str(payload["captured_at"]) if payload.get("captured_at") else None,
        "release_ids": tuple(str(release_id) for release_id in payload.get("release_ids", ())),
    }


def _package_maintenance_cycle_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "captured_at": str(payload["captured_at"]) if payload.get("captured_at") else None,
        "packages": tuple(str(package) for package in payload.get("packages", ())),
        "auto_enable_adapters": bool(payload.get("auto_enable_adapters", True)),
    }


def _approve_admin_plan_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "plan_id": str(payload["plan_id"]),
        "approved_by": str(payload["approved_by"]),
        "approved_at": str(payload["approved_at"]) if payload.get("approved_at") else None,
    }


def _cancel_admin_plan_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "plan_id": str(payload["plan_id"]),
        "canceled_by": str(payload["canceled_by"]),
        "cancellation_reason": str(payload["cancellation_reason"]),
        "canceled_at": str(payload["canceled_at"]) if payload.get("canceled_at") else None,
    }
