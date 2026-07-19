"""Loopback HTTP API for local Overseer coordination."""

from __future__ import annotations

import json
import secrets
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .cli import (
    activate_claim_status,
    active_policy_profile_status,
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
    discover_codex_project_threads_status,
    dispatch_usage_continuations_status,
    dispatch_host_security_ids_review_package_status,
    daemon_migration_plan_status,
    discover_physical_status,
    discover_user_services_status,
    discover_storage_status,
    discover_virtual_listeners_status,
    execute_admin_change_status,
    execute_claim_cleanup_status,
    export_host_security_ids_review_prompt_status,
    export_state_redacted_status,
    health_efficiency_summary_status,
    health_summary_status,
    host_security_findings_status,
    host_security_ids_review_packages_status,
    host_security_ids_review_summary_status,
    host_security_sources_status,
    host_security_source_reviews_status,
    host_security_triage_status,
    inspect_host_status,
    inspect_packages_status,
    list_state_status,
    maintenance_summary_status,
    operator_dashboard_status,
    plan_host_security_source_block_status,
    plan_host_security_remediation_status,
    physical_summary_status,
    plan_admin_change_status,
    plan_package_updates_status,
    policy_customization_helper_cli_status,
    probe_stored_health_status,
    record_resource_status,
    record_health_target_status,
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
    service_status,
    runtime_status,
    security_summary_status,
    usage_continuation_plan_status,
    usage_summary_status,
    submit_host_security_ids_review_package_status,
    unarchive_admin_history_status,
    virtual_summary_status,
)
from .ui import OPERATOR_CONSOLE_HTML

LOOPBACK_HOSTS = {"127.0.0.1", "localhost"}


def make_api_handler(store_path: str, auth_token: str | None = None):
    class OverseerApiHandler(BaseHTTPRequestHandler):
        server_version = "OverseerApi/0.1"

        def do_GET(self) -> None:
            route = urlsplit(self.path)
            path = route.path
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
            if not self._is_authorized():
                self._write_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
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
                self._handle(lambda: operator_dashboard_status(store_path))
                return
            if path == "/maintenance-summary":
                self._handle(lambda: maintenance_summary_status(store_path))
                return
            if path == "/maintenance/package-status":
                self._handle(lambda: inspect_packages_status())
                return
            if path == "/health-summary":
                self._handle(lambda: health_summary_status(store_path))
                return
            if path == "/health-efficiency":
                self._handle(lambda: health_efficiency_summary_status(store_path))
                return
            if path == "/usage-summary":
                self._handle(lambda: usage_summary_status(store_path))
                return
            if path == "/usage/continuation-plan":
                self._handle(lambda: usage_continuation_plan_status(store_path))
                return
            if path == "/physical-summary":
                self._handle(lambda: physical_summary_status(store_path))
                return
            if path == "/virtual-summary":
                self._handle(lambda: virtual_summary_status(store_path))
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
            if path == "/host/security":
                self._handle(lambda: assess_host_security_status(store_path))
                return
            if path == "/host/security/findings":
                self._handle(lambda: host_security_findings_status(store_path))
                return
            if path == "/host/security/triage":
                self._handle(lambda: host_security_triage_status(store_path))
                return
            if path == "/host/security/sources":
                self._handle(lambda: host_security_sources_status(store_path))
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
            if not self._is_authorized():
                self._write_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
            if self.path == "/claims/request":
                self._handle_json(lambda payload: request_claim_status(store_path, **_request_claim_args(payload)))
                return
            if self.path == "/resources":
                self._handle_json(lambda payload: record_resource_status(store_path, **_resource_args(payload)))
                return
            if self.path == "/claims/approve":
                self._handle_json(lambda payload: approve_claim_status(store_path, **_approve_claim_args(payload)))
                return
            if self.path == "/claims/activate":
                self._handle_json(lambda payload: activate_claim_status(store_path, **_activate_claim_args(payload)))
                return
            if self.path == "/claims/release":
                self._handle_json(lambda payload: release_claim_status(store_path, **_release_claim_args(payload)))
                return
            if self.path == "/claims/cleanup-requests":
                self._handle_json(lambda payload: request_claim_cleanup_status(store_path, **_claim_cleanup_request_args(payload)))
                return
            if self.path == "/claims/cleanup-requests/approve":
                self._handle_json(lambda payload: approve_claim_cleanup_status(store_path, **_approve_claim_cleanup_args(payload)))
                return
            if self.path == "/claims/cleanup-requests/execute":
                self._handle_json(lambda payload: execute_claim_cleanup_status(store_path, **_execute_claim_cleanup_args(payload)))
                return
            if self.path == "/host/inspect":
                self._handle(lambda: inspect_host_status(store_path))
                return
            if self.path == "/services/discover-user":
                self._handle(lambda: discover_user_services_status(store_path))
                return
            if self.path == "/physical/discover":
                self._handle_json(lambda payload: discover_physical_status(**_physical_discovery_args(store_path, payload)))
                return
            if self.path == "/health/probes/run":
                self._handle_json(lambda payload: probe_stored_health_status(store_path, **_stored_health_probe_args(payload)))
                return
            if self.path == "/health-targets":
                self._handle_json(lambda payload: record_health_target_status(store_path, **_health_target_args(payload)))
                return
            if self.path == "/physical/discover-storage":
                self._handle_json(lambda payload: discover_storage_status(**_physical_storage_discovery_args(store_path, payload)))
                return
            if self.path == "/virtual/discover-listeners":
                self._handle(lambda: discover_virtual_listeners_status(store_path))
                return
            if self.path == "/host/security/remediations/plans":
                self._handle_json(lambda payload: plan_host_security_remediation_status(store_path, **_host_security_remediation_args(payload)))
                return
            if self.path == "/host/security/source-reviews/block-plans":
                self._handle_json(lambda payload: plan_host_security_source_block_status(store_path, **_host_security_source_block_args(payload)))
                return
            if self.path == "/host/security/source-reviews":
                self._handle_json(lambda payload: create_host_security_source_review_status(store_path, **_host_security_source_review_args(payload)))
                return
            if self.path == "/host/security/ids-review-packages":
                self._handle_json(lambda payload: prepare_host_security_ids_review_package_status(store_path, **_host_security_ids_review_package_args(payload)))
                return
            if self.path == "/host/security/ids-review-packages/submit":
                self._handle_json(lambda payload: submit_host_security_ids_review_package_status(store_path, **_submit_host_security_ids_review_package_args(payload)))
                return
            if self.path == "/host/security/ids-review-packages/prompts":
                self._handle_json(lambda payload: export_host_security_ids_review_prompt_status(store_path, **_export_host_security_ids_review_prompt_args(payload)))
                return
            if self.path == "/host/security/ids-review-packages/dispatch":
                self._handle_json(lambda payload: dispatch_host_security_ids_review_package_status(store_path, **_dispatch_host_security_ids_review_package_args(payload)))
                return
            if self.path == "/host/security/ids-review-packages/results":
                self._handle_json(lambda payload: record_host_security_ids_review_result_status(store_path, **_host_security_ids_review_result_args(payload)))
                return
            if self.path == "/admin/plans":
                self._handle_json(lambda payload: plan_admin_change_status(store_path, **_admin_plan_args(payload)))
                return
            if self.path == "/maintenance/package-update-plans":
                self._handle_json(lambda payload: plan_package_updates_status(store_path, **_package_update_plan_args(payload)))
                return
            if self.path == "/admin/approve":
                self._handle_json(lambda payload: approve_admin_change_status(store_path, **_approve_admin_plan_args(payload)))
                return
            if self.path == "/admin/cancel":
                self._handle_json(lambda payload: cancel_admin_change_status(store_path, **_cancel_admin_plan_args(payload)))
                return
            if self.path == "/admin/execute":
                self._handle_admin_execute()
                return
            if self.path == "/admin/history-archive":
                self._handle_json(lambda payload: archive_admin_history_status(store_path, **_archive_admin_history_args(payload)))
                return
            if self.path == "/admin/history-archive-requests":
                self._handle_json(lambda payload: request_admin_history_archive_status(store_path, **_admin_history_archive_request_args(payload)))
                return
            if self.path == "/admin/history-archive-requests/approve":
                self._handle_json(lambda payload: approve_admin_history_archive_status(store_path, **_approve_admin_history_archive_args(payload)))
                return
            if self.path == "/admin/history-restore-requests":
                self._handle_json(lambda payload: request_admin_history_restore_status(store_path, **_admin_history_restore_request_args(payload)))
                return
            if self.path == "/admin/history-restore-requests/approve":
                self._handle_json(lambda payload: approve_admin_history_restore_status(store_path, **_approve_admin_history_restore_args(payload)))
                return
            if self.path == "/admin/adapter-enablement-requests":
                self._handle_json(lambda payload: request_admin_adapter_enablement_status(store_path, **_admin_adapter_enablement_request_args(payload)))
                return
            if self.path == "/admin/adapter-enablement-requests/approve":
                self._handle_json(lambda payload: approve_admin_adapter_enablement_status(store_path, **_approve_admin_adapter_enablement_args(payload)))
                return
            if self.path == "/admin/policy-warning-requests":
                self._handle_json(lambda payload: request_admin_policy_warning_status(store_path, **_admin_policy_warning_request_args(payload)))
                return
            if self.path == "/admin/policy-warning-requests/approve":
                self._handle_json(lambda payload: approve_admin_policy_warning_status(store_path, **_approve_admin_policy_warning_args(payload)))
                return
            if self.path == "/admin/policy-customization-helper/profile":
                self._handle_json(lambda payload: _build_policy_profile_api_status(payload))
                return
            if self.path == "/runtime/daemon-migration-requests":
                self._handle_json(lambda payload: request_daemon_migration_status(store_path, **_daemon_migration_request_args(payload)))
                return
            if self.path == "/runtime/daemon-migration-requests/approve":
                self._handle_json(lambda payload: approve_daemon_migration_status(store_path, **_approve_daemon_migration_args(payload)))
                return
            if self.path == "/usage/continuation-requests":
                self._handle_json(lambda payload: request_usage_continuation_status(store_path, **_usage_continuation_request_args(payload)))
                return
            if self.path == "/usage-limits":
                self._handle_json(lambda payload: record_usage_limit_status(store_path, **_usage_limit_args(payload)))
                return
            if self.path == "/usage/continuation-dispatches":
                self._handle_json(lambda payload: dispatch_usage_continuations_status(store_path, **_usage_continuation_dispatch_args(payload)))
                return
            if self.path == "/codex-projects/discover-threads":
                self._handle_json(lambda payload: discover_codex_project_threads_status(store_path, **_codex_project_discovery_args(payload)))
                return
            if self.path == "/admin/history-unarchive":
                self._handle_json(lambda payload: unarchive_admin_history_status(store_path, **_unarchive_admin_history_args(payload)))
                return
            self._write_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

        def log_message(self, format: str, *args: object) -> None:
            return

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

        def _handle_json(self, handler) -> None:
            try:
                payload = self._read_json()
                self._write_json(handler(payload))
            except KeyError as error:
                self._write_json({"error": f"missing field: {error.args[0]}"}, HTTPStatus.BAD_REQUEST)
            except ValueError as error:
                self._write_json({"error": str(error)}, HTTPStatus.BAD_REQUEST)

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

        def _write_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
            body = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(int(status))
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

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
        "owner_thread": str(payload["owner_thread"]),
        "requested_units": int(payload["requested_units"]),
        "intent": str(payload["intent"]),
        "risk_level": str(payload.get("risk_level", "low")),
        "earliest_start": str(payload["earliest_start"]) if payload.get("earliest_start") else None,
        "deadline": str(payload["deadline"]) if payload.get("deadline") else None,
        "requested_by": str(payload.get("requested_by", "quark")),
        "requested_at": str(payload["requested_at"]) if payload.get("requested_at") else None,
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


def _usage_continuation_dispatch_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "dispatched_by": str(payload.get("dispatched_by", "quark")),
        "dispatched_at": str(payload["dispatched_at"]) if payload.get("dispatched_at") else None,
        "resume_codex_projects": bool(payload.get("resume_codex_projects", False)),
        "codex_projects_registry": str(payload.get("codex_projects_registry", "/home/god/.codex/codex-projects.csv")),
    }


def _codex_project_discovery_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "registry_path": str(payload.get("codex_projects_registry", "/home/god/.codex/codex-projects.csv")),
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
