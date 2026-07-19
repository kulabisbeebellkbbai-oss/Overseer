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
    admin_adapter_capabilities_status,
    admin_adapter_enablement_plan_status,
    admin_executions_status,
    admin_execution_readiness_status,
    admin_history_archive_plan_status,
    admin_history_archives_status,
    admin_history_review_status,
    admin_history_restore_readiness_status,
    admin_summary_status,
    archive_admin_history_status,
    assess_host_security_status,
    approve_admin_change_status,
    approve_admin_adapter_enablement_status,
    approve_admin_history_restore_status,
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
    daemon_migration_plan_status,
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
    list_state_status,
    maintenance_summary_status,
    operator_dashboard_status,
    plan_host_security_source_block_status,
    plan_host_security_remediation_status,
    physical_summary_status,
    plan_admin_change_status,
    record_host_security_ids_review_result_status,
    release_claim_status,
    request_admin_adapter_enablement_status,
    request_admin_history_restore_status,
    request_daemon_migration_status,
    request_usage_continuation_status,
    prepare_host_security_ids_review_package_status,
    persistence_security_status,
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
                self._handle(admin_adapter_capabilities_status)
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
            if self.path == "/host/security/ids-review-packages/results":
                self._handle_json(lambda payload: record_host_security_ids_review_result_status(store_path, **_host_security_ids_review_result_args(payload)))
                return
            if self.path == "/admin/plans":
                self._handle_json(lambda payload: plan_admin_change_status(store_path, **_admin_plan_args(payload)))
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
            if self.path == "/runtime/daemon-migration-requests":
                self._handle_json(lambda payload: request_daemon_migration_status(store_path, **_daemon_migration_request_args(payload)))
                return
            if self.path == "/runtime/daemon-migration-requests/approve":
                self._handle_json(lambda payload: approve_daemon_migration_status(store_path, **_approve_daemon_migration_args(payload)))
                return
            if self.path == "/usage/continuation-requests":
                self._handle_json(lambda payload: request_usage_continuation_status(store_path, **_usage_continuation_request_args(payload)))
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
        "archived_at": str(payload["archived_at"]) if payload.get("archived_at") is not None else None,
        "plan_id": str(payload["plan_id"]) if payload.get("plan_id") is not None else None,
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


def _host_security_ids_review_result_args(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "package_id": str(payload["package_id"]),
        "status": str(payload["status"]),
        "advisory_result": str(payload["advisory_result"]),
        "reviewed_by": str(payload["reviewed_by"]),
        "reviewed_at": str(payload["reviewed_at"]) if payload.get("reviewed_at") else None,
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
