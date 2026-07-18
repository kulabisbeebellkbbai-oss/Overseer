"""Loopback HTTP API for local Overseer coordination."""

from __future__ import annotations

import json
import secrets
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .cli import (
    activate_claim_status,
    admin_executions_status,
    admin_summary_status,
    assess_host_security_status,
    approve_admin_change_status,
    approve_claim_status,
    alerts_summary_status,
    authorizations_required_status,
    cancel_admin_change_status,
    command_summary_status,
    execute_admin_change_status,
    health_efficiency_summary_status,
    health_summary_status,
    host_security_findings_status,
    inspect_host_status,
    list_state_status,
    maintenance_summary_status,
    operator_dashboard_status,
    physical_summary_status,
    plan_admin_change_status,
    release_claim_status,
    request_claim_status,
    service_status,
    runtime_status,
    security_summary_status,
    usage_summary_status,
    virtual_summary_status,
)

LOOPBACK_HOSTS = {"127.0.0.1", "localhost"}


def make_api_handler(store_path: str, auth_token: str | None = None):
    class OverseerApiHandler(BaseHTTPRequestHandler):
        server_version = "OverseerApi/0.1"

        def do_GET(self) -> None:
            if self.path == "/health":
                self._write_json({"ok": True, "service": "overseer-api"})
                return
            if not self._is_authorized():
                self._write_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
            if self.path == "/service-status":
                self._handle(lambda: service_status(store_path))
                return
            if self.path == "/runtime-status":
                self._handle(lambda: runtime_status(store_path))
                return
            if self.path == "/command-summary":
                self._handle(lambda: command_summary_status(store_path))
                return
            if self.path == "/operator-dashboard":
                self._handle(lambda: operator_dashboard_status(store_path))
                return
            if self.path == "/maintenance-summary":
                self._handle(lambda: maintenance_summary_status(store_path))
                return
            if self.path == "/health-summary":
                self._handle(lambda: health_summary_status(store_path))
                return
            if self.path == "/health-efficiency":
                self._handle(lambda: health_efficiency_summary_status(store_path))
                return
            if self.path == "/usage-summary":
                self._handle(lambda: usage_summary_status(store_path))
                return
            if self.path == "/physical-summary":
                self._handle(lambda: physical_summary_status(store_path))
                return
            if self.path == "/virtual-summary":
                self._handle(lambda: virtual_summary_status(store_path))
                return
            if self.path == "/alerts-summary":
                self._handle(lambda: alerts_summary_status(store_path))
                return
            if self.path == "/security-summary":
                self._handle(lambda: security_summary_status(store_path))
                return
            if self.path == "/host/security":
                self._handle(lambda: assess_host_security_status(store_path))
                return
            if self.path == "/host/security/findings":
                self._handle(lambda: host_security_findings_status(store_path))
                return
            if self.path == "/admin/authorizations-required":
                self._handle(lambda: authorizations_required_status(store_path))
                return
            if self.path == "/admin/executions":
                self._handle(lambda: admin_executions_status(store_path))
                return
            if self.path == "/admin/summary":
                self._handle(lambda: admin_summary_status(store_path))
                return
            if self.path == "/state":
                self._handle(lambda: list_state_status(store_path))
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
                self._handle_json(lambda payload: release_claim_status(store_path, str(payload["claim_id"])))
                return
            if self.path == "/host/inspect":
                self._handle(lambda: inspect_host_status(store_path))
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
