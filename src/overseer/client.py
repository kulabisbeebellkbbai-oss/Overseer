"""Client helpers for the local Overseer API."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen


class OverseerApiClient:
    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8766",
        auth_token: str | None = None,
        auth_token_file: str | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        if auth_token and auth_token_file:
            raise ValueError("use auth_token or auth_token_file, not both")
        self.base_url = base_url.rstrip("/")
        self.auth_token = auth_token or _load_token(auth_token_file)
        self.timeout_seconds = timeout_seconds

    def health(self) -> dict[str, Any]:
        return self._get("/health", authenticated=False)

    def service_status(self) -> dict[str, Any]:
        return self._get("/service-status")

    def runtime_status(self) -> dict[str, Any]:
        return self._get("/runtime-status")

    def command_summary(self) -> dict[str, Any]:
        return self._get("/command-summary")

    def maintenance_summary(self) -> dict[str, Any]:
        return self._get("/maintenance-summary")

    def health_summary(self) -> dict[str, Any]:
        return self._get("/health-summary")

    def health_efficiency(self) -> dict[str, Any]:
        return self._get("/health-efficiency")

    def usage_summary(self) -> dict[str, Any]:
        return self._get("/usage-summary")

    def physical_summary(self) -> dict[str, Any]:
        return self._get("/physical-summary")

    def virtual_summary(self) -> dict[str, Any]:
        return self._get("/virtual-summary")

    def alerts_summary(self) -> dict[str, Any]:
        return self._get("/alerts-summary")

    def security_summary(self) -> dict[str, Any]:
        return self._get("/security-summary")

    def state(self) -> dict[str, Any]:
        return self._get("/state")

    def request_claim(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/claims/request", payload)

    def approve_claim(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/claims/approve", payload)

    def activate_claim(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/claims/activate", payload)

    def release_claim(self, claim_id: str) -> dict[str, Any]:
        return self._post("/claims/release", {"claim_id": claim_id})

    def inspect_host(self) -> dict[str, Any]:
        return self._post("/host/inspect", {})

    def host_security(self) -> dict[str, Any]:
        return self._get("/host/security")

    def plan_admin_change(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/admin/plans", payload)

    def authorizations_required(self) -> dict[str, Any]:
        return self._get("/admin/authorizations-required")

    def admin_executions(self) -> dict[str, Any]:
        return self._get("/admin/executions")

    def admin_summary(self) -> dict[str, Any]:
        return self._get("/admin/summary")

    def approve_admin_change(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/admin/approve", payload)

    def cancel_admin_change(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/admin/cancel", payload)

    def execute_admin_change(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/admin/execute", payload)

    def _get(self, path: str, authenticated: bool = True) -> dict[str, Any]:
        request = Request(f"{self.base_url}{path}", headers=self._headers(authenticated))
        return self._read(request)

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        request = Request(
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers=self._headers(True, {"content-type": "application/json"}),
            method="POST",
        )
        return self._read(request)

    def _headers(self, authenticated: bool, headers: dict[str, str] | None = None) -> dict[str, str]:
        merged = dict(headers or {})
        if authenticated and self.auth_token:
            merged["authorization"] = f"Bearer {self.auth_token}"
        return merged

    def _read(self, request: Request) -> dict[str, Any]:
        with urlopen(request, timeout=self.timeout_seconds) as response:
            return json.loads(response.read().decode("utf-8"))


def _load_token(token_file: str | None) -> str | None:
    if token_file is None:
        return None
    token = Path(token_file).read_text(encoding="utf-8").strip()
    if not token:
        raise ValueError("auth token file is empty")
    return token
