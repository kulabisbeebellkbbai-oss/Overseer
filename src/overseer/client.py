"""Client helpers for the local Overseer API."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
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

    def daemon_migration_plan(self, service_name: str | None = None) -> dict[str, Any]:
        path = "/runtime/daemon-migration-plan"
        if service_name is not None:
            path = f"{path}?{urlencode({'service_name': service_name})}"
        return self._get(path)

    def request_daemon_migration(
        self,
        requested_by: str,
        service_name: str = "overseer",
        requested_at: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "service_name": service_name,
            "requested_by": requested_by,
        }
        if requested_at:
            payload["requested_at"] = requested_at
        return self._post("/runtime/daemon-migration-requests", payload)

    def approve_daemon_migration(
        self,
        approval_id: str,
        approved_by: str,
        approved_at: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "approval_id": approval_id,
            "approved_by": approved_by,
        }
        if approved_at:
            payload["approved_at"] = approved_at
        return self._post("/runtime/daemon-migration-requests/approve", payload)

    def persistence_security(self) -> dict[str, Any]:
        return self._get("/persistence/security")

    def command_summary(self) -> dict[str, Any]:
        return self._get("/command-summary")

    def record_resource(
        self,
        resource_id: str,
        name: str,
        resource_type: str,
        owner_domain: str,
        risk_level: str,
        state: str = "available",
        identifiers: dict[str, Any] | None = None,
        dependencies: list[str] | tuple[str, ...] = (),
        exclusive_groups: list[str] | tuple[str, ...] = (),
        current_claim_id: str | None = None,
        last_verified_at: str | None = None,
        notes: str = "",
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "resource_id": resource_id,
            "name": name,
            "resource_type": resource_type,
            "owner_domain": owner_domain,
            "risk_level": risk_level,
            "state": state,
            "identifiers": identifiers or {},
            "dependencies": list(dependencies),
            "exclusive_groups": list(exclusive_groups),
            "notes": notes,
        }
        if current_claim_id:
            payload["current_claim_id"] = current_claim_id
        if last_verified_at:
            payload["last_verified_at"] = last_verified_at
        return self._post("/resources", payload)

    def operator_dashboard(self) -> dict[str, Any]:
        return self._get("/operator-dashboard")

    def maintenance_summary(self) -> dict[str, Any]:
        return self._get("/maintenance-summary")

    def package_status(self) -> dict[str, Any]:
        return self._get("/maintenance/package-status")

    def plan_package_updates(
        self,
        packages: list[str] | tuple[str, ...] = (),
        captured_at: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"packages": list(packages)}
        if captured_at:
            payload["captured_at"] = captured_at
        return self._post("/maintenance/package-update-plans", payload)

    def health_summary(self) -> dict[str, Any]:
        return self._get("/health-summary")

    def health_efficiency(self) -> dict[str, Any]:
        return self._get("/health-efficiency")

    def run_health_probes(
        self,
        timeout_seconds: float | None = None,
        retention_per_target: int | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        if timeout_seconds is not None:
            payload["timeout_seconds"] = timeout_seconds
        if retention_per_target is not None:
            payload["retention_per_target"] = retention_per_target
        return self._post("/health/probes/run", payload)

    def record_health_target(
        self,
        target_id: str,
        resource_id: str,
        name: str,
        probe_type: str,
        target: str,
        owner_domain: str = "julian",
        expected_status: int | None = None,
        expected_content_type: str | None = None,
        latency_warn_ms: int | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "target_id": target_id,
            "resource_id": resource_id,
            "name": name,
            "probe_type": probe_type,
            "target": target,
            "owner_domain": owner_domain,
        }
        if expected_status is not None:
            payload["expected_status"] = expected_status
        if expected_content_type:
            payload["expected_content_type"] = expected_content_type
        if latency_warn_ms is not None:
            payload["latency_warn_ms"] = latency_warn_ms
        return self._post("/health-targets", payload)

    def usage_summary(self) -> dict[str, Any]:
        return self._get("/usage-summary")

    def record_usage_limit(
        self,
        limit_id: str,
        resource_id: str,
        kind: str,
        capacity: int,
        remaining: int,
        window: str,
        resets_at: str | None = None,
        observed_at: str | None = None,
        confidence: float = 1.0,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "limit_id": limit_id,
            "resource_id": resource_id,
            "kind": kind,
            "capacity": capacity,
            "remaining": remaining,
            "window": window,
            "confidence": confidence,
        }
        if resets_at:
            payload["resets_at"] = resets_at
        if observed_at:
            payload["observed_at"] = observed_at
        return self._post("/usage-limits", payload)

    def usage_continuation_plan(self) -> dict[str, Any]:
        return self._get("/usage/continuation-plan")

    def discover_codex_project_threads(self, codex_projects_registry: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        if codex_projects_registry:
            payload["codex_projects_registry"] = codex_projects_registry
        return self._post("/codex-projects/discover-threads", payload)

    def dispatch_usage_continuations(
        self,
        dispatched_by: str = "quark",
        dispatched_at: str | None = None,
        resume_codex_projects: bool = False,
        codex_projects_registry: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "dispatched_by": dispatched_by,
            "resume_codex_projects": resume_codex_projects,
        }
        if dispatched_at:
            payload["dispatched_at"] = dispatched_at
        if codex_projects_registry:
            payload["codex_projects_registry"] = codex_projects_registry
        return self._post("/usage/continuation-dispatches", payload)

    def request_usage_continuation(
        self,
        request_id: str,
        limit_id: str,
        resource_id: str,
        owner_thread: str,
        requested_units: int,
        intent: str,
        risk_level: str = "low",
        earliest_start: str | None = None,
        deadline: str | None = None,
        requested_by: str = "quark",
        requested_at: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "request_id": request_id,
            "limit_id": limit_id,
            "resource_id": resource_id,
            "owner_thread": owner_thread,
            "requested_units": requested_units,
            "intent": intent,
            "risk_level": risk_level,
            "requested_by": requested_by,
        }
        if earliest_start:
            payload["earliest_start"] = earliest_start
        if deadline:
            payload["deadline"] = deadline
        if requested_at:
            payload["requested_at"] = requested_at
        return self._post("/usage/continuation-requests", payload)

    def crew_messages(self, owner_domain: str | None = None, status: str | None = None) -> dict[str, Any]:
        query = {key: value for key, value in {"owner_domain": owner_domain, "status": status}.items() if value}
        suffix = f"?{urlencode(query)}" if query else ""
        return self._get(f"/crew/messages{suffix}")

    def record_crew_message(
        self,
        owner_domain: str,
        subject: str,
        message: str,
        priority: str = "medium",
        requested_by: str = "operator",
        message_id: str | None = None,
        related_resource_id: str | None = None,
        related_plan_id: str | None = None,
        related_limit_id: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "owner_domain": owner_domain,
            "subject": subject,
            "message": message,
            "priority": priority,
            "requested_by": requested_by,
        }
        if message_id:
            payload["message_id"] = message_id
        if related_resource_id:
            payload["related_resource_id"] = related_resource_id
        if related_plan_id:
            payload["related_plan_id"] = related_plan_id
        if related_limit_id:
            payload["related_limit_id"] = related_limit_id
        return self._post("/crew/messages", payload)

    def dispatch_crew_messages(
        self,
        owner_domain: str | None = None,
        message_id: str | None = None,
        dispatched_by: str = "sisko",
        dispatched_at: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"dispatched_by": dispatched_by}
        if owner_domain:
            payload["owner_domain"] = owner_domain
        if message_id:
            payload["message_id"] = message_id
        if dispatched_at:
            payload["dispatched_at"] = dispatched_at
        return self._post("/crew/dispatch", payload)

    def documents_status(self) -> dict[str, Any]:
        return self._get("/documents/status")

    def documents_notes(self, folder: str | None = None) -> dict[str, Any]:
        query = f"?{urlencode({'folder': folder})}" if folder else ""
        return self._get(f"/documents/notes{query}")

    def documents_search(self, query: str, context_length: int | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"query": query}
        if context_length is not None:
            payload["context_length"] = context_length
        return self._post("/documents/search", payload)

    def documents_write_note(self, path: str, content: str, mode: str = "append") -> dict[str, Any]:
        return self._post(
            "/documents/notes",
            {
                "path": path,
                "content": content,
                "mode": mode,
            },
        )

    def physical_summary(self) -> dict[str, Any]:
        return self._get("/physical-summary")

    def discover_physical(self, roots: list[str] | tuple[str, ...] = ()) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        if roots:
            payload["roots"] = list(roots)
        return self._post("/physical/discover", payload)

    def discover_storage(self, sysfs_block_root: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        if sysfs_block_root:
            payload["sysfs_block_root"] = sysfs_block_root
        return self._post("/physical/discover-storage", payload)

    def virtual_summary(self) -> dict[str, Any]:
        return self._get("/virtual-summary")

    def discover_virtual_listeners(self) -> dict[str, Any]:
        return self._post("/virtual/discover-listeners", {})

    def alerts_summary(self) -> dict[str, Any]:
        return self._get("/alerts-summary")

    def audit_summary(
        self,
        event_type: str | None = None,
        owner: str | None = None,
        subject_prefix: str | None = None,
    ) -> dict[str, Any]:
        query = {
            key: value
            for key, value in {
                "event_type": event_type,
                "owner": owner,
                "subject_prefix": subject_prefix,
            }.items()
            if value
        }
        suffix = f"?{urlencode(query)}" if query else ""
        return self._get(f"/audit-summary{suffix}")

    def approvals_summary(
        self,
        status: str | None = None,
        owner: str | None = None,
        approval_level: str | None = None,
        subject_prefix: str | None = None,
    ) -> dict[str, Any]:
        query = {
            key: value
            for key, value in {
                "status": status,
                "owner": owner,
                "approval_level": approval_level,
                "subject_prefix": subject_prefix,
            }.items()
            if value
        }
        suffix = f"?{urlencode(query)}" if query else ""
        return self._get(f"/approvals-summary{suffix}")

    def security_summary(self) -> dict[str, Any]:
        return self._get("/security-summary")

    def state(self) -> dict[str, Any]:
        return self._get("/state")

    def state_redacted(self) -> dict[str, Any]:
        return self._get("/state/redacted")

    def claim_review(self, now: str | None = None) -> dict[str, Any]:
        path = "/claims/review"
        if now is not None:
            path = f"{path}?{urlencode({'now': now})}"
        return self._get(path)

    def claim_cleanup_plan(self, now: str | None = None) -> dict[str, Any]:
        path = "/claims/cleanup-plan"
        if now is not None:
            path = f"{path}?{urlencode({'now': now})}"
        return self._get(path)

    def request_claim_cleanup(
        self,
        claim_id: str,
        requested_by: str,
        requested_at: str | None = None,
        now: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "claim_id": claim_id,
            "requested_by": requested_by,
        }
        if requested_at:
            payload["requested_at"] = requested_at
        if now:
            payload["now"] = now
        return self._post("/claims/cleanup-requests", payload)

    def approve_claim_cleanup(
        self,
        approval_id: str,
        approved_by: str,
        approved_at: str | None = None,
        now: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "approval_id": approval_id,
            "approved_by": approved_by,
        }
        if approved_at:
            payload["approved_at"] = approved_at
        if now:
            payload["now"] = now
        return self._post("/claims/cleanup-requests/approve", payload)

    def execute_claim_cleanup(
        self,
        approval_id: str,
        executed_by: str,
        executed_at: str | None = None,
        now: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "approval_id": approval_id,
            "executed_by": executed_by,
        }
        if executed_at:
            payload["executed_at"] = executed_at
        if now:
            payload["now"] = now
        return self._post("/claims/cleanup-requests/execute", payload)

    def request_claim(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/claims/request", payload)

    def approve_claim(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/claims/approve", payload)

    def activate_claim(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/claims/activate", payload)

    def release_claim(
        self,
        claim_id: str,
        released_by: str | None = None,
        reason: str | None = None,
        evidence_ids: tuple[str, ...] = (),
        released_at: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"claim_id": claim_id}
        if released_by:
            payload["released_by"] = released_by
        if reason:
            payload["reason"] = reason
        if evidence_ids:
            payload["evidence_ids"] = list(evidence_ids)
        if released_at:
            payload["released_at"] = released_at
        return self._post("/claims/release", payload)

    def inspect_host(self) -> dict[str, Any]:
        return self._post("/host/inspect", {})

    def discover_user_services(self) -> dict[str, Any]:
        return self._post("/services/discover-user", {})

    def host_security(self) -> dict[str, Any]:
        return self._get("/host/security")

    def host_security_findings(self) -> dict[str, Any]:
        return self._get("/host/security/findings")

    def host_security_triage(self) -> dict[str, Any]:
        return self._get("/host/security/triage")

    def host_security_listener_review_queue(self) -> dict[str, Any]:
        return self._get("/host/security/listener-review-queue")

    def host_security_sources(self) -> dict[str, Any]:
        return self._get("/host/security/sources")

    def host_security_source_review_queue(self) -> dict[str, Any]:
        return self._get("/host/security/source-review-queue")

    def host_security_source_reviews(self) -> dict[str, Any]:
        return self._get("/host/security/source-reviews")

    def create_host_security_source_review(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/host/security/source-reviews", payload)

    def host_security_ids_review_packages(self) -> dict[str, Any]:
        return self._get("/host/security/ids-review-packages")

    def host_security_ids_review_summary(self) -> dict[str, Any]:
        return self._get("/host/security/ids-review-summary")

    def prepare_host_security_ids_review_package(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/host/security/ids-review-packages", payload)

    def submit_host_security_ids_review_package(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/host/security/ids-review-packages/submit", payload)

    def export_host_security_ids_review_prompt(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/host/security/ids-review-packages/prompts", payload)

    def dispatch_host_security_ids_review_package(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/host/security/ids-review-packages/dispatch", payload)

    def record_host_security_ids_review_result(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/host/security/ids-review-packages/results", payload)

    def plan_host_security_source_block(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/host/security/source-reviews/block-plans", payload)

    def plan_host_security_remediation(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/host/security/remediations/plans", payload)

    def plan_host_security_listener_queue_remediations(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/host/security/listener-review-queue/remediation-plans", payload)

    def plan_admin_change(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/admin/plans", payload)

    def authorizations_required(self) -> dict[str, Any]:
        return self._get("/admin/authorizations-required")

    def admin_adapter_capabilities(self) -> dict[str, Any]:
        return self._get("/admin/adapter-capabilities")

    def admin_adapter_enablement_plan(self, kind: str | None = None) -> dict[str, Any]:
        path = "/admin/adapter-enablement-plan"
        if kind is not None:
            path = f"{path}?{urlencode({'kind': kind})}"
        return self._get(path)

    def request_admin_adapter_enablement(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/admin/adapter-enablement-requests", payload)

    def approve_admin_adapter_enablement(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/admin/adapter-enablement-requests/approve", payload)

    def request_admin_policy_warning(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/admin/policy-warning-requests", payload)

    def approve_admin_policy_warning(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/admin/policy-warning-requests/approve", payload)

    def admin_executions(self) -> dict[str, Any]:
        return self._get("/admin/executions")

    def admin_execution_readiness(self) -> dict[str, Any]:
        return self._get("/admin/execution-readiness")

    def admin_policies(self, plan_id: str | None = None) -> dict[str, Any]:
        query = f"?{urlencode({'plan_id': plan_id})}" if plan_id else ""
        return self._get(f"/admin/policies{query}")

    def active_policy_profile(self) -> dict[str, Any]:
        return self._get("/admin/active-policy-profile")

    def policy_customization_helper(self) -> dict[str, Any]:
        return self._get("/admin/policy-customization-helper")

    def build_policy_profile(self, answers: dict[str, Any]) -> dict[str, Any]:
        return self._post("/admin/policy-customization-helper/profile", {"answers": answers})

    def admin_history_review(self) -> dict[str, Any]:
        return self._get("/admin/history-review")

    def admin_history_archive_plan(self) -> dict[str, Any]:
        return self._get("/admin/history-archive-plan")

    def admin_history_archives(self, plan_id: str | None = None) -> dict[str, Any]:
        path = "/admin/history-archives"
        if plan_id is not None:
            path = f"{path}?{urlencode({'plan_id': plan_id})}"
        return self._get(path)

    def admin_history_restore_readiness(self, plan_id: str | None = None) -> dict[str, Any]:
        path = "/admin/history-restore-readiness"
        if plan_id is not None:
            path = f"{path}?{urlencode({'plan_id': plan_id})}"
        return self._get(path)

    def request_admin_history_restore(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/admin/history-restore-requests", payload)

    def approve_admin_history_restore(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/admin/history-restore-requests/approve", payload)

    def request_admin_history_archive(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/admin/history-archive-requests", payload)

    def approve_admin_history_archive(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/admin/history-archive-requests/approve", payload)

    def archive_admin_history(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/admin/history-archive", payload)

    def unarchive_admin_history(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/admin/history-unarchive", payload)

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
