import json
import sqlite3
import subprocess
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from overseer.api import make_api_handler
from overseer.admin import plan_user_service_restart
from overseer.roadex_approval_status import RoadexApprovalBindingDraft, stage_bound_roadex_approval
from overseer.store import SQLiteStore
from tests.test_backup_provisioning import seeded
from tests.test_roadex_approval_status import _write_roadex_plan


class LocalApiHarness:
    def __init__(self, store_path: Path, auth_token: str = "test-secret", roadex_decision_adapter_factory=None) -> None:
        self.store_path = store_path
        self.auth_token = auth_token
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.url = ""
        self.roadex_decision_adapter_factory = roadex_decision_adapter_factory

    def __enter__(self):
        handler = make_api_handler(str(self.store_path), self.auth_token, roadex_decision_adapter_factory=self.roadex_decision_adapter_factory)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        host, port = self.server.server_address
        self.url = f"http://{host}:{port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=5)

    def get_json(self, path: str, authenticated: bool = True) -> dict:
        request = Request(f"{self.url}{path}")
        if authenticated:
            request.add_header("Authorization", f"Bearer {self.auth_token}")
        with urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    def get_status(self, path: str, authenticated: bool = True) -> int:
        request = Request(f"{self.url}{path}")
        if authenticated:
            request.add_header("Authorization", f"Bearer {self.auth_token}")
        try:
            with urlopen(request, timeout=5) as response:
                return response.status
        except HTTPError as error:
            return error.code

    def get_text(self, path: str) -> tuple[str, str]:
        with urlopen(f"{self.url}{path}", timeout=5) as response:
            return response.read().decode("utf-8"), response.headers.get("content-type", "")

    def post_json(self, path: str, payload: dict, authenticated: bool = True) -> dict:
        data = json.dumps(payload).encode("utf-8")
        request = Request(f"{self.url}{path}", data=data, method="POST")
        request.add_header("Content-Type", "application/json")
        if authenticated:
            request.add_header("Authorization", f"Bearer {self.auth_token}")
        with urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))


class ProtectedGatewayUiRegressionTests(unittest.TestCase):
    def test_failover_recovery_ui_uses_status_contract(self):
        from overseer.ui import OPERATOR_CONSOLE_HTML

        for state in ("reserved", "draining", "blocked_preimport", "recovering"):
            self.assertIn(state, OPERATOR_CONSOLE_HTML)
        self.assertIn("item.recovery_state", OPERATOR_CONSOLE_HTML)
        self.assertIn('postJson("/agent-failover/recover"', OPERATOR_CONSOLE_HTML)
        self.assertIn("blockedFailoverExecution.blocker", OPERATOR_CONSOLE_HTML)
        self.assertNotIn("operation_owner_ref", OPERATOR_CONSOLE_HTML)

    def test_dashboard_pure_javascript_behavior_executes_in_node(self):
        from overseer.ui import OPERATOR_CONSOLE_HTML

        start = OPERATOR_CONSOLE_HTML.index("    function providerGate(")
        end = OPERATOR_CONSOLE_HTML.index("    function selectView(", start)
        functions = OPERATOR_CONSOLE_HTML[start:end]
        render_start = OPERATOR_CONSOLE_HTML.index("    function renderDriver()")
        render_end = OPERATOR_CONSOLE_HTML.index("    function renderAdmin()", render_start)
        render_function = OPERATOR_CONSOLE_HTML[render_start:render_end]
        script = functions + r"""
const providers = [
  {id:"codex", available:true, readiness:"available", capabilities:{session_discovery:true, checkpoints:true}},
  {id:"claude", available:false, readiness:"unavailable", unavailable_reason:{type:"not_installed"}, capabilities:{}}
];
if (!providerGate(providers, "codex", {checkpoints:true}, "session_discovery").enabled) process.exit(2);
if (providerGate(providers, "claude", {}, "session_discovery").enabled) process.exit(3);
if (!providerGate(providers, "missing", {}, "session_resume").blocker.includes("not configured")) process.exit(4);
const payload = validatedTransferPayload("overseer.default", "claude", "operator", "approval.1");
if (payload.approval_id !== "approval.1") process.exit(5);
let rejected = false;
try { validatedTransferPayload("overseer.default", "claude", "operator", ""); } catch (_) { rejected = true; }
if (!rejected) process.exit(6);
""" + render_function + r"""
const driverElement = {innerHTML:""};
const document = {getElementById:(id) => id === "driver" ? driverElement : null};
const safe = (value) => String(value ?? "").replaceAll('"', "&quot;");
const stationIntro = () => "";
const metric = () => "";
const kv = () => "";
const table = () => "";
const officerPanel = () => "";
const state = {driverSelection:{}, data:{
  agentProviders:{providers:[
    {id:"codex",available:true,readiness:"available",capabilities:{session_discovery:true,session_resume:true,checkpoints:true,handoff_import:true}},
    {id:"claude",available:false,readiness:"unavailable",unavailable_reason:{type:"not_installed"},capabilities:{}}
  ]},
  agentInstances:{instances:[{id:"overseer.default",primary_provider_id:"codex",required_capabilities:{},approved_fallback_provider_ids:["claude"],policy_readiness:"ready",controlled_failover_policy_ref:"policy.failover"}]},
  agentSessions:{sessions:[{id:"session.codex",provider_id:"codex",instance_id:"overseer.default",state:"active"}]},
  agentDispatches:{dispatches:[],results:[]}, agentUsage:{providers:[]}
}};
renderDriver();
if (!driverElement.innerHTML.includes('data-action="discover-agent-sessions"')) process.exit(7);
if (!driverElement.innerHTML.includes('Cancellation route is unavailable')) process.exit(8);
state.driverSelection["agent-provider-id"] = "claude";
renderDriver();
if (!driverElement.innerHTML.includes('data-action="discover-agent-sessions" disabled')) process.exit(9);
if (!driverElement.innerHTML.includes('not_installed')) process.exit(10);
state.driverSelection["agent-incoming-provider-id"] = "claude";
renderDriver();
if (!driverElement.innerHTML.includes('data-action="failover-agent" disabled')) process.exit(11);
state.data.agentProviders.providers[0].available = false;
state.data.agentProviders.providers[0].readiness = "unavailable";
state.data.agentProviders.providers[1] = {id:"claude",available:true,readiness:"available",capabilities:{handoff_import:true}};
state.data.agentInstances.instances[0].failover_policy_readiness = "ready";
renderDriver();
const failoverButton = driverElement.innerHTML.match(/<button[^>]*data-action="failover-agent"[^>]*>/)?.[0] || "";
if (!failoverButton || failoverButton.includes(" disabled")) process.exit(12);
state.data.agentInstances.instances[0].controlled_failover_policy_ref = null;
renderDriver();
const blockedFailover = driverElement.innerHTML.match(/<button[^>]*data-action="failover-agent"[^>]*>/)?.[0] || "";
if (!blockedFailover.includes(" disabled") || !blockedFailover.includes("Controlled failover policy is not configured")) process.exit(13);
"""
        result = subprocess.run(["node", "-e", script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_operator_console_contains_primary_driver_controls(self):
        from overseer.ui import OPERATOR_CONSOLE_HTML

        self.assertIn("Primary AI Driver", OPERATOR_CONSOLE_HTML)
        self.assertIn('agentProviders: "/agent-providers"', OPERATOR_CONSOLE_HTML)
        self.assertIn('agentInstances: "/agent-instances"', OPERATOR_CONSOLE_HTML)
        self.assertIn('agentSessions: "/agent-sessions"', OPERATOR_CONSOLE_HTML)
        self.assertIn('agentDispatches: "/agent-dispatches"', OPERATOR_CONSOLE_HTML)
        self.assertIn('data-action="discover-agent-sessions"', OPERATOR_CONSOLE_HTML)
        self.assertIn('data-action="resume-agent-sessions"', OPERATOR_CONSOLE_HTML)
        self.assertIn('data-action="checkpoint-agent"', OPERATOR_CONSOLE_HTML)
        self.assertIn('data-action="handoff-agent"', OPERATOR_CONSOLE_HTML)
        self.assertIn('data-action="failover-agent"', OPERATOR_CONSOLE_HTML)
        self.assertIn('data-disabled-action="cancel-agent"', OPERATOR_CONSOLE_HTML)
        self.assertIn("Provider Capabilities", OPERATOR_CONSOLE_HTML)
        self.assertIn("approval_id", OPERATOR_CONSOLE_HTML)
        self.assertIn("window.confirm", OPERATOR_CONSOLE_HTML)
        self.assertIn('agentUsage: "/agent-usage"', OPERATOR_CONSOLE_HTML)
        self.assertIn("primary.approved_fallback_provider_ids", OPERATOR_CONSOLE_HTML)
        self.assertIn("primary.active_epoch", OPERATOR_CONSOLE_HTML)
        self.assertIn('["id", "provider_id", "instance_id", "state", "checkpoint_id"]', OPERATOR_CONSOLE_HTML)
        self.assertIn('["id", "instance_id", "session_id", "driver_epoch_id", "requested_at", "requested_by"]', OPERATOR_CONSOLE_HTML)
        self.assertIn('["request_id", "state", "completed_at", "error_category"]', OPERATOR_CONSOLE_HTML)
        self.assertNotIn("primary.current_epoch", OPERATOR_CONSOLE_HTML)
        self.assertNotIn("primary.fallback_order", OPERATOR_CONSOLE_HTML)

    def test_operator_console_has_responsive_mode_contract(self):
        from overseer.ui import OPERATOR_CONSOLE_HTML

        self.assertIn('id="layout-mode"', OPERATOR_CONSOLE_HTML)
        self.assertIn('aria-live="polite"', OPERATOR_CONSOLE_HTML)
        self.assertIn('const LAYOUT_MODES = ["auto", "desktop", "tablet", "mobile"]', OPERATOR_CONSOLE_HTML)
        self.assertIn("width <= 700", OPERATOR_CONSOLE_HTML)
        self.assertIn("width <= 1024", OPERATOR_CONSOLE_HTML)
        self.assertIn('localStorage.getItem("overseerLayoutMode")', OPERATOR_CONSOLE_HTML)
        self.assertIn('localStorage.setItem("overseerLayoutMode"', OPERATOR_CONSOLE_HTML)
        self.assertIn('window.addEventListener("resize"', OPERATOR_CONSOLE_HTML)
        self.assertIn("data-layout-effective", OPERATOR_CONSOLE_HTML)
        self.assertIn("@media (prefers-reduced-motion: reduce)", OPERATOR_CONSOLE_HTML)
        self.assertIn('body[data-layout-effective="desktop"] .shell', OPERATOR_CONSOLE_HTML)
        self.assertIn('body[data-layout-effective="desktop"] main { padding-top: 60px; }', OPERATOR_CONSOLE_HTML)
        self.assertIn('#driver .action-btn { min-height: 44px; }', OPERATOR_CONSOLE_HTML)

    def test_sisko_page_has_roadex_final_human_decision_card(self):
        from overseer.ui import OPERATOR_CONSOLE_HTML

        self.assertIn('roadexHumanDecisions: "/roadex/human-decisions"', OPERATOR_CONSOLE_HTML)
        self.assertIn("Roadex final human decision", OPERATOR_CONSOLE_HTML)
        self.assertIn("What approval does", OPERATOR_CONSOLE_HTML)
        self.assertIn("Risks and safeguards", OPERATOR_CONSOLE_HTML)
        self.assertIn('data-action="decide-roadex-human"', OPERATOR_CONSOLE_HTML)
        self.assertIn('action("approve", "Approve and complete")', OPERATOR_CONSOLE_HTML)
        self.assertIn('action("deny", "Deny", "deny")', OPERATOR_CONSOLE_HTML)
        self.assertIn('action("request_revision", "Request revision", "revision")', OPERATOR_CONSOLE_HTML)
        self.assertIn('postJson("/roadex/human-decisions/decide"', OPERATOR_CONSOLE_HTML)
        self.assertIn("Approve and complete", OPERATOR_CONSOLE_HTML)
        self.assertIn("min-height: 44px", OPERATOR_CONSOLE_HTML)

    def test_roadex_human_decision_route_requires_admin_auth_and_records_denial(self):
        from overseer.backup_provisioning import stage_plan
        from tests.test_backup_provisioning import seeded

        with tempfile.TemporaryDirectory() as directory:
            store_path, plan = seeded(Path(directory))
            stage_plan(store_path, plan)
            with LocalApiHarness(Path(store_path)) as server:
                queue = server.get_json("/Overseer/roadex/human-decisions")
                with self.assertRaises(HTTPError) as error:
                    server.post_json("/Overseer/roadex/human-decisions/decide", {
                        "plan_id": plan.plan_id,
                        "decision": "deny",
                        "decided_by": "human-user",
                        "reason": "Revise the recovery boundary",
                    }, authenticated=False)
                denied = server.post_json("/Overseer/roadex/human-decisions/decide", {
                    "plan_id": plan.plan_id,
                    "decision": "deny",
                    "decided_by": "human-user",
                    "reason": "Revise the recovery boundary",
                })

        self.assertEqual(error.exception.code, 401)
        self.assertEqual(queue["pending_count"], 1)
        self.assertEqual(denied["action_status"], "denied")
        self.assertFalse(denied["host_mutation_performed"])

    def test_operator_console_places_skiller_cards_on_health_and_knowledge_pages(self):
        from overseer.ui import OPERATOR_CONSOLE_HTML

        self.assertIn('skillerEffectiveness: "/health/skiller-effectiveness"', OPERATOR_CONSOLE_HTML)
        self.assertIn('skillerGuidanceAdherence: "/health/skiller-guidance-adherence"', OPERATOR_CONSOLE_HTML)
        self.assertIn("Skiller Adaptive Review", OPERATOR_CONSOLE_HTML)
        self.assertIn("Skiller Guidance Quality", OPERATOR_CONSOLE_HTML)
        self.assertIn("Recurring Skiller Pitfalls", OPERATOR_CONSOLE_HTML)
        self.assertIn("Learning Effectiveness", OPERATOR_CONSOLE_HTML)
        self.assertIn("Effectiveness Review History", OPERATOR_CONSOLE_HTML)
        self.assertIn("Skiller Guidance Audit", OPERATOR_CONSOLE_HTML)
        self.assertIn("Thread Guidance Status", OPERATOR_CONSOLE_HTML)
        self.assertIn("Recent Guidance Findings", OPERATOR_CONSOLE_HTML)
        self.assertIn("Guidance Recommendation History", OPERATOR_CONSOLE_HTML)
        self.assertIn("Guidance Adherence History", OPERATOR_CONSOLE_HTML)

    def test_operator_console_clears_a_rejected_stored_api_token(self):
        from overseer.ui import OPERATOR_CONSOLE_HTML

        self.assertIn("err.status === 401", OPERATOR_CONSOLE_HTML)
        self.assertIn('tokenStore.removeItem("overseerToken")', OPERATOR_CONSOLE_HTML)
        self.assertIn("The stored Overseer API token is no longer valid", OPERATOR_CONSOLE_HTML)
        self.assertIn('document.body.dataset.loadState = unauthorized ? "locked" : "failed"', OPERATOR_CONSOLE_HTML)

    def test_operator_console_refreshes_visible_live_data_without_overlap(self):
        from overseer.ui import OPERATOR_CONSOLE_HTML

        self.assertIn("const AUTO_REFRESH_MS = 30000", OPERATOR_CONSOLE_HTML)
        self.assertIn("if (refreshPromise) return refreshPromise", OPERATOR_CONSOLE_HTML)
        self.assertIn('window.addEventListener("focus"', OPERATOR_CONSOLE_HTML)
        self.assertIn('document.addEventListener("visibilitychange"', OPERATOR_CONSOLE_HTML)
        self.assertIn("if (!document.hidden && state.token) refresh()", OPERATOR_CONSOLE_HTML)
        self.assertIn("auto refresh paused", OPERATOR_CONSOLE_HTML)
        self.assertIn("auto refresh on", OPERATOR_CONSOLE_HTML)
        self.assertIn('id="updated" class="muted" aria-live="polite"', OPERATOR_CONSOLE_HTML)

    def test_driver_actions_fail_closed_by_exact_capability_and_route(self):
        from overseer.ui import OPERATOR_CONSOLE_HTML

        for capability in ("session_discovery", "session_resume", "checkpoints", "handoff_import"):
            self.assertIn(f'"{capability}"', OPERATOR_CONSOLE_HTML)
        self.assertIn("provider.available !== true", OPERATOR_CONSOLE_HTML)
        self.assertIn('provider.readiness !== "available"', OPERATOR_CONSOLE_HTML)
        self.assertIn("Cancellation route is unavailable", OPERATOR_CONSOLE_HTML)
        self.assertIn("primary.failover_policy_readiness", OPERATOR_CONSOLE_HTML)
        self.assertIn("primary.current_driver_blocker", OPERATOR_CONSOLE_HTML)

    def test_gateway_prefix_serves_operator_console_with_token_form(self):
        with tempfile.TemporaryDirectory() as directory:
            with LocalApiHarness(Path(directory) / "overseer.sqlite3") as server:
                root_html, root_content_type = server.get_text("/Overseer")
                ui_html, ui_content_type = server.get_text("/Overseer/ui")

        self.assertIn("text/html", root_content_type)
        self.assertIn("text/html", ui_content_type)
        self.assertIn('id="token"', root_html)
        self.assertIn('id="token"', ui_html)
        self.assertIn('apiBase = protectedGatewayPath ? "/Overseer" : ""', ui_html)
        self.assertIn('tokenStore = protectedGatewayPath ? sessionStorage : localStorage', ui_html)

    def test_gateway_prefix_requires_auth_for_panel_endpoints(self):
        with tempfile.TemporaryDirectory() as directory:
            with LocalApiHarness(Path(directory) / "overseer.sqlite3") as server:
                with self.assertRaises(HTTPError) as error:
                    server.get_json("/Overseer/usage-summary", authenticated=False)
                authenticated = server.get_json("/Overseer/usage-summary")

        self.assertEqual(error.exception.code, 401)
        self.assertIn("items", authenticated)

    def test_gateway_prefix_exposes_authenticated_panel_matrix(self):
        endpoints = (
            "/Overseer/auth-check",
    "/Overseer/operator-dashboard",
    "/Overseer/incidents/lifecycle",
    "/Overseer/operations/gap-coverage",
    "/Overseer/operations/workflows",
            "/Overseer/health/service-evidence",
            "/Overseer/health/codex-usage",
            "/Overseer/health/skiller-effectiveness",
            "/Overseer/health/skiller-guidance-adherence",
            "/Overseer/observability/trends",
            "/Overseer/observability/metric-history",
            "/Overseer/observability/performance-history",
            "/Overseer/runtime-status",
            "/Overseer/admin/authorizations-required",
            "/Overseer/admin/execution-readiness",
            "/Overseer/admin/adapter-capabilities",
            "/Overseer/compliance/evidence",
            "/Overseer/maintenance/software-evidence",
            "/Overseer/maintenance/advisories",
            "/Overseer/maintenance/schedules",
            "/Overseer/storage/evidence",
            "/Overseer/storage/backup-operations",
            "/Overseer/virtual/evidence",
            "/Overseer/virtual/operations",
            "/Overseer/usage-summary",
            "/Overseer/usage/evidence",
            "/Overseer/documents/status",
            "/Overseer/documents/evidence",
            "/Overseer/crew/messages",
            "/Overseer/audit-summary",
            "/Overseer/approvals-summary",
            "/Overseer/claims/review",
            "/Overseer/claims/cleanup-plan",
            "/Overseer/host/security/listener-review-queue",
            "/Overseer/host/security/source-review-queue",
            "/Overseer/security/evidence",
            "/Overseer/identity/evidence",
            "/Overseer/identity/rotation-requests",
            "/Overseer/identity/rotation-readiness",
            "/Overseer/git/status",
        )
        with tempfile.TemporaryDirectory() as directory:
            with LocalApiHarness(Path(directory) / "overseer.sqlite3") as server:
                statuses = {endpoint: server.get_status(endpoint) for endpoint in endpoints}
                auth_check = server.get_json("/Overseer/auth-check")
                dashboard = server.get_json("/Overseer/operator-dashboard")
                git_status = server.get_json("/Overseer/git/status")

        self.assertTrue(auth_check["authorized"])
        self.assertIn("role_focus", dashboard)
        self.assertIn("branch", git_status)
        self.assertTrue(all(status != 401 for status in statuses.values()))
        self.assertTrue(all(status < 500 for status in statuses.values()))

    def test_gateway_prefix_allows_safe_post_actions(self):
        with tempfile.TemporaryDirectory() as directory:
            with LocalApiHarness(Path(directory) / "overseer.sqlite3") as server:
                message = server.post_json(
                    "/Overseer/crew/messages",
                    {
                        "owner_domain": "julian",
                        "subject": "Gateway UI regression",
                        "message": "Verify protected gateway POST routing.",
                        "priority": "low",
                        "requested_by": "test",
                    },
                )

        self.assertTrue(message["mutation_performed"])
        self.assertEqual(message["message"]["owner_domain"], "julian")

    def test_roadex_approval_status_route_supports_direct_and_gateway_paths(self):
        draft = RoadexApprovalBindingDraft(
            approval_ref="admin.roadex.test",
            source_kind="admin-plan",
            source_id="admin.roadex.test",
            project_id="project.test",
            workspace_id="workspace.test",
            resource_ref="service.test",
            authority_class="privileged-operation",
            subject="Restart test service",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "overseer.sqlite3"
            with SQLiteStore(path) as store:
                stage_bound_roadex_approval(
                    store,
                    draft,
                    lambda: store.save_admin_change_plan(
                        plan_user_service_restart(
                            "admin.roadex.test",
                            "roadex-test.service",
                            "Approval projection fixture",
                        )
                    ),
                )
            with LocalApiHarness(path) as server:
                direct = server.get_json("/roadex/approval-status?approval_ref=admin.roadex.test")
                prefixed = server.get_json("/Overseer/roadex/approval-status?approval_ref=admin.roadex.test")

        self.assertEqual(direct, prefixed)
        self.assertEqual(direct["approvalRef"], "admin.roadex.test")

    def test_roadex_approval_status_route_authentication_and_query_validation(self):
        draft = RoadexApprovalBindingDraft(
            approval_ref="admin.roadex.test",
            source_kind="admin-plan",
            source_id="admin.roadex.test",
            project_id="project.test",
            workspace_id="workspace.test",
            resource_ref="service.test",
            authority_class="privileged-operation",
            subject="Restart test service",
        )
        with tempfile.TemporaryDirectory() as directory:
            with SQLiteStore(Path(directory) / "overseer.sqlite3") as store:
                stage_bound_roadex_approval(
                    store,
                    draft,
                    lambda: store.save_admin_change_plan(
                        plan_user_service_restart(
                            "admin.roadex.test",
                            "roadex-test.service",
                            "Approval projection fixture",
                        )
                    ),
                )
            with LocalApiHarness(Path(directory) / "overseer.sqlite3") as server:
                with self.assertRaises(HTTPError) as unauth:
                    server.get_json("/roadex/approval-status?approval_ref=admin.roadex.test", authenticated=False)
                self.assertEqual(unauth.exception.code, 401)
                self.assertEqual(server.get_status("/roadex/approval-status"), 400)
                self.assertEqual(server.get_status("/Overseer/roadex/approval-status?approval_ref=admin.roadex.test&approval_ref=admin.roadex.test"), 400)

    def test_roadex_approval_status_route_rejects_duplicate_approval_ref_query_values(self):
        paths = (
            "/roadex/approval-status",
            "/Overseer/roadex/approval-status",
        )
        queries = (
            "approval_ref=admin.roadex.test&approval_ref=admin.roadex.test",
            "approval_ref=&approval_ref=admin.roadex.test",
            "approval_ref=admin.roadex.test&approval_ref=",
        )
        draft = RoadexApprovalBindingDraft(
            approval_ref="admin.roadex.test",
            source_kind="admin-plan",
            source_id="admin.roadex.test",
            project_id="project.test",
            workspace_id="workspace.test",
            resource_ref="service.test",
            authority_class="privileged-operation",
            subject="Restart test service",
        )
        with tempfile.TemporaryDirectory() as directory:
            with SQLiteStore(Path(directory) / "overseer.sqlite3") as store:
                stage_bound_roadex_approval(
                    store,
                    draft,
                    lambda: store.save_admin_change_plan(
                        plan_user_service_restart(
                            "admin.roadex.test",
                            "roadex-test.service",
                            "Approval projection fixture",
                        )
                    ),
                )
            with LocalApiHarness(Path(directory) / "overseer.sqlite3") as server:
                for path in paths:
                    for query in queries:
                        with self.subTest(path=path, query=query):
                            with self.assertRaises(HTTPError) as error:
                                server.get_json(f"{path}?{query}", authenticated=True)
                            self.assertEqual(error.exception.code, 400)

    def test_roadex_approval_status_route_missing_approval_is_not_revealed(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            with LocalApiHarness(store_path) as server:
                with self.assertRaises(HTTPError) as missing:
                    server.get_json("/Overseer/roadex/approval-status?approval_ref=admin.roadex.missing")
                body = missing.exception.read().decode("utf-8")

            self.assertEqual(missing.exception.code, 404)
            parsed = json.loads(body)
            self.assertEqual(parsed, {"error": "missing record"})
            self.assertNotIn("admin.roadex.missing", body)

    def test_roadex_approval_status_route_reports_no_exact_binding_for_legacy_source(self):
        def database_dump_bytes(path: Path) -> bytes:
            with sqlite3.connect(path) as connection:
                return "\n".join(connection.iterdump()).encode("utf-8")

        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            with SQLiteStore(store_path) as store:
                draft = RoadexApprovalBindingDraft(
                    approval_ref="admin.roadex.legacy",
                    source_kind="admin-plan",
                    source_id="admin.roadex.legacy",
                    project_id="project.test",
                    workspace_id="workspace.test",
                    resource_ref="service.test",
                    authority_class="privileged-operation",
                    subject="Restart test service",
                )
                stage_bound_roadex_approval(
                    store,
                    draft,
                    lambda: store.save_admin_change_plan(
                        plan_user_service_restart(
                            "admin.roadex.legacy",
                            "roadex-test.service",
                            "Legacy approval fixture",
                        )
                    ),
                )
                store._connection.execute("DROP INDEX IF EXISTS idx_roadex_approval_bindings_source_kind")
                store._connection.execute("DROP INDEX IF EXISTS idx_roadex_approval_bindings_source_id")
                store._connection.execute("DROP TABLE IF EXISTS roadex_approval_bindings")
                store._connection.commit()
                self.assertIsNone(
                    store._connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='roadex_approval_bindings'"
                    ).fetchone()
                )
                pre_get_dump = database_dump_bytes(store_path)
            with LocalApiHarness(store_path) as server:
                with self.assertRaises(HTTPError) as legacy:
                    server.get_json("/Overseer/roadex/approval-status?approval_ref=admin.roadex.legacy")
                body = legacy.exception.read().decode("utf-8")
                self.assertEqual(legacy.exception.code, 404)
                self.assertEqual(json.loads(body), {"error": "missing record"})
            post_get_dump = database_dump_bytes(store_path)
            self.assertEqual(pre_get_dump, post_get_dump)

    def test_roadex_approval_status_route_rejects_malformed_roadex_source_payload_without_connection_abort(self):
        def mutate_source_payload(variant: str, payload: dict[str, object]) -> str:
            if variant == "missing_field":
                payload.pop("decision_reason")
            else:
                payload["evidence_ids"] = []
            return json.dumps(payload, sort_keys=True, separators=(",", ":"))

        for variant in ("missing_field", "bad_evidence_ids"):
            with tempfile.TemporaryDirectory() as directory:
                store_path, source = seeded(Path(directory) / "source")
                draft = RoadexApprovalBindingDraft(
                    approval_ref="admin.roadex.human",
                    source_kind="roadex-human-decision",
                    source_id=source.plan_id,
                    project_id="project.test",
                    workspace_id="workspace.test",
                    resource_ref="service.test",
                    authority_class="privileged-operation",
                    subject="Restart test service",
                )
                with SQLiteStore(store_path) as store:
                    stage_bound_roadex_approval(
                        store,
                        draft,
                        lambda: _write_roadex_plan(store, source),
                    )
                    source_payload = json.loads(
                        store._connection.execute(
                            "SELECT payload FROM backup_provisioning_plans WHERE id=?",
                            (source.plan_id,),
                        ).fetchone()["payload"]
                    )
                    updated_source = mutate_source_payload(variant, source_payload)
                    store._connection.execute(
                        "UPDATE backup_provisioning_plans SET payload=? WHERE id=?",
                        (updated_source, source.plan_id),
                    )
                    store._connection.commit()

                with LocalApiHarness(store_path) as server:
                    request = Request(
                        f"{server.url}/Overseer/roadex/approval-status?approval_ref={draft.approval_ref}"
                    )
                    request.add_header("Authorization", f"Bearer {server.auth_token}")
                    with self.assertRaises(HTTPError) as malformed:
                        urlopen(request, timeout=5)
                    body = malformed.exception.read().decode("utf-8")

                parsed = json.loads(body)
                self.assertEqual(malformed.exception.code, 400)
                self.assertEqual(parsed["error"], "malformed_source")
                self.assertEqual(parsed["code"], "ROAD_EX_APPROVAL_SOURCE_MALFORMED")

    def test_roadex_approval_status_route_rejects_malformed_binding_created_at_for_terminal_statuses(self):
        for status in (
            "approved",
            "executed",
            "failed",
            "rolled_back",
        ):
            with tempfile.TemporaryDirectory() as directory:
                store_path, source = seeded(Path(directory) / "source")
                malformed = "NOT_A_TIMESTAMP_SECRET"
                draft = RoadexApprovalBindingDraft(
                    approval_ref=f"admin.roadex.{status}",
                    source_kind="roadex-human-decision",
                    source_id=source.plan_id,
                    project_id="project.test",
                    workspace_id="workspace.test",
                    resource_ref="service.test",
                    authority_class="privileged-operation",
                    subject="Restart test service",
                )
                with SQLiteStore(store_path) as store:
                    stage_bound_roadex_approval(
                        store,
                        draft,
                        lambda: _write_roadex_plan(store, source),
                    )
                    source_payload = json.loads(
                        store._connection.execute(
                            "SELECT payload FROM backup_provisioning_plans WHERE id=?",
                            (source.plan_id,),
                        ).fetchone()["payload"]
                    )
                    source_payload["status"] = status
                    source_payload["approved_by"] = "human-user"
                    source_payload["approved_at"] = "2026-08-02T00:00:00+00:00"
                    source_payload["executed_at"] = "2026-08-02T00:01:00+00:00"
                    source_payload["evidence_digest"] = "sha256:" + "3" * 64
                    source_payload["failed_operation"] = "step.backup"
                    source_payload["error_code"] = "ROAD_EX_ERROR"
                    store._connection.execute(
                        "UPDATE backup_provisioning_plans SET payload=? WHERE id=?",
                        (
                            json.dumps(source_payload, sort_keys=True, separators=(",", ":")),
                            source.plan_id,
                        ),
                    )
                    store._connection.commit()
                    binding_payload = json.loads(
                        store._connection.execute(
                            "SELECT payload FROM roadex_approval_bindings WHERE approval_ref=?",
                            (draft.approval_ref,),
                        ).fetchone()["payload"]
                    )
                    binding_payload["created_at"] = malformed
                    store._connection.execute(
                        "UPDATE roadex_approval_bindings SET payload=? WHERE approval_ref=?",
                        (
                            json.dumps(binding_payload, sort_keys=True, separators=(",", ":")),
                            draft.approval_ref,
                        ),
                    )
                    store._connection.commit()

                with LocalApiHarness(store_path) as server:
                    request = Request(
                        f"{server.url}/Overseer/roadex/approval-status?approval_ref={draft.approval_ref}"
                    )
                    request.add_header("Authorization", f"Bearer {server.auth_token}")
                    with self.assertRaises(HTTPError) as malformed:
                        urlopen(request, timeout=5)
                    body = malformed.exception.read().decode("utf-8")

                parsed = json.loads(body)
                self.assertEqual(malformed.exception.code, 400)
                self.assertEqual(parsed["error"], "malformed_source")
                self.assertEqual(parsed["code"], "ROAD_EX_APPROVAL_SOURCE_MALFORMED")
    def test_roadex_approval_status_route_does_not_return_malformed_source_secret(self):
        secret = "ROADEX_SOURCE_SECRET_ABC123"
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            with SQLiteStore(store_path) as store:
                draft = RoadexApprovalBindingDraft(
                    approval_ref="admin.roadex.test",
                    source_kind="admin-plan",
                    source_id="admin.roadex.test",
                    project_id="project.test",
                    workspace_id="workspace.test",
                    resource_ref="service.test",
                    authority_class="privileged-operation",
                    subject="Restart test service",
                )
                stage_bound_roadex_approval(
                    store,
                    draft,
                    lambda: store.save_admin_change_plan(
                        plan_user_service_restart(
                            "admin.roadex.test",
                            "roadex-test.service",
                            "Approval projection fixture",
                        )
                    ),
                )
                payload = json.loads(
                    store._connection.execute(
                        "SELECT payload FROM roadex_approval_bindings WHERE approval_ref=?",
                        (draft.approval_ref,),
                    ).fetchone()["payload"]
                )
                payload["source_id"] = secret
                store._connection.execute(
                    "UPDATE roadex_approval_bindings SET payload=? WHERE approval_ref=?",
                    (json.dumps(payload), draft.approval_ref),
                )
                store._connection.commit()

            with LocalApiHarness(store_path) as server:
                request = Request(f"{server.url}/Overseer/roadex/approval-status?approval_ref=admin.roadex.test")
                request.add_header("Authorization", f"Bearer {server.auth_token}")
                with self.assertRaises(HTTPError) as malformed:
                    urlopen(request, timeout=5)
                body = malformed.exception.read().decode("utf-8")

            self.assertEqual(malformed.exception.code, 400)
            self.assertNotIn(secret, body)
            parsed = json.loads(body)
            self.assertEqual(parsed["error"], "malformed_source")
            self.assertEqual(parsed["code"], "ROAD_EX_APPROVAL_SOURCE_MALFORMED")

    def test_roadex_approval_status_route_rejects_malformed_binding_projection_without_leaks(self):
        variants = (
            "malformed_json",
            "missing_field",
            "extra_field",
            "invalid_enum",
            "identity_mismatch",
            "coherent_tamper",
        )

        for variant in variants:
            with tempfile.TemporaryDirectory() as directory:
                store_path = Path(directory) / "overseer.sqlite3"
                with SQLiteStore(store_path) as store:
                    draft = RoadexApprovalBindingDraft(
                        approval_ref="admin.roadex.test",
                        source_kind="admin-plan",
                        source_id="admin.roadex.test",
                        project_id="project.test",
                        workspace_id="workspace.test",
                        resource_ref="service.test",
                        authority_class="privileged-operation",
                        subject="Restart test service",
                    )
                    stage_bound_roadex_approval(
                        store,
                        draft,
                        lambda: store.save_admin_change_plan(
                            plan_user_service_restart(
                                "admin.roadex.test",
                                "roadex-test.service",
                                "Approval projection fixture",
                            )
                        ),
                    )
                    payload_row = store._connection.execute(
                        "SELECT payload FROM roadex_approval_bindings WHERE approval_ref=?",
                        (draft.approval_ref,),
                    ).fetchone()
                    payload = json.loads(payload_row["payload"])

                    if variant == "malformed_json":
                        payload_text = "{bad json"
                    elif variant == "missing_field":
                        del payload["authority_class"]
                        payload_text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
                    elif variant == "extra_field":
                        payload["unexpected_field"] = "bad"
                        payload_text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
                    elif variant == "invalid_enum":
                        payload["source_kind"] = "manual"
                        payload_text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
                    elif variant == "identity_mismatch":
                        payload["source_id"] = "admin.roadex.attacker"
                        payload_text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
                    else:
                        payload["project_id"] = 99
                        payload_text = json.dumps(payload, sort_keys=True, separators=(",", ":"))

                    store._connection.execute(
                        "UPDATE roadex_approval_bindings SET payload=? WHERE approval_ref=?",
                        (payload_text, draft.approval_ref),
                    )
                    store._connection.commit()

                with LocalApiHarness(store_path) as server:
                    request = Request(
                        f"{server.url}/Overseer/roadex/approval-status?approval_ref=admin.roadex.test"
                    )
                    request.add_header("Authorization", f"Bearer {server.auth_token}")
                    with self.assertRaises(HTTPError) as malformed:
                        urlopen(request, timeout=5)
                    body = malformed.exception.read().decode("utf-8")

                self.assertEqual(malformed.exception.code, 400)
                parsed = json.loads(body)
                self.assertEqual(parsed["error"], "malformed_source")
                self.assertEqual(parsed["code"], "ROAD_EX_APPROVAL_SOURCE_MALFORMED")
                self.assertNotIn("admin.roadex.test", body)
                self.assertNotIn("99", body)

    def test_roadex_approval_status_route_has_no_mutation(self):
        draft = RoadexApprovalBindingDraft(
            approval_ref="admin.roadex.test",
            source_kind="admin-plan",
            source_id="admin.roadex.test",
            project_id="project.test",
            workspace_id="workspace.test",
            resource_ref="service.test",
            authority_class="privileged-operation",
            subject="Restart test service",
        )
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            with SQLiteStore(store_path) as store:
                stage_bound_roadex_approval(
                    store,
                    draft,
                    lambda: store.save_admin_change_plan(
                        plan_user_service_restart(
                            "admin.roadex.test",
                            "roadex-test.service",
                            "Approval projection fixture",
                        )
                    ),
                )
                before_binding = store.load_roadex_approval_binding(draft.approval_ref)
                before_master = store._connection.execute(
                    "SELECT name, sql FROM sqlite_master WHERE type='table' AND name='roadex_approval_bindings'"
                ).fetchall()
                before_rows = store._connection.execute("SELECT COUNT(*) AS count FROM roadex_approval_bindings").fetchone()["count"]
            with LocalApiHarness(store_path) as server:
                server.get_json("/roadex/approval-status?approval_ref=admin.roadex.test")
            with SQLiteStore(store_path) as store:
                after_binding = store.load_roadex_approval_binding(draft.approval_ref)
                after_master = store._connection.execute(
                    "SELECT name, sql FROM sqlite_master WHERE type='table' AND name='roadex_approval_bindings'"
                ).fetchall()
                after_rows = store._connection.execute("SELECT COUNT(*) AS count FROM roadex_approval_bindings").fetchone()["count"]

        self.assertEqual(before_rows, after_rows)
        self.assertEqual(before_binding, after_binding)
        self.assertEqual(before_master, after_master)


if __name__ == "__main__":
    unittest.main()
