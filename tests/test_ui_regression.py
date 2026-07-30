import json
import subprocess
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from overseer.api import make_api_handler


class LocalApiHarness:
    def __init__(self, store_path: Path, auth_token: str = "test-secret") -> None:
        self.store_path = store_path
        self.auth_token = auth_token
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.url = ""

    def __enter__(self):
        handler = make_api_handler(str(self.store_path), self.auth_token)
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
state.data.agentInstances.instances[0].controlled_failover_policy_ref = null;
renderDriver();
if (!driverElement.innerHTML.includes("Controlled failover policy is not configured")) process.exit(12);
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
        self.assertIn('#driver .action-btn { min-height: 44px; }', OPERATOR_CONSOLE_HTML)

    def test_driver_actions_fail_closed_by_exact_capability_and_route(self):
        from overseer.ui import OPERATOR_CONSOLE_HTML

        for capability in ("session_discovery", "session_resume", "checkpoints", "handoff_import"):
            self.assertIn(f'"{capability}"', OPERATOR_CONSOLE_HTML)
        self.assertIn("provider.available !== true", OPERATOR_CONSOLE_HTML)
        self.assertIn('provider.readiness !== "available"', OPERATOR_CONSOLE_HTML)
        self.assertIn("Cancellation route is unavailable", OPERATOR_CONSOLE_HTML)

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


if __name__ == "__main__":
    unittest.main()
