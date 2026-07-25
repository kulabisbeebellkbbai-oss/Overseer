import json
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
