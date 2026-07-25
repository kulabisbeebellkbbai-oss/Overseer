import tempfile
import time
import unittest
from pathlib import Path

from tests.test_ui_full_regression import SAFE_POST_PAYLOADS
from tests.test_ui_regression import LocalApiHarness


GET_ENDPOINT_BUDGETS = {
    "/Overseer/auth-check": 1.0,
    "/Overseer/operator-dashboard": 1.5,
    "/Overseer/operations/gap-coverage": 2.5,
    "/Overseer/runtime-status": 1.0,
    "/Overseer/admin/authorizations-required": 1.0,
    "/Overseer/admin/execution-readiness": 1.0,
    "/Overseer/admin/adapter-capabilities": 1.0,
    "/Overseer/admin/active-policy-profile": 1.0,
    "/Overseer/usage-summary": 1.0,
    "/Overseer/documents/status": 2.5,
    "/Overseer/documents/notes?folder=Overseer": 2.5,
    "/Overseer/documents/knowledge-capture-plan?limit=12": 2.5,
    "/Overseer/crew/messages": 1.0,
    "/Overseer/audit-summary": 1.0,
    "/Overseer/approvals-summary": 1.0,
    "/Overseer/claims/review": 1.0,
    "/Overseer/claims/cleanup-plan": 1.0,
    "/Overseer/physical-summary": 1.0,
    "/Overseer/virtual-summary": 1.0,
    "/Overseer/health-summary": 1.0,
    "/Overseer/security-summary": 1.0,
    "/Overseer/host/security/listener-review-queue": 2.5,
    "/Overseer/host/security/source-review-queue": 2.5,
    "/Overseer/git/status": 2.5,
}

GET_ENDPOINT_ALLOWED_STATUSES = {
    "/Overseer/runtime-status": {200, 404},
    "/Overseer/host/security/listener-review-queue": {200, 400},
    "/Overseer/host/security/source-review-queue": {200, 400},
}

SAFE_POST_BUDGETS = {
    "/Overseer/resources": 1.0,
    "/Overseer/claims/request": 1.0,
    "/Overseer/usage-limits": 1.0,
    "/Overseer/usage/continuation-requests": 1.0,
    "/Overseer/usage/continuation-dispatches": 1.0,
    "/Overseer/health-targets": 1.0,
    "/Overseer/health/probes/run": 1.5,
    "/Overseer/crew/messages": 1.0,
    "/Overseer/crew/dispatch": 1.0,
    "/Overseer/admin/plans": 1.0,
    "/Overseer/admin/approve": 1.0,
    "/Overseer/admin/policy-customization-helper/profile": 1.0,
}


def _timed(call):
    start = time.perf_counter()
    result = call()
    return result, time.perf_counter() - start


class PerformanceRegressionTests(unittest.TestCase):
    def test_operator_console_html_loads_within_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            with LocalApiHarness(Path(directory) / "overseer.sqlite3") as server:
                (html, content_type), elapsed = _timed(lambda: server.get_text("/Overseer/ui"))

        self.assertIn("text/html", content_type)
        self.assertIn("Overseer", html)
        self.assertLess(elapsed, 1.0)

    def test_authenticated_panel_endpoint_matrix_stays_within_budgets(self):
        with tempfile.TemporaryDirectory() as directory:
            with LocalApiHarness(Path(directory) / "overseer.sqlite3") as server:
                for endpoint, budget in GET_ENDPOINT_BUDGETS.items():
                    with self.subTest(endpoint=endpoint):
                        status, elapsed = _timed(lambda endpoint=endpoint: server.get_status(endpoint))
                        self.assertIn(status, GET_ENDPOINT_ALLOWED_STATUSES.get(endpoint, {200}))
                        self.assertLess(elapsed, budget)

    def test_safe_mutating_workflow_routes_stay_within_budgets(self):
        with tempfile.TemporaryDirectory() as directory:
            with LocalApiHarness(Path(directory) / "overseer.sqlite3") as server:
                for endpoint, budget in SAFE_POST_BUDGETS.items():
                    payload = SAFE_POST_PAYLOADS[endpoint.removeprefix("/Overseer")]
                    with self.subTest(endpoint=endpoint):
                        response, elapsed = _timed(lambda endpoint=endpoint, payload=payload: server.post_json(endpoint, payload))
                        self.assertIsInstance(response, dict)
                        self.assertLess(elapsed, budget)


if __name__ == "__main__":
    unittest.main()
