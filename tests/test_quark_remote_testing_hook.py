import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from overseer.api import make_api_handler
from overseer.remote_testing import remote_testing_status
from overseer.store import SQLiteStore


HOOK = Path(__file__).resolve().parents[1] / "scripts" / "quark_remote_testing_stop_hook.py"


def _write_transcript(path: Path, user_text: str, assistant_text: str) -> None:
    rows = [
        {"type": "event_msg", "payload": {"type": "user_message", "message": user_text}},
        {"type": "response_item", "payload": {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": assistant_text}]}},
    ]
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


class QuarkRemoteTestingHookTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = self.root / "state" / "overseer.sqlite3"
        self.store.parent.mkdir()
        SQLiteStore(self.store).close()
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0), make_api_handler(str(self.store), "ordinary-api-token")
        )
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        host, port = self.server.server_address
        self.api_url = f"http://{host}:{port}"
        self.token_file = self.root / "api-token"
        self.token_file.write_text("ordinary-api-token\n", encoding="utf-8")
        self.token_file.chmod(0o600)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=5)
        self.temporary.cleanup()

    def _run_hook(
        self,
        root: Path,
        transcript: Path,
        dry_run: bool = False,
        *,
        api_url: str | None = None,
        token_file: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        payload = {
            "session_id": "session.test",
            "cwd": str(root / "Overseer"),
            "transcript_path": str(transcript),
            "hook_event_name": "Stop",
        }
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        env["OVERSEER_API_URL"] = api_url or self.api_url
        env["OVERSEER_TOKEN_FILE"] = str(token_file or self.token_file)
        args = [sys.executable, str(HOOK), "--from-stdin", "--stop-check"]
        if dry_run:
            args.append("--dry-run")
        return subprocess.run(args, input=json.dumps(payload), text=True, capture_output=True, env=env, check=False)

    def test_hook_noops_when_final_already_has_quark_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transcript = root / "transcript.jsonl"
            _write_transcript(
                transcript,
                "proceed",
                "Implemented the UI route. Quark remote testing evidence: job-20260726T000000Z passed.",
            )

            result = self._run_hook(root, transcript)

            self.assertEqual(result.returncode, 0)
            self.assertFalse((root / "local-secrets" / "remote-testing").exists())

    def test_hook_noops_for_ui_work_without_explicit_testing_request(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transcript = root / "transcript.jsonl"
            _write_transcript(transcript, "proceed", "Implemented the dashboard UI panel and endpoint wiring.")

            result = self._run_hook(root, transcript, dry_run=True)

            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertFalse((root / "local-secrets" / "remote-testing").exists())

    def test_hook_noops_for_meta_discussion_about_testing_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transcript = root / "transcript.jsonl"
            _write_transcript(
                transcript,
                "the hook should act like a listener and should only test when the originating thread asks for a test",
                "Updated the hook policy and tests.",
            )

            result = self._run_hook(root, transcript, dry_run=True)

            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertFalse((root / "local-secrets" / "remote-testing").exists())

    def test_hook_dry_run_reports_would_queue_explicit_full_ui_regression(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transcript = root / "transcript.jsonl"
            _write_transcript(transcript, "run a remote UI regression test through Tank", "Implemented the dashboard UI panel and endpoint wiring.")

            result = self._run_hook(root, transcript, dry_run=True)

            self.assertEqual(result.returncode, 0)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["action"], "would_queue")
            self.assertEqual(payload["job_type"], "overseer.full_ui_regression")

    def test_hook_dry_run_accepts_explicit_mobile_emulator_regression_request(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transcript = root / "transcript.jsonl"
            _write_transcript(transcript, "run a mobile UI emulator regression test through Quark", "Updated the responsive mobile page.")

            result = self._run_hook(root, transcript, dry_run=True)

            self.assertEqual(result.returncode, 0)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["action"], "would_queue")
            self.assertEqual(payload["job_type"], "overseer.full_ui_regression")

    def test_hook_queues_quark_job_and_crew_message(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transcript = root / "transcript.jsonl"
            _write_transcript(transcript, "have Quark run a remote browser regression test", "Added the authenticated UI page and protected gateway panel.")

            result = self._run_hook(root, transcript)
            status = remote_testing_status(self.root)
            store = SQLiteStore(self.store)
            try:
                messages = store.list_crew_messages()
            finally:
                store.close()

            self.assertEqual(result.returncode, 2)
            self.assertIn("Quark scheduled requested coordinated remote testing", result.stderr)
            self.assertEqual(len(status["pending_jobs"]), 1)
            self.assertEqual(status["pending_jobs"][0]["job_type"], "overseer.full_ui_regression")
            self.assertEqual(messages[0].owner_domain.value, "quark")

    def test_hook_collects_existing_result_for_same_lease(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transcript = root / "transcript.jsonl"
            _write_transcript(transcript, "run the remote UI regression test through Tank", "Fixed the protected gateway UI panel.")
            first = self._run_hook(root, transcript)
            status = remote_testing_status(self.root)
            job_id = status["pending_jobs"][0]["job_id"]
            pending_file = next((self.root / "local-secrets" / "remote-testing" / "jobs" / "pending").glob("*.json"))
            pending_file.unlink()
            done = self.root / "local-secrets" / "remote-testing" / "jobs" / "done"
            done.mkdir(parents=True, exist_ok=True)
            (done / "result.json").write_text(
                json.dumps(
                    {
                        "job_id": job_id,
                        "job_type": "overseer.full_ui_regression",
                        "status": "passed",
                        "stage": "full-ui-regression",
                        "findings": [],
                    }
                ),
                encoding="utf-8",
            )

            second = self._run_hook(root, transcript)

            self.assertEqual(first.returncode, 2)
            self.assertEqual(second.returncode, 2)
            self.assertIn("Quark remote testing evidence collected for requested test", second.stderr)
            self.assertIn("passed", second.stderr)

    def test_hook_fails_closed_when_triggered_and_api_is_unavailable(self):
        transcript = self.root / "unavailable.jsonl"
        _write_transcript(
            transcript,
            "run a remote UI regression test through Tank",
            "Fixed the protected gateway UI panel.",
        )

        result = self._run_hook(
            self.root,
            transcript,
            api_url="http://127.0.0.1:1",
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("unable to coordinate requested remote test", result.stderr)
        self.assertNotIn("ordinary-api-token", result.stderr)

    def test_hook_has_no_authority_store_or_project_source_fallback(self):
        source = HOOK.read_text(encoding="utf-8")

        self.assertNotIn("sqlite3", source)
        self.assertNotIn("SQLiteStore", source)
        self.assertNotIn("import_overseer", source)
        self.assertNotIn("OVERSEER_STORE", source)
        self.assertNotIn("OVERSEER_SOURCE_ROOT", source)

    def test_hook_continuation_does_not_queue_without_existing_job(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transcript = root / "transcript.jsonl"
            _write_transcript(
                transcript,
                "<hook_prompt>Quark scheduled coordinated remote testing before final delivery.</hook_prompt>",
                "Implemented the dashboard UI panel and endpoint wiring.",
            )

            result = self._run_hook(root, transcript)

            self.assertEqual(result.returncode, 0)
            self.assertFalse((root / "local-secrets" / "remote-testing").exists())


if __name__ == "__main__":
    unittest.main()
