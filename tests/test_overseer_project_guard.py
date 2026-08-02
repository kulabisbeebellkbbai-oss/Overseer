from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).parents[1] / "scripts/overseer_project_guard.py"
SPEC = importlib.util.spec_from_file_location("overseer_project_guard", SCRIPT)
assert SPEC and SPEC.loader
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class OverseerProjectGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = self.root / "overseer.sqlite3"
        self.findings = self.root / "findings.json"
        connection = sqlite3.connect(self.store)
        connection.executescript(
            """
            CREATE TABLE crew_messages (id TEXT PRIMARY KEY, owner_domain TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE admin_change_plans (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE claims (id TEXT PRIMARY KEY, resource_id TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE usage_continuation_requests (id TEXT PRIMARY KEY, limit_id TEXT NOT NULL, resource_id TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE backup_provisioning_plans (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE storage_root_authorizations (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, root_id TEXT NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL);
            """
        )
        record = {
            "id": "crew.kira.real",
            "owner_domain": "kira",
            "status": "acknowledged",
            "review_status": "approved",
            "related_plan_id": "backup-provision.real",
            "related_resource_id": "storage.real",
            "requested_by": "TheUnderdark",
            "decided_by": "kira",
        }
        connection.execute(
            "INSERT INTO crew_messages (id, owner_domain, payload) VALUES (?, ?, ?)",
            (record["id"], record["owner_domain"], json.dumps(record)),
        )
        connection.commit()
        connection.close()
        self.environment = patch.dict(os.environ, {
            "OVERSEER_STORE": str(self.store),
            "OVERSEER_EVIDENCE_FINDINGS": str(self.findings),
        })
        self.environment.start()

    def tearDown(self) -> None:
        self.environment.stop()
        self.temporary.cleanup()

    def transcript(self, name: str, assistant: str, tool: str | None = None) -> Path:
        path = self.root / f"{name}.jsonl"
        entries = [
            {"type": "event_msg", "payload": {"type": "user_message", "message": "Fix the local Overseer service and storage workflow."}},
        ]
        if tool is not None:
            entries.append({"type": "response_item", "payload": {"type": "function_call_output", "output": tool}})
        entries.append({"type": "event_msg", "payload": {"type": "agent_message", "message": assistant}})
        path.write_text("".join(json.dumps(item) + "\n" for item in entries), encoding="utf-8")
        return path

    def payload(self, transcript: Path) -> dict[str, str]:
        return {"transcript_path": str(transcript), "cwd": str(Path(__file__).parents[1])}

    def test_stop_accepts_exact_authoritative_record(self) -> None:
        claim = {
            "record_type": "crew_message",
            "record_id": "crew.kira.real",
            "expected": {
                "owner_domain": "kira",
                "status": "acknowledged",
                "review_status": "approved",
                "related_plan_id": "backup-provision.real",
                "requested_by": "TheUnderdark",
            },
        }
        transcript = self.transcript("exact", f"Fixed the workflow.\nOverseer evidence: {json.dumps(claim, sort_keys=True)}")
        self.assertEqual(guard.stop_check(self.payload(transcript)), 0)
        self.assertFalse(self.findings.exists())

    def test_stop_denies_missing_authoritative_record(self) -> None:
        claim = {
            "record_type": "crew_message",
            "record_id": "crew.kira.fake",
            "expected": {"owner_domain": "kira", "status": "acknowledged", "review_status": "approved", "requested_by": "TheUnderdark"},
        }
        transcript = self.transcript("missing", f"Fixed the workflow.\nOverseer evidence: {json.dumps(claim)}")
        self.assertEqual(guard.stop_check(self.payload(transcript)), 2)
        state = json.loads(self.findings.read_text(encoding="utf-8"))
        finding = next(iter(state["findings"].values()))
        self.assertEqual(finding["failure_class"], "not_found")
        self.assertEqual(finding["occurrence_count"], 1)

    def test_stop_denies_mismatched_authoritative_fields(self) -> None:
        claim = {
            "record_type": "crew_message",
            "record_id": "crew.kira.real",
            "expected": {"owner_domain": "odo", "status": "acknowledged", "review_status": "approved", "requested_by": "TheUnderdark", "related_plan_id": "backup-provision.fake"},
        }
        result = guard.verify_claim(claim, self.store)
        self.assertFalse(result["accepted"])
        self.assertEqual(result["failure_class"], "field_mismatch")
        self.assertEqual(result["mismatches"], ["owner_domain", "related_plan_id"])

    def test_stop_denies_claim_that_omits_required_exact_fields(self) -> None:
        claim = {"record_type": "crew_message", "record_id": "crew.kira.real", "expected": {"owner_domain": "kira"}}
        result = guard.verify_claim(claim, self.store)
        self.assertFalse(result["accepted"])
        self.assertEqual(result["failure_class"], "malformed")
        self.assertIn("required exact fields missing", result["reason"])

    def test_repeated_forged_record_escalates_once_to_odo(self) -> None:
        claim = {
            "record_type": "crew_message",
            "record_id": "crew.kira.fake",
            "expected": {"owner_domain": "kira", "status": "acknowledged", "review_status": "approved", "requested_by": "TheUnderdark"},
        }
        assistant = f"Fixed the workflow.\nOverseer evidence: {json.dumps(claim)}"
        with patch.object(guard, "escalate_to_odo", return_value="crew.odo.hook-evidence.test") as escalate:
            self.assertEqual(guard.stop_check(self.payload(self.transcript("attempt-one", assistant))), 2)
            self.assertEqual(guard.stop_check(self.payload(self.transcript("attempt-two", assistant))), 2)
            self.assertEqual(guard.stop_check(self.payload(self.transcript("attempt-three", assistant))), 2)
        escalate.assert_called_once()
        state = json.loads(self.findings.read_text(encoding="utf-8"))
        finding = next(iter(state["findings"].values()))
        self.assertEqual(finding["occurrence_count"], 3)
        self.assertEqual(finding["odo_message_id"], "crew.odo.hook-evidence.test")

    def test_same_stop_replay_is_idempotent(self) -> None:
        claim = {"record_type": "crew_message", "record_id": "crew.kira.fake", "expected": {"owner_domain": "kira", "status": "acknowledged", "review_status": "approved", "requested_by": "TheUnderdark"}}
        transcript = self.transcript("same-attempt", f"Fixed it.\nOverseer evidence: {json.dumps(claim)}")
        self.assertEqual(guard.stop_check(self.payload(transcript)), 2)
        self.assertEqual(guard.stop_check(self.payload(transcript)), 2)
        state = json.loads(self.findings.read_text(encoding="utf-8"))
        finding = next(iter(state["findings"].values()))
        self.assertEqual(finding["occurrence_count"], 1)
        self.assertIsNone(finding["odo_message_id"])

    def test_failed_tool_output_and_unstructured_reference_do_not_pass(self) -> None:
        transcript = self.transcript(
            "failed-tool",
            "Fixed the service. Overseer evidence: crew.kira.fake",
            tool="command failed: crew.kira.real",
        )
        self.assertEqual(guard.stop_check(self.payload(transcript)), 2)


if __name__ == "__main__":
    unittest.main()
