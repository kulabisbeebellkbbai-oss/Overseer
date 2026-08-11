import json
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from http.server import ThreadingHTTPServer

from overseer.api import make_api_handler
from overseer.roadex_approval_fixture import (
    approve_roadex_approval_fixture_api,
    stage_roadex_approval_fixture_api,
)
from overseer.roadex_approval_status import roadex_approval_status
from overseer.store import (
    ROADEX_APPROVAL_FIXTURE_SCHEMA_VERSION,
    SQLiteStore,
)


class RoadexApprovalFixtureTests(unittest.TestCase):
    def test_forward_schema_history_is_current_without_repeated_migration(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = str(Path(directory) / "state.sqlite3")
            with SQLiteStore(store_path) as store:
                store._connection.execute("DROP TABLE roadex_approval_fixtures")
                store._connection.execute("DELETE FROM schema_migrations")
                store._connection.executemany(
                    "INSERT INTO schema_migrations(version, description, applied_at) "
                    "VALUES (?, ?, ?)",
                    (
                        (1, "first migration", "2026-08-01T00:00:00+00:00"),
                        (2, "bootstrap JSON payload store", "2026-08-02T00:00:00+00:00"),
                        (10, "future migration", "2026-08-10T00:00:00+00:00"),
                    ),
                )
                store._connection.commit()

            with SQLiteStore(store_path) as store:
                first_history = store.list_schema_migrations()
                self.assertIsNotNone(
                    store._connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' "
                        "AND name='roadex_approval_fixtures'"
                    ).fetchone()
                )

            with patch.object(
                SQLiteStore,
                "initialize",
                side_effect=AssertionError("forward schema history was rerun"),
            ):
                with SQLiteStore(store_path) as store:
                    second_history = store.list_schema_migrations()

            self.assertEqual(first_history, second_history)
            self.assertEqual([row.version for row in first_history[:3]], [1, 2, 10])

    def test_fixture_schema_migration_rolls_back_ddl_and_history_then_retries(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = str(Path(directory) / "state.sqlite3")
            with SQLiteStore(store_path) as store:
                store._connection.execute("DROP TABLE roadex_approval_fixtures")
                store._connection.execute("DELETE FROM schema_migrations")
                store._connection.execute(
                    "INSERT INTO schema_migrations(version, description, applied_at) "
                    "VALUES (2, 'bootstrap JSON payload store', '2026-08-09T00:00:00+00:00')"
                )
                store._connection.commit()

            class FailingMigrationStore(SQLiteStore):
                def _record_schema_migration(self, version, description):
                    if version == ROADEX_APPROVAL_FIXTURE_SCHEMA_VERSION:
                        raise RuntimeError("injected fixture migration failure")
                    return super()._record_schema_migration(version, description)

            with self.assertRaisesRegex(RuntimeError, "injected fixture migration failure"):
                FailingMigrationStore(store_path)

            with sqlite3.connect(store_path) as connection:
                table = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                    ("roadex_approval_fixtures",),
                ).fetchone()
                self.assertIsNone(table)
                self.assertEqual(
                    [row[0] for row in connection.execute(
                        "SELECT version FROM schema_migrations ORDER BY version"
                    ).fetchall()],
                    [2],
                )

            with SQLiteStore(store_path) as store:
                self.assertIsNotNone(
                    store._connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' "
                        "AND name='roadex_approval_fixtures'"
                    ).fetchone()
                )
                self.assertEqual(
                    [row.version for row in store.list_schema_migrations()[:2]],
                    [2, 3],
                )

    def test_c901_schema_is_upgraded_idempotently_before_fixture_use(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = str(Path(directory) / "state.sqlite3")
            with SQLiteStore(store_path) as store:
                store._connection.execute("DROP TABLE roadex_approval_fixtures")
                store._connection.execute("DELETE FROM schema_migrations")
                store._connection.execute(
                    "INSERT INTO schema_migrations(version, description, applied_at) "
                    "VALUES (2, 'bootstrap JSON payload store', '2026-08-09T00:00:00+00:00')"
                )
                store._connection.commit()

            payload = {
                "projectId": "project.fixture",
                "workspaceId": "workspace.fixture",
                "resourceRef": "fixture.harmless",
                "subject": "C901 schema migration",
            }
            locator = stage_roadex_approval_fixture_api(store_path, payload)
            with SQLiteStore(store_path) as store:
                table = store._connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                    ("roadex_approval_fixtures",),
                ).fetchone()
                self.assertIsNotNone(table)
                self.assertEqual(store.list_roadex_approval_fixtures()[0].status, "pending")
                self.assertEqual(
                    [row.version for row in store.list_schema_migrations()[:2]],
                    [2, 3],
                )
            approved = approve_roadex_approval_fixture_api(
                store_path,
                {"approvalRef": locator["approvalRef"]},
                human_identity="fixture-human",
            )
            self.assertEqual(approved["decision"], "approved")
            replay = approve_roadex_approval_fixture_api(
                store_path,
                {"approvalRef": locator["approvalRef"]},
                human_identity="fixture-human",
            )
            self.assertEqual(replay["decision"], "approved")
            with self.assertRaisesRegex(ValueError, "immutable"):
                approve_roadex_approval_fixture_api(
                    store_path,
                    {"approvalRef": locator["approvalRef"]},
                    human_identity="different-human",
                )

    def test_stage_rolls_back_source_when_binding_persistence_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = str(Path(directory) / "state.sqlite3")
            payload = {
                "projectId": "project.fixture",
                "workspaceId": "workspace.fixture",
                "resourceRef": "fixture.harmless",
                "subject": "Harmless smoke",
            }
            with patch.object(
                SQLiteStore,
                "save_roadex_approval_binding",
                side_effect=RuntimeError("injected binding failure"),
            ):
                with self.assertRaisesRegex(RuntimeError, "injected binding failure"):
                    stage_roadex_approval_fixture_api(store_path, payload)
            with SQLiteStore(store_path) as store:
                self.assertEqual(store.list_roadex_approval_fixtures(), ())
                count = store._connection.execute(
                    "SELECT COUNT(*) AS count FROM roadex_approval_bindings"
                ).fetchone()["count"]
                self.assertEqual(count, 0)

    def test_stage_is_atomic_and_projects_pending_without_operational_records(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = str(Path(directory) / "state.sqlite3")
            locator = stage_roadex_approval_fixture_api(
                store_path,
                {
                    "projectId": "project.fixture",
                    "workspaceId": "workspace.fixture",
                    "resourceRef": "fixture.harmless",
                    "subject": "Harmless Roadex approval continuation smoke",
                },
            )

            self.assertEqual(locator["provider"], "overseer")
            self.assertEqual(locator["authorityClass"], "project-workflow")
            self.assertEqual(
                set(locator),
                {
                    "provider",
                    "approvalRef",
                    "projectId",
                    "workspaceId",
                    "resourceRef",
                    "authorityClass",
                    "scopeDigest",
                },
            )
            projection = roadex_approval_status(store_path, locator["approvalRef"])
            self.assertEqual(projection["decision"], "pending")
            self.assertEqual(projection["sourceKind"], "roadex-approval-fixture")

            with SQLiteStore(store_path) as store:
                source = store.load_roadex_approval_fixture(locator["approvalRef"])
                binding = store.load_roadex_approval_binding(locator["approvalRef"])
                self.assertEqual(source.id, binding.source_id)
                for table in (
                    "admin_change_plans",
                    "backup_provisioning_plans",
                    "storage_execution_requests",
                    "storage_dispatch_records",
                ):
                    exists = store._connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                        (table,),
                    ).fetchone()
                    count = 0 if exists is None else store._connection.execute(
                        f"SELECT COUNT(*) AS count FROM {table}"
                    ).fetchone()["count"]
                    self.assertEqual(count, 0)

    def test_stage_rejects_authority_shaped_or_session_fields_without_writes(self):
        forbidden = (
            "outcome",
            "schema",
            "accessor",
            "decisionMapping",
            "scopeDigest",
            "console",
            "sessionId",
            "managedThreadId",
            "runnerRunId",
        )
        for field in forbidden:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                store_path = str(Path(directory) / "state.sqlite3")
                payload = {
                    "projectId": "project.fixture",
                    "workspaceId": "workspace.fixture",
                    "resourceRef": "fixture.harmless",
                    "subject": "Harmless smoke",
                    field: "caller-controlled",
                }
                with self.assertRaisesRegex(ValueError, "exact fields"):
                    stage_roadex_approval_fixture_api(store_path, payload)
                with SQLiteStore(store_path) as store:
                    self.assertEqual(store.list_roadex_approval_fixtures(), ())

    def test_human_approval_is_non_executing_and_changes_only_fixture_projection(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = str(Path(directory) / "state.sqlite3")
            locator = stage_roadex_approval_fixture_api(
                store_path,
                {
                    "projectId": "project.fixture",
                    "workspaceId": "workspace.fixture",
                    "resourceRef": "fixture.harmless",
                    "subject": "Harmless smoke",
                },
            )
            before = roadex_approval_status(store_path, locator["approvalRef"])
            approved = approve_roadex_approval_fixture_api(
                store_path,
                {"approvalRef": locator["approvalRef"]},
                human_identity="fixture-human",
            )
            after = roadex_approval_status(store_path, locator["approvalRef"])

            self.assertEqual(approved["decision"], "approved")
            self.assertEqual(after["decision"], "approved")
            self.assertNotEqual(before["decisionVersion"], after["decisionVersion"])
            with SQLiteStore(store_path) as store:
                for table in (
                    "admin_change_plans",
                    "backup_provisioning_plans",
                    "storage_execution_requests",
                    "storage_dispatch_records",
                    "storage_execution_results",
                ):
                    exists = store._connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                        (table,),
                    ).fetchone()
                    count = 0 if exists is None else store._connection.execute(
                        f"SELECT COUNT(*) AS count FROM {table}"
                    ).fetchone()["count"]
                    self.assertEqual(count, 0)


class RoadexApprovalFixtureApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.store_path = str(Path(self.temporary.name) / "state.sqlite3")
        handler = make_api_handler(
            self.store_path,
            "agent-secret",
            human_approval_token="human-secret",
            human_approval_identity="fixture-human",
        )
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.url = f"http://{host}:{port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temporary.cleanup()

    def _post(self, path, payload, token):
        request = Request(
            self.url + path,
            data=json.dumps(payload).encode(),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())

    def _post_status(self, path, payload, token):
        try:
            return self._post(path, payload, token)[0]
        except HTTPError as error:
            return error.code

    def test_stage_requires_agent_auth_and_approve_requires_distinct_human_auth(self):
        stage_payload = {
            "projectId": "project.fixture",
            "workspaceId": "workspace.fixture",
            "resourceRef": "fixture.harmless",
            "subject": "Harmless smoke",
        }
        self.assertEqual(
            self._post_status("/roadex/approval-fixtures/stage", stage_payload, "human-secret"),
            401,
        )
        status, locator = self._post(
            "/roadex/approval-fixtures/stage", stage_payload, "agent-secret"
        )
        self.assertEqual(status, 200)
        approval = {"approvalRef": locator["approvalRef"]}
        self.assertEqual(
            self._post_status("/roadex/approval-fixtures/approve", approval, "agent-secret"),
            403,
        )
        self.assertEqual(
            self._post_status(
                "/roadex/approval-fixtures/approve",
                {**approval, "outcome": "approved"},
                "human-secret",
            ),
            400,
        )
        status, projection = self._post(
            "/roadex/approval-fixtures/approve", approval, "human-secret"
        )
        self.assertEqual(status, 200)
        self.assertEqual(projection["decision"], "approved")


if __name__ == "__main__":
    unittest.main()
