import tempfile
import unittest
from pathlib import Path

from overseer.advisories import advisory_status, refresh_advisories_status
from overseer.backup_ops import backup_operations_status, record_backup_job_status, record_restore_test_status, stage_backup_cleanup_request_status
from overseer.compliance_evidence import compliance_evidence_status
from overseer.core import Claim, ClaimStatus, ClaimType, OwnerDomain, Resource, ResourceState, ResourceType, RiskLevel
from overseer.documentation_evidence import documentation_evidence_status
from overseer.health import HealthEvidence, HealthStatus, HealthTarget, ProbeType
from overseer.host import HostCommandObservation, HostInspectionSnapshot
from overseer.identity_evidence import identity_evidence_status
from overseer.identity_ops import identity_rotation_requests_status, stage_identity_rotation_request_status
from overseer.incident_lifecycle import incident_lifecycle_status
from overseer.maintenance_schedule import maintenance_schedules_status, record_maintenance_schedule_status
from overseer.metric_history import capture_metric_history_status, metric_history_status
from overseer.observability_trends import observability_trends_status
from overseer.ops import operations_gap_coverage_status
from overseer.performance_history import performance_history_status
from overseer.security_evidence import security_evidence_status
from overseer.service_evidence import service_evidence_status
from overseer.software_evidence import software_evidence_status
from overseer.storage_evidence import storage_evidence_status
from overseer.store import SQLiteStore
from overseer.usage_evidence import usage_evidence_status
from overseer.usage_limits import LimitKind, UsageContinuationRequest, UsageLimit
from overseer.virtual_evidence import virtual_evidence_status
from overseer.virtual_ops import (
    record_virtual_runtime_status,
    stage_virtual_restore_request_status,
    stage_virtual_snapshot_request_status,
    virtual_operations_status,
)
from overseer.ui import OPERATOR_CONSOLE_HTML
from tests.test_ui_regression import LocalApiHarness


EXPECTED_OPERATION_KEYS = {
    "coverage",
    "operation_records",
    "incidents",
    "risk_register",
    "change_calendar",
    "service_details",
    "service_actions",
    "log_evidence",
    "host_resources",
    "software_inventory",
    "security_drift",
    "network",
    "storage_backup",
    "physical_lifecycle",
    "virtual_runtime",
    "observability",
    "usage_costs",
    "compliance",
    "documentation",
    "identity_access",
}


class OperationsGapCoverageTests(unittest.TestCase):
    def test_gap_coverage_payload_covers_expected_sysops_surfaces(self):
        with tempfile.TemporaryDirectory() as directory:
            payload = operations_gap_coverage_status(Path(directory) / "overseer.sqlite3")

        self.assertEqual(set(payload), EXPECTED_OPERATION_KEYS)
        self.assertGreaterEqual(len(payload["coverage"]), 13)
        self.assertIn("load_1m", payload["host_resources"])
        self.assertIn("dpkg_packages", payload["software_inventory"])
        self.assertIn("dns_servers", payload["network"])
        self.assertIn("local_users", payload["identity_access"])
        self.assertIn("docs_count", payload["documentation"])

    def test_gap_coverage_is_available_through_protected_gateway(self):
        with tempfile.TemporaryDirectory() as directory:
            with LocalApiHarness(Path(directory) / "overseer.sqlite3") as server:
                payload = server.get_json("/Overseer/operations/gap-coverage")

        self.assertEqual(set(payload), EXPECTED_OPERATION_KEYS)
        self.assertTrue(payload["coverage"])

    def test_operation_records_can_be_created_and_filtered(self):
        with tempfile.TemporaryDirectory() as directory:
            with LocalApiHarness(Path(directory) / "overseer.sqlite3") as server:
                created = server.post_json(
                    "/Overseer/operations/records",
                    {
                        "record_id": "ops.test.incident",
                        "kind": "incident",
                        "owner_domain": "sisko",
                        "status": "triaged",
                        "subject": "Test incident",
                        "summary": "Track test incident state.",
                        "severity": "medium",
                        "next_step": "verify closure",
                    },
                )
                records = server.get_json("/Overseer/operations/records?kind=incident&status=triaged")
                coverage = server.get_json("/Overseer/operations/gap-coverage")

        self.assertTrue(created["mutation_performed"])
        self.assertFalse(created["host_mutation_performed"])
        self.assertEqual(records["records"], 1)
        self.assertEqual(records["items"][0]["id"], "ops.test.incident")
        self.assertEqual(coverage["operation_records"]["records"], 1)

    def test_operation_workflows_can_be_staged_and_transitioned(self):
        with tempfile.TemporaryDirectory() as directory:
            with LocalApiHarness(Path(directory) / "overseer.sqlite3") as server:
                catalog = server.get_json("/Overseer/operations/workflows")
                staged = server.post_json(
                    "/Overseer/operations/workflows/stage",
                    {
                        "template_id": "security.baseline",
                        "record_id": "ops.test.security",
                        "requested_by": "sisko",
                    },
                )
                transitioned = server.post_json(
                    "/Overseer/operations/records/transition",
                    {
                        "record_id": "ops.test.security",
                        "status": "waiting_approval",
                        "updated_by": "sisko",
                        "next_step": "review enforcement evidence",
                        "summary_note": "Staged to the approval boundary.",
                    },
                )

        self.assertGreaterEqual(len(catalog["templates"]), 9)
        self.assertFalse(catalog["host_mutation_performed"])
        self.assertEqual(staged["record"]["kind"], "security_baseline")
        self.assertEqual(staged["record"]["status"], "staged")
        self.assertEqual(transitioned["record"]["status"], "waiting_approval")
        self.assertEqual(transitioned["record"]["next_step"], "review enforcement evidence")
        self.assertGreaterEqual(len(transitioned["record"]["metadata"]["transitions"]), 2)
        self.assertFalse(transitioned["host_mutation_performed"])

    def test_incident_lifecycle_and_trends_use_stored_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "state" / "overseer.sqlite3"
            store_path.parent.mkdir()
            with LocalApiHarness(store_path) as server:
                server.post_json(
                    "/Overseer/operations/records",
                    {
                        "record_id": "incident.test",
                        "kind": "incident",
                        "owner_domain": "sisko",
                        "status": "triaged",
                        "subject": "Test incident",
                        "summary": "Track lifecycle.",
                    },
                )
            store = SQLiteStore(store_path)
            try:
                store.save_health_evidence(
                    HealthEvidence(
                        id="evidence.trend",
                        resource_id="svc.trend",
                        target="manual://trend",
                        probe_type=ProbeType.MANUAL,
                        observed_status=HealthStatus.FAILED,
                        owner_domain=OwnerDomain.JULIAN,
                        recovery_required=True,
                        captured_at="2026-07-21T05:50:00Z",
                    )
                )
            finally:
                store.close()

            lifecycle = incident_lifecycle_status(store_path)
            trends = observability_trends_status(store_path)
            metric_capture = capture_metric_history_status(
                store_path,
                Path(directory),
                snapshot_id="metric.trend",
                max_snapshots=10,
            )
            metric_history = metric_history_status(Path(directory))
            with LocalApiHarness(store_path) as server:
                api_lifecycle = server.get_json("/Overseer/incidents/lifecycle")
                api_trends = server.get_json("/Overseer/observability/trends")
                api_metric_history = server.get_json("/Overseer/observability/metric-history")

        self.assertEqual(lifecycle["records"], 1)
        self.assertEqual(api_lifecycle["records"], 1)
        self.assertTrue(lifecycle["post_incident_checklist"])
        self.assertEqual(trends["resource_trends"][0]["resource_id"], "svc.trend")
        self.assertEqual(api_trends["resource_trends"][0]["unhealthy"], 1)
        self.assertEqual(metric_capture["snapshot"]["id"], "metric.trend")
        self.assertEqual(metric_history["snapshots"][0]["attention_resources"], ["svc.trend"])
        self.assertEqual(api_metric_history["snapshot_count"], 1)
        self.assertFalse(trends["host_mutation_performed"])

    def test_service_evidence_redacts_logs_and_builds_validation_checklist(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log_path = root / "service.log"
            log_path.write_text("started\napi_key=secret-value\nAuthorization: Bearer abc123\n", encoding="utf-8")
            store_path = root / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            try:
                store.save_resource(
                    Resource(
                        id="svc.test",
                        name="Test Service",
                        type=ResourceType.SERVICE,
                        owner_domain=OwnerDomain.JULIAN,
                        risk_level=RiskLevel.MEDIUM,
                        identifiers={"unit": "missing-test.service", "config_paths": ["/etc/test/secret.conf"]},
                    )
                )
                store.save_resource(
                    Resource(
                        id="svc.system.test",
                        name="System Test Service",
                        type=ResourceType.SERVICE,
                        owner_domain=OwnerDomain.JULIAN,
                        risk_level=RiskLevel.MEDIUM,
                        identifiers={"unit": "system-test.service", "journal_scope": "system"},
                    )
                )
                store.save_health_target(
                    HealthTarget(
                        id="health.test.log",
                        resource_id="svc.test",
                        name="Test Log",
                        probe_type=ProbeType.LOG,
                        target=str(log_path),
                    )
                )
                store.save_health_evidence(
                    HealthEvidence(
                        id="evidence.test",
                        resource_id="svc.test",
                        target=str(log_path),
                        probe_type=ProbeType.LOG,
                        observed_status=HealthStatus.DEGRADED,
                        owner_domain=OwnerDomain.JULIAN,
                        observed_error="password=should-hide",
                        recovery_required=True,
                        captured_at="2026-07-21T05:20:00Z",
                    )
                )
            finally:
                store.close()

            payload = service_evidence_status(store_path)
            with LocalApiHarness(store_path) as server:
                api_payload = server.get_json("/Overseer/health/service-evidence")
                journal_request = server.post_json(
                    "/Overseer/health/journal-access-requests",
                    {
                        "resource_id": "svc.system.test",
                        "unit": "system-test.service",
                        "requested_by": "julian",
                        "reason": "need system journal evidence for failing service",
                    },
                )

        item = next(row for row in payload["items"] if row["resource_id"] == "svc.test")
        log_sample = "\n".join(item["log_evidence"][0]["sample"])
        self.assertEqual(payload["services"], 2)
        self.assertEqual(api_payload["services"], 2)
        self.assertEqual(item["health"], "degraded")
        self.assertIn("[redacted]", log_sample)
        self.assertNotIn("secret-value", log_sample)
        self.assertNotIn("abc123", log_sample)
        self.assertIn("validation_checklist", item)
        self.assertIn("journal_excerpt", item)
        self.assertIn("journal_access", payload)
        self.assertTrue(payload["journal_access"]["system_review_requests"])
        self.assertEqual(journal_request["record"]["status"], "waiting_approval")
        self.assertFalse(journal_request["host_mutation_performed"])
        self.assertFalse(payload["host_mutation_performed"])

    def test_security_evidence_uses_stored_snapshot_for_firewall_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            try:
                store.save_host_snapshot(
                    HostInspectionSnapshot(
                        id="host.test.snapshot",
                        captured_at="2026-07-21T05:30:00Z",
                        hostname="test-host",
                        os_release={"ID": "debian", "PRETTY_NAME": "Debian"},
                        observations=(
                            HostCommandObservation(
                                name="ss",
                                command=("ss", "-ltnp"),
                                exit_code=0,
                                stdout="LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(('sshd',pid=1,fd=3))",
                            ),
                            HostCommandObservation(
                                name="firewalld-state",
                                command=("firewall-cmd", "--state"),
                                exit_code=0,
                                stdout="running",
                            ),
                            HostCommandObservation(
                                name="firewalld-public-zone",
                                command=("firewall-cmd", "--zone=public", "--list-all"),
                                exit_code=0,
                                stdout="public\n  services: ssh",
                            ),
                        ),
                    )
                )
            finally:
                store.close()

            payload = security_evidence_status(store_path)
            with LocalApiHarness(store_path) as server:
                api_payload = server.get_json("/Overseer/security/evidence")

        self.assertEqual(payload["snapshot_id"], "host.test.snapshot")
        self.assertEqual(api_payload["snapshot_id"], "host.test.snapshot")
        self.assertTrue(payload["listener_exposure"])
        self.assertEqual(payload["listener_exposure"][0]["severity"], "high")
        self.assertTrue(payload["firewall_provenance"])
        self.assertTrue(payload["firewall_policy_diff"])
        self.assertFalse(payload["host_mutation_performed"])

    def test_firewall_policy_diff_can_stage_enforcement_and_ids_review_without_host_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            config = root / "config"
            state.mkdir()
            config.mkdir()
            (config / "desired-firewall.json").write_text(
                '{"rules":[{"action":"deny_tcp","port":9443,"reason":"close unexpected gateway exposure"}]}\n',
                encoding="utf-8",
            )
            store_path = state / "overseer.sqlite3"
            with LocalApiHarness(store_path) as server:
                diff = server.get_json("/Overseer/security/evidence")
                staged = server.post_json(
                    "/Overseer/host/security/firewall-policy/enforcement-plans",
                    {
                        "rule_index": 0,
                        "requested_by": "odo",
                        "reason": "stage desired firewall policy for IDS review",
                    },
                )
                prompt_exists = Path(staged["prompt_path"]).exists()

        self.assertEqual(diff["firewall_policy_diff"][0]["index"], 0)
        self.assertEqual(diff["firewall_policy_diff"][0]["action"], "deny_tcp")
        self.assertEqual(staged["kind"], "firewall_deny_tcp")
        self.assertEqual(staged["target"], "tcp/9443")
        self.assertTrue(staged["ids_review_required_before_approval"])
        self.assertEqual(staged["ids_review_package"]["status"], "prepared")
        self.assertTrue(prompt_exists)
        self.assertFalse(staged["host_mutation_performed"])

    def test_storage_evidence_finds_backup_markers_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "backups").mkdir()
            (root / "backups" / "restore-test.md").write_text("restore evidence\n", encoding="utf-8")
            payload = storage_evidence_status(root)

        self.assertGreaterEqual(payload["mount_count"], 1)
        self.assertEqual(payload["backup_marker_count"], 1)
        self.assertEqual(payload["backup_markers"][0]["path"], "backups/restore-test.md")
        self.assertIn("free_bytes", payload["capacity_summary"])
        self.assertTrue(payload["smart_health"])
        self.assertFalse(payload["host_mutation_performed"])

    def test_backup_operations_registry_stages_jobs_restore_tests_and_cleanup_without_host_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = record_backup_job_status(root, "backup.test", "state/", schedule="daily", retention="7 days")
            restore = record_restore_test_status(root, "restore.test", "backup.test", "backups/restore-test.md")
            cleanup = stage_backup_cleanup_request_status(root, "artifacts", reason="review generated artifacts")
            status = backup_operations_status(root)
            evidence = storage_evidence_status(root)

        self.assertEqual(job["job"]["id"], "backup.test")
        self.assertEqual(restore["restore_test"]["job_id"], "backup.test")
        self.assertEqual(cleanup["cleanup_request"]["status"], "waiting_approval")
        self.assertEqual(status["job_count"], 1)
        self.assertEqual(status["restore_test_count"], 1)
        self.assertEqual(evidence["backup_jobs"][0]["id"], "backup.test")
        self.assertFalse(cleanup["host_mutation_performed"])

    def test_virtual_evidence_detects_port_conflicts_and_cleanup_candidates(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            try:
                for resource_id in ("vm.one", "vm.two"):
                    store.save_resource(
                        Resource(
                            id=resource_id,
                            name=resource_id,
                            type=ResourceType.VIRTUAL_ASSET,
                            owner_domain=OwnerDomain.DAX,
                            risk_level=RiskLevel.MEDIUM,
                            state=ResourceState.AVAILABLE,
                            identifiers={"kind": "vm", "ports": [8766], "snapshot_path": f"/var/lib/{resource_id}.snap"},
                        )
                    )
                store.save_claim(
                    Claim(
                        id="claim.expired",
                        resource_id="vm.one",
                        claim_type=ClaimType.LEASE,
                        owner_thread="thread.test",
                        owner_role=OwnerDomain.DAX,
                        intent="test",
                        requested_action="use vm",
                        risk_level=RiskLevel.MEDIUM,
                        status=ClaimStatus.EXPIRED,
                        port_reservations=frozenset({8766}),
                    )
                )
            finally:
                store.close()

            payload = virtual_evidence_status(store_path)
            with LocalApiHarness(store_path) as server:
                api_payload = server.get_json("/Overseer/virtual/evidence")

        self.assertEqual(payload["runtime_assets"], 2)
        self.assertEqual(api_payload["runtime_assets"], 2)
        self.assertGreaterEqual(payload["port_conflicts"], 1)
        self.assertTrue(payload["runtime_adapters"])
        self.assertEqual(payload["cleanup"][0]["claim_id"], "claim.expired")
        self.assertFalse(payload["host_mutation_performed"])

    def test_virtual_operations_registry_stages_runtime_snapshot_and_restore_without_host_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = record_virtual_runtime_status(
                root,
                "vm.test",
                kind="container",
                state="running",
                adapter="podman",
                ports=(8080,),
                snapshot_hint="/var/lib/vm.test.snap",
            )
            snapshot = stage_virtual_snapshot_request_status(root, "vm.test", snapshot_name="before-update")
            restore = stage_virtual_restore_request_status(root, "vm.test", "/var/lib/vm.test.snap")
            status = virtual_operations_status(root)
            store_path = root / "state" / "overseer.sqlite3"
            evidence = virtual_evidence_status(store_path)
            with LocalApiHarness(store_path) as server:
                api_status = server.get_json("/Overseer/virtual/operations")
                api_snapshot = server.post_json(
                    "/Overseer/virtual/snapshot-requests",
                    {"resource_id": "vm.api", "snapshot_name": "before-ui-test"},
                )

        self.assertEqual(runtime["runtime_record"]["resource_id"], "vm.test")
        self.assertEqual(snapshot["snapshot_request"]["status"], "waiting_approval")
        self.assertEqual(restore["restore_request"]["restore_point"], ".../vm.test.snap")
        self.assertEqual(status["runtime_record_count"], 1)
        self.assertEqual(evidence["runtime_records"][0]["resource_id"], "vm.test")
        self.assertEqual(api_status["runtime_record_count"], 1)
        self.assertEqual(api_snapshot["snapshot_request"]["status"], "waiting_approval")
        self.assertFalse(restore["host_mutation_performed"])

    def test_performance_history_reads_regression_artifacts_without_running_tests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports = root / "artifacts" / "regression"
            reports.mkdir(parents=True)
            (reports / "full-regression-20260725T000000Z.json").write_text(
                """
{
  "status": "passed",
  "started_at": "2026-07-25T00:00:00+00:00",
  "finished_at": "2026-07-25T00:01:00+00:00",
  "duration_seconds": 60.0,
  "suites": [
    {"name": "operator-performance", "status": "passed", "duration_seconds": 2.0},
    {"name": "operator-functional", "status": "passed", "duration_seconds": 10.0},
    {"name": "project-regression", "status": "passed", "duration_seconds": 48.0}
  ]
}
""".strip()
                + "\n",
                encoding="utf-8",
            )
            payload = performance_history_status(root)

        self.assertEqual(payload["report_count"], 1)
        self.assertEqual(payload["reports"][0]["operator_performance_status"], "passed")
        self.assertEqual(payload["reports"][0]["operator_performance_seconds"], 2.0)
        self.assertFalse(payload["host_mutation_performed"])

    def test_documentation_evidence_indexes_runbooks_and_workflows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            docs = root / "docs"
            docs.mkdir()
            (docs / "operator-workflows.md").write_text("# Operator Workflows\n\n### Approve A Request\n", encoding="utf-8")
            (docs / "operations-gap-coverage.md").write_text("# Operations Gap Coverage\n", encoding="utf-8")
            payload = documentation_evidence_status(root)

        self.assertEqual(payload["docs"], 2)
        self.assertTrue(any(row["runbook"] == "operator-workflows.md" and row["present"] for row in payload["runbook_coverage"]))
        self.assertEqual(payload["workflow_coverage"][0]["workflow"], "Approve A Request")
        self.assertFalse(payload["host_mutation_performed"])

    def test_usage_evidence_reports_exhaustion_and_thread_allocation(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            store = SQLiteStore(store_path)
            try:
                store.save_usage_limit(
                    UsageLimit(
                        id="limit.test",
                        resource_id="svc.quota",
                        kind=LimitKind.DAILY_QUOTA,
                        capacity=10,
                        remaining=0,
                        resets_at="2026-07-22T00:00:00Z",
                        window="daily",
                    )
                )
                store.save_usage_continuation_request(
                    UsageContinuationRequest(
                        id="usage.test",
                        limit_id="limit.test",
                        resource_id="svc.quota",
                        owner_thread="thread.test",
                        requested_units=3,
                        intent="continue work",
                    )
                )
            finally:
                store.close()

            payload = usage_evidence_status(store_path)
            with LocalApiHarness(store_path) as server:
                api_payload = server.get_json("/Overseer/usage/evidence")

        self.assertEqual(payload["limits"], 1)
        self.assertEqual(api_payload["limits"], 1)
        self.assertEqual(payload["limit_evidence"][0]["status"], "exhausted")
        self.assertEqual(payload["allocation_by_thread"][0]["requested_units"], 3)
        self.assertFalse(payload["host_mutation_performed"])

    def test_identity_evidence_redacts_secret_files_and_hashes_ssh_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            ssh = home / ".ssh"
            ssh.mkdir(parents=True)
            (ssh / "id_test.pub").write_text("ssh-ed25519 AAAATEST user@example\n", encoding="utf-8")
            (root / "local-secrets").mkdir()
            (root / "local-secrets" / "api-token").write_text("do-not-return\n", encoding="utf-8")
            rotation = stage_identity_rotation_request_status(
                root,
                "/home/god/Documents/Codex Workspace/Overseer/local-secrets/api-token",
                subject_type="secret",
            )
            rotation_status = identity_rotation_requests_status(root)
            payload = identity_evidence_status(root, home)
            store_path = root / "state" / "overseer.sqlite3"
            with LocalApiHarness(store_path) as server:
                api_rotation = server.get_json("/Overseer/identity/rotation-requests")
                api_stage = server.post_json(
                    "/Overseer/identity/rotation-requests",
                    {"subject": "local-secrets/test-token", "subject_type": "secret"},
                )

        self.assertEqual(payload["ssh_public_keys"], 1)
        self.assertTrue(str(payload["ssh_keys"][0]["fingerprint"]).startswith("sha256:"))
        self.assertEqual(payload["secret_files"][0]["content"], "[redacted]")
        self.assertEqual(rotation["request"]["subject"], ".../api-token")
        self.assertEqual(rotation_status["request_count"], 1)
        self.assertEqual(payload["rotation_requests"][0]["status"], "waiting_approval")
        self.assertEqual(api_rotation["request_count"], 1)
        self.assertEqual(api_stage["request"]["status"], "waiting_approval")
        self.assertNotIn("do-not-return", str(payload))
        self.assertFalse(payload["host_mutation_performed"])

    def test_software_evidence_reports_package_lifecycle_surfaces(self):
        payload = software_evidence_status()

        self.assertTrue(payload["package_managers"])
        self.assertIn("apt", payload)
        self.assertTrue(payload["provenance"])
        self.assertIn("metadata_age_days", payload["apt"])
        self.assertTrue(payload["release_notes"])
        self.assertTrue(payload["patch_readiness"])
        self.assertFalse(payload["host_mutation_performed"])

    def test_advisory_feeds_refresh_into_local_cache_without_host_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            def fake_fetch(url, headers, timeout):
                if "services.nvd.nist.gov" in url:
                    return {
                        "vulnerabilities": [
                            {
                                "cve": {
                                    "id": "CVE-2026-0001",
                                    "published": "2026-07-20T00:00:00.000",
                                    "lastModified": "2026-07-20T01:00:00.000",
                                    "vulnStatus": "Analyzed",
                                    "descriptions": [{"lang": "en", "value": "Test openssl advisory."}],
                                    "metrics": {
                                        "cvssMetricV31": [
                                            {"baseSeverity": "HIGH", "cvssData": {"baseScore": 8.1}}
                                        ]
                                    },
                                    "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"}],
                                }
                            }
                        ]
                    }
                return {}

            refreshed = refresh_advisories_status(
                store_path,
                package_names=["openssl"],
                source="nvd",
                max_results_per_package=2,
                requested_by="obrien",
                fetcher=fake_fetch,
            )
            cached = advisory_status(store_path)
            with LocalApiHarness(store_path) as server:
                api_payload = server.get_json("/Overseer/maintenance/advisories")

        self.assertTrue(refreshed["mutation_performed"])
        self.assertFalse(refreshed["host_mutation_performed"])
        self.assertTrue(refreshed["external_request_performed"])
        self.assertEqual(cached["findings"][0]["cve_id"], "CVE-2026-0001")
        self.assertEqual(cached["by_severity"]["high"], 1)
        self.assertTrue(any(row["package"] == "openssl" for row in api_payload["package_summary"]))
        self.assertFalse(api_payload["host_mutation_performed"])

    def test_debian_advisory_feed_parser_uses_package_specific_security_tracker_data(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"

            def fake_fetch(url, headers, timeout):
                return {
                    "apt": {
                        "CVE-2026-0002": {
                            "description": "Test apt advisory.",
                            "releases": {"bookworm": {"status": "open", "urgency": "medium"}},
                        }
                    }
                }

            refreshed = refresh_advisories_status(
                store_path,
                package_names=["apt"],
                source="debian",
                max_results_per_package=1,
                fetcher=fake_fetch,
            )
            cached = advisory_status(store_path, ["apt"])

        self.assertEqual(refreshed["findings"][0]["source"], "debian")
        self.assertEqual(cached["findings"][0]["severity"], "medium")
        self.assertIn("security-tracker.debian.org", cached["findings"][0]["url"])

    def test_compliance_evidence_reports_local_secret_guards(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".gitignore").write_text("local-secrets/\nstate/api-token\n*.sqlite3\n*.db\n", encoding="utf-8")
            payload = compliance_evidence_status(root / "overseer.sqlite3", root)
            with LocalApiHarness(root / "overseer.sqlite3") as server:
                api_payload = server.get_json("/Overseer/compliance/evidence")

        self.assertTrue(all(row["present"] for row in payload["local_secret_guards"]))
        self.assertTrue(api_payload["local_secret_guards"])
        self.assertTrue(payload["desired_state_drift"])
        self.assertTrue(payload["evidence_matrix"])
        self.assertFalse(payload["host_mutation_performed"])

    def test_maintenance_schedules_can_be_recorded_without_host_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            created = record_maintenance_schedule_status(
                store_path,
                schedule_id="schedule.test",
                target="svc.test",
                recurrence="weekly",
                window="Sunday 02:00-04:00",
                risk_level="low",
            )
            listed = maintenance_schedules_status(store_path)
            with LocalApiHarness(store_path) as server:
                api_payload = server.get_json("/Overseer/maintenance/schedules")

        self.assertTrue(created["mutation_performed"])
        self.assertFalse(created["host_mutation_performed"])
        self.assertEqual(listed["schedules"], 1)
        self.assertEqual(api_payload["items"][0]["id"], "schedule.test")

    def test_operator_console_displays_gap_coverage_surfaces(self):
        expected_text = (
            "Operations Coverage",
            "Record Operation",
            "Operation Records",
            "Incident Board",
            "Risk Register",
            "Incident Lifecycle",
            "Incident Sources",
            "Post Incident Checklist",
            "Change Calendar",
            "Maintenance Schedule",
            "Maintenance Schedules",
            "Patch And Software Inventory",
            "Package Manager Evidence",
            "Package Provenance",
            "Patch Readiness",
            "Compliance And Drift",
            "Policy Exceptions",
            "Desired State Baselines",
            "Local Secret Guards",
            "Compliance Evidence Matrix",
            "Storage And Backup",
            "Backup Job Registry",
            "Restore Test Record",
            "Backup Cleanup Request",
            "Backup Jobs",
            "Restore Tests",
            "Backup Cleanup Requests",
            "Mount Health",
            "Backup Markers",
            "Storage Cleanup Candidates",
            "Capacity Summary",
            "Physical Lifecycle",
            "Virtual Runtime Inventory",
            "Virtual Runtime Evidence",
            "Port Pool Evidence",
            "Virtual Cleanup Evidence",
            "Security Baseline Drift",
            "Security Baseline Checks",
            "Firewall Provenance",
            "Listener Exposure Evidence",
            "Protective Plan Provenance",
            "Firewall Policy Enforcement",
            "Identity And Secrets",
            "Identity Access Review",
            "SSH Key Custody",
            "Secret File Custody",
            "Rotation Reminders",
            "Identity Rotation Request",
            "Identity Rotation Requests",
            "Network Gateway Analysis",
            "Host Resources",
            "Service Evidence",
            "Service Validation Checklist",
            "Redacted Service Logs",
            "Log Evidence",
            "System Journal Access Request",
            "Journal Access Status",
            "System Journal Requests",
            "Service Details",
            "Service Actions",
            "Observability And Performance",
            "Cost And Forecast Coverage",
            "Quota Evidence",
            "Continuation Queue Evidence",
            "Usage Allocation By Thread",
            "Documentation Coverage",
            "Runbook Coverage",
            "Workflow Coverage",
            "Stale Document Candidates",
            "ADR Index",
            "Release Index",
            "Health Trend History",
            "Metric History Capture",
            "Metric History Snapshots",
            "Performance Regression History",
            "Host Snapshot Trend",
            "Journal Excerpts",
            "SMART Health",
            "Runtime Adapter Availability",
            "Firewall Policy Diff",
            "Release Note References",
            "Advisory Refresh",
            "Advisory Feed Status",
            "Advisory Sources",
            "Advisory Package Summary",
            "Advisory Severity",
            "Advisory Findings",
            "Desired State Drift",
        )
        self.assertIn('operations: "/operations/gap-coverage"', OPERATOR_CONSOLE_HTML)
        for text in expected_text:
            with self.subTest(text=text):
                self.assertIn(text, OPERATOR_CONSOLE_HTML)


if __name__ == "__main__":
    unittest.main()
