import re
import tempfile
import unittest
from pathlib import Path
from urllib.error import HTTPError

from overseer.ui import OPERATOR_CONSOLE_HTML
from tests.test_ui_regression import LocalApiHarness


EXPECTED_VIEWS = {
    "overview": {
        "title": "Strategic Operations",
        "actions": {"dispatch-crew-messages", "send-crew-message"},
        "officers": {"Sisko", "Kira", "O'Brien", "Odo", "Quark", "Dax", "Julian"},
    },
    "admin": {
        "title": "Maintenance Operations",
        "actions": {
            "discover-user-services",
            "plan-package-updates",
            "run-package-maintenance-cycle",
            "record-maintenance-schedule",
            "refresh-advisories",
            "plan-admin-change",
            "approve-admin-change",
            "execute-admin-change",
            "cancel-admin-change",
            "request-admin-adapter-enablement",
            "approve-admin-adapter-enablement",
            "request-admin-archive",
            "approve-admin-archive",
            "archive-admin-history",
            "request-admin-restore",
            "approve-admin-restore",
            "unarchive-admin-history",
            "build-policy-profile",
            "request-policy-warning",
            "approve-policy-warning",
            "send-crew-message",
        },
        "officers": {"Sisko", "O'Brien"},
    },
    "assets": {
        "title": "Asset Control",
        "actions": {
            "discover-physical",
            "discover-storage",
            "discover-listeners",
            "register-resource",
            "record-backup-job",
            "record-restore-test",
            "stage-backup-cleanup-request",
            "send-crew-message",
        },
        "officers": {"Kira", "Dax"},
    },
    "claims": {
        "title": "Deconfliction Matrix",
        "actions": {
            "request-claim",
            "approve-claim",
            "activate-claim",
            "release-claim",
            "request-claim-cleanup",
            "approve-claim-cleanup",
            "execute-claim-cleanup",
            "record-virtual-runtime",
            "stage-virtual-snapshot-request",
            "stage-virtual-restore-request",
            "send-crew-message",
        },
        "officers": {"Dax"},
    },
    "security": {
        "title": "Security Board",
        "actions": {
            "inspect-host",
            "plan-listener-queue-remediations",
            "plan-host-security-remediation",
            "record-source-review",
            "plan-source-block",
            "stage-firewall-policy-enforcement",
            "stage-identity-rotation-request",
            "prepare-ids-review-package",
            "export-ids-review-prompt",
            "dispatch-ids-review-package",
            "record-ids-review-result",
            "send-crew-message",
        },
        "officers": {"Odo"},
    },
    "health": {
        "title": "Diagnostics Lab",
        "actions": {
            "run-health-probes",
            "register-health-target",
            "stage-journal-access-request",
            "capture-metric-history",
            "send-crew-message",
        },
        "officers": {"Julian"},
    },
    "usage": {
        "title": "Quota Exchange",
        "actions": {
            "discover-codex-threads",
            "dispatch-usage-continuations",
            "record-usage-limit",
            "request-usage-continuation",
            "send-crew-message",
        },
        "officers": {"Quark"},
    },
    "ezri": {
        "title": "Knowledge Base",
        "actions": {
            "documents-search",
            "documents-list-notes",
            "documents-write-note",
            "documents-capture-knowledge",
            "send-crew-message",
        },
        "officers": {"Ezri"},
    },
    "audit": {
        "title": "Audit Log",
        "actions": {"send-crew-message"},
        "officers": {"Sisko"},
    },
}


ACTION_ROUTES = {
    "activate-claim": ("POST", "/claims/activate"),
    "approve-admin-adapter-enablement": ("POST", "/admin/adapter-enablement-requests/approve"),
    "approve-admin-archive": ("POST", "/admin/history-archive-requests/approve"),
    "approve-admin-change": ("POST", "/admin/approve"),
    "approve-admin-restore": ("POST", "/admin/history-restore-requests/approve"),
    "approve-claim": ("POST", "/claims/approve"),
    "approve-claim-cleanup": ("POST", "/claims/cleanup-requests/approve"),
    "approve-policy-warning": ("POST", "/admin/policy-warning-requests/approve"),
    "archive-admin-history": ("POST", "/admin/history-archive"),
    "build-policy-profile": ("POST", "/admin/policy-customization-helper/profile"),
    "cancel-admin-change": ("POST", "/admin/cancel"),
    "capture-metric-history": ("POST", "/observability/metric-history/capture"),
    "discover-codex-threads": ("POST", "/codex-projects/discover-threads"),
    "discover-listeners": ("POST", "/virtual/discover-listeners"),
    "discover-physical": ("POST", "/physical/discover"),
    "discover-storage": ("POST", "/physical/discover-storage"),
    "discover-user-services": ("POST", "/services/discover-user"),
    "dispatch-crew-messages": ("POST", "/crew/dispatch"),
    "dispatch-ids-review-package": ("POST", "/host/security/ids-review-packages/dispatch"),
    "dispatch-usage-continuations": ("POST", "/usage/continuation-dispatches"),
    "documents-capture-knowledge": ("POST", "/documents/knowledge-capture"),
    "documents-list-notes": ("GET", "/documents/notes"),
    "documents-search": ("POST", "/documents/search"),
    "documents-write-note": ("POST", "/documents/notes"),
    "execute-admin-change": ("POST", "/admin/execute"),
    "execute-claim-cleanup": ("POST", "/claims/cleanup-requests/execute"),
    "export-ids-review-prompt": ("POST", "/host/security/ids-review-packages/prompts"),
    "inspect-host": ("POST", "/host/inspect"),
    "plan-admin-change": ("POST", "/admin/plans"),
    "plan-host-security-remediation": ("POST", "/host/security/remediations/plans"),
    "plan-listener-queue-remediations": ("POST", "/host/security/listener-review-queue/remediation-plans"),
    "plan-package-updates": ("POST", "/maintenance/package-update-plans"),
    "plan-source-block": ("POST", "/host/security/source-reviews/block-plans"),
    "prepare-ids-review-package": ("POST", "/host/security/ids-review-packages"),
    "stage-firewall-policy-enforcement": ("POST", "/host/security/firewall-policy/enforcement-plans"),
    "stage-identity-rotation-request": ("POST", "/identity/rotation-requests"),
    "record-backup-job": ("POST", "/storage/backup-jobs"),
    "record-ids-review-result": ("POST", "/host/security/ids-review-packages/results"),
    "record-maintenance-schedule": ("POST", "/maintenance/schedules"),
    "record-restore-test": ("POST", "/storage/restore-tests"),
    "refresh-advisories": ("POST", "/maintenance/advisories/refresh"),
    "record-operation": ("POST", "/operations/records"),
    "record-source-review": ("POST", "/host/security/source-reviews"),
    "record-usage-limit": ("POST", "/usage-limits"),
    "record-virtual-runtime": ("POST", "/virtual/runtime-records"),
    "register-health-target": ("POST", "/health-targets"),
    "register-resource": ("POST", "/resources"),
    "release-claim": ("POST", "/claims/release"),
    "request-admin-adapter-enablement": ("POST", "/admin/adapter-enablement-requests"),
    "request-admin-archive": ("POST", "/admin/history-archive-requests"),
    "request-admin-restore": ("POST", "/admin/history-restore-requests"),
    "request-claim": ("POST", "/claims/request"),
    "request-claim-cleanup": ("POST", "/claims/cleanup-requests"),
    "request-policy-warning": ("POST", "/admin/policy-warning-requests"),
    "request-usage-continuation": ("POST", "/usage/continuation-requests"),
    "run-package-maintenance-cycle": ("POST", "/maintenance/package-maintenance-cycle"),
    "run-health-probes": ("POST", "/health/probes/run"),
    "send-crew-message": ("POST", "/crew/messages"),
    "stage-backup-cleanup-request": ("POST", "/storage/cleanup-requests"),
    "stage-journal-access-request": ("POST", "/health/journal-access-requests"),
    "stage-operation-workflow": ("POST", "/operations/workflows/stage"),
    "stage-virtual-restore-request": ("POST", "/virtual/restore-requests"),
    "stage-virtual-snapshot-request": ("POST", "/virtual/snapshot-requests"),
    "transition-operation": ("POST", "/operations/records/transition"),
    "unarchive-admin-history": ("POST", "/admin/history-unarchive"),
}

SAFE_POST_PAYLOADS = {
    "/resources": {
        "resource_id": "resource.ui.full",
        "name": "UI Full Resource",
        "resource_type": "virtual_asset",
        "owner_domain": "dax",
        "risk_level": "low",
        "identifiers": {"kind": "ui-test"},
    },
    "/claims/request": {
        "claim_id": "claim.ui.full",
        "resource_id": "resource.ui.full",
        "claim_type": "lease",
        "owner_thread": "ui-full-regression",
        "owner_role": "dax",
        "intent": "exercise disposable UI workflow",
        "requested_action": "observe test resource",
        "risk_level": "low",
    },
    "/usage-limits": {
        "limit_id": "limit.ui.full",
        "resource_id": "resource.ui.full",
        "kind": "daily_quota",
        "capacity": 10,
        "remaining": 1,
        "window": "daily",
        "confidence": 1,
    },
    "/usage/continuation-requests": {
        "request_id": "usage.ui.full",
        "limit_id": "limit.ui.full",
        "resource_id": "resource.ui.full",
        "owner_thread": "ui-full-regression",
        "requested_units": 1,
        "intent": "exercise disposable usage continuation workflow",
        "risk_level": "low",
        "requested_by": "quark",
    },
    "/usage/continuation-dispatches": {"dispatched_by": "quark", "resume_codex_projects": False},
    "/health-targets": {
        "target_id": "health.ui.full",
        "resource_id": "resource.ui.full",
        "name": "UI Full Health",
        "probe_type": "manual",
        "target": "manual://ui-full-regression",
    },
    "/health/probes/run": {"retention_per_target": 5},
    "/health/journal-access-requests": {
        "resource_id": "resource.ui.full",
        "unit": "disposable-ui-test.service",
        "requested_by": "julian",
        "reason": "exercise disposable journal access staging workflow",
    },
    "/storage/backup-jobs": {
        "job_id": "backup.ui.full",
        "target": "state/",
        "schedule": "manual",
        "retention": "one test generation",
        "requested_by": "kira",
        "risk_level": "low",
        "status": "staged",
    },
    "/storage/restore-tests": {
        "test_id": "restore.ui.full",
        "job_id": "backup.ui.full",
        "restore_point": "backups/restore-test.md",
        "status": "planned",
        "validated_by": "kira",
    },
    "/storage/cleanup-requests": {
        "path": "artifacts",
        "requested_by": "kira",
        "reason": "exercise disposable backup cleanup request workflow",
    },
    "/virtual/runtime-records": {
        "resource_id": "vm.ui.full",
        "kind": "container",
        "state": "running",
        "adapter": "manual",
        "ports": [8080],
        "snapshot_hint": "snapshots/vm.ui.full.before",
        "notes": "exercise disposable virtual runtime workflow",
    },
    "/virtual/snapshot-requests": {
        "resource_id": "vm.ui.full",
        "snapshot_name": "before-ui-full-regression",
        "requested_by": "dax",
        "reason": "exercise disposable virtual snapshot staging workflow",
    },
    "/virtual/restore-requests": {
        "resource_id": "vm.ui.full",
        "restore_point": "snapshots/vm.ui.full.before",
        "requested_by": "dax",
        "reason": "exercise disposable virtual restore staging workflow",
    },
    "/identity/rotation-requests": {
        "subject": "local-secrets/test-token",
        "subject_type": "secret",
        "requested_by": "odo",
        "reason": "exercise disposable identity rotation staging workflow",
        "urgency": "medium",
    },
    "/crew/messages": {
        "owner_domain": "julian",
        "subject": "UI full regression",
        "message": "Exercise disposable crew channel workflow.",
        "priority": "low",
        "requested_by": "ui-test",
    },
    "/crew/dispatch": {"dispatched_by": "sisko", "owner_domain": "julian"},
    "/admin/plans": {
        "plan_id": "admin.ui.full",
        "kind": "user_service_restart",
        "target": "disposable-ui-test.service",
        "reason": "route smoke only; do not execute",
        "current_state": "inactive",
    },
    "/admin/approve": {"plan_id": "admin.ui.full", "approved_by": "sisko"},
    "/admin/policy-customization-helper/profile": {
        "answers": {"name": "ui-full-regression", "description": "Disposable UI regression profile."}
    },
    "/operations/records": {
        "record_id": "ops.ui.full",
        "kind": "incident",
        "owner_domain": "sisko",
        "status": "open",
        "subject": "UI full regression operation",
        "summary": "Disposable operation record for route coverage.",
        "severity": "low",
        "next_step": "close after regression",
    },
    "/operations/records/transition": {
        "record_id": "ops.ui.full",
        "status": "verified",
        "updated_by": "sisko",
        "next_step": "close after regression",
        "summary_note": "Disposable operation record verified.",
    },
    "/operations/workflows/stage": {
        "template_id": "incident.lifecycle",
        "record_id": "ops.ui.workflow",
        "requested_by": "sisko",
    },
    "/maintenance/schedules": {
        "schedule_id": "schedule.ui.full",
        "target": "disposable-ui-test.service",
        "recurrence": "weekly",
        "window": "Sunday 02:00-04:00",
        "timezone": "UTC",
        "status": "active",
        "owner_domain": "obrien",
        "risk_level": "low",
    },
    "/maintenance/advisories/refresh": {
        "packages": ["openssl"],
        "source": "nvd",
        "max_results_per_package": 1,
        "requested_by": "obrien",
        "dry_run": True,
    },
    "/observability/metric-history/capture": {
        "snapshot_id": "metric.ui.full",
        "requested_by": "julian",
        "notes": "exercise disposable metric history workflow",
        "max_snapshots": 5,
    },
}

ROUTES_EXPECTED_TO_REQUIRE_FIXTURES = {
    "/admin/adapter-enablement-requests/approve",
    "/admin/cancel",
    "/admin/execute",
    "/admin/history-archive",
    "/admin/history-archive-requests",
    "/admin/history-archive-requests/approve",
    "/admin/history-restore-requests",
    "/admin/history-restore-requests/approve",
    "/admin/history-unarchive",
    "/admin/policy-warning-requests",
    "/admin/policy-warning-requests/approve",
    "/claims/activate",
    "/claims/approve",
    "/claims/cleanup-requests",
    "/claims/cleanup-requests/approve",
    "/claims/cleanup-requests/execute",
    "/claims/release",
    "/host/security/ids-review-packages",
    "/host/security/ids-review-packages/dispatch",
    "/host/security/ids-review-packages/prompts",
    "/host/security/ids-review-packages/results",
    "/host/security/firewall-policy/enforcement-plans",
    "/host/security/remediations/plans",
    "/host/security/source-reviews",
    "/host/security/source-reviews/block-plans",
}


def _handled_actions() -> set[str]:
    return set(re.findall(r'if \(action === "([^"]+)"\)', OPERATOR_CONSOLE_HTML))


def _data_actions() -> set[str]:
    return {
        action
        for action in re.findall(r'data-action="([^"]+)"', OPERATOR_CONSOLE_HTML)
        if not action.startswith("${")
    }


def _nav_views() -> set[str]:
    return set(re.findall(r'data-view="([^"]+)"', OPERATOR_CONSOLE_HTML))


def _section_ids() -> set[str]:
    return set(re.findall(r'<section id="([^"]+)"', OPERATOR_CONSOLE_HTML))


def _api_routes() -> dict[str, set[str]]:
    api = Path("src/overseer/api.py").read_text(encoding="utf-8")
    get_routes = set(re.findall(r'if path == "([^"]+)":', api.split("def do_POST", 1)[0]))
    post_routes = set(re.findall(r'if path == "([^"]+)":', api.split("def do_POST", 1)[1]))
    return {"GET": get_routes, "POST": post_routes}


class FullOperatorUiRegressionTests(unittest.TestCase):
    def test_every_navigation_page_has_section_renderer_and_expected_controls(self):
        views = _nav_views()
        self.assertEqual(views, set(EXPECTED_VIEWS))
        self.assertEqual(_section_ids(), set(EXPECTED_VIEWS))

        for view, contract in EXPECTED_VIEWS.items():
            with self.subTest(view=view):
                self.assertIn(f'function render{view.title() if view != "ezri" else "Ezri"}()', OPERATOR_CONSOLE_HTML)
                self.assertIn(contract["title"], OPERATOR_CONSOLE_HTML)
                for officer in contract["officers"]:
                    self.assertIn(officer, OPERATOR_CONSOLE_HTML)
                for action in contract["actions"]:
                    self.assertIn(f'data-action="{action}"', OPERATOR_CONSOLE_HTML)

    def test_every_visible_action_is_handled_and_has_an_api_route(self):
        handled_actions = _handled_actions()
        self.assertEqual(handled_actions, set(ACTION_ROUTES))
        self.assertTrue(_data_actions().issubset(handled_actions))

        routes = _api_routes()
        for action, (method, route) in ACTION_ROUTES.items():
            with self.subTest(action=action):
                self.assertIn(route, routes[method])

    def test_all_action_form_fields_are_present_in_the_ui_contract(self):
        required_ids = {
            "admin-adapter-approval-id",
            "admin-adapter-approved-by",
            "admin-adapter-kind",
            "admin-adapter-requested-by",
            "admin-approval-plan-id",
            "admin-approved-by",
            "admin-archive-approval-id",
            "admin-archive-approved-by",
            "admin-archive-execute-approval-id",
            "admin-archive-execute-plan-id",
            "admin-archive-plan-id",
            "admin-archive-requested-by",
            "admin-archived-by",
            "admin-cancel-plan-id",
            "admin-cancel-reason",
            "admin-canceled-by",
            "admin-current-state",
            "admin-execute-plan-id",
            "admin-kind",
            "admin-package",
            "admin-plan-id",
            "admin-port",
            "admin-reason",
            "admin-restore-approval-id",
            "admin-restore-approved-by",
            "admin-restore-plan-id",
            "admin-restore-requested-by",
            "admin-target",
            "admin-unarchive-approval-id",
            "admin-unarchive-plan-id",
            "admin-unarchived-by",
            "advisory-dry-run",
            "advisory-max-results",
            "advisory-packages",
            "advisory-requested-by",
            "advisory-source",
            "backup-cleanup-path",
            "backup-cleanup-reason",
            "backup-cleanup-requested-by",
            "backup-job-id",
            "backup-notes",
            "backup-requested-by",
            "backup-retention",
            "backup-risk",
            "backup-schedule",
            "backup-status",
            "backup-target",
            "claim-action",
            "claim-activate-approval-id",
            "claim-activate-id",
            "claim-approval-id",
            "claim-decided-by",
            "claim-expires-at",
            "claim-id",
            "claim-intent",
            "claim-owner-role",
            "claim-owner-thread",
            "claim-port",
            "claim-release-condition",
            "claim-release-id",
            "claim-release-reason",
            "claim-released-by",
            "claim-resource-id",
            "claim-risk",
            "claim-type",
            "cleanup-approval-id",
            "cleanup-approved-by",
            "cleanup-claim-id",
            "cleanup-execute-approval-id",
            "cleanup-executed-by",
            "cleanup-requested-by",
            "documents-context-length",
            "documents-folder",
            "documents-note-content",
            "documents-note-mode",
            "documents-note-path",
            "documents-query",
            "firewall-enforcement-reason",
            "firewall-plan-id",
            "firewall-requested-by",
            "firewall-rule-index",
            "health-expected-content-type",
            "health-expected-status",
            "health-name",
            "health-probe-type",
            "health-resource-id",
            "health-target",
            "health-target-id",
            "identity-rotation-reason",
            "identity-rotation-requested-by",
            "identity-rotation-subject",
            "identity-rotation-subject-type",
            "identity-rotation-urgency",
            "journal-reason",
            "journal-requested-by",
            "journal-resource-id",
            "journal-unit",
            "ids-advisory-result",
            "ids-dispatch-package-id",
            "ids-dispatched-by",
            "ids-export-package-id",
            "ids-owner-thread",
            "ids-package-id",
            "ids-plan-id",
            "ids-requested-by",
            "ids-result-package-id",
            "ids-result-status",
            "ids-reviewed-by",
            "ids-source-review-id",
            "knowledge-capture-limit",
            "maintenance-schedule-blackout",
            "maintenance-schedule-id",
            "maintenance-schedule-metadata",
            "maintenance-schedule-notes",
            "maintenance-schedule-owner",
            "maintenance-schedule-recurrence",
            "maintenance-schedule-risk",
            "maintenance-schedule-rollback",
            "maintenance-schedule-status",
            "maintenance-schedule-target",
            "maintenance-schedule-timezone",
            "maintenance-schedule-validation",
            "maintenance-schedule-window",
            "metric-history-id",
            "metric-history-notes",
            "metric-history-requested-by",
            "metric-history-retention",
            "op-evidence-ids",
            "op-kind",
            "op-metadata",
            "op-next-step",
            "op-owner",
            "op-record-id",
            "op-resource-id",
            "op-severity",
            "op-status",
            "op-subject",
            "op-summary",
            "op-transition-by",
            "op-transition-next-step",
            "op-transition-note",
            "op-transition-record-id",
            "op-transition-status",
            "op-workflow-record-id",
            "op-workflow-requested-by",
            "op-workflow-resource-id",
            "op-workflow-template-id",
            "policy-profile-description",
            "policy-profile-name",
            "policy-warning-approval-id",
            "policy-warning-approved-by",
            "policy-warning-check-id",
            "policy-warning-plan-id",
            "policy-warning-requested-by",
            "resource-id",
            "resource-identifiers",
            "resource-name",
            "resource-owner",
            "resource-risk",
            "resource-type",
            "restore-job-id",
            "restore-notes",
            "restore-point",
            "restore-status",
            "restore-test-id",
            "restore-validated-by",
            "restore-virtual-point",
            "restore-virtual-reason",
            "restore-virtual-requested-by",
            "restore-virtual-resource-id",
            "security-listener",
            "security-plan-id",
            "security-remediation-action",
            "security-remediation-reason",
            "security-snapshot-id",
            "source-block-action",
            "source-block-plan-id",
            "source-block-reason",
            "source-block-review-id",
            "source-disposition",
            "source-listener",
            "source-rationale",
            "source-remote-address",
            "source-review-id",
            "source-reviewed-by",
            "source-snapshot-id",
            "usage-capacity",
            "usage-confidence",
            "usage-deadline",
            "usage-dispatched-by",
            "usage-earliest-start",
            "usage-intent",
            "usage-kind",
            "usage-limit-id",
            "usage-observed-at",
            "usage-owner-thread",
            "usage-remaining",
            "usage-request-id",
            "usage-request-limit-id",
            "usage-request-resource-id",
            "usage-requested-by",
            "usage-requested-units",
            "usage-resource-id",
            "usage-resets-at",
            "usage-resume-codex-projects",
            "usage-risk",
            "usage-window",
            "virtual-adapter",
            "virtual-kind",
            "virtual-notes",
            "virtual-ports",
            "virtual-resource-id",
            "virtual-snapshot-hint",
            "virtual-state",
            "snapshot-name",
            "snapshot-reason",
            "snapshot-requested-by",
            "snapshot-resource-id",
        }
        for element_id in sorted(required_ids):
            with self.subTest(element_id=element_id):
                self.assertIn(f'id="{element_id}"', OPERATOR_CONSOLE_HTML)

    def test_dashboard_drilldown_and_source_link_controls_are_present(self):
        self.assertIn("data-view-target", OPERATOR_CONSOLE_HTML)
        self.assertIn("crew-card", OPERATOR_CONSOLE_HTML)
        self.assertIn("Resource Registry", OPERATOR_CONSOLE_HTML)
        self.assertIn("Account Repositories", OPERATOR_CONSOLE_HTML)
        self.assertIn("Current Repo Links", OPERATOR_CONSOLE_HTML)
        self.assertIn("authorizationDecisionBoard", OPERATOR_CONSOLE_HTML)
        self.assertIn("Approval Decisions", OPERATOR_CONSOLE_HTML)
        self.assertIn("Request Changes", OPERATOR_CONSOLE_HTML)
        self.assertIn("formatCell", OPERATOR_CONSOLE_HTML)
        self.assertIn('target="_blank"', OPERATOR_CONSOLE_HTML)

    def test_generated_javascript_does_not_split_regex_literals(self):
        self.assertIn(".split(/[,\\n]/)", OPERATOR_CONSOLE_HTML)
        self.assertNotIn(".split(/[,\n", OPERATOR_CONSOLE_HTML)

    def test_console_exposes_load_state_marker_for_regression_runner(self):
        self.assertIn('document.body.dataset.loadState = "locked";', OPERATOR_CONSOLE_HTML)
        self.assertIn('document.body.dataset.loadState = "loading";', OPERATOR_CONSOLE_HTML)
        self.assertIn('document.body.dataset.loadState = failures.length ? "partial" : "ready";', OPERATOR_CONSOLE_HTML)
        self.assertIn('document.body.dataset.loadFailures = String(failures.length);', OPERATOR_CONSOLE_HTML)

    def test_documents_folder_navigation_preserves_selected_folder(self):
        self.assertIn('documentsFolder: "Overseer"', OPERATOR_CONSOLE_HTML)
        self.assertIn("documentsNotesPath()", OPERATOR_CONSOLE_HTML)
        self.assertIn('if (key === "documentsNotes") return documentsNotesPath();', OPERATOR_CONSOLE_HTML)
        self.assertIn('state.documentsFolder = value("documents-folder") || "Overseer";', OPERATOR_CONSOLE_HTML)
        self.assertIn("applyActionResult(action, result);", OPERATOR_CONSOLE_HTML)
        self.assertIn('if (action === "documents-list-notes") state.data.documentsNotes = result;', OPERATOR_CONSOLE_HTML)
        self.assertNotIn('document.getElementById("updated").textContent = new Date().toLocaleString();\n      render();\n      const endpointEntries', OPERATOR_CONSOLE_HTML)
        self.assertIn('value="${safe(currentFolder)}"', OPERATOR_CONSOLE_HTML)
        self.assertIn("documentChildPath(currentFolder, file)", OPERATOR_CONSOLE_HTML)
        self.assertIn("documentFileFill(row)", OPERATOR_CONSOLE_HTML)
        self.assertIn('row.kind === "folder" ? "documents-list-notes" : ""', OPERATOR_CONSOLE_HTML)
        self.assertIn("targetView && targetView !== state.view && !fillTarget.dataset.action", OPERATOR_CONSOLE_HTML)

    def test_ezri_workflows_panel_links_operator_runbooks(self):
        self.assertIn('table("Workflows", workflows, ["workflow", "page", "owner", "action", "source"]', OPERATOR_CONSOLE_HTML)
        self.assertIn("limit: 80", OPERATOR_CONSOLE_HTML)
        self.assertIn("function ezriWorkflowRows()", OPERATOR_CONSOLE_HTML)
        self.assertIn("function workflowFill(row)", OPERATOR_CONSOLE_HTML)
        expected_workflows = [
            "Approve a pending admin request",
            "View VM leases and virtual claims",
            "Record a backup job",
            "Record a restore test",
            "Stage backup cleanup request",
            "View logs from an unhealthy service",
            "Record virtual runtime state",
            "Stage virtual snapshot request",
            "Stage virtual restore request",
            "Stage system journal access request",
            "Capture metric history snapshot",
            "Check an exhausted limit refresh",
            "Adjust service schedule",
            "Refresh CVE advisory feeds",
            "Inspect host security posture",
            "Stage firewall policy enforcement",
            "Stage identity rotation request",
            "Capture crew and audit knowledge",
            "View audit log",
        ]
        for workflow in expected_workflows:
            with self.subTest(workflow=workflow):
                self.assertIn(workflow, OPERATOR_CONSOLE_HTML)
        self.assertIn("Overseer/Runbooks/operator-workflows.md", OPERATOR_CONSOLE_HTML)
        self.assertIn('"documents-note-path": source', OPERATOR_CONSOLE_HTML)
        self.assertIn('"documents-folder": folder || "Overseer"', OPERATOR_CONSOLE_HTML)
        self.assertIn('"documents-query": row?.query || row?.workflow || source', OPERATOR_CONSOLE_HTML)
        for action in ACTION_ROUTES:
            with self.subTest(action=action):
                self.assertIn(f'action: "{action}"', OPERATOR_CONSOLE_HTML)

    def test_safe_disposable_workflows_execute_through_gateway_routes(self):
        with tempfile.TemporaryDirectory() as directory:
            with LocalApiHarness(Path(directory) / "overseer.sqlite3") as server:
                resource = server.post_json("/Overseer/resources", SAFE_POST_PAYLOADS["/resources"])
                claim = server.post_json("/Overseer/claims/request", SAFE_POST_PAYLOADS["/claims/request"])
                usage_limit = server.post_json("/Overseer/usage-limits", SAFE_POST_PAYLOADS["/usage-limits"])
                usage_request = server.post_json(
                    "/Overseer/usage/continuation-requests",
                    SAFE_POST_PAYLOADS["/usage/continuation-requests"],
                )
                usage_dispatch = server.post_json(
                    "/Overseer/usage/continuation-dispatches",
                    SAFE_POST_PAYLOADS["/usage/continuation-dispatches"],
                )
                health_target = server.post_json("/Overseer/health-targets", SAFE_POST_PAYLOADS["/health-targets"])
                health_probe = server.post_json("/Overseer/health/probes/run", SAFE_POST_PAYLOADS["/health/probes/run"])
                journal_request = server.post_json(
                    "/Overseer/health/journal-access-requests",
                    SAFE_POST_PAYLOADS["/health/journal-access-requests"],
                )
                backup_job = server.post_json("/Overseer/storage/backup-jobs", SAFE_POST_PAYLOADS["/storage/backup-jobs"])
                restore_test = server.post_json("/Overseer/storage/restore-tests", SAFE_POST_PAYLOADS["/storage/restore-tests"])
                backup_cleanup = server.post_json(
                    "/Overseer/storage/cleanup-requests",
                    SAFE_POST_PAYLOADS["/storage/cleanup-requests"],
                )
                virtual_runtime = server.post_json(
                    "/Overseer/virtual/runtime-records",
                    SAFE_POST_PAYLOADS["/virtual/runtime-records"],
                )
                virtual_snapshot = server.post_json(
                    "/Overseer/virtual/snapshot-requests",
                    SAFE_POST_PAYLOADS["/virtual/snapshot-requests"],
                )
                virtual_restore = server.post_json(
                    "/Overseer/virtual/restore-requests",
                    SAFE_POST_PAYLOADS["/virtual/restore-requests"],
                )
                identity_rotation = server.post_json(
                    "/Overseer/identity/rotation-requests",
                    SAFE_POST_PAYLOADS["/identity/rotation-requests"],
                )
                crew_message = server.post_json("/Overseer/crew/messages", SAFE_POST_PAYLOADS["/crew/messages"])
                crew_dispatch = server.post_json("/Overseer/crew/dispatch", SAFE_POST_PAYLOADS["/crew/dispatch"])
                admin_plan = server.post_json("/Overseer/admin/plans", SAFE_POST_PAYLOADS["/admin/plans"])
                admin_approval = server.post_json("/Overseer/admin/approve", SAFE_POST_PAYLOADS["/admin/approve"])
                policy_profile = server.post_json(
                    "/Overseer/admin/policy-customization-helper/profile",
                    SAFE_POST_PAYLOADS["/admin/policy-customization-helper/profile"],
                )
                operation_record = server.post_json(
                    "/Overseer/operations/records",
                    SAFE_POST_PAYLOADS["/operations/records"],
                )
                operation_transition = server.post_json(
                    "/Overseer/operations/records/transition",
                    SAFE_POST_PAYLOADS["/operations/records/transition"],
                )
                operation_workflow = server.post_json(
                    "/Overseer/operations/workflows/stage",
                    SAFE_POST_PAYLOADS["/operations/workflows/stage"],
                )
                maintenance_schedule = server.post_json(
                    "/Overseer/maintenance/schedules",
                    SAFE_POST_PAYLOADS["/maintenance/schedules"],
                )
                advisory_refresh = server.post_json(
                    "/Overseer/maintenance/advisories/refresh",
                    SAFE_POST_PAYLOADS["/maintenance/advisories/refresh"],
                )
                metric_capture = server.post_json(
                    "/Overseer/observability/metric-history/capture",
                    SAFE_POST_PAYLOADS["/observability/metric-history/capture"],
                )
                dashboard = server.get_json("/Overseer/operator-dashboard")
                operations = server.get_json("/Overseer/operations/gap-coverage")
                claims = server.get_json("/Overseer/claims/review")
                usage = server.get_json("/Overseer/usage-summary")
                health = server.get_json("/Overseer/health-summary")
                crew = server.get_json("/Overseer/crew/messages")
                approvals = server.get_json("/Overseer/approvals-summary")
                root_notes = server.get_json("/Overseer/documents/notes?folder=Overseer")
                runbook_notes = server.get_json("/Overseer/documents/notes?folder=Overseer%2FRunbooks")

        self.assertTrue(resource["mutation_performed"])
        self.assertEqual(claim["claim"], "claim.ui.full")
        self.assertEqual(usage_limit["limit"]["id"], "limit.ui.full")
        self.assertTrue(usage_request["mutation_performed"])
        self.assertEqual(usage_dispatch["dispatched"], 1)
        self.assertTrue(health_target["mutation_performed"])
        self.assertEqual(len(health_probe["evidence"]), 1)
        self.assertEqual(journal_request["record"]["status"], "waiting_approval")
        self.assertFalse(journal_request["host_mutation_performed"])
        self.assertEqual(backup_job["job"]["id"], "backup.ui.full")
        self.assertEqual(restore_test["restore_test"]["id"], "restore.ui.full")
        self.assertEqual(backup_cleanup["cleanup_request"]["status"], "waiting_approval")
        self.assertFalse(backup_cleanup["host_mutation_performed"])
        self.assertEqual(virtual_runtime["runtime_record"]["resource_id"], "vm.ui.full")
        self.assertEqual(virtual_snapshot["snapshot_request"]["status"], "waiting_approval")
        self.assertEqual(virtual_restore["restore_request"]["status"], "waiting_approval")
        self.assertFalse(virtual_restore["host_mutation_performed"])
        self.assertEqual(identity_rotation["request"]["status"], "waiting_approval")
        self.assertFalse(identity_rotation["host_mutation_performed"])
        self.assertEqual(crew_message["message"]["owner_domain"], "julian")
        self.assertEqual(crew_dispatch["acknowledged"], 1)
        self.assertEqual(admin_plan["id"], "admin.ui.full")
        self.assertTrue(admin_approval["approved"])
        self.assertEqual(policy_profile["profile"]["name"], "ui-full-regression")
        self.assertEqual(operation_record["record"]["id"], "ops.ui.full")
        self.assertEqual(operation_transition["record"]["status"], "verified")
        self.assertEqual(operation_workflow["record"]["id"], "ops.ui.workflow")
        self.assertEqual(maintenance_schedule["schedule"]["id"], "schedule.ui.full")
        self.assertEqual(advisory_refresh["status"], "dry_run")
        self.assertFalse(advisory_refresh["external_request_performed"])
        self.assertEqual(metric_capture["snapshot"]["id"], "metric.ui.full")
        self.assertFalse(metric_capture["host_mutation_performed"])
        self.assertIn("role_focus", dashboard)
        self.assertGreaterEqual(operations["operation_records"]["records"], 1)
        self.assertGreaterEqual(claims["claims"], 1)
        self.assertGreaterEqual(usage["limits"], 1)
        self.assertGreaterEqual(health["targets"], 1)
        self.assertGreaterEqual(crew["summary"]["total"], 1)
        self.assertGreaterEqual(approvals["approval_count"], 1)
        self.assertEqual(root_notes["folder"], "Overseer")
        self.assertIn("Runbooks/", root_notes["files"])
        self.assertEqual(runbook_notes["folder"], "Overseer/Runbooks")
        self.assertIn("ui-regression-testing.md", runbook_notes["files"])

    def test_high_risk_workflows_are_wired_but_not_executed_without_fixtures(self):
        with tempfile.TemporaryDirectory() as directory:
            with LocalApiHarness(Path(directory) / "overseer.sqlite3") as server:
                for route in sorted(ROUTES_EXPECTED_TO_REQUIRE_FIXTURES):
                    with self.subTest(route=route):
                        with self.assertRaises(HTTPError) as error:
                            server.post_json(f"/Overseer{route}", {})
                        self.assertIn(error.exception.code, {400, 404})


if __name__ == "__main__":
    unittest.main()
