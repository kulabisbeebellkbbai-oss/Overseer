import re
import unittest
from pathlib import Path

from overseer.ui import OPERATOR_CONSOLE_HTML
from tests.test_ui_full_regression import ACTION_ROUTES, EXPECTED_VIEWS


RUNBOOK_PATH = Path("docs/operator-workflows.md")
RUNBOOK_SOURCE = "Overseer/Runbooks/operator-workflows.md"


def _normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def _workflow_rows() -> list[dict[str, str]]:
    rows = []
    pattern = re.compile(
        r'\{workflow: "([^"]+)", page: "([^"]+)", owner: "([^"]+)", action: "([^"]+)", source, query: "([^"]+)"\}'
    )
    for workflow, page, owner, action, query in pattern.findall(OPERATOR_CONSOLE_HTML):
        rows.append(
            {
                "workflow": workflow,
                "page": page,
                "owner": owner,
                "action": action,
                "source": RUNBOOK_SOURCE,
                "query": query,
            }
        )
    return rows


def _runbook_headings() -> set[str]:
    text = RUNBOOK_PATH.read_text(encoding="utf-8")
    return {_normalize(match) for match in re.findall(r"^### (.+)$", text, flags=re.MULTILINE)}


def _button_actions() -> set[str]:
    return {
        action
        for action in re.findall(r'data-action="([^"]+)"', OPERATOR_CONSOLE_HTML)
        if not action.startswith("${")
    }


def _action_handler_names() -> set[str]:
    return set(re.findall(r'if \(action === "([^"]+)"\)', OPERATOR_CONSOLE_HTML))


def _field_ids() -> set[str]:
    return set(re.findall(r'id="([^"]+)"', OPERATOR_CONSOLE_HTML))


def _document_references() -> set[str]:
    return set(re.findall(r'value\("([^"$`]+)"\)', OPERATOR_CONSOLE_HTML)) | set(
        re.findall(r'getElementById\("([^"$`]+)"\)', OPERATOR_CONSOLE_HTML)
    )


RUNBOOK_SPLIT_WORKFLOWS = {
    _normalize("Archive Or Restore Admin History"): {
        _normalize("Archive inactive admin history"),
        _normalize("Approve admin history archive"),
        _normalize("Run approved admin archive"),
        _normalize("Restore archived admin history"),
        _normalize("Approve admin history restore"),
        _normalize("Unarchive an approved admin plan"),
    },
    _normalize("Accept And Approve A Policy Warning"): {
        _normalize("Accept a policy warning"),
        _normalize("Approve a policy warning"),
    },
    _normalize("Clean Up Stale Or Expired Claims"): {
        _normalize("Clean up stale or expired claims"),
        _normalize("Approve claim cleanup"),
        _normalize("Execute approved claim cleanup"),
    },
    _normalize("Prepare, Export, Dispatch, And Record IDS Review"): {
        _normalize("Prepare an IDS review package"),
        _normalize("Export an IDS review prompt"),
        _normalize("Dispatch an IDS review package"),
        _normalize("Record an IDS review result"),
    },
}


def _workflow_is_covered_by_runbook_split(workflow: str, headings: set[str]) -> bool:
    return any(workflow in split_rows and heading in headings for heading, split_rows in RUNBOOK_SPLIT_WORKFLOWS.items())


class OperatorWorkflowRegressionTests(unittest.TestCase):
    def test_every_ezri_workflow_has_runbook_coverage(self):
        runbook_text = _normalize(RUNBOOK_PATH.read_text(encoding="utf-8"))
        headings = _runbook_headings()
        workflows = _workflow_rows()

        self.assertGreater(len(workflows), 0)
        for row in workflows:
            workflow = _normalize(row["workflow"])
            query = _normalize(row["query"])
            with self.subTest(workflow=row["workflow"]):
                self.assertEqual(row["source"], RUNBOOK_SOURCE)
                self.assertIn(row["page"], {"Any", "Overview", "Admin", "Assets", "Claims", "Security", "Health", "Usage", "Documents", "Audit"})
                self.assertTrue(workflow in headings or query in runbook_text or _workflow_is_covered_by_runbook_split(workflow, headings))

    def test_each_documented_workflow_is_represented_by_ezri(self):
        workflow_names = {_normalize(row["workflow"]) for row in _workflow_rows()}
        for heading in _runbook_headings():
            with self.subTest(heading=heading):
                if heading in RUNBOOK_SPLIT_WORKFLOWS:
                    self.assertTrue(RUNBOOK_SPLIT_WORKFLOWS[heading].issubset(workflow_names))
                else:
                    self.assertIn(heading, workflow_names)

    def test_every_visible_control_has_a_workflow_or_navigation_contract(self):
        action_names = _button_actions()
        handled_actions = _action_handler_names()
        workflow_actions = {row["action"] for row in _workflow_rows()}

        self.assertEqual(action_names, handled_actions)
        for action in action_names:
            with self.subTest(action=action):
                self.assertIn(action, ACTION_ROUTES)
                self.assertIn(action, workflow_actions)

        for view in EXPECTED_VIEWS:
            with self.subTest(view=view):
                self.assertIn(f'data-view="{view}"', OPERATOR_CONSOLE_HTML)
                self.assertIn(f'id="{view}"', OPERATOR_CONSOLE_HTML)

    def test_action_inputs_and_fill_targets_are_addressable(self):
        field_ids = _field_ids()
        dynamic_prefixes = ("${prefix}-", "policy-answer-${")
        for field_id in sorted(_document_references()):
            with self.subTest(field_id=field_id):
                self.assertTrue(field_id in field_ids or field_id.startswith(dynamic_prefixes))


if __name__ == "__main__":
    unittest.main()
