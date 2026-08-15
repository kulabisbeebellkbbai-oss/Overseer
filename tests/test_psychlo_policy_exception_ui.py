from __future__ import annotations

from overseer.ui import OPERATOR_CONSOLE_HTML


def test_policy_exception_approval_uses_dedicated_human_decision_controls():
    html = OPERATOR_CONSOLE_HTML

    assert "psychloPolicyExceptionDecisionCard" in html
    assert 'kind === "psychlo_policy_exception"' in html
    assert 'data-action="decide-psychlo-policy-exception"' in html
    assert 'postJson("/roadex/psychlo/policy-exception-decision"' in html
    assert 'request_id: requestId' in html
    assert 'decision: source.dataset.decision' in html
    assert 'decided_by: decidedBy' in html
    assert 'reason: reason' in html
    assert 'source.closest(".decision-card")' in html
    assert 'placeholder="Enter the approving human identity"' in html
    assert 'value="independent-human-reviewer"' not in html


def test_policy_exception_card_does_not_route_through_generic_admin_approval_or_execution():
    html = OPERATOR_CONSOLE_HTML
    start = html.index("    function psychloPolicyExceptionDecisionCard(")
    end = html.index("    function adminPlanDecisionCard(", start)
    card = html[start:end]

    assert "approve-and-execute-admin-change" not in card
    assert "approve-admin-change" not in card
    assert "/admin/approve" not in card
    assert "/admin/execute" not in card


def test_policy_exception_decision_is_listed_in_operator_workflow_contract():
    assert (
        '{workflow: "Approve a pending Psychlo policy exception", page: "Admin", '
        'owner: "independent human", action: "decide-psychlo-policy-exception"'
    ) in OPERATOR_CONSOLE_HTML
