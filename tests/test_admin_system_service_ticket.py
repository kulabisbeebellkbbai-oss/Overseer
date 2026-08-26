from __future__ import annotations

from unittest.mock import patch

from overseer.admin import (
    AdminAdapterStatus,
    AdminChangeKind,
    AdminCommandStep,
    approve_admin_change_plan,
    admin_execution_capability_for,
    missing_admin_change_fields,
    plan_system_service_restart,
    run_admin_command_step,
)
from overseer.cli import plan_admin_change_status
from overseer.policy import evaluate_admin_change_policy
from overseer.ui import OPERATOR_CONSOLE_HTML


def test_system_service_restart_plan_contains_only_a_ticket_marker() -> None:
    plan = plan_system_service_restart(
        "admin.restart-system.smoke",
        "overseer-approval-smoke.service",
        "exercise the independent approval and executor boundary",
        "inactive",
    )

    assert plan.kind is AdminChangeKind.SYSTEM_SERVICE_RESTART
    assert plan.target == "overseer-approval-smoke.service"
    assert tuple(step.command for step in plan.steps) == (
        (
            "__overseer_ticketed_system_service_restart_v1",
            "overseer-approval-smoke.service",
        ),
    )
    assert plan.rollback_steps == ()
    assert plan.verification_steps == ()
    assert all("systemctl" not in token for step in plan.steps for token in step.command)


def test_system_service_restart_plan_is_complete_after_sisko_approval() -> None:
    plan = plan_system_service_restart(
        "admin.restart-system.smoke",
        "overseer-approval-smoke.service",
        "exercise the independent approval and executor boundary",
        "inactive",
    )

    assert missing_admin_change_fields(plan) == ()
    assert approve_admin_change_plan(plan, "sisko").can_execute() is True


def test_system_service_ticket_policy_uses_executor_verification_contract() -> None:
    plan = approve_admin_change_plan(
        plan_system_service_restart(
            "admin.restart-system.smoke",
            "overseer-approval-smoke.service",
            "exercise the independent approval and executor boundary",
            "inactive",
        ),
        "sisko",
    )

    decision = evaluate_admin_change_policy(
        plan,
        admin_execution_capability_for(plan.kind),
    )

    assert decision.can_proceed() is True
    checks = {check.id: check for check in decision.checks}
    assert "executor" in checks["admin.rollback"].summary
    assert "executor" in checks["admin.verification"].summary


def test_system_service_restart_capability_names_the_ticket_executor() -> None:
    capability = admin_execution_capability_for(AdminChangeKind.SYSTEM_SERVICE_RESTART)

    assert capability.status is AdminAdapterStatus.ENABLED
    assert capability.adapter_name == "signed-systemd-ticket-executor"
    assert capability.supported_commands == (
        ("__overseer_ticketed_system_service_restart_v1",),
    )


def test_v1_1_6_marks_legacy_user_service_execution_unsupported() -> None:
    capability = admin_execution_capability_for(AdminChangeKind.USER_SERVICE_RESTART)

    assert capability.status is AdminAdapterStatus.UNSUPPORTED
    assert "retired" in capability.summary


def test_explicit_in_process_runner_keeps_legacy_plan_testable_without_systemd() -> None:
    capability = admin_execution_capability_for(
        AdminChangeKind.USER_SERVICE_RESTART,
        injected_runner=True,
    )

    assert capability.status is AdminAdapterStatus.ENABLED
    assert capability.adapter_name == "injected-test-runner"


def test_cli_planner_supports_the_ticketed_system_service_kind() -> None:
    status = plan_admin_change_status(
        None,
        "admin.restart-system.smoke",
        "system_service_restart",
        "overseer-approval-smoke.service",
        "exercise the independent approval and executor boundary",
        "inactive",
    )

    assert status["kind"] == "system_service_restart"
    assert status["steps"][0]["command"] == [
        "__overseer_ticketed_system_service_restart_v1",
        "overseer-approval-smoke.service",
    ]


def test_ui_stages_ticketed_restart_and_hides_retired_user_restart() -> None:
    plan_options = OPERATOR_CONSOLE_HTML.split("function adminKindOptions()", 1)[1].split(
        "function adminAdapterKindOptions()",
        1,
    )[0]
    adapter_options = OPERATOR_CONSOLE_HTML.split("function adminAdapterKindOptions()", 1)[1].split(
        "function firmwareBlockerRows",
        1,
    )[0]

    assert "system_service_restart" in plan_options
    assert "system_service_restart" in adapter_options
    assert "user_service_restart" not in plan_options
    assert "user_service_restart" not in adapter_options


def test_direct_user_manager_and_ticket_marker_execution_fail_closed(monkeypatch) -> None:
    monkeypatch.setenv("OVERSEER_DEDICATED_PRINCIPAL", "1")
    steps = (
        AdminCommandStep(
            "legacy user restart",
            ("systemctl", "--user", "restart", "example.service"),
            "retired direct path",
        ),
        AdminCommandStep(
            "ticketed restart",
            (
                "__overseer_ticketed_system_service_restart_v1",
                "overseer-approval-smoke.service",
            ),
            "requires executor socket",
        ),
    )

    with patch("overseer.admin.subprocess.run") as subprocess_run:
        results = tuple(run_admin_command_step(step) for step in steps)

    subprocess_run.assert_not_called()
    assert all(result.exit_code != 0 for result in results)
    assert "retired" in results[0].stderr
    assert "ticket executor" in results[1].stderr
