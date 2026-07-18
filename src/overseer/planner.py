"""Dry-run operation planner for maintenance and security workflows."""

from __future__ import annotations

from dataclasses import dataclass

from .adapters import DryRunExecutor, ExecutionMode, ExecutionRequest, ExecutionResult
from .core import ApprovalLevel, OwnerDomain
from .maintenance import MaintenancePlan, assess_maintenance_readiness
from .security import SecuritySignal, recommend_security_response


@dataclass(frozen=True)
class PlannedOperation:
    request: ExecutionRequest
    result: ExecutionResult
    approval_level: ApprovalLevel
    reason: str

    def requires_approval(self) -> bool:
        return self.approval_level != ApprovalLevel.NONE


class OperationPlanner:
    def __init__(self, executor: DryRunExecutor | None = None) -> None:
        self.executor = executor or DryRunExecutor()

    def plan_maintenance(self, plan: MaintenancePlan) -> PlannedOperation:
        readiness = assess_maintenance_readiness(plan)
        approval = readiness.approval_level
        request = ExecutionRequest(
            id=plan.id,
            action=f"maintenance:{plan.kind.value}",
            target_resource_id=plan.resource_id,
            owner_domain=OwnerDomain.OBRIEN,
            mode=ExecutionMode.DRY_RUN,
            reason=readiness.reason,
        )
        result = self.executor.execute(request)
        return PlannedOperation(request, result, approval, readiness.reason)

    def plan_security_response(self, signal: SecuritySignal) -> PlannedOperation:
        response = recommend_security_response(signal)
        request = ExecutionRequest(
            id=f"security.{signal.id}",
            action=f"security:{response.action.value}",
            target_resource_id=signal.resource_id,
            owner_domain=response.owner_domain,
            mode=ExecutionMode.DRY_RUN,
            reason=response.reason,
        )
        result = self.executor.execute(request)
        return PlannedOperation(request, result, response.approval_level, response.reason)
