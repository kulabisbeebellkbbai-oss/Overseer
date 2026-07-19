"""Dry-run operation planner for maintenance and security workflows."""

from __future__ import annotations

from dataclasses import dataclass

from .adapters import DryRunExecutor, ExecutionMode, ExecutionRequest, ExecutionResult
from .audit import ApprovalRequest
from .core import ApprovalLevel, OwnerDomain
from .maintenance import MaintenancePlan, assess_maintenance_readiness
from .security import SecuritySignal, recommend_security_response


@dataclass(frozen=True)
class PlannedOperation:
    request: ExecutionRequest
    result: ExecutionResult
    approval_level: ApprovalLevel
    reason: str
    approval_request: ApprovalRequest | None = None

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
        approval_request = _approval_request_for_operation(
            request,
            approval,
            readiness.reason,
            evidence_required=plan.precheck_ids,
        )
        return PlannedOperation(request, result, approval, readiness.reason, approval_request)

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
        approval_request = _approval_request_for_operation(
            request,
            response.approval_level,
            response.reason,
            evidence_required=(signal.id,),
        )
        return PlannedOperation(request, result, response.approval_level, response.reason, approval_request)


def _approval_request_for_operation(
    request: ExecutionRequest,
    approval_level: ApprovalLevel,
    reason: str,
    evidence_required: tuple[str, ...] = (),
) -> ApprovalRequest | None:
    if approval_level == ApprovalLevel.NONE:
        return None
    return ApprovalRequest(
        id=f"approval.operation.{request.id}",
        subject_id=request.id,
        approval_level=approval_level,
        requester_thread="operation-planner",
        owner_domain=request.owner_domain,
        reason=reason,
        evidence_required=evidence_required,
    )
