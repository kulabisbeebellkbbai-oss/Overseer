"""Adapter contracts and dry-run execution boundary."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from .core import OwnerDomain
from .health import HealthEvidence, HealthTarget
from .maintenance import MaintenancePlan
from .physical import PhysicalIdentity
from .security import ProtectiveAction, SecuritySignal
from .usage_limits import UsageLimit


class ExecutionMode(StrEnum):
    DRY_RUN = "dry_run"
    LIVE = "live"


class ExecutionStatus(StrEnum):
    SKIPPED = "skipped"
    PLANNED = "planned"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"


@dataclass(frozen=True)
class ExecutionRequest:
    id: str
    action: str
    target_resource_id: str
    owner_domain: OwnerDomain
    mode: ExecutionMode = ExecutionMode.DRY_RUN
    reason: str = ""


@dataclass(frozen=True)
class ExecutionResult:
    id: str
    request_id: str
    status: ExecutionStatus
    owner_domain: OwnerDomain
    summary: str
    evidence_ids: tuple[str, ...] = ()
    mode: ExecutionMode = ExecutionMode.DRY_RUN

    def changed_host_state(self) -> bool:
        return self.mode == ExecutionMode.LIVE and self.status == ExecutionStatus.COMPLETED


class HealthProbeAdapter(Protocol):
    def probe(self, target: HealthTarget) -> HealthEvidence:
        """Probe a health target and return evidence."""


class MaintenanceAdapter(Protocol):
    def run(self, plan: MaintenancePlan) -> ExecutionResult:
        """Run a maintenance plan."""


class PhysicalDiscoveryAdapter(Protocol):
    def discover(self) -> tuple[PhysicalIdentity, ...]:
        """Discover physical assets."""


class SecurityActionAdapter(Protocol):
    def respond(self, signal: SecuritySignal, action: ProtectiveAction) -> ExecutionResult:
        """Run a security response action."""


class UsageLimitAdapter(Protocol):
    def observe(self, resource_id: str) -> UsageLimit:
        """Observe usage-limit state for a resource."""


class DryRunExecutor:
    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        if request.mode == ExecutionMode.LIVE:
            return ExecutionResult(
                id=f"exec.{request.id}.blocked",
                request_id=request.id,
                status=ExecutionStatus.BLOCKED,
                owner_domain=request.owner_domain,
                summary="live execution requires an authorized adapter",
                mode=request.mode,
            )

        return ExecutionResult(
            id=f"exec.{request.id}.planned",
            request_id=request.id,
            status=ExecutionStatus.PLANNED,
            owner_domain=request.owner_domain,
            summary=f"dry run planned action {request.action} for {request.target_resource_id}",
            evidence_ids=(f"dryrun.{request.id}",),
            mode=request.mode,
        )
