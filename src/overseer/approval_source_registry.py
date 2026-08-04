"""Code-owned allowlist for exact approval-source projections.

The registry deliberately contains opaque accessors, never table names or SQL.
Only reviewed adapters may turn a stored payload into a source decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Literal, Mapping, Protocol, TYPE_CHECKING, cast

if TYPE_CHECKING:
    from .roadex_approval_status import RoadexApprovalBinding


ApprovalDecision = Literal[
    "pending", "approved", "changes-requested", "rejected", "expired", "revoked"
]
_DECISIONS = frozenset({"pending", "approved", "changes-requested", "rejected", "expired", "revoked"})


@dataclass(frozen=True)
class ProjectedDecision:
    decision: ApprovalDecision
    source_status: str
    updated_at: str


class ApprovalSourceStore(Protocol):
    def registered_source_exists(self, accessor: str, source_id: str) -> bool: ...

    def load_registered_source_payload(self, accessor: str, source_id: str) -> str: ...


@dataclass(frozen=True)
class ApprovalSourceAdapter:
    source_kind: str
    accessor: str
    decode_exact: Callable[[str], object]
    require_initial: Callable[[object], None]
    evidence_digest: Callable[[object], str]
    project_decision: Callable[[ApprovalSourceStore, object, object], ProjectedDecision]


def _admin_decode(payload: str) -> object:
    from .roadex_approval_status import _decode_admin_plan_payload

    return _decode_admin_plan_payload(payload)


def _admin_require_initial(source: object) -> None:
    from .roadex_approval_status import _require_initial_admin_source_state

    _require_initial_admin_source_state(source)


def _admin_digest(source: object) -> str:
    from .roadex_approval_status import _source_digest_from_admin_source

    return _source_digest_from_admin_source(source)


def _admin_project(store: ApprovalSourceStore, binding: object, source: object) -> ProjectedDecision:
    from .roadex_approval_status import _project_admin_source_decision

    return _project_admin_source_decision(store, cast("RoadexApprovalBinding", binding), source)


def _backup_decode(payload: str) -> object:
    from .roadex_approval_status import _decode_roadex_plan_payload

    return _decode_roadex_plan_payload(payload)


def _backup_require_initial(source: object) -> None:
    from .roadex_approval_status import _require_initial_backup_source_state

    _require_initial_backup_source_state(source)


def _backup_digest(source: object) -> str:
    from .roadex_approval_status import _source_digest_from_backup_source

    return _source_digest_from_backup_source(source)


def _backup_project(store: ApprovalSourceStore, binding: object, source: object) -> ProjectedDecision:
    from .roadex_approval_status import _project_backup_source_decision

    return _project_backup_source_decision(store, cast("RoadexApprovalBinding", binding), source)


def _builtins() -> tuple[ApprovalSourceAdapter, ...]:
    return (
        ApprovalSourceAdapter(
            source_kind="admin-plan",
            accessor="admin-change-plan",
            decode_exact=_admin_decode,
            require_initial=_admin_require_initial,
            evidence_digest=_admin_digest,
            project_decision=_admin_project,
        ),
        ApprovalSourceAdapter(
            source_kind="roadex-human-decision",
            accessor="backup-provisioning-plan",
            decode_exact=_backup_decode,
            require_initial=_backup_require_initial,
            evidence_digest=_backup_digest,
            project_decision=_backup_project,
        ),
    )


def build_approval_source_registry(
    adapters: tuple[ApprovalSourceAdapter, ...] | None = None,
) -> Mapping[str, ApprovalSourceAdapter]:
    """Return the immutable reviewed adapter registry.

    ``adapters`` exists solely for core-function tests; authenticated entry
    points always use the module's production registry.
    """
    selected = _builtins() if adapters is None else adapters
    result: dict[str, ApprovalSourceAdapter] = {}
    for adapter in selected:
        if not isinstance(adapter, ApprovalSourceAdapter):
            raise ValueError("approval source adapter must be exact")
        if not isinstance(adapter.source_kind, str) or not adapter.source_kind:
            raise ValueError("approval source adapter kind must be non-empty")
        if not isinstance(adapter.accessor, str) or not adapter.accessor:
            raise ValueError("approval source adapter accessor must be non-empty")
        if adapter.source_kind in result:
            raise ValueError("duplicate approval source kind")
        result[adapter.source_kind] = adapter
    return MappingProxyType(result)


def require_registry(registry: Mapping[str, ApprovalSourceAdapter]) -> Mapping[str, ApprovalSourceAdapter]:
    if not isinstance(registry, MappingProxyType):
        raise ValueError("approval source registry must be immutable")
    return registry


def resolve_adapter(
    registry: Mapping[str, ApprovalSourceAdapter], source_kind: str
) -> ApprovalSourceAdapter:
    require_registry(registry)
    if not isinstance(source_kind, str):
        raise ValueError("unsupported source_kind")
    try:
        return registry[source_kind]
    except KeyError as error:
        raise ValueError("unsupported source_kind") from error


def validate_projected_decision(projected: ProjectedDecision) -> ProjectedDecision:
    if not isinstance(projected, ProjectedDecision):
        raise ValueError("approval source adapter returned malformed projection")
    if projected.decision not in _DECISIONS:
        raise ValueError("unsupported projected decision")
    if not isinstance(projected.source_status, str) or not projected.source_status:
        raise ValueError("approval source status is malformed")
    if not isinstance(projected.updated_at, str) or not projected.updated_at:
        raise ValueError("approval source timestamp is malformed")
    return projected


PRODUCTION_APPROVAL_SOURCE_REGISTRY = build_approval_source_registry()


__all__ = [
    "ApprovalDecision",
    "ApprovalSourceAdapter",
    "ApprovalSourceStore",
    "PRODUCTION_APPROVAL_SOURCE_REGISTRY",
    "ProjectedDecision",
    "build_approval_source_registry",
    "require_registry",
    "resolve_adapter",
    "validate_projected_decision",
]
