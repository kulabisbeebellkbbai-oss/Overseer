"""Crew-scoped operator messages."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from .core import OwnerDomain, RiskLevel


class CrewMessageStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    CLOSED = "closed"


@dataclass(frozen=True)
class CrewMessage:
    id: str
    owner_domain: OwnerDomain
    subject: str
    message: str
    priority: RiskLevel = RiskLevel.MEDIUM
    status: CrewMessageStatus = CrewMessageStatus.OPEN
    requested_by: str = "operator"
    created_at: str | None = None
    updated_at: str | None = None
    related_resource_id: str | None = None
    related_plan_id: str | None = None
    related_limit_id: str | None = None


def build_crew_message(
    owner_domain: str,
    subject: str,
    message: str,
    priority: str = RiskLevel.MEDIUM.value,
    requested_by: str = "operator",
    message_id: str | None = None,
    created_at: str | None = None,
    related_resource_id: str | None = None,
    related_plan_id: str | None = None,
    related_limit_id: str | None = None,
) -> CrewMessage:
    if not subject.strip():
        raise ValueError("subject is required")
    if not message.strip():
        raise ValueError("message is required")
    now = created_at or datetime.now(UTC).replace(microsecond=0).isoformat()
    domain = OwnerDomain(owner_domain)
    return CrewMessage(
        id=message_id or _message_id(domain, subject, now),
        owner_domain=domain,
        subject=subject.strip(),
        message=message.strip(),
        priority=RiskLevel(priority),
        requested_by=requested_by.strip() or "operator",
        created_at=now,
        updated_at=now,
        related_resource_id=related_resource_id,
        related_plan_id=related_plan_id,
        related_limit_id=related_limit_id,
    )


def crew_message_status(message: CrewMessage) -> dict[str, object]:
    return {
        "id": message.id,
        "owner_domain": OwnerDomain(message.owner_domain).value,
        "subject": message.subject,
        "message": message.message,
        "priority": RiskLevel(message.priority).value,
        "status": CrewMessageStatus(message.status).value,
        "requested_by": message.requested_by,
        "created_at": message.created_at,
        "updated_at": message.updated_at,
        "related_resource_id": message.related_resource_id,
        "related_plan_id": message.related_plan_id,
        "related_limit_id": message.related_limit_id,
    }


def _message_id(owner_domain: OwnerDomain, subject: str, created_at: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", subject.lower()).strip("-") or "message"
    stamp = re.sub(r"[^0-9]", "", created_at)[:14] or "pending"
    return f"crew.{owner_domain.value}.{slug[:48]}.{stamp}"
