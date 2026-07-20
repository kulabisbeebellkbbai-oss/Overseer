"""Documents-backed knowledge capture for Overseer events."""

from __future__ import annotations

import re
from hashlib import sha256
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import AuditEvent, AuditEventType
from .core import OwnerDomain, RiskLevel
from .crew import CrewMessage, CrewMessageStatus
from .documents import DEFAULT_OBSIDIAN_ENV_FILE, documents_write_note_status
from .store import SQLiteStore


DEFAULT_KNOWLEDGE_KINDS = ("crew", "audit")
DEFAULT_KNOWLEDGE_LIMIT = 50
CAPTURED_BY = "ezri"


@dataclass(frozen=True)
class KnowledgeCaptureCandidate:
    kind: str
    source_id: str
    path: str
    title: str
    owner_domain: str
    occurred_at: str | None
    content: str


def knowledge_capture_status(
    store_path: str | Path,
    env_file: str = DEFAULT_OBSIDIAN_ENV_FILE,
    kinds: Sequence[str] = DEFAULT_KNOWLEDGE_KINDS,
    limit: int = DEFAULT_KNOWLEDGE_LIMIT,
    dry_run: bool = False,
) -> dict[str, Any]:
    normalized_kinds = _normalize_kinds(kinds)
    if limit < 1:
        raise ValueError("limit must be positive")
    store = SQLiteStore(store_path)
    try:
        candidates = knowledge_capture_candidates(store, normalized_kinds, limit)
    finally:
        store.close()

    items: list[dict[str, Any]] = []
    captured = 0
    failed = 0
    for candidate in candidates:
        item: dict[str, Any] = {
            "kind": candidate.kind,
            "source_id": candidate.source_id,
            "path": candidate.path,
            "title": candidate.title,
            "owner_domain": candidate.owner_domain,
            "occurred_at": candidate.occurred_at,
            "captured": False,
        }
        if not dry_run:
            try:
                write = documents_write_note_status(env_file, candidate.path, candidate.content, "replace")
                item["captured"] = bool(write.get("mutation_performed"))
                captured += 1 if item["captured"] else 0
            except ValueError as error:
                item["error"] = str(error)
                failed += 1
        items.append(item)

    return {
        "store": str(Path(store_path)),
        "kinds": list(normalized_kinds),
        "limit": limit,
        "dry_run": dry_run,
        "candidate_count": len(candidates),
        "captured": captured,
        "failed": failed,
        "items": items,
        "mutation_performed": bool(captured),
        "host_mutation_performed": False,
    }


def knowledge_capture_candidates(
    store: SQLiteStore,
    kinds: Sequence[str] = DEFAULT_KNOWLEDGE_KINDS,
    limit: int = DEFAULT_KNOWLEDGE_LIMIT,
) -> tuple[KnowledgeCaptureCandidate, ...]:
    normalized_kinds = _normalize_kinds(kinds)
    candidates: list[KnowledgeCaptureCandidate] = []
    if "crew" in normalized_kinds:
        candidates.extend(_crew_candidate(message) for message in store.list_crew_messages())
    if "audit" in normalized_kinds:
        candidates.extend(_audit_candidate(event) for event in store.list_audit_events())
    candidates.sort(key=lambda candidate: candidate.occurred_at or "", reverse=True)
    return tuple(candidates[:limit])


def _crew_candidate(message: CrewMessage) -> KnowledgeCaptureCandidate:
    owner = OwnerDomain(message.owner_domain).value
    status = CrewMessageStatus(message.status).value
    priority = RiskLevel(message.priority).value
    title = f"{_officer_name(owner)} Request: {message.subject}"
    content = "\n".join(
        (
            "---",
            f"overseer_id: {message.id}",
            "overseer_kind: crew_message",
            f"owner_domain: {owner}",
            f"status: {status}",
            f"priority: {priority}",
            f"captured_by: {CAPTURED_BY}",
            "---",
            "",
            f"# {title}",
            "",
            "## Summary",
            message.subject,
            "",
            "## Request",
            message.message,
            "",
            "## Routing",
            f"- Owner: {owner}",
            f"- Status: {status}",
            f"- Priority: {priority}",
            f"- Requested by: {message.requested_by}",
            f"- Created at: {message.created_at or ''}",
            f"- Updated at: {message.updated_at or ''}",
            f"- Related resource: {message.related_resource_id or ''}",
            f"- Related plan: {message.related_plan_id or ''}",
            f"- Related limit: {message.related_limit_id or ''}",
            "",
        )
    )
    return KnowledgeCaptureCandidate(
        kind="crew",
        source_id=message.id,
        path=f"Overseer/Knowledge/Crew/{owner}/{_safe_filename(message.id)}.md",
        title=title,
        owner_domain=owner,
        occurred_at=message.updated_at or message.created_at,
        content=content,
    )


def _audit_candidate(event: AuditEvent) -> KnowledgeCaptureCandidate:
    owner = OwnerDomain(event.owner_domain).value
    event_type = AuditEventType(event.event_type).value
    risk = RiskLevel(event.risk_level).value
    title = f"{_officer_name(owner)} {event_type.title()}: {event.subject_id}"
    evidence = "\n".join(f"- {evidence_id}" for evidence_id in event.evidence_ids) or "- none"
    content = "\n".join(
        (
            "---",
            f"overseer_id: {event.id}",
            "overseer_kind: audit_event",
            f"owner_domain: {owner}",
            f"event_type: {event_type}",
            f"risk_level: {risk}",
            f"captured_by: {CAPTURED_BY}",
            "---",
            "",
            f"# {title}",
            "",
            "## Summary",
            event.summary,
            "",
            "## Event",
            f"- Type: {event_type}",
            f"- Owner: {owner}",
            f"- Subject: {event.subject_id}",
            f"- Risk: {risk}",
            f"- Occurred at: {event.occurred_at or ''}",
            "",
            "## Evidence",
            evidence,
            "",
        )
    )
    return KnowledgeCaptureCandidate(
        kind="audit",
        source_id=event.id,
        path=f"Overseer/Knowledge/Events/{owner}/{_safe_filename(event.id)}.md",
        title=title,
        owner_domain=owner,
        occurred_at=event.occurred_at,
        content=content,
    )


def _normalize_kinds(kinds: Sequence[str]) -> tuple[str, ...]:
    normalized = tuple(dict.fromkeys(str(kind).strip().lower() for kind in kinds if str(kind).strip()))
    selected = normalized or DEFAULT_KNOWLEDGE_KINDS
    invalid = sorted(set(selected) - set(DEFAULT_KNOWLEDGE_KINDS))
    if invalid:
        raise ValueError(f"unsupported knowledge capture kind: {', '.join(invalid)}")
    return selected


def _safe_filename(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-")
    if not safe:
        return "event"
    if len(safe) <= 96:
        return safe
    digest = sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"{safe[:83].rstrip('-')}-{digest}"


def _officer_name(owner_domain: str) -> str:
    return {
        "sisko": "Sisko",
        "kira": "Kira",
        "obrien": "O'Brien",
        "odo": "Odo",
        "quark": "Quark",
        "dax": "Dax",
        "julian": "Julian",
        "ezri": "Ezri",
    }.get(owner_domain, owner_domain.title())
