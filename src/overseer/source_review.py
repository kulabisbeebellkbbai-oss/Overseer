"""Source evidence review records for host security workflows."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class SourceReviewDisposition(StrEnum):
    NEEDS_REVIEW = "needs_review"
    EXPECTED = "expected"
    SUSPICIOUS = "suspicious"
    HOSTILE = "hostile"
    BENIGN = "benign"


@dataclass(frozen=True)
class HostSecuritySourceReview:
    id: str
    source_connection_id: str
    snapshot_id: str
    listener: str
    remote_address: str
    remote_port: str
    source_scope: str
    evidence: str
    disposition: SourceReviewDisposition
    rationale: str
    reviewed_by: str | None = None
    reviewed_at: str | None = None
    created_at: str | None = None

    def can_stage_block_plan(self) -> bool:
        return (
            self.disposition == SourceReviewDisposition.HOSTILE
            and self.source_scope == "external"
            and bool(self.reviewed_by)
            and bool(self.rationale.strip())
        )
