"""Worker-local collection deadline propagation."""

from __future__ import annotations

import time
from contextlib import contextmanager
from contextvars import ContextVar
from collections.abc import Iterator


class CollectionDeadlineExceeded(TimeoutError):
    """Raised when collection persistence reaches its absolute deadline."""


_COLLECTION_DEADLINE: ContextVar[float | None] = ContextVar(
    "overseer_collection_deadline",
    default=None,
)


def current_collection_deadline() -> float | None:
    return _COLLECTION_DEADLINE.get()


@contextmanager
def collection_deadline_scope(deadline: float) -> Iterator[None]:
    token = _COLLECTION_DEADLINE.set(float(deadline))
    try:
        yield
    finally:
        _COLLECTION_DEADLINE.reset(token)


def require_collection_time(deadline: float | None = None) -> float | None:
    effective = current_collection_deadline() if deadline is None else deadline
    if effective is None:
        return None
    remaining = float(effective) - time.monotonic()
    if remaining <= 0:
        raise CollectionDeadlineExceeded("collection deadline exceeded before persistence")
    return remaining
