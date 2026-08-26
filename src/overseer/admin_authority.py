"""Cross-thread and cross-process serialization for admin-plan authority."""

from __future__ import annotations

import fcntl
import os
import stat
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


_PROCESS_LOCK = threading.RLock()
_LOCAL = threading.local()


def _lock_path(store_path: str | Path) -> Path:
    database_path = Path(store_path).absolute()
    return database_path.with_name(f".{database_path.name}.admin-authority.lock")


@contextmanager
def admin_authority_lock(store_path: str | Path) -> Iterator[None]:
    """Hold one re-entrant process lock and one advisory lock per store."""

    lock_path = _lock_path(store_path)
    depths = getattr(_LOCAL, "depths", None)
    if depths is None:
        depths = {}
        _LOCAL.depths = depths
    key = str(lock_path)
    if depths.get(key, 0):
        depths[key] += 1
        try:
            yield
        finally:
            depths[key] -= 1
        return

    lock_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    with _PROCESS_LOCK:
        descriptor = os.open(lock_path, flags, 0o600)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("admin authority lock is not a regular file")
            if metadata.st_uid != os.geteuid():
                raise ValueError("admin authority lock has an unexpected owner")
            if stat.S_IMODE(metadata.st_mode) != 0o600:
                os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            depths[key] = 1
            try:
                yield
            finally:
                depths.pop(key, None)
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
