from __future__ import annotations

import os
from pathlib import Path

import pytest

import overseer.admin_authority as admin_authority_module
from overseer.admin_authority import admin_authority_lock, admin_authority_lock_path


def test_admin_authority_lock_uses_the_exact_store_sibling(tmp_path: Path) -> None:
    store = tmp_path / "overseer.sqlite3"

    with admin_authority_lock(store):
        lock = admin_authority_lock_path(store)
        assert lock == tmp_path / ".overseer.sqlite3.admin-authority.lock"
        assert lock.stat().st_size == 0
        assert lock.stat().st_mode & 0o777 == 0o600


def test_admin_authority_lock_rejects_a_hardlinked_lock_file(tmp_path: Path) -> None:
    store = tmp_path / "overseer.sqlite3"
    lock = admin_authority_lock_path(store)
    lock.write_bytes(b"")
    lock.chmod(0o600)
    os.link(lock, tmp_path / "hardlink")

    with pytest.raises(ValueError, match="link count"):
        with admin_authority_lock(store):
            raise AssertionError("hardlinked authority lock must not be acquired")


def test_admin_authority_lock_rejects_a_nonempty_lock_file(tmp_path: Path) -> None:
    store = tmp_path / "overseer.sqlite3"
    lock = admin_authority_lock_path(store)
    lock.write_bytes(b"unexpected")
    lock.chmod(0o600)

    with pytest.raises(ValueError, match="not empty"):
        with admin_authority_lock(store):
            raise AssertionError("nonempty authority lock must not be acquired")


def test_admin_authority_lock_rechecks_size_after_exclusive_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = tmp_path / "overseer.sqlite3"
    real_flock = admin_authority_module.fcntl.flock
    mutated = False

    def mutate_before_lock(descriptor: int, operation: int) -> None:
        nonlocal mutated
        if operation == admin_authority_module.fcntl.LOCK_EX and not mutated:
            os.write(descriptor, b"raced")
            mutated = True
        real_flock(descriptor, operation)

    monkeypatch.setattr(admin_authority_module.fcntl, "flock", mutate_before_lock)

    with pytest.raises(ValueError, match="changed while being acquired"):
        with admin_authority_lock(store):
            raise AssertionError("mutated authority lock must not be acquired")
