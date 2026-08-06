from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

import pytest

from overseer.backup_acceptance import (
    AcceptanceExpectation,
    TheUnderdarkAcceptanceClient,
    run_donuthole_acceptance,
)


RUNTIME = "sha256:" + "a" * 64
CONFIG = "sha256:" + "b" * 64
CONTRACT = "sha256:" + "c" * 64
NAMESPACE = "sha256:" + "d" * 64
SNAPSHOT = "sha256:" + "e" * 64


def _read(result: Mapping[str, object]) -> dict[str, object]:
    return {
        "ok": True,
        "contract_version": "1.0",
        "request_id": "read",
        "result": dict(result),
        "evidence": {"evidence_ids": [], "host_state_changed": False, "redactions_applied": True},
    }


def _health(*, process: str = "sha256:" + "f" * 64) -> dict[str, object]:
    return {
        "ok": True,
        "contract_version": "1.0",
        "result": {
            "status": "healthy",
            "contract_version": "1.0",
            "dependencies": {
                "operation_journal": "ready",
                "authorization_verifier": "ready",
                "bounded_executor": "ready",
                "admission_controller": "ready",
                "read_backend": "ready",
                "snapshot_paginator": "ready",
            },
            "runtime": {"runtime_digest": RUNTIME, "config_digest": CONFIG, "process_start_id": process},
        },
    }


@dataclass
class FakeClient:
    health: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        self.calls: list[tuple[str, object]] = []
        self.health = self.health or _health()

    def health_get(self) -> Mapping[str, object]:
        self.calls.append(("health", {}))
        return self.health

    def project_get(self, project_id: str) -> Mapping[str, object]:
        self.calls.append(("project", project_id))
        return _read({"project_id": project_id, "status": "active", "policy_revision": "7", "roots": [], "redactions_applied": True})

    def root_get(self, project_id: str, root_id: str) -> Mapping[str, object]:
        self.calls.append(("root", (project_id, root_id)))
        return _read({"project_id": project_id, "root_id": root_id, "alias": "secret-alias", "status": "registered", "policy_revision": "7", "limits": {"max_bytes": 100}, "namespace_identity": NAMESPACE, "symlink_policy": "deny", "redactions_applied": True})

    def directory_list(self, project_id: str, root_id: str, relative_path: str, policy_revision: str) -> Mapping[str, object]:
        self.calls.append(("directory", relative_path))
        return _read({"entries": [{"name": "secret-name", "kind": "file", "size": 1}], "next_cursor": None, "snapshot_identity": SNAPSHOT, "total_count": 1})


def expected() -> AcceptanceExpectation:
    return AcceptanceExpectation(
        service_contract_version="1.0", acceptance_contract_version="1.0", acceptance_contract_digest=CONTRACT,
        project_id="project.donuthole", root_id="backup-root", policy_revision="7", nested_relative_path="nested",
        runtime_digest=RUNTIME, config_digest=CONFIG,
    )


def test_exact_health_and_read_envelopes_are_accepted_and_ordered() -> None:
    client = FakeClient()
    report = run_donuthole_acceptance(client, expected())
    assert report.passed is True
    assert [name for name, _ in client.calls] == ["health", "project", "root", "directory", "directory"]
    assert [value for name, value in client.calls if name == "directory"] == ["", "nested"]


@pytest.mark.parametrize("where", ["health", "project", "root", "directory"])
def test_extra_or_missing_fields_fail_closed(where: str) -> None:
    client = FakeClient()
    if where == "health":
        client.health = _health(); client.health["extra"] = "private"
    else:
        # Alter the common response produced by a purpose-built subclass below.
        class Bad(FakeClient):
            def project_get(self, project_id: str) -> Mapping[str, object]:
                value = super().project_get(project_id); value["result"]["extra"] = "private"; return value
            def root_get(self, project_id: str, root_id: str) -> Mapping[str, object]:
                value = super().root_get(project_id, root_id); value["result"].pop("alias"); return value
            def directory_list(self, project_id: str, root_id: str, relative_path: str, policy_revision: str) -> Mapping[str, object]:
                value = super().directory_list(project_id, root_id, relative_path, policy_revision); value["evidence"].pop("host_state_changed"); return value
        client = Bad()
    report = run_donuthole_acceptance(client, expected())
    assert report.passed is False
    assert report.safe_code.endswith("RESPONSE_INVALID")
    assert "private" not in repr(report)


def test_mismatch_short_circuits_and_exact_sequence_is_not_started() -> None:
    client = FakeClient(health=_health())
    client.health["result"]["runtime"]["runtime_digest"] = "sha256:" + "0" * 64
    report = run_donuthole_acceptance(client, expected())
    assert (report.passed, report.safe_code) == (False, "ACTIVE_RUNTIME_MISMATCH")
    assert [name for name, _ in client.calls] == ["health"]


def test_canonical_digest_is_deterministic_redacted_and_process_restart_stable() -> None:
    first = run_donuthole_acceptance(FakeClient(), expected())
    second = run_donuthole_acceptance(FakeClient(health=_health(process="sha256:" + "0" * 64)), expected())
    assert first.results_digest == second.results_digest
    assert "project.donuthole" not in first.results_digest


def test_fixture_expectation_validation_and_compatibility_property() -> None:
    assert expected().contract_digest == CONTRACT
    with pytest.raises(ValueError):
        AcceptanceExpectation("1.0", "1.0", CONTRACT, "project", "root", "7", "../escape", RUNTIME, CONFIG)
    with pytest.raises(ValueError):
        AcceptanceExpectation("1.1", "acceptance.v1", CONTRACT, "project", "root", "7", "nested", RUNTIME, CONFIG)


def test_entries_are_bounded_but_never_persisted() -> None:
    client = FakeClient()
    client.directory_list = lambda *args: _read({"entries": [{"name": "x" * 5000}], "next_cursor": None, "snapshot_identity": SNAPSHOT, "total_count": 1})
    report = run_donuthole_acceptance(client, expected())
    assert report.passed is False
    assert report.safe_code == "DIRECTORY_RESPONSE_INVALID"
    assert "x" not in repr(report)


def test_read_only_tool_surface_has_exactly_four_calls_and_no_mutation() -> None:
    called: list[str] = []
    client = TheUnderdarkAcceptanceClient(lambda name, args: called.append(name) or {})
    assert {"health_get", "project_get", "root_get", "directory_list"}.issubset(set(dir(client)))
    with pytest.raises(ValueError, match="read-only"):
        client.call_tool("underdark_file_write", {})
    assert called == []
    with pytest.raises(ValueError, match="read-only"):
        client.call_tool("underdark_backup_create", {})
