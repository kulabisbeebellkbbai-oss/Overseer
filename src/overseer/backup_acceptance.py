"""Strict, read-only TheUnderdark acceptance checks."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Callable, Mapping, Protocol

from .backup_execution import BehaviorAcceptance


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_READ_TOOLS = frozenset({"underdark_health_get", "underdark_project_get", "underdark_root_get", "underdark_directory_list"})
_DEPENDENCIES = frozenset({"operation_journal", "authorization_verifier", "bounded_executor", "admission_controller", "read_backend", "snapshot_paginator"})
_EVIDENCE = {"evidence_ids": [], "host_state_changed": False, "redactions_applied": True}


class AcceptanceClient(Protocol):
    def health_get(self) -> Mapping[str, object]: ...
    def project_get(self, project_id: str) -> Mapping[str, object]: ...
    def root_get(self, project_id: str, root_id: str) -> Mapping[str, object]: ...
    def directory_list(self, project_id: str, root_id: str, relative_path: str, policy_revision: str) -> Mapping[str, object]: ...


@dataclass(frozen=True)
class AcceptanceExpectation:
    service_contract_version: str
    acceptance_contract_version: str
    acceptance_contract_digest: str
    project_id: str
    root_id: str
    policy_revision: str
    nested_relative_path: str
    runtime_digest: str
    config_digest: str

    def __post_init__(self) -> None:
        if self.service_contract_version != "1.0":
            raise ValueError("service contract must be version 1.0")
        if type(self.acceptance_contract_version) is not str or _IDENTIFIER.fullmatch(self.acceptance_contract_version) is None:
            raise ValueError("acceptance_contract_version is not a safe identifier")
        for name in ("project_id", "root_id", "policy_revision"):
            if type(getattr(self, name)) is not str or _IDENTIFIER.fullmatch(getattr(self, name)) is None:
                raise ValueError(f"{name} is not a safe identifier")
        path = self.nested_relative_path
        if type(path) is not str or not path or path.startswith("/") or any(part in {"", ".", ".."} for part in path.split("/")):
            raise ValueError("nested_relative_path is not approved")
        for name in ("acceptance_contract_digest", "runtime_digest", "config_digest"):
            if type(getattr(self, name)) is not str or _DIGEST.fullmatch(getattr(self, name)) is None:
                raise ValueError(f"{name} is not a sha256 digest")

    @property
    def contract_digest(self) -> str:
        return self.acceptance_contract_digest


DonutHoleAcceptanceExpectation = AcceptanceExpectation


class TheUnderdarkAcceptanceClient:
    """A facade whose public call surface contains only the four read calls."""

    __slots__ = ("_call_tool",)

    def __init__(self, call_tool: Callable[[str, Mapping[str, object]], Mapping[str, object]]) -> None:
        if not callable(call_tool):
            raise TypeError("call_tool must be callable")
        self._call_tool = call_tool

    def call_tool(self, name: str, arguments: Mapping[str, object]) -> Mapping[str, object]:
        if name not in _READ_TOOLS:
            raise ValueError("TheUnderdark acceptance client is read-only")
        if type(arguments) is not dict:
            raise ValueError("acceptance arguments must be an object")
        return self._call_tool(name, dict(arguments))

    def health_get(self) -> Mapping[str, object]:
        return self.call_tool("underdark_health_get", {})

    def project_get(self, project_id: str) -> Mapping[str, object]:
        return self.call_tool("underdark_project_get", {"project_id": project_id})

    def root_get(self, project_id: str, root_id: str) -> Mapping[str, object]:
        return self.call_tool("underdark_root_get", {"project_id": project_id, "root_id": root_id})

    def directory_list(self, project_id: str, root_id: str, relative_path: str, policy_revision: str) -> Mapping[str, object]:
        return self.call_tool("underdark_directory_list", {"project_id": project_id, "root_id": root_id, "relative_path": relative_path, "policy_revision": policy_revision, "cursor": None, "limit": 2})


def _digest(value: object) -> bool:
    return type(value) is str and _DIGEST.fullmatch(value) is not None


def _failed(expected: AcceptanceExpectation, code: str) -> BehaviorAcceptance:
    return BehaviorAcceptance(expected.acceptance_contract_version, expected.acceptance_contract_digest, False, code, "sha256:" + hashlib.sha256(("failure\n" + code).encode()).hexdigest())


def _envelope(value: object, keys: set[str], code: str) -> tuple[Mapping[str, object] | None, str]:
    if not isinstance(value, Mapping) or set(value) != {"ok", "contract_version", "request_id", "result", "evidence"}:
        return None, code
    if value["ok"] is not True or value["contract_version"] != "1.0" or value["request_id"] != "read":
        return None, code
    if value["evidence"] != _EVIDENCE:
        return None, code
    result = value["result"]
    if not isinstance(result, Mapping) or set(result) != keys:
        return None, code
    return result, ""


def _health(value: object) -> tuple[Mapping[str, object] | None, str]:
    if not isinstance(value, Mapping) or set(value) != {"ok", "contract_version", "result"} or value["ok"] is not True or value["contract_version"] != "1.0":
        return None, "HEALTH_RESPONSE_INVALID"
    result = value["result"]
    if not isinstance(result, Mapping) or set(result) != {"status", "contract_version", "dependencies", "runtime"} or result["status"] != "healthy" or result["contract_version"] != "1.0":
        return None, "HEALTH_RESPONSE_INVALID"
    dependencies = result["dependencies"]
    if not isinstance(dependencies, Mapping) or set(dependencies) != _DEPENDENCIES or any(item != "ready" for item in dependencies.values()):
        return None, "HEALTH_RESPONSE_INVALID"
    runtime = result["runtime"]
    if not isinstance(runtime, Mapping) or set(runtime) != {"runtime_digest", "config_digest", "process_start_id"} or not all(_digest(runtime.get(key)) for key in runtime):
        return None, "HEALTH_RESPONSE_INVALID"
    return result, ""


def _bounded_entries(entries: object) -> bool:
    if not isinstance(entries, list) or len(entries) > 2:
        return False
    for entry in entries:
        if not isinstance(entry, Mapping) or len(entry) > 8 or not entry:
            return False
        if any(not isinstance(key, str) or len(key) > 64 for key in entry):
            return False
        if any(isinstance(item, (Mapping, list, bytes)) or not isinstance(item, (str, int, float, bool, type(None))) for item in entry.values()):
            return False
        if len(json.dumps(entry, ensure_ascii=True, separators=(",", ":"))) > 1024:
            return False
    return True


def _canonical(health: Mapping[str, object], project: Mapping[str, object], root: Mapping[str, object], root_list: Mapping[str, object], nested: Mapping[str, object]) -> str:
    safe = {
        "health": {"status": health["status"], "runtime_digest": health["runtime"]["runtime_digest"], "config_digest": health["runtime"]["config_digest"]},
        "project": {"status": project["status"], "policy_revision": project["policy_revision"], "root_count": len(project["roots"])},
        "root": {"status": root["status"], "policy_revision": root["policy_revision"], "limits": root["limits"], "namespace_identity": root["namespace_identity"], "symlink_policy": root["symlink_policy"]},
        "root_directory": {"snapshot_identity": root_list["snapshot_identity"], "total_count": root_list["total_count"], "cursor_present": root_list["next_cursor"] is not None},
        "nested_directory": {"snapshot_identity": nested["snapshot_identity"], "total_count": nested["total_count"], "cursor_present": nested["next_cursor"] is not None},
    }
    return "sha256:" + hashlib.sha256(json.dumps(safe, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def run_donuthole_acceptance(client: AcceptanceClient, expected: AcceptanceExpectation) -> BehaviorAcceptance:
    if not isinstance(expected, AcceptanceExpectation):
        raise TypeError("expected must be an AcceptanceExpectation")
    try:
        health, code = _health(client.health_get())
        if health is None:
            return _failed(expected, code)
        runtime = health["runtime"]
        if runtime["runtime_digest"] != expected.runtime_digest:
            return _failed(expected, "ACTIVE_RUNTIME_MISMATCH")
        if runtime["config_digest"] != expected.config_digest:
            return _failed(expected, "ACTIVE_CONFIG_MISMATCH")
        if health["contract_version"] != expected.service_contract_version:
            return _failed(expected, "SERVICE_CONTRACT_MISMATCH")
        project, code = _envelope(client.project_get(expected.project_id), {"project_id", "status", "policy_revision", "roots", "redactions_applied"}, "PROJECT_RESPONSE_INVALID")
        if project is None or project["project_id"] != expected.project_id or project["policy_revision"] != expected.policy_revision or project["redactions_applied"] is not True or not isinstance(project["roots"], list) or len(project["roots"]) > 64:
            return _failed(expected, code or "PROJECT_RESPONSE_INVALID")
        root, code = _envelope(client.root_get(expected.project_id, expected.root_id), {"project_id", "root_id", "alias", "status", "policy_revision", "limits", "namespace_identity", "symlink_policy", "redactions_applied"}, "ROOT_RESPONSE_INVALID")
        if root is None or root["project_id"] != expected.project_id or root["root_id"] != expected.root_id or root["policy_revision"] != expected.policy_revision or not _digest(root["namespace_identity"]) or root["redactions_applied"] is not True:
            return _failed(expected, code or "ROOT_RESPONSE_INVALID")
        root_list, code = _envelope(client.directory_list(expected.project_id, expected.root_id, "", expected.policy_revision), {"entries", "next_cursor", "snapshot_identity", "total_count"}, "DIRECTORY_RESPONSE_INVALID")
        if root_list is None or not _valid_directory(root_list):
            return _failed(expected, code or "DIRECTORY_RESPONSE_INVALID")
        nested, code = _envelope(client.directory_list(expected.project_id, expected.root_id, expected.nested_relative_path, expected.policy_revision), {"entries", "next_cursor", "snapshot_identity", "total_count"}, "DIRECTORY_RESPONSE_INVALID")
        if nested is None or not _valid_directory(nested):
            return _failed(expected, code or "DIRECTORY_RESPONSE_INVALID")
        return BehaviorAcceptance(expected.acceptance_contract_version, expected.acceptance_contract_digest, True, "ACCEPTANCE_PASSED", _canonical(health, project, root, root_list, nested))
    except Exception:
        return _failed(expected, "ACCEPTANCE_CLIENT_ERROR")


def _valid_directory(result: Mapping[str, object]) -> bool:
    return _bounded_entries(result["entries"]) and (result["next_cursor"] is None or (type(result["next_cursor"]) is str and len(result["next_cursor"]) <= 256)) and _digest(result["snapshot_identity"]) and type(result["total_count"]) is int and result["total_count"] >= len(result["entries"])


__all__ = ["AcceptanceExpectation", "DonutHoleAcceptanceExpectation", "TheUnderdarkAcceptanceClient", "run_donuthole_acceptance"]
