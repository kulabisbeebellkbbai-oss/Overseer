from types import SimpleNamespace

import pytest

import overseer.cli as cli
from overseer.core import OwnerDomain


def obrien_message(resource_id, plan_id=None):
    return SimpleNamespace(
        id="crew.obrien.resource-routing",
        owner_domain=OwnerDomain.OBRIEN,
        related_plan_id=plan_id,
        related_resource_id=resource_id,
    )


@pytest.mark.parametrize(
    "resource_id",
    (
        " ",
        " package.apt.openssl ",
        "resource.codex.workspace.arcade",
        "workspace.arcade",
        "package.apt.OpenSSL",
        "package.apt.openssl/invalid",
        "package.apt.",
    ),
)
def test_obrien_does_not_route_untyped_or_invalid_resources_to_apt(monkeypatch, resource_id):
    def unexpected_apt_planning(*args, **kwargs):
        raise AssertionError("untyped resource reached APT package planning")

    monkeypatch.setattr(cli, "plan_package_updates_status", unexpected_apt_planning)

    result = cli._dispatch_obrien_message(
        "unused",
        obrien_message(resource_id),
        "dispatcher",
        "2026-08-10T12:00:00+00:00",
    )

    assert result["status"] == "skipped"
    assert result["actions"] == []
    assert "opaque" in result["reason"]


@pytest.mark.parametrize("resource_id", (None, ""))
def test_obrien_without_resource_performs_read_only_inventory(resource_id, monkeypatch):
    calls = []

    def inspect(*args, **kwargs):
        calls.append((args, kwargs))
        return {"updates": [], "host_mutation_performed": False}

    monkeypatch.setattr(cli, "inspect_packages_status", inspect)
    monkeypatch.setattr(
        cli,
        "plan_package_updates_status",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("inventory must not stage an APT plan")),
    )

    result = cli._dispatch_obrien_message(
        "unused",
        obrien_message(resource_id),
        "dispatcher",
        "2026-08-10T12:00:00+00:00",
    )

    assert result["status"] == "dispatched"
    assert calls == [
        (
            (),
            {"captured_at": "2026-08-10T12:00:00+00:00"},
        )
    ]
    assert "exact related_plan_id" in result["reason"]


def test_obrien_does_not_use_legacy_auto_execution_for_nonbackup_plan(monkeypatch, tmp_path):
    monkeypatch.setattr(
        cli,
        "inspect_packages_status",
        lambda **kwargs: {"updates": [], "host_mutation_performed": False},
    )
    monkeypatch.setattr(
        cli,
        "_advance_obrien_package_plan",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("legacy package execution was used")),
    )

    result = cli._dispatch_obrien_message(
        str(tmp_path / "state.sqlite3"),
        obrien_message(None, "admin.apt.upgrade.exact"),
        "dispatcher",
        "2026-08-10T12:00:00+00:00",
    )

    assert result["status"] == "dispatched"
    assert "exact related_plan_id" in result["reason"]
