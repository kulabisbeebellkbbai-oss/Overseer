from __future__ import annotations

from pathlib import Path

import overseer.api as api


class _FakeBridge:
    def close(self) -> None:
        pass


class _FakeServer:
    def __init__(self, address, handler, **kwargs):
        self.address = address
        self.handler = handler
        self.kwargs = kwargs
        self.closed = False

    def serve_forever(self) -> None:
        return None

    def server_close(self) -> None:
        self.closed = True


def test_run_api_server_binds_psychlo_authority_to_explicit_api_store(monkeypatch, tmp_path: Path):
    """The API --store is the default authority store for the Psychlo bridge."""
    api_store = tmp_path / "primary.sqlite3"
    captured: dict[str, object] = {}

    def create_bridge(environment):
        captured["environment"] = environment
        return _FakeBridge()

    monkeypatch.setenv("OVERSEER_PSYCHLO_PEER_SECRET_FILE", str(tmp_path / "secret"))
    monkeypatch.delenv("OVERSEER_STORE_DATABASE", raising=False)
    monkeypatch.delenv("OVERSEER_STORE_PATH", raising=False)
    monkeypatch.setattr(api, "create_bridge_from_environment", create_bridge)
    monkeypatch.setattr(api, "BoundedThreadingHTTPServer", _FakeServer)

    api.run_api_server(str(api_store))

    environment = captured["environment"]
    assert isinstance(environment, dict)
    assert environment["OVERSEER_STORE_DATABASE"] == str(api_store)


def test_run_api_server_rejects_conflicting_environment_authority_store(monkeypatch, tmp_path: Path):
    api_store = tmp_path / "primary.sqlite3"
    configured_store = tmp_path / "configured.sqlite3"
    captured: dict[str, object] = {}

    def create_bridge(environment):
        captured["environment"] = environment
        return _FakeBridge()

    monkeypatch.setenv("OVERSEER_PSYCHLO_PEER_SECRET_FILE", str(tmp_path / "secret"))
    monkeypatch.setenv("OVERSEER_STORE_DATABASE", str(configured_store))
    monkeypatch.setattr(api, "create_bridge_from_environment", create_bridge)
    monkeypatch.setattr(api, "BoundedThreadingHTTPServer", _FakeServer)

    api.run_api_server(str(api_store))

    environment = captured["environment"]
    assert isinstance(environment, dict)
    assert environment["OVERSEER_STORE_DATABASE"] == str(api_store)
