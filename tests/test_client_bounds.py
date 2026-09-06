from __future__ import annotations

import pytest

import overseer.client as client_module
from overseer.client import OverseerApiClient


class _FakeResponse:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.requested_bytes: int | None = None

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, amount: int = -1) -> bytes:
        self.requested_bytes = amount
        return self.body if amount < 0 else self.body[:amount]


def test_client_rejects_a_response_larger_than_the_configured_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _FakeResponse(b'{"value":"oversized"}')
    monkeypatch.setattr(client_module, "urlopen", lambda *_args, **_kwargs: response)
    client = OverseerApiClient(max_response_bytes=8)

    with pytest.raises(ValueError, match="response body exceeds configured limit"):
        client.health()

    assert response.requested_bytes == 9


def test_client_accepts_valid_json_at_the_configured_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = b'{"ok":true}'
    response = _FakeResponse(body)
    monkeypatch.setattr(client_module, "urlopen", lambda *_args, **_kwargs: response)
    client = OverseerApiClient(max_response_bytes=len(body))

    assert client.health() == {"ok": True}
    assert response.requested_bytes == len(body) + 1


@pytest.mark.parametrize("limit", (True, 0, -1, 1.5))
def test_client_rejects_an_invalid_response_bound(limit: object) -> None:
    with pytest.raises(ValueError, match="max response bytes must be a positive integer"):
        OverseerApiClient(max_response_bytes=limit)  # type: ignore[arg-type]
