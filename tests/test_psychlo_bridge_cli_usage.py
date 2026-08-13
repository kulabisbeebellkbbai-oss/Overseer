from pathlib import Path

import pytest

from overseer.psychlo_bridge_cli import _closed_json


def test_usage_authority_input_is_private_bounded_and_no_follow(tmp_path: Path):
    authority = tmp_path / "authority.json"
    authority.write_text('{"authorityId":"meter","authorityBindingId":"binding","authorityBindingDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","accountId":"account","publicKey":"key"}', encoding="utf-8")
    authority.chmod(0o600)
    value = _closed_json(authority, {"authorityId", "authorityBindingId", "authorityBindingDigest", "accountId", "publicKey"})
    assert value["authorityId"] == "meter"
    authority.chmod(0o640)
    with pytest.raises(ValueError, match="unsafe"):
        _closed_json(authority, None)
    authority.chmod(0o600)
    link = tmp_path / "authority-link.json"
    link.symlink_to(authority)
    with pytest.raises(OSError):
        _closed_json(link, None)


def test_usage_authority_input_rejects_extra_keys_and_oversize(tmp_path: Path):
    authority = tmp_path / "authority.json"
    authority.write_text('{"authorityId":"meter","extra":"no"}', encoding="utf-8")
    authority.chmod(0o600)
    with pytest.raises(ValueError, match="configuration"):
        _closed_json(authority, {"authorityId"})
    authority.write_bytes(b" " * (1024 * 1024 + 1))
    authority.chmod(0o600)
    with pytest.raises(ValueError, match="unsafe|large"):
        _closed_json(authority, None)
