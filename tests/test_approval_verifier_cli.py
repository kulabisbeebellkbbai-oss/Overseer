from __future__ import annotations

import getpass
import json
import os
from pathlib import Path

import pytest

from overseer.approval_auth import load_approval_verifier
from overseer.cli import main as cli_main


ADMIN_SECRET = "admin-approval-secret-strong-1"


def test_create_approval_verifier_prompts_twice_and_writes_only_a_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "admin-verifier.json"
    prompts: list[str] = []

    def prompt(label: str) -> str:
        prompts.append(label)
        return ADMIN_SECRET

    monkeypatch.setattr(getpass, "getpass", prompt)

    result = cli_main(
        [
            "create-approval-verifier",
            "--scope",
            "admin-plan-approval",
            "--output",
            str(output),
        ]
    )
    captured = capsys.readouterr()

    assert result == 0
    assert len(prompts) == 2
    assert output.is_file()
    assert output.stat().st_uid == os.geteuid()
    assert output.stat().st_nlink == 1
    assert output.stat().st_mode & 0o777 == 0o600
    assert ADMIN_SECRET not in output.read_text(encoding="utf-8")
    assert ADMIN_SECRET not in captured.out
    assert ADMIN_SECRET not in captured.err
    status = json.loads(captured.out)
    assert status == {
        "identity": "sisko",
        "output": str(output),
        "scope": "admin-plan-approval",
        "status": "created",
    }
    assert load_approval_verifier(output).authenticate(ADMIN_SECRET) == "sisko"


def test_create_approval_verifier_mismatch_leaves_no_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "admin-verifier.json"
    responses = iter((ADMIN_SECRET, "different-approval-secret-1"))
    monkeypatch.setattr(getpass, "getpass", lambda _label: next(responses))

    with pytest.raises(ValueError, match="confirmation"):
        cli_main(
            [
                "create-approval-verifier",
                "--scope",
                "admin-plan-approval",
                "--output",
                str(output),
            ]
        )

    assert not output.exists()


def test_create_approval_verifier_refuses_to_replace_an_existing_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "admin-verifier.json"
    output.write_text("preserve me", encoding="utf-8")
    output.chmod(0o600)
    monkeypatch.setattr(getpass, "getpass", lambda _label: ADMIN_SECRET)

    with pytest.raises(FileExistsError):
        cli_main(
            [
                "create-approval-verifier",
                "--scope",
                "admin-plan-approval",
                "--output",
                str(output),
            ]
        )

    assert output.read_text(encoding="utf-8") == "preserve me"


def test_create_approval_verifier_enforces_owner_mode_under_restrictive_umask(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "admin-verifier.json"
    monkeypatch.setattr(getpass, "getpass", lambda _label: ADMIN_SECRET)
    previous_umask = os.umask(0o477)
    try:
        assert cli_main(
            [
                "create-approval-verifier",
                "--scope",
                "admin-plan-approval",
                "--output",
                str(output),
            ]
        ) == 0
    finally:
        os.umask(previous_umask)

    assert output.stat().st_mode & 0o777 == 0o600
