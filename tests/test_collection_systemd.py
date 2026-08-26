from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
UNIT_PATH = ROOT / "systemd" / "overseer.service"
API_UNIT_PATH = ROOT / "systemd" / "overseer-api.service"
QUARK_UNIT_PATH = ROOT / "systemd" / "overseer-quark-scheduler.service"
OPERATIONS_PATH = ROOT / "docs" / "v1.1-operations.md"


def test_overseer_runtime_unit_runs_scheduler_without_bulk_flags() -> None:
    unit = UNIT_PATH.read_text(encoding="utf-8")

    assert "Type=simple" in unit
    assert "EnvironmentFile=%h/.config/overseer/runtime.env" in unit
    assert "WorkingDirectory=@OVERSEER_INSTALL@" in unit
    assert "ExecStart=/usr/bin/env -- ${OVERSEER_PYTHON} -m overseer.cli run --store ${OVERSEER_STORE}" in unit
    assert "Restart=on-failure" in unit
    assert "RestartSec=5" in unit
    assert "--probe-health-targets" not in unit
    assert "--inspect-host" not in unit
    assert "--dispatch-crew-messages" not in unit
    assert "--dispatch-usage-continuations" not in unit
    assert "--capture-knowledge-events" not in unit
    assert "--audit-station" not in unit
    assert "ListenStream=" not in unit
    assert "ListenDatagram=" not in unit
    assert "-m overseer.api" not in unit


def test_overseer_runtime_unit_is_a_source_template_not_a_live_install() -> None:
    unit = UNIT_PATH.read_text(encoding="utf-8")

    assert "OVERSEER_PYTHON" in unit
    assert "ExecStartPre=/usr/bin/test -d ${OVERSEER_INSTALL}/src" in unit
    assert "OVERSEER_STORE" in unit
    assert "Environment=PYTHONPATH=" not in unit
    assert "/home/" not in unit
    assert "enable --now" not in unit
    assert "systemctl" not in unit


def test_overseer_runtime_unit_passes_disposable_systemd_verify(tmp_path: Path) -> None:
    unit = UNIT_PATH.read_text(encoding="utf-8")
    install_path = tmp_path / "install"
    (install_path / "src").mkdir(parents=True)
    store_path = tmp_path / "state" / "overseer.sqlite3"
    store_path.parent.mkdir()
    environment_path = tmp_path / "runtime.env"
    environment_path.write_text(
        "\n".join(
            (
                "OVERSEER_PYTHON=/usr/bin/python3",
                f"OVERSEER_INSTALL={install_path}",
                f"OVERSEER_STORE={store_path}",
                f"PYTHONPATH={install_path / 'src'}",
                "PYTHONDONTWRITEBYTECODE=1",
                "",
            )
        ),
        encoding="utf-8",
    )
    environment_path.chmod(0o600)
    disposable_unit = tmp_path / "overseer.service"
    disposable_unit.write_text(
        unit.replace(
            "EnvironmentFile=%h/.config/overseer/runtime.env",
            f"EnvironmentFile={environment_path}",
        ).replace("WorkingDirectory=@OVERSEER_INSTALL@", f"WorkingDirectory={install_path}"),
        encoding="utf-8",
    )

    result = subprocess.run(
        ["systemd-analyze", "verify", str(disposable_unit)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_overseer_api_unit_imports_the_reviewed_release_without_changing_its_listener() -> None:
    unit = API_UNIT_PATH.read_text(encoding="utf-8")

    assert "WorkingDirectory=@OVERSEER_INSTALL@" in unit
    assert 'Environment="PYTHONPATH=@OVERSEER_INSTALL@/src"' in unit
    assert "Environment=PYTHONDONTWRITEBYTECODE=1" in unit
    assert 'ExecStartPre=/usr/bin/test -d "@OVERSEER_INSTALL@/src"' in unit
    assert (
        'ExecStart="@OVERSEER_PYTHON@" -m overseer.cli serve-api '
        '--store "@OVERSEER_STORE@" --host 127.0.0.1 --port 8766 '
        '--auth-token-file "@OVERSEER_API_TOKEN_FILE@" '
        '--human-approval-token-file "@OVERSEER_HUMAN_APPROVAL_TOKEN_FILE@" '
        '--human-approval-identity sisko'
    ) in unit
    assert "EnvironmentFile=" not in unit
    assert "Wants=" not in unit
    assert "ListenStream=" not in unit
    assert "ListenDatagram=" not in unit
    assert "0.0.0.0" not in unit
    assert "systemctl" not in unit


def test_overseer_api_unit_passes_disposable_systemd_verify(tmp_path: Path) -> None:
    unit = API_UNIT_PATH.read_text(encoding="utf-8")
    install_path = tmp_path / "install with spaces"
    (install_path / "src").mkdir(parents=True)
    store_path = tmp_path / "state with spaces" / "overseer.sqlite3"
    store_path.parent.mkdir()
    token_path = tmp_path / "api token with spaces"
    token_path.write_text("not-a-live-secret\n", encoding="utf-8")
    approval_token_path = tmp_path / "approval token with spaces"
    approval_token_path.write_text("different-not-a-live-secret\n", encoding="utf-8")
    disposable_unit = tmp_path / "overseer-api.service"
    disposable_unit.write_text(
        unit.replace("@OVERSEER_INSTALL@", str(install_path))
        .replace("@OVERSEER_PYTHON@", "/usr/bin/python3")
        .replace("@OVERSEER_STORE@", str(store_path))
        .replace("@OVERSEER_API_TOKEN_FILE@", str(token_path))
        .replace("@OVERSEER_HUMAN_APPROVAL_TOKEN_FILE@", str(approval_token_path)),
        encoding="utf-8",
    )

    result = subprocess.run(
        ["systemd-analyze", "verify", str(disposable_unit)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_quark_unit_uses_the_active_reviewed_overseer_release() -> None:
    unit = QUARK_UNIT_PATH.read_text(encoding="utf-8")

    assert "EnvironmentFile=%h/.config/overseer/runtime.env" in unit
    assert "WorkingDirectory=@OVERSEER_INSTALL@" in unit
    assert (
        "ExecStart=/usr/bin/env -- ${OVERSEER_PYTHON} -m overseer.quark_scheduler_cli "
        "--db %h/.local/share/overseer/codex-usage-mcp/state.sqlite3 run-cycle"
    ) in unit
    assert "ReadWritePaths=%h/.local/share/overseer/codex-usage-mcp" in unit
    assert "codex-usage-mcp-venv" not in unit
    assert "Environment=PYTHONPATH=" not in unit


def test_quark_unit_passes_disposable_systemd_verify(tmp_path: Path) -> None:
    unit = QUARK_UNIT_PATH.read_text(encoding="utf-8")
    install_path = tmp_path / "install"
    (install_path / "src").mkdir(parents=True)
    runtime_environment = tmp_path / "runtime.env"
    runtime_environment.write_text(
        "\n".join(
            (
                "OVERSEER_PYTHON=/usr/bin/python3",
                f"OVERSEER_INSTALL={install_path}",
                f"PYTHONPATH={install_path / 'src'}",
                "PYTHONDONTWRITEBYTECODE=1",
                "",
            )
        ),
        encoding="utf-8",
    )
    disposable_unit = tmp_path / "overseer-quark-scheduler.service"
    disposable_unit.write_text(
        unit.replace(
            "EnvironmentFile=%h/.config/overseer/runtime.env",
            f"EnvironmentFile={runtime_environment}",
        )
        .replace("@OVERSEER_INSTALL@", str(install_path)),
        encoding="utf-8",
    )

    result = subprocess.run(
        ["systemd-analyze", "verify", str(disposable_unit)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stderr == ""


def test_v11_runbook_preserves_exact_state_without_secret_argv_or_globs() -> None:
    operations = OPERATIONS_PATH.read_text(encoding="utf-8")

    assert '"$OVERSEER_ROLLBACK_ROOT/overseer.service.prior"' in operations
    assert '"$OVERSEER_ROLLBACK_ROOT/overseer-api.service.prior"' in operations
    assert '"$OVERSEER_ROLLBACK_ROOT/runtime.env.prior"' in operations
    assert 'runtime.env.prior-state.txt' in operations
    assert 'overseer.service.prior-mode.txt' in operations
    assert 'overseer-api.service.prior-mode.txt' in operations
    assert 'case "$OVERSEER_PRIOR_ENV_STATE" in' in operations
    assert 'absent) rm -- "$OVERSEER_LIVE_ENV" ;;' in operations
    assert 'runtime.is-enabled.txt' in operations
    assert 'runtime.is-active.txt' in operations
    assert 'api.is-active.txt' in operations
    assert 'case "$OVERSEER_PRIOR_RUNTIME_ENABLEMENT" in' in operations
    assert 'case "$OVERSEER_PRIOR_RUNTIME_ACTIVITY" in' in operations
    assert 'case "$OVERSEER_PRIOR_API_ACTIVITY" in' in operations
    assert 'from urllib.request import Request, urlopen' in operations
    assert 'Authorization: Bearer $OVERSEER_API_TOKEN' not in operations
    assert 'pre-v1.1.mode.txt' in operations
    assert '"$OVERSEER_ROLLBACK_ROOT/store.prior.sqlite3-wal"' not in operations
    assert '"$OVERSEER_ACTIVATION_OUTPUT"/*' not in operations
    assert '"$OVERSEER_FORENSIC_ROOT"/*' not in operations
    assert 'store.before.sqlite3*' not in operations
    assert 'status --porcelain=v1 --untracked-files=all --ignored=matching' in operations
    assert '"PYTHONDONTWRITEBYTECODE=1"' in operations
    assert 'test ! -s "$OVERSEER_EVIDENCE_DIR/source-status.txt"' in operations
    assert 'test ! -s "$OVERSEER_ACTIVATION_OUTPUT/source-status.before.txt"' in operations
    assert 'test ! -s "$OVERSEER_ACTIVATION_OUTPUT/source-status.pre-start.txt"' in operations
    assert 'OVERSEER_APPROVED_TREE' in operations
    assert 'OVERSEER_APPROVED_SOURCE_MANIFEST' in operations
    assert 'OVERSEER_APPROVED_PYTHON_SHA256' in operations
    assert 'OVERSEER_APPROVED_DEPENDENCIES_SHA256' in operations
    assert 'OVERSEER_APPROVED_ENV_SHA256' in operations
    assert 'OVERSEER_APPROVED_RENDERED_UNIT_SHA256' in operations
    assert 'OVERSEER_APPROVED_RENDERED_API_UNIT_SHA256' in operations
    assert 'OVERSEER_RENDERED_UNIT=/absolute/path/to/forensic-evidence/overseer-v1.1/activation-output/rendered/overseer.service' in operations
    assert 'OVERSEER_RENDERED_API_UNIT=/absolute/path/to/forensic-evidence/overseer-v1.1/activation-output/rendered/overseer-api.service' in operations
    assert 'OVERSEER_API_TOKEN_FILE' in operations
    assert 'OVERSEER_HUMAN_APPROVAL_TOKEN_FILE' in operations
    assert 'OVERSEER_LIVE_API_UNIT' in operations
    assert 'OVERSEER_API_DROPIN_DIR' in operations
    assert 'api-dropins.before.sha256' in operations
    assert 'api-dropins.after.sha256' in operations
    assert 'cmp -s "$OVERSEER_ROLLBACK_ROOT/api-dropins.before.json"' in operations
    assert 'set -euo pipefail' in operations
    assert 'writers.after-stop.txt' in operations
    assert 'writers.after-backup.txt' in operations
    assert 'store.prior.mode.txt' not in operations
    assert 'api-dropins.before.json' in operations
    assert 'effective-api.before-start.txt' in operations
    assert 'effective-runtime.before-start.txt' in operations
    assert 'process-provenance.json' in operations
    assert 'os.readlink(f"/proc/{pid}/cwd")' in operations
    assert '"OVERSEER_PYTHON": str(Path(sys.argv[2]).absolute())' in operations
    assert 'OVERSEER_PSYCHLO_COORDINATION_TIMER=overseer-psychlo-coordination-tick.timer' in operations
    assert 'psychlo-coordination-timer.before.txt' in operations
    assert 'test "$OVERSEER_PSYCHLO_COORDINATION_TIMER_LOAD_STATE" = not-found' in operations
    assert 'test ! -s "$OVERSEER_EVIDENCE_DIR/systemd-verify.stderr"' in operations
    assert 'test ! -s "$OVERSEER_ACTIVATION_OUTPUT/systemd-verify.stderr"' in operations
