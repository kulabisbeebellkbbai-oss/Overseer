from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
UNIT_PATH = ROOT / "systemd" / "overseer.service"
OPERATIONS_PATH = ROOT / "docs" / "v1.1-operations.md"


def test_overseer_runtime_unit_runs_scheduler_without_bulk_flags() -> None:
    unit = UNIT_PATH.read_text(encoding="utf-8")

    assert "Type=simple" in unit
    assert "EnvironmentFile=%h/.config/overseer/runtime.env" in unit
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
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        ["systemd-analyze", "verify", str(disposable_unit)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_v11_runbook_preserves_exact_state_without_secret_argv_or_globs() -> None:
    operations = OPERATIONS_PATH.read_text(encoding="utf-8")

    assert '"$OVERSEER_ROLLBACK_ROOT/overseer.service.prior"' in operations
    assert '"$OVERSEER_ROLLBACK_ROOT/runtime.env.prior"' in operations
    assert 'runtime.is-enabled.txt' in operations
    assert 'runtime.is-active.txt' in operations
    assert 'api.is-active.txt' in operations
    assert 'case "$OVERSEER_PRIOR_RUNTIME_ENABLEMENT" in' in operations
    assert 'case "$OVERSEER_PRIOR_RUNTIME_ACTIVITY" in' in operations
    assert 'case "$OVERSEER_PRIOR_API_ACTIVITY" in' in operations
    assert 'from urllib.request import Request, urlopen' in operations
    assert 'Authorization: Bearer $OVERSEER_API_TOKEN' not in operations
    assert 'install -m 0600 "$OVERSEER_ROLLBACK_ROOT/store.prior.sqlite3" "$OVERSEER_LIVE_STORE"' in operations
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
