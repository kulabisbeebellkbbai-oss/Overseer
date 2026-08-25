from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UNIT_PATH = ROOT / "systemd" / "overseer.service"


def test_overseer_runtime_unit_runs_scheduler_without_bulk_flags() -> None:
    unit = UNIT_PATH.read_text(encoding="utf-8")

    assert "Type=simple" in unit
    assert "EnvironmentFile=%h/.config/overseer/runtime.env" in unit
    assert "ExecStart=${OVERSEER_PYTHON} -m overseer.cli run --store ${OVERSEER_STORE}" in unit
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
    assert "OVERSEER_INSTALL" in unit
    assert "OVERSEER_STORE" in unit
    assert "Environment=PYTHONPATH=${OVERSEER_INSTALL}/src" in unit
    assert "/home/" not in unit
    assert "enable --now" not in unit
    assert "systemctl" not in unit
