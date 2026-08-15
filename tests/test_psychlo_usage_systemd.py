from pathlib import Path
import subprocess


def test_psychlo_usage_requires_the_private_attribution_authority_feed():
    unit = (
        Path(__file__).resolve().parents[1]
        / "systemd"
        / "overseer-psychlo-usage.service"
    ).read_text(encoding="utf-8")

    assert "overseer-codex-usage-snapshot.service" not in unit
    assert "OVERSEER_PSYCHLO_USAGE_ATTRIBUTION_LEDGER" in unit
    assert "OVERSEER_PSYCHLO_USAGE_AUTHORITY_FILE" in unit
    assert "OVERSEER_PSYCHLO_USAGE_OBSERVATION_FILE" in unit
    assert "OVERSEER_PSYCHLO_USAGE_RECEIPTS_FILE" in unit
    assert "BindReadOnlyPaths=%h/.config/overseer/psychlo-usage-authority.json" in unit
    assert "BindReadOnlyPaths=%h/.local/share/overseer/psychlo-meter" in unit
    assert "codex-usage-mcp/state.sqlite3" not in unit
    assert "ExecStartPre=" not in unit
    assert "%h/.local/share/overseer/venvs/psychlo-v1-1-cryptography-46.0.7-86d2f47/bin/python -m overseer.psychlo_bridge_cli emit-usage" in unit
    assert "PYTHONPATH=%h/.local/share/overseer/project/src" in unit
    assert "BindReadOnlyPaths=%h/.local/share/overseer/venvs/psychlo-v1-1-cryptography-46.0.7-86d2f47" in unit


def test_percentage_meter_is_a_separate_fail_closed_one_shot():
    root = Path(__file__).resolve().parents[1]
    meter_path = root / "systemd" / "overseer-psychlo-meter.service"
    meter = meter_path.read_text(encoding="utf-8")
    assert "ConditionPathExists=%h/.config/overseer/psychlo-meter/producer-enabled" in meter
    assert "LoadCredential=psychlo-usage-authority-private-key:%h/.config/overseer/psychlo-usage-authority-private-key.pem" in meter
    assert "%d/psychlo-usage-authority-private-key" in meter
    assert "%h/.local/share/overseer/venvs/psychlo-v1-1-cryptography-46.0.7-86d2f47/bin/python -m overseer.psychlo_usage_meter_cli" in meter
    assert "PYTHONPATH=%h/.local/share/overseer/project/src" in meter
    assert "BindReadOnlyPaths=%h/.local/share/overseer/venvs/psychlo-v1-1-cryptography-46.0.7-86d2f47" in meter
    assert "ExecStartPre=" not in meter
    assert "ProtectHome=tmpfs" in meter
    assert "BindReadOnlyPaths=%h/.config/overseer/psychlo-meter/config.json" in meter
    assert "BindReadOnlyPaths=%h/.config/overseer/psychlo-usage-authority-private-key.pem" not in meter
    assert "psychlo-usage.timer" not in meter
    subprocess.run(["systemd-analyze", "verify", str(meter_path)], check=True, capture_output=True, text=True)


def test_coordination_tick_timer_is_checked_in_inactive_bounded_and_valid():
    root = Path(__file__).resolve().parents[1]
    service_path = root / "systemd" / "overseer-psychlo-coordination-tick.service"
    timer_path = root / "systemd" / "overseer-psychlo-coordination-tick.timer"
    service = service_path.read_text(encoding="utf-8")
    timer = timer_path.read_text(encoding="utf-8")

    assert "ExecStart=/usr/bin/python3 -m overseer.psychlo_bridge_cli tick" in service
    assert "OVERSEER_STORE_DATABASE=%h/.local/share/overseer/project/state/overseer.sqlite3" in service
    assert "LoadCredential=psychlo-overseer-peer-secret:%h/.config/psychlo/overseer-peer-secret" in service
    assert "OnUnitActiveSec=1min" in timer
    assert "WantedBy=timers.target" in timer
    assert "enable --now" not in (service + timer)
    subprocess.run(["systemd-analyze", "verify", str(service_path), str(timer_path)], check=True, capture_output=True, text=True)
