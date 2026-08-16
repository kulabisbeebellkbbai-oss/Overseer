from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
CODEX_EXECUTABLE = "/home/god/.codex/packages/standalone/releases/0.147.0-x86_64-unknown-linux-musl/bin/codex"


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
    root = ROOT
    meter_path = root / "systemd" / "overseer-psychlo-meter.service"
    meter = meter_path.read_text(encoding="utf-8")
    assert "ConditionPathExists=%h/.config/overseer/psychlo-meter/producer-enabled" in meter
    assert "LoadCredential=psychlo-usage-authority-private-key:%h/.config/overseer/psychlo-usage-authority-private-key.pem" in meter
    assert "%d/psychlo-usage-authority-private-key" in meter
    assert "%h/.local/share/overseer/venvs/psychlo-v1-1-cryptography-46.0.7-86d2f47/bin/python -m overseer.psychlo_usage_meter_cli" in meter
    assert "PYTHONPATH=%h/.local/share/overseer/project/src" in meter
    assert "BindReadOnlyPaths=%h/.local/share/overseer/venvs/psychlo-v1-1-cryptography-46.0.7-86d2f47" in meter
    assert "RuntimeDirectory=overseer-psychlo-meter" in meter
    assert "RuntimeDirectoryMode=0700" in meter
    assert "RuntimeDirectoryPreserve=no" in meter
    assert "ExecStartPre=/usr/bin/install -m 0600 %d/auth.json %t/overseer-psychlo-meter/auth.json" in meter
    assert "ProtectHome=tmpfs" in meter
    assert "BindReadOnlyPaths=%h/.config/overseer/psychlo-meter/config.json" in meter
    assert "BindReadOnlyPaths=%h/.config/overseer/psychlo-usage-authority-private-key.pem" not in meter
    assert "psychlo-usage.timer" not in meter
    subprocess.run(["systemd-analyze", "verify", str(meter_path)], check=True, capture_output=True, text=True)


def test_percentage_meter_receives_only_scoped_codex_login_and_binary():
    meter = (ROOT / "systemd" / "overseer-psychlo-meter.service").read_text(encoding="utf-8")

    assert "LoadCredential=auth.json:%h/.codex/auth.json" in meter
    assert "RuntimeDirectory=overseer-psychlo-meter" in meter
    assert "RuntimeDirectoryMode=0700" in meter
    assert "RuntimeDirectoryPreserve=no" in meter
    assert "ExecStartPre=/usr/bin/install -m 0600 %d/auth.json %t/overseer-psychlo-meter/auth.json" in meter
    assert "Environment=CODEX_HOME=%t/overseer-psychlo-meter" in meter
    assert "Environment=CODEX_HOME=%d" not in meter
    assert f"Environment=PATH={Path(CODEX_EXECUTABLE).parent}:/usr/bin" in meter
    assert f"BindReadOnlyPaths={CODEX_EXECUTABLE}" in meter
    assert "BindReadOnlyPaths=%h/.codex" not in meter
    assert "LoadCredential=psychlo-overseer-peer-secret" not in meter


def test_cycle_sequences_meter_before_delivery_and_timer_targets_cycle():
    cycle_path = ROOT / "systemd" / "overseer-psychlo-cycle.service"
    timer_path = ROOT / "systemd" / "overseer-psychlo-usage.timer"
    cycle = cycle_path.read_text(encoding="utf-8")
    timer = timer_path.read_text(encoding="utf-8")

    commands = [line for line in cycle.splitlines() if line.startswith("ExecStart=")]
    assert commands == [
        "ExecStart=/usr/bin/systemctl --user start --wait overseer-psychlo-meter.service",
        "ExecStart=/usr/bin/systemctl --user start --wait overseer-psychlo-usage.service",
    ]
    assert "LoadCredential=" not in cycle
    assert "[Install]" not in cycle
    assert "Unit=overseer-psychlo-cycle.service" in timer
    assert "Unit=overseer-psychlo-usage.service" not in timer
    assert "OnActiveSec=15min" in timer
    assert "OnUnitActiveSec=15min" in timer
    subprocess.run(
        ["systemd-analyze", "verify", str(cycle_path), str(timer_path)],
        check=True,
        capture_output=True,
        text=True,
    )


def test_coordination_tick_timer_is_checked_in_inactive_bounded_and_valid():
    root = ROOT
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
