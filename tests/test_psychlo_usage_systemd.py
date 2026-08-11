from pathlib import Path
import subprocess


def test_psychlo_usage_waits_for_a_fresh_codex_usage_capture():
    unit = (
        Path(__file__).resolve().parents[1]
        / "systemd"
        / "overseer-psychlo-usage.service"
    ).read_text(encoding="utf-8")

    assert "Requires=overseer-codex-usage-snapshot.service" in unit
    assert (
        "After=overseer-api.service psychlo.service "
        "overseer-codex-usage-snapshot.service"
    ) in unit


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
