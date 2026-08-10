from pathlib import Path


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
