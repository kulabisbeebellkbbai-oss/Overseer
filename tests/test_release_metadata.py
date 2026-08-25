from pathlib import Path
import tomllib

from overseer import codex_usage


ROOT = Path(__file__).resolve().parents[1]


def test_v11_release_metadata_is_consistent() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package_metadata = (
        ROOT / "src" / "overseer_local.egg-info" / "PKG-INFO"
    ).read_text(encoding="utf-8")
    codex_usage_source = Path(codex_usage.__file__).read_text(encoding="utf-8")

    assert project["project"]["version"] == "1.1.4"
    assert "Version: 1.1.4\n" in package_metadata
    assert '"version": "0.1.0"' not in codex_usage_source
    assert codex_usage_source.count('"version": "1.1.4"') == 3
