from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path


def _runner_module():
    path = Path("scripts/run_full_regression.py")
    spec = importlib.util.spec_from_file_location("run_full_regression", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_provider_neutral_stage_has_exact_suites_and_excludes_live_agent() -> None:
    runner = _runner_module()
    stage = next(item for item in runner.SUITES if item["name"] == "provider-neutral-agent")

    assert stage["command"][4:6] == ["-m", "not live_agent"]
    assert stage["command"][6:] == [
        "tests/test_agent_contracts.py",
        "tests/test_agent_registry.py",
        "tests/test_agent_store.py",
        "tests/test_agent_handoff.py",
        "tests/test_agent_manager.py",
        "tests/test_agent_operations.py",
        "tests/test_agent_failover.py",
        "tests/test_agent_adapter_contract.py",
        "tests/test_agent_api.py",
        "tests/test_agent_migration.py",
    ]


def test_failed_suite_artifact_is_bounded_and_structurally_redacted(
    monkeypatch,
) -> None:
    runner = _runner_module()
    secret = "synthetic-secret-value"
    prompt = "private operator prompt"
    private_path = "/home/example/private/workspace/file.txt"
    sensitive = "\n".join(
        [
            f'api_key: "{secret}"',
            f"Authorization: Bearer {secret}",
            f"Cookie: session={secret}",
            f"prompt={prompt}",
            f"workspace={private_path}",
            "-----BEGIN RSA PRIVATE KEY-----",
            secret,
            "-----END RSA PRIVATE KEY-----",
            *(f"ordinary diagnostic {index}" for index in range(200)),
            "1 failed, 2 passed in 0.10s",
        ]
    )

    monkeypatch.setattr(
        runner.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 1, sensitive, sensitive
        ),
    )
    result = runner._run_suite(
        {
            "name": "synthetic",
            "command": [
                "/usr/bin/python3",
                "-m",
                "pytest",
                "--token",
                secret,
                "--prompt",
                prompt,
                private_path,
            ],
        }
    )
    encoded = json.dumps(result)

    assert "stdout" not in result
    assert "stderr" not in result
    assert secret not in encoded
    assert prompt not in encoded
    assert private_path not in encoded
    assert "Authorization" not in encoded
    assert "Cookie" not in encoded
    assert "PRIVATE KEY" not in encoded
    assert len(encoded) <= runner.MAX_RESULT_JSON_CHARS
    assert result["diagnostic"]["classification"] == "test_failure"
    assert result["test_counts"]["failed"] == 1
    assert result["test_counts"]["passed"] == 2
    assert result["command"][-5:] == [
        "--token",
        "[REDACTED]",
        "--prompt",
        "[REDACTED]",
        "[REDACTED_PATH]",
    ]


def test_successful_suite_omits_output_and_keeps_safe_counts(monkeypatch) -> None:
    runner = _runner_module()
    monkeypatch.setattr(
        runner.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, "12 passed, 1 skipped in 0.25s\nsecret token: hidden", ""
        ),
    )

    result = runner._run_suite(
        {"name": "synthetic", "command": ["python3", "-m", "pytest", "-q"]}
    )

    assert result["status"] == "passed"
    assert result["test_counts"] == {"passed": 12, "skipped": 1}
    assert "diagnostic" not in result
    assert "stdout" not in result
    assert "stderr" not in result
