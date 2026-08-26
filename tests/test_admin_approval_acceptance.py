from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import overseer.cli as cli_module
from overseer.admin import (
    AdminCommandResult,
)
from overseer.admin_executor import (
    ALLOWLIST_SCHEMA_VERSION,
    execute_ticket,
)
from overseer.admin_ticket_execution import execute_system_service_restart_ticket
from overseer.approval_auth import create_approval_document, load_approval_verifier
from overseer.api import make_api_handler
from overseer.cli import (
    approve_admin_change_status,
    execute_admin_change_status,
    plan_admin_change_status,
)
from overseer.store import SQLiteStore
from overseer.ui import OPERATOR_CONSOLE_HTML


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_UNIT = ROOT / "systemd" / "overseer-approval-smoke.service"


def approval_verifier(tmp_path: Path, secret: str, scope: str):
    path = tmp_path / f"{scope}.json"
    path.write_text(json.dumps(create_approval_document(secret, scope)), encoding="utf-8")
    path.chmod(0o600)
    return load_approval_verifier(path)


@contextmanager
def approval_api(
    store_path: Path,
    *,
    admin_token: str = "agent-token",
    approval_token: str | None = "approval-token-strong-1",
    approval_identity: str | None = "sisko",
    roadex_approval_token: str | None = None,
):
    admin_verifier = None
    if approval_token is not None:
        if approval_identity != "sisko":
            raise ValueError("test verifier identity is fixed by scope")
        admin_verifier = approval_verifier(
            store_path.parent,
            approval_token,
            "admin-plan-approval",
        )
    roadex_verifier = (
        approval_verifier(
            store_path.parent,
            roadex_approval_token,
            "roadex-fixture-approval",
        )
        if roadex_approval_token is not None
        else None
    )
    handler = make_api_handler(
        str(store_path),
        admin_token,
        admin_approval_verifier=admin_verifier,
        roadex_fixture_approval_verifier=roadex_verifier,
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def post_json(base_url: str, path: str, payload: dict[str, object], token: str):
    request = Request(
        f"{base_url}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "authorization": f"Bearer {token}",
            "content-type": "application/json",
        },
        method="POST",
    )
    with urlopen(request, timeout=5) as response:
        return response.status, json.loads(response.read().decode("utf-8"))


def test_sisko_admin_plan_rejects_a_different_claimed_approver(
    tmp_path: Path,
) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    plan_admin_change_status(
        store_path,
        "admin.approval.identity",
        "user_service_restart",
        "overseer-approval-smoke.service",
        "verify the independent approval identity boundary",
        "inactive",
    )

    with pytest.raises(ValueError, match="Sisko approval identity is required"):
        approve_admin_change_status(
            store_path,
            "admin.approval.identity",
            "obrien",
        )


def test_admin_approval_api_requires_independent_token_and_derives_identity(
    tmp_path: Path,
) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    plan_admin_change_status(
        store_path,
        "admin.approval.api",
        "user_service_restart",
        "overseer-approval-smoke.service",
        "verify independent API approval",
        "inactive",
    )

    with approval_api(store_path) as base_url:
        with pytest.raises(HTTPError) as denied:
            post_json(
                base_url,
                "/admin/approve",
                {"plan_id": "admin.approval.api"},
                "agent-token",
            )
        denied_payload = json.loads(denied.value.read().decode("utf-8"))

        status, approved = post_json(
            base_url,
            "/admin/approve",
            {"plan_id": "admin.approval.api"},
            "approval-token-strong-1",
        )

    assert denied.value.code == 403
    assert denied_payload == {
        "error": "unauthorized",
        "reason": "independent_approval_token_required",
    }
    assert status == 200
    assert approved["approved"] is True
    assert approved["approved_by"] == "sisko"


def test_admin_approval_api_rejects_secret_reused_by_another_approval_scope(
    tmp_path: Path,
) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    plan_admin_change_status(
        store_path,
        "admin.approval.scope-collision",
        "system_service_restart",
        "overseer-approval-smoke.service",
        "reject a human credential shared by two approval scopes",
        "inactive",
    )

    reused_secret = "reused-human-approval-secret-1"
    with approval_api(
        store_path,
        approval_token=reused_secret,
        roadex_approval_token=reused_secret,
    ) as base_url:
        with pytest.raises(HTTPError) as denied:
            post_json(
                base_url,
                "/admin/approve",
                {"plan_id": "admin.approval.scope-collision"},
                reused_secret,
            )
        payload = json.loads(denied.value.read().decode("utf-8"))

    assert denied.value.code == 403
    assert payload == {
        "error": "unauthorized",
        "reason": "approval_credential_scope_collision",
    }


def test_roadex_approval_api_rejects_secret_reused_by_another_approval_scope(
    tmp_path: Path,
) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    reused_secret = "reused-human-approval-secret-1"

    with approval_api(
        store_path,
        approval_token=reused_secret,
        roadex_approval_token=reused_secret,
    ) as base_url:
        with pytest.raises(HTTPError) as denied:
            post_json(
                base_url,
                "/roadex/approval-fixtures/approve",
                {},
                reused_secret,
            )
        payload = json.loads(denied.value.read().decode("utf-8"))

    assert denied.value.code == 403
    assert payload == {
        "error": "unauthorized",
        "reason": "approval_credential_scope_collision",
    }


def test_admin_approval_api_rejects_client_supplied_identity(tmp_path: Path) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    plan_admin_change_status(
        store_path,
        "admin.approval.injected-identity",
        "user_service_restart",
        "overseer-approval-smoke.service",
        "reject client supplied approval authority",
        "inactive",
    )

    with approval_api(store_path) as base_url:
        with pytest.raises(HTTPError) as denied:
            post_json(
                base_url,
                "/admin/approve",
                {
                    "plan_id": "admin.approval.injected-identity",
                    "approved_by": "obrien",
                },
                "approval-token-strong-1",
            )
        payload = json.loads(denied.value.read().decode("utf-8"))

    assert denied.value.code == 400
    assert payload["error"] == "admin approval payload contains unsupported fields"


def test_admin_execute_api_rejects_fields_other_than_plan_id(tmp_path: Path) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    plan_admin_change_status(
        store_path,
        "admin.execute.exact-payload",
        "system_service_restart",
        "overseer-approval-smoke.service",
        "reject execution authority supplied by the client",
        "inactive",
    )

    with approval_api(store_path) as base_url:
        with pytest.raises(HTTPError) as denied:
            post_json(
                base_url,
                "/admin/execute",
                {
                    "plan_id": "admin.execute.exact-payload",
                    "executor_socket": "/tmp/attacker.sock",
                },
                "agent-token",
            )
        payload = json.loads(denied.value.read().decode("utf-8"))

    assert denied.value.code == 400
    assert payload == {"error": "admin execution payload must contain only plan_id"}


def test_ticketed_approval_api_runs_allowlisted_restart_once_and_replays(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    target = "overseer-approval-smoke.service"
    plan_admin_change_status(
        store_path,
        "admin.approval.ticket-e2e",
        "system_service_restart",
        target,
        "exercise the complete independent approval boundary",
        "inactive",
    )

    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    private_key_path = tmp_path / "authority.key"
    private_key_path.write_bytes(bytes(range(32)))
    private_key_path.chmod(0o600)
    public_key_path = tmp_path / "executor-public.key"
    public_key_path.write_bytes(private_key.public_key().public_bytes_raw())
    public_key_path.chmod(0o644)
    allowlist_path = tmp_path / "allowlist.json"
    allowlist_path.write_text(
        json.dumps(
            {
                "schemaVersion": ALLOWLIST_SCHEMA_VERSION,
                "allowed": [{"operation": "restart-system-unit", "unit": target}],
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    allowlist_path.chmod(0o644)
    ledger_dir = tmp_path / "executor-state"
    ledger_dir.mkdir(mode=0o700)
    ledger_path = ledger_dir / "ledger.sqlite3"
    socket_path = tmp_path / "executor.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    os.chmod(socket_path, 0o600)
    monkeypatch.setenv("OVERSEER_ADMIN_TICKET_PRIVATE_KEY", str(private_key_path))
    monkeypatch.setenv("OVERSEER_ADMIN_EXECUTOR_SOCKET", str(socket_path))
    command_calls: list[tuple[str, ...]] = []

    def runner(argv):
        command_calls.append(tuple(argv))
        return 0, b"ok\n", b""

    def adapter(plan, plan_digest, **kwargs):
        def sender(_socket_address, raw_ticket):
            receipt = execute_ticket(
                raw_ticket,
                allowlist_file=allowlist_path,
                public_key_file=public_key_path,
                ledger=ledger_path,
                expected_owner_uid=os.geteuid(),
                runner=runner,
            )
            return json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("ascii")

        return execute_system_service_restart_ticket(
            plan,
            plan_digest,
            sender=sender,
            **kwargs,
        )

    monkeypatch.setattr(cli_module, "execute_system_service_restart_ticket", adapter)
    try:
        with approval_api(
            store_path,
            approval_token="admin-approval-secret-1",
            roadex_approval_token="roadex-approval-secret-1",
        ) as base_url:
            with pytest.raises(HTTPError) as ordinary_denied:
                post_json(
                    base_url,
                    "/admin/approve",
                    {"plan_id": "admin.approval.ticket-e2e"},
                    "agent-token",
                )
            with pytest.raises(HTTPError) as wrong_scope_denied:
                post_json(
                    base_url,
                    "/admin/approve",
                    {"plan_id": "admin.approval.ticket-e2e"},
                    "roadex-approval-secret-1",
                )
            approval_status, approved = post_json(
                base_url,
                "/admin/approve",
                {"plan_id": "admin.approval.ticket-e2e"},
                "admin-approval-secret-1",
            )
            execution_status, executed = post_json(
                base_url,
                "/admin/execute",
                {"plan_id": "admin.approval.ticket-e2e"},
                "agent-token",
            )
            replay_status, replayed = post_json(
                base_url,
                "/admin/execute",
                {"plan_id": "admin.approval.ticket-e2e"},
                "agent-token",
            )
    finally:
        listener.close()

    assert ordinary_denied.value.code == 403
    assert wrong_scope_denied.value.code == 403
    assert approval_status == 200
    assert approved["approved_by"] == "sisko"
    assert execution_status == 200
    assert executed["status"] == "completed"
    assert executed["mutation_performed"] is True
    assert replay_status == 200
    assert replayed["replayed"] is True
    assert replayed["mutation_performed"] is False
    assert command_calls == [
        ("/usr/bin/systemctl", "restart", "--", target),
        ("/usr/bin/systemctl", "is-active", "--quiet", "--", target),
    ]


def test_direct_cli_admin_approval_is_retired(tmp_path: Path) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    plan_admin_change_status(
        store_path,
        "admin.approval.no-cli-bypass",
        "user_service_restart",
        "overseer-approval-smoke.service",
        "prove direct CLI approval is unavailable",
        "inactive",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "overseer.cli",
            "approve-admin-change",
            "--store",
            str(store_path),
            "--plan-id",
            "admin.approval.no-cli-bypass",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )

    assert result.returncode != 0
    assert "direct CLI admin approval is disabled" in result.stderr


def test_api_handler_rejects_shared_agent_and_approval_credentials(
    tmp_path: Path,
) -> None:
    verifier = approval_verifier(tmp_path, "shared-token-strong-1", "admin-plan-approval")
    with pytest.raises(ValueError, match="must be independent"):
        make_api_handler(
            str(tmp_path / "overseer.sqlite3"),
            "shared-token-strong-1",
            admin_approval_verifier=verifier,
        )


def test_completed_admin_execution_replay_returns_original_without_commands(
    tmp_path: Path,
) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    plan_admin_change_status(
        store_path,
        "admin.approval.replay",
        "user_service_restart",
        "overseer-approval-smoke.service",
        "verify replay safety",
        "inactive",
    )
    approve_admin_change_status(
        store_path,
        "admin.approval.replay",
        "sisko",
        "2026-08-26T04:00:00+00:00",
    )

    def successful_runner(step):
        return AdminCommandResult(step.title, step.command, 0, "ok", "")

    original = execute_admin_change_status(
        store_path,
        "admin.approval.replay",
        runner=successful_runner,
    )
    replay = execute_admin_change_status(
        store_path,
        "admin.approval.replay",
        runner=lambda step: pytest.fail(f"replay ran command {step.command}"),
    )

    with SQLiteStore(store_path) as store:
        persisted = store.load_admin_execution(original["id"])

    assert replay["id"] == original["id"]
    assert replay["status"] == "completed"
    assert replay["replayed"] is True
    assert replay["mutation_performed"] is False
    assert persisted.summary == "admin change completed and verified"
    assert persisted.plan_digest


def test_completed_execution_does_not_replay_for_replaced_plan_authority(
    tmp_path: Path,
) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    plan_admin_change_status(
        store_path,
        "admin.approval.replaced-plan",
        "user_service_restart",
        "overseer-approval-smoke.service",
        "verify immutable replay binding",
        "inactive",
    )
    approve_admin_change_status(
        store_path,
        "admin.approval.replaced-plan",
        "sisko",
    )
    execute_admin_change_status(
        store_path,
        "admin.approval.replaced-plan",
        runner=lambda step: AdminCommandResult(step.title, step.command, 0, "ok", ""),
    )
    plan_admin_change_status(
        store_path,
        "admin.approval.replaced-plan",
        "user_service_restart",
        "different.service",
        "replace the authority under the same identifier",
        "inactive",
    )

    with pytest.raises(ValueError, match="plan binding"):
        execute_admin_change_status(
            store_path,
            "admin.approval.replaced-plan",
            runner=lambda step: pytest.fail(f"replacement ran command {step.command}"),
        )


def test_completed_replay_does_not_load_a_current_policy_profile(
    tmp_path: Path,
) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    plan_admin_change_status(
        store_path,
        "admin.approval.policy-independent-replay",
        "user_service_restart",
        "overseer-approval-smoke.service",
        "verify policy-independent replay",
        "inactive",
    )
    approve_admin_change_status(
        store_path,
        "admin.approval.policy-independent-replay",
        "sisko",
    )
    original = execute_admin_change_status(
        store_path,
        "admin.approval.policy-independent-replay",
        runner=lambda step: AdminCommandResult(step.title, step.command, 0, "ok", ""),
    )
    invalid_profile = tmp_path / "invalid-policy.json"
    invalid_profile.write_text("not json", encoding="utf-8")

    replay = execute_admin_change_status(
        store_path,
        "admin.approval.policy-independent-replay",
        runner=lambda step: pytest.fail(f"replay ran command {step.command}"),
        policy_profile_path=invalid_profile,
    )

    assert replay["id"] == original["id"]
    assert replay["replayed"] is True


def test_concurrent_admin_execution_has_one_command_running_winner(
    tmp_path: Path,
) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    plan_admin_change_status(
        store_path,
        "admin.approval.concurrent-replay",
        "user_service_restart",
        "overseer-approval-smoke.service",
        "verify concurrent replay safety",
        "inactive",
    )
    approve_admin_change_status(
        store_path,
        "admin.approval.concurrent-replay",
        "sisko",
    )
    command_count = 0
    command_count_lock = threading.Lock()

    def successful_runner(step):
        nonlocal command_count
        with command_count_lock:
            command_count += 1
        time.sleep(0.05)
        return AdminCommandResult(step.title, step.command, 0, "ok", "")

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                execute_admin_change_status,
                store_path,
                "admin.approval.concurrent-replay",
                successful_runner,
            )
            for _ in range(2)
        ]
        results = [future.result() for future in futures]

    assert command_count == 2
    assert {result["replayed"] for result in results} == {False, True}
    assert len({result["id"] for result in results}) == 1


def test_disposable_approval_fixture_is_non_networked_and_remains_active() -> None:
    unit = FIXTURE_UNIT.read_text(encoding="utf-8")

    assert "Type=oneshot" in unit
    assert "ExecStart=/usr/bin/true" in unit
    assert "RemainAfterExit=yes" in unit
    assert "PrivateNetwork=yes" in unit
    assert "NoNewPrivileges=yes" in unit
    assert "ProtectSystem=strict" in unit
    assert "[Install]" not in unit


def test_admin_ui_uses_an_ephemeral_independent_approval_credential() -> None:
    assert 'id="admin-approval-token"' in OPERATOR_CONSOLE_HTML
    assert 'type="password"' in OPERATOR_CONSOLE_HTML
    assert 'autocomplete="off"' in OPERATOR_CONSOLE_HTML
    assert 'id="admin-approved-by"' not in OPERATOR_CONSOLE_HTML
    assert 'postApprovalJson("/admin/approve"' in OPERATOR_CONSOLE_HTML
    assert 'approvalTokenInput.value = ""' in OPERATOR_CONSOLE_HTML


def test_periodic_render_preserves_in_progress_admin_form_values() -> None:
    assert "function captureFormValues(" in OPERATOR_CONSOLE_HTML
    assert "function restoreFormValues(" in OPERATOR_CONSOLE_HTML
    assert "const formValues = captureFormValues(document);" in OPERATOR_CONSOLE_HTML
    assert "restoreFormValues(formValues, document);" in OPERATOR_CONSOLE_HTML


def test_admin_approval_token_race_clears_replaced_fields_on_success_and_failure() -> None:
    helper_start = OPERATOR_CONSOLE_HTML.index("    let approvalRequestInFlight = false;")
    helper_end = OPERATOR_CONSOLE_HTML.index("    function readLayoutMode", helper_start)
    helpers = OPERATOR_CONSOLE_HTML[helper_start:helper_end]
    approval_start = OPERATOR_CONSOLE_HTML.index("    async function postApprovalJson")
    approval_end = OPERATOR_CONSOLE_HTML.index("    async function runAction", approval_start)
    approval_request = OPERATOR_CONSOLE_HTML[approval_start:approval_end]
    script = helpers + approval_request + r'''
const apiBase = "";
let currentToken;
let detachedTokens;
let planField;
let respond;
let observedAuthorization;
const document = {
  getElementById(id) {
    if (id === "admin-approval-token") return currentToken;
    if (id === "admin-approval-plan-id") return planField;
    return null;
  },
  querySelectorAll(selector) {
    if (selector === "#admin-approval-token") return [currentToken, ...detachedTokens];
    if (selector.includes(".section input")) return [planField, currentToken];
    return [];
  }
};
globalThis.fetch = async (_url, options) => {
  observedAuthorization = options.headers.authorization;
  const values = captureFormValues(document);
  const submittedToken = currentToken;
  currentToken = {id:"admin-approval-token", type:"password", value:""};
  detachedTokens.push(submittedToken);
  restoreFormValues(values, document);
  if (currentToken.value !== "") process.exit(2);
  if (planField.value !== "keep-this-field") process.exit(3);
  return await new Promise((resolve) => { respond = resolve; });
};
async function exercise(response) {
  currentToken = {id:"admin-approval-token", type:"password", value:"submitted-token"};
  detachedTokens = [];
  planField = {id:"admin-approval-plan-id", type:"text", value:"keep-this-field"};
  const request = postApprovalJson("/admin/approve", {plan_id:"approval.race"});
  await Promise.resolve();
  if (observedAuthorization !== "Bearer submitted-token") process.exit(4);
  if (currentToken.value !== "") process.exit(5);
  respond(response);
  let failed = false;
  try { await request; } catch (_) { failed = true; }
  if (response.ok === false && !failed) process.exit(6);
  if (response.ok !== false && failed) process.exit(7);
  if ([currentToken, ...detachedTokens].some((field) => field.value !== "")) process.exit(8);
}
(async () => {
  await exercise({ok:false, status:403});
  await exercise({ok:true, status:200, json:async () => ({approved:true})});
})().catch(() => process.exit(9));
'''
    result = subprocess.run(["node", "-e", script], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
