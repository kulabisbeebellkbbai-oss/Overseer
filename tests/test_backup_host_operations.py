from types import SimpleNamespace
import json
import os
import pwd
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.error

import pytest

from overseer.backup_contract import PROVISIONING_CONTRACT_VERSION, runtime_artifact_identity
from overseer.backup_host_operations import ConcreteHostProvisioningAdapter,EXPECTED_BACKUP_TOOL_SCHEMAS,HostOperationResult,PRIVILEGED_CONFIRMATION,RedactedHostOperationError,_normalize_schema,capability_digest,runtime_digest
from overseer.backup_provisioning import ProvisioningStep

class Result:
    def __init__(self,returncode=0,stdout=b"",stderr=b"private diagnostic"): self.returncode=returncode; self.stdout=stdout; self.stderr=stderr

def adapter(steps,runner,**kwargs):
    commit="a"*40
    return ConcreteHostProvisioningAdapter(SimpleNamespace(steps=tuple(steps),rollback_steps=(),adapter_commit=commit),privileged_confirmation=PRIVILEGED_CONFIRMATION,runner=runner,euid_provider=lambda:1000,username_provider=lambda uid:"god",**kwargs)


def test_restart_start_enable_system_service_returns_changed_and_monotonic_evidence():
    step = ProvisioningStep("start_enable_system_service", {"unit": "overseer-api.service", "scope": "system"})
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        if "show" in argv:
            return Result(stdout=(b"enabled\nactive\n100\n" if len([x for x in calls if "show" in x]) == 1 else b"enabled\nactive\n101\n"))
        return Result()

    result = adapter([step], runner).execute(step)
    assert set(result) == {"ok", "operation", "disposition", "safe_code", "evidence", "redactions_applied"}
    assert result["disposition"] == "changed"
    assert result["evidence"] == {"active_enter_timestamp_monotonic": "101"}
    assert "--property=UnitFileState,ActiveState,ActiveEnterTimestampMonotonic" in calls[-1]


def test_exact_existing_root_registration_is_verified_noop():
    registration = {"project_id": "project.donuthole", "root_id": "backup-root", "policy_revision": "1", "host_path": "/source", "alias": "source", "max_bytes": 10, "authorization_ref": "approval"}
    step = ProvisioningStep("register_authorized_roots", {"registrations": (registration,)})

    def runner(argv, **kwargs):
        if "register-root" in argv and "--verify-exact" not in argv:
            return Result(returncode=1, stderr=json.dumps({"ok": False, "error": {"code": "ROOT_EXISTS"}, "redactions_applied": True}).encode())
        return Result(stdout=b'{"exact":true}\n')

    result = adapter([step], runner).execute(step)
    assert result["disposition"] == "verified_noop"


def test_conflicting_existing_root_fails_closed():
    registration = {"project_id": "project.donuthole", "root_id": "backup-root", "policy_revision": "1", "host_path": "/source", "alias": "source", "max_bytes": 10, "authorization_ref": "approval"}
    step = ProvisioningStep("register_authorized_roots", {"registrations": (registration,)})

    def runner(argv, **kwargs):
        if "register-root" in argv and "--verify-exact" not in argv:
            return Result(returncode=1, stderr=json.dumps({"ok": False, "error": {"code": "ROOT_EXISTS"}, "redactions_applied": True}).encode())
        return Result(stdout=b'{"exact":false}\n')

    with pytest.raises(RedactedHostOperationError, match="ROOT_CONFLICT") as failure:
        adapter([step], runner).execute(step)
    assert failure.value.code == "ROOT_CONFLICT"


def test_host_operation_result_rejects_unsafe_evidence():
    with pytest.raises(ValueError, match="evidence"):
        HostOperationResult.changed("SOURCE_ALREADY_PUBLISHED", {"stdout": "secret"})
    with pytest.raises(ValueError, match="evidence"):
        HostOperationResult.verified_noop("SOURCE_ALREADY_PUBLISHED", {"private_value": "leak"})

def test_host_operation_result_has_no_failure_factory_and_rejects_unbounded_codes():
    assert not hasattr(HostOperationResult, "failed")
    with pytest.raises(ValueError):
        HostOperationResult.changed("ARBITRARY_123", {})

def test_child_stdout_is_bounded_before_any_decode():
    step = ProvisioningStep("verify_endpoint_migration_ready", {"host": "127.0.0.1", "port": 8799, "forbid_simultaneous_user_and_system_service": True})
    with pytest.raises(RedactedHostOperationError) as failure:
        adapter([step], lambda *_a, **_k: Result(stdout=b"x" * 8193)).execute(step)
    assert failure.value.code == "PROCESS_STDOUT_OVERSIZED"

def test_endpoint_inactive_exit_status_is_not_verified_noop():
    step = ProvisioningStep("verify_endpoint_migration_ready", {"host": "127.0.0.1", "port": 1, "forbid_simultaneous_user_and_system_service": True})
    with pytest.raises(RedactedHostOperationError):
        adapter([step], lambda *_a, **_k: Result(returncode=3)).execute(step)

def test_nonempty_directory_removal_is_conflict(tmp_path):
    target = tmp_path / "state"
    target.mkdir()
    (target / "child").write_text("x")
    step = ProvisioningStep("remove_directory_if_empty", {"path": str(target)})
    with pytest.raises(RedactedHostOperationError, match="DIRECTORY_CONFLICT"):
        adapter([step], lambda argv, **_k: Result(returncode=1) if "/usr/bin/rmdir" in argv else Result()).execute(step)

def test_directory_probe_accepts_real_directory_link_count_and_rejects_symlink(tmp_path):
    target = tmp_path / "dir"; target.mkdir(); target.chmod(0o755)
    owner = pwd.getpwuid(os.getuid()).pw_name
    step = ProvisioningStep("ensure_directory", {"path": str(target), "mode": 0o755, "owner": owner})
    assert adapter([step], lambda *_a, **_k: Result()).execute(step)["disposition"] == "verified_noop"
    link = tmp_path / "link"; link.symlink_to(target)
    with pytest.raises(RedactedHostOperationError, match="DIRECTORY_CONFLICT"):
        link_step = ProvisioningStep("ensure_directory", {"path": str(link), "mode": 0o755, "owner": owner})
        adapter([link_step], lambda *_a, **_k: Result()).execute(link_step)

def test_exact_file_removal_rejects_foreign_and_dangling_symlink(tmp_path):
    owner = pwd.getpwuid(os.getuid()).pw_name
    target = tmp_path / "config"; target.write_text("approved"); target.chmod(0o600)
    digest = "sha256:" + __import__("hashlib").sha256(b"approved").hexdigest()
    step = ProvisioningStep("remove_private_config", {"path": str(target), "config_digest": digest, "owner": owner, "mode": 0o600})
    target.write_text("foreign")
    with pytest.raises(RedactedHostOperationError, match="FILE_CONFLICT"): adapter([step], lambda *_a, **_k: Result()).execute(step)
    target.unlink(); target.symlink_to(tmp_path / "missing")
    with pytest.raises(RedactedHostOperationError, match="FILE_CONFLICT"): adapter([step], lambda *_a, **_k: Result()).execute(step)

def test_file_identity_rejects_hardlink_nlink_and_secret_hex_rerun_is_noop(tmp_path):
    owner = pwd.getpwuid(os.getuid()).pw_name
    real = tmp_path / "real"; real.write_text("x"); real.chmod(0o600); link = tmp_path / "link"; link.hardlink_to(real)
    with pytest.raises(RedactedHostOperationError, match="FILE_CONFLICT"):
        from overseer.backup_host_operations import _safe_existing_file_identity
        _safe_existing_file_identity(link, owner, 0o600)
    secret = tmp_path / "secret"; secret.write_bytes(b"x" * 96); secret.chmod(0o600)
    step = ProvisioningStep("generate_secret_file", {"path": str(secret), "mode": 0o600, "owner": owner, "bytes": 48, "return_value": False})
    assert adapter([step], lambda *_a, **_k: Result()).execute(step)["disposition"] == "verified_noop"

def test_root_exists_requires_exact_success_schema():
    item = {"project_id": "project.donuthole", "root_id": "backup-root", "policy_revision": "1", "host_path": "/source", "alias": "source", "max_bytes": 10, "authorization_ref": "approval"}
    step = ProvisioningStep("register_authorized_roots", {"registrations": (item,)})
    def runner(argv, **_kwargs):
        if "--verify-exact" in argv: return Result(stdout=b'{"exact":true,"extra":1}')
        return Result(returncode=1, stderr=b'{"ok":false,"error":{"code":"ROOT_EXISTS"},"redactions_applied":true}')
    with pytest.raises(RedactedHostOperationError, match="ROOT_CONFLICT"): adapter([step], runner).execute(step)

def test_acl_requires_exact_before_and_after_probe():
    step = ProvisioningStep("ensure_read_only_acl", {"path": "/approved/source", "principal": "backup", "permissions": "r-X"})
    calls = []
    def runner(argv, **_kwargs):
        calls.append(argv)
        if "/usr/bin/getfacl" in argv: return Result(stdout=b"user::rwx\nuser:backup:rw-\n")
        return Result()
    with pytest.raises(RedactedHostOperationError, match="FILE_CONFLICT"):
        adapter([step], runner).execute(step)
    assert not any("setfacl" in call for call in calls)

def test_restart_rejects_invalid_service_state_or_timestamp():
    step = ProvisioningStep("start_enable_system_service", {"unit": "overseer-api.service", "scope": "system"})
    def runner(argv, **_kwargs):
        return Result(stdout=b"enabled\nactive\nnot-a-timestamp\n") if "show" in argv else Result()
    with pytest.raises(RedactedHostOperationError, match="SYSTEMD_ATTESTATION_INVALID"):
        adapter([step], runner).execute(step)

def test_runtime_removal_rejects_foreign_digest_and_dangling_symlink(tmp_path):
    root = tmp_path / "runtime"; root.mkdir(); (root / "app.py").write_text("foreign")
    owner = pwd.getpwuid(os.getuid()).pw_name
    step = ProvisioningStep("remove_runtime_if_unreferenced", {"path": str(root), "runtime_digest": "sha256:" + "0" * 64, "owner": owner})
    plan = SimpleNamespace(steps=(step,), rollback_steps=(), adapter_commit="a" * 40)
    with pytest.raises(RedactedHostOperationError, match="RUNTIME_CONFLICT"):
        ConcreteHostProvisioningAdapter(plan, privileged_confirmation=PRIVILEGED_CONFIRMATION, runner=lambda *_a, **_k: Result(), euid_provider=lambda: 1000, username_provider=lambda _uid: "god").execute(step)
    link = tmp_path / "dangling"; link.symlink_to(tmp_path / "missing")
    dangling = ProvisioningStep("remove_runtime_if_unreferenced", {"path": str(link), "runtime_digest": "sha256:" + "0" * 64})
    plan = SimpleNamespace(steps=(dangling,), rollback_steps=(), adapter_commit="a" * 40)
    with pytest.raises(RedactedHostOperationError, match="RUNTIME_CONFLICT"):
        ConcreteHostProvisioningAdapter(plan, privileged_confirmation=PRIVILEGED_CONFIRMATION, runner=lambda *_a, **_k: Result(), euid_provider=lambda: 1000, username_provider=lambda _uid: "god").execute(dangling)


def test_runtime_reference_probe_is_tree_scoped_and_valid_plan_removal_succeeds(tmp_path):
    root = tmp_path / "runtime"; root.mkdir(); (root / "app.py").write_text("runtime")
    commit = "a" * 40
    digest = runtime_digest(root, commit)
    step = ProvisioningStep("remove_runtime_if_unreferenced", {"path": str(root), "runtime_digest": digest})
    plan = SimpleNamespace(steps=(step,), rollback_steps=(), adapter_commit=commit)

    def runner(argv, **kwargs):
        if argv[2] == "/usr/bin/python3":
            if argv[5] == "references":
                return Result(stdout=b'{"count":0,"status":"clear"}')
            assert argv[5] == "absence"
            return Result(stdout=b'{"status":"absent"}')
        if argv[2] == "/usr/bin/rm":
            shutil.rmtree(root)
        return Result()

    result = ConcreteHostProvisioningAdapter(plan, privileged_confirmation=PRIVILEGED_CONFIRMATION, runner=runner, euid_provider=lambda: 1000, username_provider=lambda _uid: "god").execute(step)
    assert result["safe_code"] == "RUNTIME_REMOVED"
    assert not root.exists()


@pytest.mark.parametrize("reference_status", ["referenced", "error"])
def test_runtime_reference_probe_blocks_reference_or_unreadable_inspection(tmp_path, reference_status):
    root = tmp_path / "runtime"; root.mkdir(); (root / "app.py").write_text("runtime")
    commit = "a" * 40
    step = ProvisioningStep("remove_runtime_if_unreferenced", {"path": str(root), "runtime_digest": runtime_digest(root, commit)})
    plan = SimpleNamespace(steps=(step,), rollback_steps=(), adapter_commit=commit)

    def runner(argv, **kwargs):
        if argv[2] == "/usr/bin/python3":
            payload = {"status": reference_status} if reference_status == "error" else {"count": 1, "status": reference_status}
            return Result(stdout=json.dumps(payload).encode())
        return Result()

    with pytest.raises(RedactedHostOperationError, match="RUNTIME_CONFLICT"):
        ConcreteHostProvisioningAdapter(plan, privileged_confirmation=PRIVILEGED_CONFIRMATION, runner=runner, euid_provider=lambda: 1000, username_provider=lambda _uid: "god").execute(step)


@pytest.mark.parametrize(("status", "expected"), [("absent", "DIRECTORY_ALREADY_ABSENT"), ("removed", "DIRECTORY_REMOVED"), ("conflict", "DIRECTORY_CONFLICT")])
def test_privileged_directory_boundary_distinguishes_absent_removed_and_conflict(tmp_path, status, expected):
    step = ProvisioningStep("remove_directory_if_empty", {"path": str(tmp_path / "state")})
    def runner(argv, **kwargs):
        if argv[2] == "/usr/bin/python3":
            return Result(stdout=json.dumps({"status": status}).encode())
        return Result()
    action = ConcreteHostProvisioningAdapter(SimpleNamespace(steps=(step,), rollback_steps=()), privileged_confirmation=PRIVILEGED_CONFIRMATION, runner=runner, euid_provider=lambda: 1000, username_provider=lambda _uid: "god")
    if status == "conflict":
        with pytest.raises(RedactedHostOperationError, match="DIRECTORY_CONFLICT"):
            action.execute(step)
    else:
        assert action.execute(step)["safe_code"] == expected


def test_privileged_attestation_is_one_exact_fd_bound_shape_on_eacces(monkeypatch, tmp_path):
    import overseer.backup_host_operations as host
    owner = pwd.getpwuid(os.getuid()).pw_name
    config = {"x": 1}
    encoded = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
    digest = "sha256:" + __import__("hashlib").sha256(encoded).hexdigest()
    step = ProvisioningStep("install_private_config", {"path": str(tmp_path / "config"), "mode": 0o600, "owner": owner, "config": config, "config_digest": digest})
    monkeypatch.setattr(host, "_safe_existing_file_identity", lambda *_a: (_ for _ in ()).throw(PermissionError("EACCES")))
    def runner(argv, **kwargs):
        if argv[2] == "/usr/bin/python3":
            assert argv[5] == "attest"
            return Result(stdout=json.dumps({"dev": 1, "digest": digest, "gid": os.getgid(), "ino": 2, "mode": 384, "nlink": 1, "size": len(encoded), "status": "present", "uid": os.getuid()}).encode())
        raise AssertionError("EACCES rerun must not use separate stat/hash commands")
    result = adapter([step], runner).execute(step)
    assert result["disposition"] == "verified_noop" and result["safe_code"] == "CONFIG_ALREADY_CURRENT"


def test_real_boundary_helper_attest_stays_bound_to_original_fd_across_swap(tmp_path):
    from overseer.backup_host_operations import _PRIVILEGED_BOUNDARY_HELPER
    path = tmp_path / "attested"; replacement = tmp_path / "replacement"; barrier = tmp_path / "barrier"
    original = b"original-bytes"; replacement_bytes = b"replacement-bytes-that-are-different"
    path.write_bytes(original); replacement.write_bytes(replacement_bytes); path.chmod(0o600)
    owner = pwd.getpwuid(os.getuid()).pw_name
    fd = os.open(path, os.O_RDONLY)
    try:
        original_stat = os.fstat(fd)
        original_digest = "sha256:" + __import__("hashlib").sha256(original).hexdigest()
        process = subprocess.Popen([sys.executable, "-c", _PRIVILEGED_BOUNDARY_HELPER, "attest", str(path), owner, "384", str(barrier)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for _ in range(5000):
            if Path(str(barrier) + ".ready").exists():
                break
            time.sleep(0.001)
        else:
            process.kill()
            raise AssertionError("helper did not reach fd-bound barrier")
        os.replace(replacement, path)
        Path(str(barrier) + ".go").touch()
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == 0, stderr.decode(errors="replace")
        result = json.loads(stdout.decode("ascii"))
        assert result == {"status": "unsafe"}
    finally:
        os.close(fd)


def test_real_boundary_helper_attest_rejects_hardlink_created_after_initial_fstat(tmp_path):
    from overseer.backup_host_operations import _PRIVILEGED_BOUNDARY_HELPER
    path = tmp_path / "attested"; link = tmp_path / "attested-link"; barrier = tmp_path / "barrier"
    path.write_bytes(b"stable"); path.chmod(0o600)
    owner = pwd.getpwuid(os.getuid()).pw_name
    process = subprocess.Popen([sys.executable, "-c", _PRIVILEGED_BOUNDARY_HELPER, "attest", str(path), owner, "384", str(barrier)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        for _ in range(5000):
            if Path(str(barrier) + ".ready").exists():
                break
            time.sleep(0.001)
        else:
            process.kill()
            raise AssertionError("helper did not reach fd-bound barrier")
        link.hardlink_to(path)
        Path(str(barrier) + ".go").touch()
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == 0, stderr.decode(errors="replace")
        assert json.loads(stdout.decode("ascii")) == {"status": "unsafe"}
    finally:
        if process.poll() is None:
            process.kill(); process.wait()
        link.unlink(missing_ok=True)


def test_real_boundary_helper_unlink_rejects_same_digest_replacement_by_inode(tmp_path):
    from overseer.backup_host_operations import _PRIVILEGED_BOUNDARY_HELPER
    path = tmp_path / "target"; replacement = tmp_path / "replacement"
    content = b"approved-content"
    path.write_bytes(content); path.chmod(0o600)
    replacement.write_bytes(content); replacement.chmod(0o600)
    owner = pwd.getpwuid(os.getuid()).pw_name
    expected = os.stat(path, follow_symlinks=False)
    digest = "sha256:" + __import__("hashlib").sha256(content).hexdigest()
    os.replace(replacement, path)
    process = subprocess.run([sys.executable, "-c", _PRIVILEGED_BOUNDARY_HELPER, "unlink", str(path), owner, "384", str(expected.st_dev), str(expected.st_ino), digest], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    assert process.returncode == 0, process.stderr.decode(errors="replace")
    assert json.loads(process.stdout.decode("ascii")) == {"status": "conflict"}
    assert path.exists()


def test_real_boundary_helper_unlink_removes_exact_attested_identity(tmp_path):
    from overseer.backup_host_operations import _PRIVILEGED_BOUNDARY_HELPER
    path = tmp_path / "target"
    content = b"approved-content"
    path.write_bytes(content); path.chmod(0o600)
    owner = pwd.getpwuid(os.getuid()).pw_name
    expected = os.stat(path, follow_symlinks=False)
    digest = "sha256:" + __import__("hashlib").sha256(content).hexdigest()
    process = subprocess.run([sys.executable, "-c", _PRIVILEGED_BOUNDARY_HELPER, "unlink", str(path), owner, "384", str(expected.st_dev), str(expected.st_ino), digest], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    assert process.returncode == 0, process.stderr.decode(errors="replace")
    assert json.loads(process.stdout.decode("ascii")) == {"size": len(content), "status": "removed"}
    assert not path.exists()


@pytest.mark.parametrize("identity", ("+1", " 1", "01", "-1", str(1 << 64), "True"))
def test_real_boundary_helper_unlink_rejects_noncanonical_identity_arguments(tmp_path, identity):
    from overseer.backup_host_operations import _PRIVILEGED_BOUNDARY_HELPER
    path = tmp_path / "target"; content = b"approved-content"
    path.write_bytes(content); path.chmod(0o600)
    owner = pwd.getpwuid(os.getuid()).pw_name
    expected = os.stat(path, follow_symlinks=False)
    digest = "sha256:" + __import__("hashlib").sha256(content).hexdigest()
    process = subprocess.run([sys.executable, "-c", _PRIVILEGED_BOUNDARY_HELPER, "unlink", str(path), owner, "384", identity, str(expected.st_ino), digest], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    assert process.returncode == 0, process.stderr.decode(errors="replace")
    assert json.loads(process.stdout.decode("ascii")) == {"status": "error"}
    assert path.exists()


def test_boundary_integer_fields_use_explicit_bounds():
    from overseer.backup_host_operations import MAX_BOUNDARY_BYTES
    base = {"dev": (1 << 63) + 7, "digest": "sha256:" + "a" * 64, "gid": (1 << 32) - 1, "ino": (1 << 64) - 1, "mode": 0o600, "nlink": 1, "size": MAX_BOUNDARY_BYTES, "status": "present", "uid": (1 << 32) - 1}
    assert adapter([], lambda *_a, **_k: Result(stdout=json.dumps(base).encode()))._boundary("attest", "/unused", "god", "384")["dev"] == (1 << 63) + 7
    for key, value in (("dev", True), ("ino", -1), ("uid", 1 << 32), ("gid", -1), ("mode", 0o10000), ("nlink", 0), ("size", MAX_BOUNDARY_BYTES + 1)):
        payload = dict(base); payload[key] = value
        with pytest.raises(RedactedHostOperationError, match="FILE_CONFLICT"):
            adapter([], lambda *_a, payload=payload, **_k: Result(stdout=json.dumps(payload).encode()))._boundary("attest", "/unused", "god", "384")
    for count in (True, -1, 65):
        payload = {"count": count, "status": "clear"}
        with pytest.raises(RedactedHostOperationError, match="FILE_CONFLICT"):
            adapter([], lambda *_a, payload=payload, **_k: Result(stdout=json.dumps(payload).encode()))._boundary("references", "/unused")


def test_installed_runtime_exact_digest_is_verified_noop(tmp_path):
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    (source / "runtime.py").write_text("runtime = 1\n")
    shutil.copy2(source / "runtime.py", destination / "runtime.py")
    commit = "a" * 40
    digest = runtime_digest(source, commit)
    step = ProvisioningStep("install_runtime", {"source": str(source), "commit": commit, "runtime_digest": digest, "destination": str(destination), "owner": "root", "immutable": True})
    calls = []
    result = adapter([step], lambda argv, **kwargs: calls.append(argv) or Result()).execute(step)
    assert result["disposition"] == "verified_noop"
    assert result["safe_code"] == "RUNTIME_ALREADY_CURRENT"
    assert calls == []


def test_installed_runtime_conflict_fails_closed_before_mutation(tmp_path):
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    (source / "runtime.py").write_text("runtime = 1\n")
    (destination / "runtime.py").write_text("runtime = 2\n")
    commit = "a" * 40
    step = ProvisioningStep("install_runtime", {"source": str(source), "commit": commit, "runtime_digest": runtime_digest(source, commit), "destination": str(destination), "owner": "root", "immutable": True})
    calls = []
    with pytest.raises(RedactedHostOperationError, match="RUNTIME_CONFLICT"):
        adapter([step], lambda argv, **kwargs: calls.append(argv) or Result()).execute(step)
    assert calls == []

def test_construction_requires_explicit_confirmation_and_root():
    plan=SimpleNamespace(steps=(),rollback_steps=())
    with pytest.raises(PermissionError): ConcreteHostProvisioningAdapter(plan,privileged_confirmation="yes",euid_provider=lambda:1000,username_provider=lambda uid:"god")
    with pytest.raises(PermissionError): ConcreteHostProvisioningAdapter(plan,privileged_confirmation=PRIVILEGED_CONFIRMATION,euid_provider=lambda:0,username_provider=lambda uid:"root")
    with pytest.raises(PermissionError): ConcreteHostProvisioningAdapter(plan,privileged_confirmation=PRIVILEGED_CONFIRMATION,euid_provider=lambda:1001,username_provider=lambda uid:"other")


def test_package_only_import_loads_the_reviewed_contract_without_tests_directory(tmp_path):
    source_package = Path(__file__).parents[1] / "src/overseer"
    package_root = tmp_path / "package-only"
    shutil.copytree(source_package, package_root / "overseer", ignore=shutil.ignore_patterns("__pycache__"))

    result = subprocess.run(
        [sys.executable, "-c", "from overseer.backup_host_operations import EXPECTED_BACKUP_TOOL_SCHEMAS; print(sorted(EXPECTED_BACKUP_TOOL_SCHEMAS))"],
        cwd=package_root,
        env={**os.environ, "PYTHONPATH": ""},
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "['underdark_backup_create', 'underdark_backup_verify_restore']"

def test_exact_plan_step_uses_argv_without_shell_and_redacts_process_output():
    commit="a"*40; step=ProvisioningStep("verify_published_adapter_source",{"path":"/approved/source","commit":commit,"capability_digest":capability_digest(commit,EXPECTED_BACKUP_TOOL_SCHEMAS),"provisioning_contract_version":PROVISIONING_CONTRACT_VERSION,"runtime_artifact_identity":runtime_artifact_identity(commit,EXPECTED_BACKUP_TOOL_SCHEMAS)}); calls=[]
    def runner(argv,**kwargs): calls.append((argv,kwargs)); return Result(stdout=("a"*40+"\n").encode())
    result=adapter([step],runner).execute(step)
    assert calls==[(["/usr/bin/git","-C","/approved/source","rev-parse","HEAD"],{"shell":False,"stdin":-3,"stdout":-1,"stderr":-1,"check":False})]
    assert result=={"ok":True,"operation":"verify_published_adapter_source","disposition":"verified_noop","safe_code":"SOURCE_ALREADY_PUBLISHED","evidence":{"source_commit_verified":True},"redactions_applied":True}
    assert "private diagnostic" not in repr(result)


def test_capability_digest_is_bound_to_provisioning_contract_version():
    commit = "a" * 40

    current = capability_digest(commit, EXPECTED_BACKUP_TOOL_SCHEMAS, PROVISIONING_CONTRACT_VERSION)
    successor = capability_digest(commit, EXPECTED_BACKUP_TOOL_SCHEMAS, "2")

    assert current != successor


def test_published_source_rejects_contract_identity_mismatch_before_running_host_process():
    commit = "a" * 40
    step = ProvisioningStep(
        "verify_published_adapter_source",
        {
            "path": "/approved/source",
            "commit": commit,
            "capability_digest": capability_digest(commit, EXPECTED_BACKUP_TOOL_SCHEMAS),
            "provisioning_contract_version": "2",
            "runtime_artifact_identity": runtime_artifact_identity(commit, EXPECTED_BACKUP_TOOL_SCHEMAS),
        },
    )
    calls = []

    with pytest.raises(RuntimeError, match="contract identity"):
        adapter([step], lambda argv, **kwargs: calls.append(argv) or Result(stdout=(commit + "\n").encode())).execute(step)

    assert calls == []

def test_failed_process_exposes_only_validated_redacted_error_code():
    step=ProvisioningStep("ensure_system_user",{"name":"backup","home":"/nonexistent","shell":"/usr/sbin/nologin"})
    safe=json.dumps({"ok":False,"error":{"code":"PRIVATE_STATE_INVALID"},"redactions_applied":True}).encode()
    with pytest.raises(RuntimeError,match=r"PRIVATE_STATE_INVALID") as failure:
        adapter([step],lambda *_a,**_k:Result(returncode=2,stdout=b"",stderr=safe)).execute(step)
    assert isinstance(failure.value,RedactedHostOperationError) and failure.value.code=="PRIVATE_STATE_INVALID"
    assert "private diagnostic" not in str(failure.value)

    with pytest.raises(RuntimeError,match=r"PROCESS_STDERR_SINGLE_LINE_UNCLASSIFIED") as failure:
        adapter([step],lambda *_a,**_k:Result(returncode=2,stdout=b"",stderr=b'{"error":{"code":"TOKEN_LEAK"}}')).execute(step)
    assert failure.value.code=="PROCESS_STDERR_SINGLE_LINE_UNCLASSIFIED" and "TOKEN_LEAK" not in str(failure.value)

def test_failed_process_preserves_final_redacted_child_code_after_sudo_diagnostic():
    step=ProvisioningStep("ensure_system_user",{"name":"backup","home":"/nonexistent","shell":"/usr/sbin/nologin"})
    child=json.dumps({"ok":False,"error":{"code":"AUTHORIZATION_MISMATCH"},"redactions_applied":True}).encode()
    wrapped=b"sudo: wrapper diagnostic\n"+child+b"\n"
    with pytest.raises(RedactedHostOperationError) as failure:
        adapter([step],lambda *_a,**_k:Result(returncode=2,stderr=wrapped)).execute(step)
    assert failure.value.code=="AUTHORIZATION_MISMATCH"
    assert "sudo" not in str(failure.value) and "wrapper" not in str(failure.value)

@pytest.mark.parametrize(("stderr","expected"),[
    (json.dumps({"ok":False,"error":{"code":"AUTHORIZATION_MISMATCH"},"redactions_applied":True}).encode()+b"\nprivate trailing output\n","PROCESS_STDERR_MULTILINE_UNCLASSIFIED"),
    (b"prefix\n"+b"x"*4097,"PROCESS_STDERR_FINAL_LINE_OVERSIZED"),
    (b"prefix\n"+json.dumps({"ok":False,"error":{"code":"not-allowlisted"},"redactions_applied":True}).encode(),"PROCESS_STDERR_MULTILINE_UNCLASSIFIED"),
    (b"prefix\n\xff\n","PROCESS_STDERR_ENCODING_INVALID"),
])
def test_failed_process_rejects_unsafe_or_nonfinal_child_diagnostics(stderr,expected):
    step=ProvisioningStep("ensure_system_user",{"name":"backup","home":"/nonexistent","shell":"/usr/sbin/nologin"})
    with pytest.raises(RedactedHostOperationError) as failure:
        adapter([step],lambda *_a,**_k:Result(returncode=2,stderr=stderr)).execute(step)
    assert failure.value.code==expected
    assert "private" not in str(failure.value) and "not-allowlisted" not in str(failure.value)

@pytest.mark.parametrize(("stderr","expected"),[
    (b"sudo: a password is required\n","SUDO_AUTH_REQUIRED"),
    (b"sudo: unknown user bounded-service\n","SUDO_TARGET_USER_INVALID"),
    (b"sudo: unable to execute /approved/tool: Permission denied\n","SUDO_EXEC_PERMISSION_DENIED"),
    (b"sudo: unable to execute /approved/tool: No such file or directory\n","SUDO_EXEC_NOT_FOUND"),
    (b"sudo: account validation failure, is your account locked?\n","SUDO_ACCOUNT_REJECTED"),
    (b"sudo: PAM account management error: bounded failure class\n","SUDO_ACCOUNT_REJECTED"),
])
def test_failed_process_maps_only_allowlisted_final_wrapper_class(stderr,expected):
    step=ProvisioningStep("ensure_system_user",{"name":"backup","home":"/nonexistent","shell":"/usr/sbin/nologin"})
    with pytest.raises(RedactedHostOperationError) as failure:
        adapter([step],lambda *_a,**_k:Result(returncode=1,stderr=stderr)).execute(step)
    assert failure.value.code==expected
    assert stderr.decode().strip() not in str(failure.value)

@pytest.mark.parametrize("stderr",[
    b"sudo: arbitrary private diagnostic\n",
    b"sudo: unable to execute /approved/tool: Operation not permitted\n",
    b"sudo: unable to execute /approved/tool: Permission denied\nprivate trailing output\n",
    b"x"*8193,
])
def test_failed_process_rejects_unallowlisted_or_oversized_wrapper_output(stderr):
    step=ProvisioningStep("ensure_system_user",{"name":"backup","home":"/nonexistent","shell":"/usr/sbin/nologin"})
    with pytest.raises(RedactedHostOperationError) as failure:
        adapter([step],lambda *_a,**_k:Result(returncode=1,stderr=stderr)).execute(step)
    expected="PROCESS_STDERR_OVERSIZED" if len(stderr)>8192 else ("PROCESS_STDERR_SINGLE_LINE_UNCLASSIFIED" if len(stderr.splitlines())==1 else "PROCESS_STDERR_MULTILINE_UNCLASSIFIED")
    assert failure.value.code==expected
    assert "private" not in str(failure.value) and "/approved/tool" not in str(failure.value)

@pytest.mark.parametrize(("stderr","expected"),[
    (b"","PROCESS_STDERR_EMPTY"),
    (b"\n \t\n","PROCESS_STDERR_EMPTY"),
    (b"\xff","PROCESS_STDERR_ENCODING_INVALID"),
    (b"x"*4097,"PROCESS_STDERR_FINAL_LINE_OVERSIZED"),
    (b"private single line","PROCESS_STDERR_SINGLE_LINE_UNCLASSIFIED"),
    (b"private first line\nprivate final line\n","PROCESS_STDERR_MULTILINE_UNCLASSIFIED"),
])
def test_failed_process_reports_only_structural_stderr_class(stderr,expected):
    step=ProvisioningStep("ensure_system_user",{"name":"backup","home":"/nonexistent","shell":"/usr/sbin/nologin"})
    with pytest.raises(RedactedHostOperationError) as failure:
        adapter([step],lambda *_a,**_k:Result(returncode=1,stderr=stderr)).execute(step)
    assert failure.value.code==expected
    assert "private" not in str(failure.value)

def test_failed_process_reports_invalid_output_type_without_rendering_it():
    step=ProvisioningStep("ensure_system_user",{"name":"backup","home":"/nonexistent","shell":"/usr/sbin/nologin"})
    opaque=object()
    with pytest.raises(RedactedHostOperationError) as failure:
        adapter([step],lambda *_a,**_k:Result(returncode=1,stderr=opaque)).execute(step)
    assert failure.value.code=="PROCESS_OUTPUT_TYPE_INVALID"
    assert repr(opaque) not in str(failure.value)

def test_changed_arguments_and_unknown_operations_are_denied_before_runner():
    step=ProvisioningStep("ensure_system_user",{"name":"backup","home":"/nonexistent","shell":"/usr/sbin/nologin"}); calls=[]; host=adapter([step],lambda *args,**kwargs:calls.append(args) or Result())
    with pytest.raises(ValueError,match="exact approved"): host.execute(ProvisioningStep("ensure_system_user",{**step.arguments,"name":"root"}))
    with pytest.raises(ValueError,match="exact approved"): host.execute(ProvisioningStep("run_shell",{"command":"id"}))
    assert calls==[]

def test_secret_generation_uses_os_file_api_and_never_returns_secret(tmp_path):
    secret=tmp_path/"secret"; step=ProvisioningStep("generate_secret_file",{"path":str(secret),"mode":0o600,"owner":pwd.getpwuid(os.getuid()).pw_name,"bytes":48,"return_value":False}); calls=[]
    def runner(argv,**kwargs):
        calls.append(argv)
        if "/usr/bin/openssl" in argv: secret.write_bytes(b"x" * 96); secret.chmod(0o600)
        return Result()
    result=adapter([step],runner).execute(step)
    assert calls[:3]==[["/usr/bin/sudo","--","/usr/bin/openssl","rand","-hex","-out",str(secret),"48"],["/usr/bin/sudo","--","/usr/bin/chmod","0600",str(secret)],["/usr/bin/sudo","--","/usr/bin/chown",pwd.getpwuid(os.getuid()).pw_name+":"+pwd.getpwuid(os.getuid()).pw_name,str(secret)]]
    assert "secret" not in result and "private" not in repr(result)

def test_system_service_start_enable_operation_refreshed_after_enable():
    step=ProvisioningStep("start_enable_system_service",{"unit":"overseer-api.service","scope":"system"})
    calls=[]
    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return Result(stdout=(b"enabled\nactive\n100\n" if len([x for x, _ in calls if "show" in x]) == 1 else b"enabled\nactive\n101\n")) if "show" in argv else Result()
    result=adapter([step],runner).execute(step)
    assert result["disposition"] == "changed" and result["redactions_applied"] is True
    assert sum("show" in argv for argv, _ in calls) == 2
    assert "--now" not in calls[0][0] and "--now" not in calls[1][0]

def test_start_enable_system_service_preserves_exact_allowlisted_step_contract():
    step=ProvisioningStep("start_enable_system_service",{"unit":"overseer-api.service","scope":"system"})
    calls=[]
    host=adapter([step],lambda argv,**kwargs:calls.append((argv,kwargs)) or Result())
    with pytest.raises(ValueError,match="exact approved"): host.execute(ProvisioningStep("start_enable_system_service",{"unit":"other.service","scope":"system"}))
    with pytest.raises(ValueError,match="exact approved"): host.execute(ProvisioningStep("start_enable_system_service",{"unit":"overseer-api.service","scope":"system","extra":"flag"}))
    assert calls==[]

def test_rollback_file_removal_crosses_only_exact_sudo_argv(tmp_path):
    target=tmp_path/"config"; target.write_text("private"); target.chmod(0o600); owner=pwd.getpwuid(os.getuid()).pw_name
    digest="sha256:"+__import__("hashlib").sha256(b"private").hexdigest()
    step=ProvisioningStep("remove_private_config",{"path":str(target),"config_digest":digest,"owner":owner,"mode":0o600})
    calls=[]; host=adapter([step],lambda argv,**kwargs:calls.append(argv) or Result())
    assert host.execute(step)["disposition"] == "changed"
    assert not target.exists() and calls == []

def test_rollback_retains_service_identity_while_mutable_backup_state_remains():
    step=ProvisioningStep("remove_system_user_if_unused",{"name":"donuthole-backup","retained_path":"/var/lib/codex-development-backups/donuthole"}); calls=[]
    def runner(argv,**kwargs):
        calls.append((argv,kwargs))
        if argv[2] == "/usr/bin/pgrep": return Result(returncode=1)
        return Result(stdout=b"/var/lib/codex-development-backups/donuthole/state/registry.sqlite3\n" if argv[2]=="/usr/bin/find" else b"")
    result=adapter([step],runner).execute(step)
    assert result=={"ok":True,"operation":"remove_system_user_if_unused","disposition":"verified_noop","safe_code":"SYSTEM_USER_RETAINED_WITH_STATE","evidence":{},"redactions_applied":True}
    assert calls==[
            (["/usr/bin/sudo","--","/usr/bin/pgrep","-u","donuthole-backup"],{"shell":False,"stdin":-3,"stdout":-1,"stderr":-1,"check":False}),
            (["/usr/bin/sudo","--","/usr/bin/test","-e","/var/lib/codex-development-backups/donuthole"],{"shell":False,"stdin":-3,"stdout":-1,"stderr":-1,"check":False}),
        (["/usr/bin/sudo","--","/usr/bin/find","/var/lib/codex-development-backups/donuthole","-mindepth","1","-print","-quit"],{"shell":False,"stdin":-3,"stdout":-1,"stderr":-1,"check":False}),
    ]
    assert "registry.sqlite3" not in repr(result)

def test_rollback_deletes_unused_service_identity_with_exact_argv_when_no_state_remains():
    step=ProvisioningStep("remove_system_user_if_unused",{"name":"donuthole-backup","retained_path":"/var/lib/codex-development-backups/donuthole"}); calls=[]
    def runner(argv,**kwargs):
        calls.append(argv)
        if argv[2] == "/usr/bin/pgrep": return Result(returncode=1)
        return Result(returncode=1 if argv[2]=="/usr/bin/test" else 0,stdout=b"")
    result=adapter([step],runner).execute(step)
    assert result["disposition"] == "changed" and result["redactions_applied"] is True
    assert calls==[
            ["/usr/bin/sudo","--","/usr/bin/pgrep","-u","donuthole-backup"],
            ["/usr/bin/sudo","--","/usr/bin/test","-e","/var/lib/codex-development-backups/donuthole"],
        ["/usr/bin/sudo","--","/usr/sbin/userdel","donuthole-backup"],
    ]

def test_rollback_never_deletes_service_identity_when_retained_path_inspection_fails():
    step=ProvisioningStep("remove_system_user_if_unused",{"name":"donuthole-backup","retained_path":"/var/lib/codex-development-backups/donuthole"}); calls=[]
    def runner(argv,**kwargs):
        calls.append(argv)
        if argv[2] == "/usr/bin/pgrep": return Result(returncode=1)
        if argv[2]=="/usr/bin/find": return Result(returncode=1,stderr=b"private filesystem diagnostic")
        return Result()
    with pytest.raises(RedactedHostOperationError) as failure: adapter([step],runner).execute(step)
    assert failure.value.code=="PROCESS_STDERR_SINGLE_LINE_UNCLASSIFIED"
    assert calls==[
            ["/usr/bin/sudo","--","/usr/bin/pgrep","-u","donuthole-backup"],
            ["/usr/bin/sudo","--","/usr/bin/test","-e","/var/lib/codex-development-backups/donuthole"],
        ["/usr/bin/sudo","--","/usr/bin/find","/var/lib/codex-development-backups/donuthole","-mindepth","1","-print","-quit"],
    ]
    assert "private" not in str(failure.value)

def test_runtime_digest_is_commit_tree_and_mode_bound(tmp_path):
    (tmp_path/"src").mkdir(); target=tmp_path/"src"/"module.py"; target.write_text("value=1\n"); target.chmod(0o600)
    first=runtime_digest(tmp_path,"a"*40)
    assert first==runtime_digest(tmp_path,"a"*40) and first!=runtime_digest(tmp_path,"b"*40)
    target.chmod(0o644); assert runtime_digest(tmp_path,"a"*40)!=first

def test_mcp_verification_requires_exact_strict_backup_tool_schemas():
    commit="a"*40; digest=capability_digest(commit,EXPECTED_BACKUP_TOOL_SCHEMAS)
    step=ProvisioningStep("verify_mcp_service",{"url":"http://127.0.0.1:8799/mcp","capability_digest":digest,"provisioning_contract_version":PROVISIONING_CONTRACT_VERSION,"runtime_artifact_identity":runtime_artifact_identity(commit,EXPECTED_BACKUP_TOOL_SCHEMAS),"required_tools":tuple(EXPECTED_BACKUP_TOOL_SCHEMAS)})
    tools=[{"name":name,"inputSchema":schema} for name,schema in EXPECTED_BACKUP_TOOL_SCHEMAS.items()]
    result=adapter([step],lambda *_a,**_k:Result(),mcp_tool_loader=lambda url:tools).execute(step)
    assert result["ok"] and result["disposition"] == "verified_noop"
    altered=[dict(tools[0]),tools[1]]; altered[0]["inputSchema"]={**altered[0]["inputSchema"],"additionalProperties":True}; calls=[]
    with pytest.raises((ValueError,RuntimeError)): adapter([step],lambda *_a,**_k:Result(),mcp_tool_loader=lambda url:calls.append(url) or altered,mcp_retry_delays=(0,0),sleep=lambda _delay:None).execute(step)
    assert calls==[step.arguments["url"]]


def test_mcp_schema_normalization_removes_only_titles_and_preserves_semantics():
    schema = {
        "title": "Backup create",
        "type": "object",
        "additionalProperties": False,
        "minProperties": 2,
        "properties": {
            "request_id": {"title": "Request Id", "type": "string", "minLength": 1},
        },
        "required": ["request_id", "project_id"],
        "$defs": {"digest": {"title": "Digest", "type": "string", "pattern": "^sha256:"}},
        "allOf": [{"title": "Tighten", "minProperties": 2}],
    }

    assert _normalize_schema(schema) == {
        "type": "object",
        "additionalProperties": False,
        "minProperties": 2,
        "properties": {"request_id": {"type": "string", "minLength": 1}},
        "required": ["project_id", "request_id"],
        "$defs": {"digest": {"type": "string", "pattern": "^sha256:"}},
        "allOf": [{"minProperties": 2}],
    }
def test_mcp_verification_retries_only_transport_startup_failures():
    commit="a"*40; digest=capability_digest(commit,EXPECTED_BACKUP_TOOL_SCHEMAS)
    step=ProvisioningStep("verify_mcp_service",{"url":"http://127.0.0.1:8799/mcp","capability_digest":digest,"provisioning_contract_version":PROVISIONING_CONTRACT_VERSION,"runtime_artifact_identity":runtime_artifact_identity(commit,EXPECTED_BACKUP_TOOL_SCHEMAS),"required_tools":tuple(EXPECTED_BACKUP_TOOL_SCHEMAS)})
    tools=[{"name":name,"inputSchema":schema} for name,schema in EXPECTED_BACKUP_TOOL_SCHEMAS.items()]; calls=[]; sleeps=[]
    def loader(url):
        calls.append(url)
        if len(calls)<3: raise urllib.error.URLError("not listening")
        return tools
    result=adapter([step],lambda *_a,**_k:Result(),mcp_tool_loader=loader,mcp_retry_delays=(0.1,0.2),sleep=sleeps.append).execute(step)
    assert result["ok"] and result["disposition"] == "verified_noop"
    assert calls==[step.arguments["url"]]*3 and sleeps==[0.1,0.2]

def test_mcp_verification_reports_stable_redacted_readiness_exhaustion():
    commit="a"*40; digest=capability_digest(commit,EXPECTED_BACKUP_TOOL_SCHEMAS)
    step=ProvisioningStep("verify_mcp_service",{"url":"http://127.0.0.1:8799/mcp","capability_digest":digest,"provisioning_contract_version":PROVISIONING_CONTRACT_VERSION,"runtime_artifact_identity":runtime_artifact_identity(commit,EXPECTED_BACKUP_TOOL_SCHEMAS),"required_tools":tuple(EXPECTED_BACKUP_TOOL_SCHEMAS)}); calls=[]; sleeps=[]
    def loader(url): calls.append(url); raise ConnectionRefusedError("private endpoint detail")
    with pytest.raises(RedactedHostOperationError) as failure:
        adapter([step],lambda *_a,**_k:Result(),mcp_tool_loader=loader,mcp_retry_delays=(0.1,0.2),sleep=sleeps.append).execute(step)
    assert failure.value.code=="MCP_SERVICE_NOT_READY" and "private endpoint detail" not in str(failure.value)
    assert calls==[step.arguments["url"]]*3 and sleeps==[0.1,0.2]

def test_default_mcp_loader_initializes_session_then_lists_tools(monkeypatch):
    import json
    import overseer.backup_host_operations as host
    requests=[]; payloads=[{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}},{}, {"jsonrpc":"2.0","id":2,"result":{"tools":[]}}]
    class Response:
        def __init__(self,payload,index): self.payload=payload; self.headers={"mcp-session-id":"session-1"} if index==0 else {}
        def __enter__(self): return self
        def __exit__(self,*_): pass
        def read(self,_limit): return json.dumps(self.payload).encode()
    def open_request(request,timeout):
        requests.append((json.loads(request.data),dict(request.headers),timeout)); index=len(requests)-1; return Response(payloads[index],index)
    monkeypatch.setattr(host.urllib.request,"urlopen",open_request)
    assert host._load_mcp_tools("http://127.0.0.1:8799/mcp")==[]
    assert [item[0].get("method") for item in requests]==["initialize","notifications/initialized","tools/list"]
    assert requests[1][1]["Mcp-session-id"]=="session-1" and requests[2][2]==10

def test_install_excludes_local_environments_and_caches(monkeypatch):
    import overseer.backup_host_operations as host
    commit="a"*40; expected="sha256:"+"b"*64; step=ProvisioningStep("install_runtime",{"source":"/published","commit":commit,"runtime_digest":expected,"destination":"/installed","owner":"root","immutable":True}); calls=[]
    monkeypatch.setattr(host,"runtime_digest",lambda path,revision:expected)
    adapter([step],lambda argv,**kwargs:calls.append(argv) or Result()).execute(step)
    rsync=next(argv for argv in calls if "/usr/bin/rsync" in argv)
    assert {"--exclude=.git","--exclude=.venv","--exclude=.codex","--exclude=.agents","--exclude=__pycache__","--exclude=.pytest_cache","--exclude=tests","--exclude=docs"}<=set(rsync)
    pip=next(argv for argv in calls if argv[-2:]==["install","/installed"])
    assert "--no-deps" not in pip
    import_check=next(argv for argv in calls if argv[-2:]==["-c","import theunderdark.production_cli"])
    assert calls.index(pip)<calls.index(import_check)

def test_runtime_digest_excludes_agent_metadata_tests_and_docs(tmp_path):
    for directory in (".codex",".agents","tests","docs"):
        target=tmp_path/directory; target.mkdir(); (target/"local.txt").write_text("local-only")
    (tmp_path/"src").mkdir(); (tmp_path/"src"/"runtime.py").write_text("value=1\n")
    before=runtime_digest(tmp_path,"a"*40)
    for directory in (".codex",".agents","tests","docs"):
        (tmp_path/directory/"local.txt").write_text("changed")
    assert runtime_digest(tmp_path,"a"*40)==before

def test_registration_runs_as_config_owner_and_codex_step_is_read_only():
    registration={"project_id":"project.donuthole","root_id":"backup-root","policy_revision":"1","host_path":"/source","alias":"source","max_bytes":10,"authorization_ref":"approval"}
    register=ProvisioningStep("register_authorized_roots",{"tool":"underdark_root_register","authorization_endpoint":"http://127.0.0.1:8766/storage/roots/verify","registrations":(registration,),"token_file":"/private/token"})
    verify=ProvisioningStep("verify_codex_url",{"url":"http://127.0.0.1:8799/mcp"}); calls=[]
    def runner(argv,**kwargs):
        calls.append(argv)
        if "--verify-exact" in argv: return Result(stdout=b'{"exact":true}')
        return Result(stdout=json.dumps({"transport":{"url":"http://127.0.0.1:8799/mcp"}}).encode())
    host=adapter([register,verify],runner); host.execute(register); result=host.execute(verify)
    assert calls[0][:5]==["/usr/bin/sudo","-u","donuthole-backup","--","/opt/theunderdark/.venv/bin/theunderdark-production"]
    assert calls[2][:5]==["/home/god/.local/bin/codex","mcp","get","theunderdark","--json"] and result["disposition"] == "verified_noop"

def test_token_copy_rejects_symlink_and_permissive_source(tmp_path):
    destination=tmp_path/"destination"; source=tmp_path/"token"; source.write_text("token"); source.chmod(0o644)
    step=ProvisioningStep("install_overseer_api_token",{"source_path":str(source),"destination_path":str(destination),"mode":0o600,"owner":"backup","return_value":False}); host=adapter([step],lambda *_a,**_k:Result())
    with pytest.raises(PermissionError): host.execute(step)
    source.chmod(0o600); source.unlink(); real=tmp_path/"real"; real.write_text("token"); real.chmod(0o600); source.symlink_to(real)
    with pytest.raises(PermissionError): host.execute(step)

def test_systemd_rendering_quotes_paths_with_spaces():
    import overseer.backup_host_operations as host
    rendered=host._unit({"user":"backup","exec_start":('/path with space/app','serve','--config','/config with space'),"umask":"0077","read_only_paths":('/source with space',),"read_write_paths":('/state with space',),"restrict_address_families":('AF_UNIX','AF_INET')})
    assert 'ExecStart="/path with space/app" "serve" "--config" "/config with space"' in rendered
    assert 'ReadOnlyPaths="/source with space"' in rendered and 'ReadWritePaths="/state with space"' in rendered

def test_operator_cli_wires_concrete_adapter_without_root_owned_control_store(tmp_path,monkeypatch,capsys):
    import os
    import overseer.backup_provisioning_cli as cli
    store=tmp_path/"overseer.sqlite3"; store.write_bytes(b"operator-control"); before=(store.stat().st_uid,store.read_bytes()); observed={}
    class Host:
        def __init__(self,plan,*,privileged_confirmation): observed.update(uid=os.geteuid(),confirmation=privileged_confirmation,plan=plan)
    def execute(path,payload,adapter_factory):
        adapter_factory(object()); return {"ok":True,"redactions_applied":True}
    monkeypatch.setattr(cli,"ConcreteHostProvisioningAdapter",Host); monkeypatch.setattr(cli,"execute_plan_api",execute)
    confirmation=PRIVILEGED_CONFIRMATION
    assert cli.main(["--store",str(store),"execute","--plan-id","plan","--privileged-confirmation",confirmation])==0
    assert observed["uid"]==os.geteuid()!=0 and observed["confirmation"]==confirmation
    assert (store.stat().st_uid,store.read_bytes())==before and "redactions_applied" in capsys.readouterr().out
