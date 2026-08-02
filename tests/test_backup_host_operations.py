from types import SimpleNamespace
import json

import pytest

from overseer.backup_host_operations import ConcreteHostProvisioningAdapter,EXPECTED_BACKUP_TOOL_SCHEMAS,PRIVILEGED_CONFIRMATION,RedactedHostOperationError,capability_digest,runtime_digest
from overseer.backup_provisioning import ProvisioningStep

class Result:
    def __init__(self,returncode=0,stdout=b"",stderr=b"private diagnostic"): self.returncode=returncode; self.stdout=stdout; self.stderr=stderr

def adapter(steps,runner,**kwargs):
    commit="a"*40
    return ConcreteHostProvisioningAdapter(SimpleNamespace(steps=tuple(steps),rollback_steps=(),adapter_commit=commit),privileged_confirmation=PRIVILEGED_CONFIRMATION,runner=runner,euid_provider=lambda:1000,username_provider=lambda uid:"god",**kwargs)

def test_construction_requires_explicit_confirmation_and_root():
    plan=SimpleNamespace(steps=(),rollback_steps=())
    with pytest.raises(PermissionError): ConcreteHostProvisioningAdapter(plan,privileged_confirmation="yes",euid_provider=lambda:1000,username_provider=lambda uid:"god")
    with pytest.raises(PermissionError): ConcreteHostProvisioningAdapter(plan,privileged_confirmation=PRIVILEGED_CONFIRMATION,euid_provider=lambda:0,username_provider=lambda uid:"root")
    with pytest.raises(PermissionError): ConcreteHostProvisioningAdapter(plan,privileged_confirmation=PRIVILEGED_CONFIRMATION,euid_provider=lambda:1001,username_provider=lambda uid:"other")

def test_exact_plan_step_uses_argv_without_shell_and_redacts_process_output():
    commit="a"*40; step=ProvisioningStep("verify_published_adapter_source",{"path":"/approved/source","commit":commit,"capability_digest":capability_digest(commit,EXPECTED_BACKUP_TOOL_SCHEMAS)}); calls=[]
    def runner(argv,**kwargs): calls.append((argv,kwargs)); return Result(stdout=("a"*40+"\n").encode())
    result=adapter([step],runner).execute(step)
    assert calls==[(["/usr/bin/git","-C","/approved/source","rev-parse","HEAD"],{"shell":False,"stdin":-3,"stdout":-1,"stderr":-1,"check":False})]
    assert result=={"ok":True,"operation":"verify_published_adapter_source","changed":False,"redactions_applied":True}
    assert "private diagnostic" not in repr(result)

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
    secret=tmp_path/"secret"; step=ProvisioningStep("generate_secret_file",{"path":str(secret),"mode":0o600,"owner":"backup","bytes":48,"return_value":False}); calls=[]
    result=adapter([step],lambda argv,**kwargs:calls.append(argv) or Result()).execute(step)
    assert calls==[["/usr/bin/sudo","--","/usr/bin/openssl","rand","-hex","-out",str(secret),"24"],["/usr/bin/sudo","--","/usr/bin/chmod","0600",str(secret)],["/usr/bin/sudo","--","/usr/bin/chown","backup:backup",str(secret)]]
    assert "secret" not in result and "private" not in repr(result)

def test_rollback_file_removal_crosses_only_exact_sudo_argv(tmp_path):
    target=tmp_path/"config"; target.write_text("private"); step=ProvisioningStep("remove_private_config",{"path":str(target)})
    calls=[]; host=adapter([step],lambda argv,**kwargs:calls.append(argv) or Result())
    assert host.execute(step)["changed"] is True
    assert calls==[["/usr/bin/sudo","--","/usr/bin/test","-e",str(target)],["/usr/bin/sudo","--","/usr/bin/rm","-f","--",str(target)]]

def test_runtime_digest_is_commit_tree_and_mode_bound(tmp_path):
    (tmp_path/"src").mkdir(); target=tmp_path/"src"/"module.py"; target.write_text("value=1\n"); target.chmod(0o600)
    first=runtime_digest(tmp_path,"a"*40)
    assert first==runtime_digest(tmp_path,"a"*40) and first!=runtime_digest(tmp_path,"b"*40)
    target.chmod(0o644); assert runtime_digest(tmp_path,"a"*40)!=first

def test_mcp_verification_requires_exact_strict_backup_tool_schemas():
    commit="a"*40; digest=capability_digest(commit,EXPECTED_BACKUP_TOOL_SCHEMAS)
    step=ProvisioningStep("verify_mcp_service",{"url":"http://127.0.0.1:8799/mcp","capability_digest":digest,"required_tools":tuple(EXPECTED_BACKUP_TOOL_SCHEMAS)})
    tools=[{"name":name,"inputSchema":schema} for name,schema in EXPECTED_BACKUP_TOOL_SCHEMAS.items()]
    result=adapter([step],lambda *_a,**_k:Result(),mcp_tool_loader=lambda url:tools).execute(step)
    assert result["ok"] and result["changed"] is False
    altered=[dict(tools[0]),tools[1]]; altered[0]["inputSchema"]={**altered[0]["inputSchema"],"additionalProperties":True}
    with pytest.raises((ValueError,RuntimeError)): adapter([step],lambda *_a,**_k:Result(),mcp_tool_loader=lambda url:altered).execute(step)

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
    def runner(argv,**kwargs): calls.append(argv); return Result(stdout=json.dumps({"transport":{"url":"http://127.0.0.1:8799/mcp"}}).encode())
    host=adapter([register,verify],runner); host.execute(register); result=host.execute(verify)
    assert calls[0][:5]==["/usr/bin/sudo","-u","donuthole-backup","--","/opt/theunderdark/.venv/bin/theunderdark-production"]
    assert calls[1][:5]==["/home/god/.local/bin/codex","mcp","get","TheUnderdark","--json"] and result["changed"] is False

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
