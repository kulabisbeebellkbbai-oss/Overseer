"""Explicit privileged host operations for an exact approved backup plan.

Importing this module is inert. Construction requires an explicit privilege
confirmation and root identity; execution accepts only byte-for-byte plan steps.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import pwd
from pathlib import Path
from typing import Callable, Mapping

from .backup_contract import (
    PROVISIONING_CONTRACT_VERSION,
    load_provisioning_contract,
    runtime_artifact_identity,
)
from .backup_provisioning import DonutHoleBackupProvisioningPlan, ProvisioningStep

PRIVILEGED_CONFIRMATION="execute-exact-donuthole-backup-provisioning-plan"
OPERATOR_USER="god"
_CONTRACT_FIXTURE = Path(__file__).resolve().parents[2] / "tests/fixtures/contracts/donuthole_backup_provisioning_v1.json"


def _reviewed_backup_tool_schemas() -> dict[str, object]:
    contract = load_provisioning_contract(_CONTRACT_FIXTURE)
    tools = contract.raw["mcp_tools"]
    if not isinstance(tools, Mapping):
        raise RuntimeError("reviewed provisioning contract tool schemas are invalid")
    return json.loads(json.dumps(tools, sort_keys=True, separators=(",", ":")))


EXPECTED_BACKUP_TOOL_SCHEMAS = _reviewed_backup_tool_schemas()
RUNTIME_EXCLUDED={".git",".venv",".codex",".agents","__pycache__",".pytest_cache","tests","docs"}
MAX_REDACTED_DIAGNOSTIC_LINE_BYTES=4096
MAX_WRAPPER_DIAGNOSTIC_BYTES=8192
WRAPPER_ERROR_PATTERNS=(
    (re.compile(r"^sudo: a password is required$"),"SUDO_AUTH_REQUIRED"),
    (re.compile(r"^sudo: unknown user .{1,128}$"),"SUDO_TARGET_USER_INVALID"),
    (re.compile(r"^sudo: unable to execute .{1,2048}: Permission denied$"),"SUDO_EXEC_PERMISSION_DENIED"),
    (re.compile(r"^sudo: unable to execute .{1,2048}: No such file or directory$"),"SUDO_EXEC_NOT_FOUND"),
    (re.compile(r"^sudo: (?:account validation failure, is your account locked\?|PAM account management error: .{1,512})$"),"SUDO_ACCOUNT_REJECTED"),
)

class RedactedHostOperationError(RuntimeError):
    """A stable diagnostic safe to persist outside the privileged adapter."""
    def __init__(self,code:str)->None:
        self.code=code if re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}",code) else "PROCESS_FAILED"
        super().__init__(f"allowlisted host operation failed ({self.code})")

class ConcreteHostProvisioningAdapter:
    def __init__(self,plan:DonutHoleBackupProvisioningPlan,*,privileged_confirmation:str,runner:Callable[...,object]=subprocess.run,euid_provider:Callable[[],int]=os.geteuid,username_provider:Callable[[int],str]=lambda uid:pwd.getpwuid(uid).pw_name,mcp_tool_loader:Callable[[str],list[Mapping[str,object]]]|None=None,mcp_retry_delays:tuple[float,...]=(0.25,0.5,1.0,2.0,2.0),sleep:Callable[[float],None]=time.sleep)->None:
        uid=euid_provider()
        if privileged_confirmation!=PRIVILEGED_CONFIRMATION or uid==0 or username_provider(uid)!=OPERATOR_USER: raise PermissionError("explicit god-operator provisioning construction is required")
        if any(isinstance(delay,bool) or not isinstance(delay,(int,float)) or not math.isfinite(delay) or delay<0 for delay in mcp_retry_delays): raise ValueError("MCP retry delays must be finite non-negative numbers")
        self.plan=plan; self._allowed=tuple((*plan.steps,*plan.rollback_steps)); self._run_process=runner; self._mcp_tool_loader=mcp_tool_loader or _load_mcp_tools; self._mcp_retry_delays=tuple(float(delay) for delay in mcp_retry_delays); self._sleep=sleep

    def execute(self,step:ProvisioningStep)->Mapping[str,object]:
        if step not in self._allowed: raise ValueError("host provisioning step is not an exact approved plan step")
        handler=getattr(self,"_"+step.operation,None)
        if not callable(handler): raise ValueError("approved operation has no concrete host implementation")
        changed=bool(handler(dict(step.arguments)))
        return {"ok":True,"operation":step.operation,"changed":changed,"redactions_applied":True}

    def _run(self,argv:list[str],*,acceptable=(0,))->object:
        if not argv or any(not isinstance(value,str) or "\x00" in value for value in argv): raise ValueError("invalid process argument vector")
        result=self._run_process(argv,shell=False,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
        if getattr(result,"returncode",1) not in acceptable:
            raise RedactedHostOperationError(_redacted_process_error_code(getattr(result,"stderr",b"")))
        return result
    def _sudo(self,argv:list[str],*,user:str|None=None,acceptable=(0,)):
        prefix=["/usr/bin/sudo"]+(["-u",user] if user else [])+["--"]
        return self._run(prefix+argv,acceptable=acceptable)

    def _verify_published_adapter_source(self,a):
        _require_contract_identity(a)
        result=self._run(["/usr/bin/git","-C",a["path"],"rev-parse","HEAD"])
        if getattr(result,"stdout",b"").decode().strip()!=a["commit"]: raise RuntimeError("published adapter commit mismatch")
        if capability_digest(a["commit"],EXPECTED_BACKUP_TOOL_SCHEMAS,a["provisioning_contract_version"])!=a["capability_digest"]: raise RuntimeError("published capability digest mismatch")
        return False
    def _install_runtime(self,a):
        if runtime_digest(a["source"],a["commit"])!=a["runtime_digest"]: raise RuntimeError("published runtime artifact digest mismatch")
        excludes=[f"--exclude={name}" for name in sorted(RUNTIME_EXCLUDED)]
        self._sudo(["/usr/bin/install","-d","-m","0755",a["destination"]]); self._sudo(["/usr/bin/rsync","-a","--delete",*excludes,a["source"].rstrip("/")+"/",a["destination"].rstrip("/")+"/"])
        self._sudo(["/usr/bin/python3","-m","venv",a["destination"]+"/.venv"]); self._sudo([a["destination"]+"/.venv/bin/pip","install",a["destination"]])
        self._sudo([a["destination"]+"/.venv/bin/python","-c","import theunderdark.production_cli"])
        if runtime_digest(a["destination"],a["commit"])!=a["runtime_digest"]: raise RuntimeError("installed runtime digest mismatch")
        return True
    def _verify_endpoint_migration_ready(self,a): self._run(["/usr/bin/systemctl","--user","is-active","theunderdark-mcp.service"],acceptable=(0,3,4)); return False
    def _ensure_system_user(self,a): self._sudo(["/usr/sbin/useradd","--system","--home-dir",a["home"],"--shell",a["shell"],a["name"]],acceptable=(0,9)); return True
    def _ensure_directory(self,a): self._sudo(["/usr/bin/install","-d","-m",format(a["mode"],"04o"),"-o",a["owner"],"-g",a["owner"],a["path"]]); return True
    def _generate_secret_file(self,a): return self._secret(a,binary=False)
    def _generate_cursor_key(self,a): return self._secret(a,binary=True)
    def _secret(self,a,binary):
        size=a["bytes"] if binary else a["bytes"]//2
        self._sudo(["/usr/bin/openssl","rand",*([] if binary else ["-hex"]),"-out",a["path"],str(size)]); self._sudo(["/usr/bin/chmod",format(a["mode"],"04o"),a["path"]]); self._sudo(["/usr/bin/chown",a["owner"]+":"+a["owner"],a["path"]]); return True
    def _install_overseer_api_token(self,a):
        flags=os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)
        try: fd=os.open(a["source_path"],flags)
        except OSError as exc: raise PermissionError("source token must be a private regular non-symlink file") from exc
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)&0o077: raise PermissionError("source token must be a private regular non-symlink file")
            data=b""
            while True:
                chunk=os.read(fd,65536)
                if not chunk: break
                data+=chunk
                if len(data)>65536: raise ValueError("source token exceeds bounded size")
        finally: os.close(fd)
        if not data.strip(): raise ValueError("source token is empty")
        self._install_bytes(a["destination_path"],data,a["mode"],a["owner"]); return True
    def _ensure_read_only_acl(self,a): self._sudo(["/usr/bin/setfacl","-R","-m",f"u:{a['principal']}:{a['permissions']}",a["path"]]); return True
    def _install_private_config(self,a):
        encoded=json.dumps(a["config"],sort_keys=True,separators=(",",":")).encode()
        if "sha256:"+hashlib.sha256(encoded).hexdigest()!=a["config_digest"]: raise ValueError("config digest mismatch")
        self._install_bytes(a["path"],encoded,a["mode"],a["owner"]); return True
    def _register_authorized_roots(self,a):
        for item in a["registrations"]:
            self._sudo(["/opt/theunderdark/.venv/bin/theunderdark-production","register-root","--config","/etc/codex-development-backups/donuthole.json","--project-id",item["project_id"],"--root-id",item["root_id"],"--policy-revision",item["policy_revision"],"--host-path",item["host_path"],"--alias",item["alias"],"--max-bytes",str(item["max_bytes"]),"--authorization-ref",item["authorization_ref"]],user="donuthole-backup")
        return True
    def _stop_disable_user_service(self,a): self._run(["/usr/bin/systemctl","--user","disable","--now",a["unit"]],acceptable=(0,1,5)); return True
    def _start_enable_system_service(self,a):
        self._sudo(["/usr/bin/systemctl","enable",a["unit"]])
        self._sudo(["/usr/bin/systemctl","restart",a["unit"]])
        return True
    def _stop_disable_system_service(self,a): self._sudo(["/usr/bin/systemctl","disable","--now",a["unit"]],acceptable=(0,1,5)); return True
    def _restore_enable_user_service(self,a): self._run(["/usr/bin/systemctl","--user","enable","--now",a["unit"]]); return True
    def _install_systemd_unit(self,a): self._install_bytes(a["path"],_unit(a["properties"]).encode(),0o644,"root"); self._sudo(["/usr/bin/systemctl","daemon-reload"]); return True
    def _remove_systemd_unit(self,a): return self._unlink(a["path"],daemon_reload=True)
    def _verify_mcp_service(self,a):
        for delay in (*self._mcp_retry_delays,None):
            try:
                tools=self._mcp_tool_loader(a["url"])
                break
            except (urllib.error.URLError,TimeoutError,ConnectionError) as error:
                if isinstance(error,urllib.error.HTTPError): raise
                if delay is None: raise RedactedHostOperationError("MCP_SERVICE_NOT_READY") from None
                self._sleep(delay)
        normalized={str(tool.get("name")):_normalize_schema(tool.get("inputSchema")) for tool in tools if tool.get("name") in a["required_tools"]}; expected={name:EXPECTED_BACKUP_TOOL_SCHEMAS[name] for name in a["required_tools"]}
        if normalized!=expected or capability_digest(self.plan.adapter_commit,normalized,a["provisioning_contract_version"])!=a["capability_digest"]: raise RuntimeError("MCP capability verification failed")
        return False
    def _verify_codex_url(self,a):
        result=self._run(["/home/god/.local/bin/codex","mcp","get","theunderdark","--json"])
        try: value=json.loads(getattr(result,"stdout",b"").decode())
        except Exception as exc: raise RuntimeError("Codex MCP configuration is unreadable") from exc
        configured=value.get("transport",{}).get("url") or value.get("url")
        if configured!=a["url"]: raise RuntimeError("Codex MCP URL does not match approved endpoint")
        return False
    def _verify_gpg_identity(self,a):
        if _digest_file(a["path"])!=a["sha256"]: raise RuntimeError("GPG identity mismatch")
        return False
    def _verify_backup_policy(self,a):
        if a!={"retention":3,"plaintext_archive":False,"restore_required":True}: raise ValueError("backup policy mismatch")
        return False
    def _remove_private_config(self,a): return self._unlink(a["path"])
    def _remove_read_only_acl(self,a): self._sudo(["/usr/bin/setfacl","-R","-x",f"u:{a['principal']}",a["path"]],acceptable=(0,1)); return True
    def _remove_cursor_key_if_unreferenced(self,a): return self._unlink(a["path"])
    def _remove_overseer_api_token(self,a): return self._unlink(a["path"])
    def _remove_secret_file_if_no_backups(self,a):
        result=self._sudo(["/usr/bin/find",a["artifact_dir"],"-mindepth","1","-print","-quit"],acceptable=(0,1))
        if getattr(result,"stdout",b"").strip(): return False
        return self._unlink(a["path"])
    def _remove_directory_if_empty(self,a):
        result=self._sudo(["/usr/bin/rmdir",a["path"]],acceptable=(0,1)); return getattr(result,"returncode",1)==0
    def _remove_system_user_if_unused(self,a):
        present=self._sudo(["/usr/bin/test","-e",a["retained_path"]],acceptable=(0,1)).returncode==0
        if present:
            retained=self._sudo(["/usr/bin/find",a["retained_path"],"-mindepth","1","-print","-quit"])
            if getattr(retained,"stdout",b"").strip(): return False
        removed=self._sudo(["/usr/sbin/userdel",a["name"]],acceptable=(0,6))
        return getattr(removed,"returncode",1)==0
    def _remove_runtime_if_unreferenced(self,a): self._sudo(["/usr/bin/rm","-r","--one-file-system",a["path"]],acceptable=(0,1)); return True
    def _install_bytes(self,path,data,mode,owner):
        fd,name=tempfile.mkstemp(prefix="overseer-provision-"); staging=Path(name)
        try:
            with os.fdopen(fd,"wb") as output: output.write(data); output.flush(); os.fsync(output.fileno())
            self._sudo(["/usr/bin/install","-m",format(mode,"04o"),"-o",owner,"-g",owner,str(staging),path])
        finally: staging.unlink(missing_ok=True)
    def _unlink(self,path,daemon_reload=False):
        present=self._sudo(["/usr/bin/test","-e",path],acceptable=(0,1)).returncode==0
        self._sudo(["/usr/bin/rm","-f","--",path])
        if daemon_reload: self._sudo(["/usr/bin/systemctl","daemon-reload"])
        return present

def _redacted_child_error_code(stderr):
    """Extract only a bounded final structured diagnostic emitted by a child."""
    if not isinstance(stderr,(bytes,bytearray)): return "PROCESS_FAILED"
    lines=bytes(stderr).splitlines(); final=next((line for line in reversed(lines) if line.strip()),b"")
    if not final or len(final)>MAX_REDACTED_DIAGNOSTIC_LINE_BYTES: return "PROCESS_FAILED"
    try: diagnostic=json.loads(final.decode("utf-8","strict"))
    except (UnicodeDecodeError,json.JSONDecodeError): return "PROCESS_FAILED"
    if not isinstance(diagnostic,dict) or diagnostic.get("redactions_applied") is not True: return "PROCESS_FAILED"
    error=diagnostic.get("error"); candidate=error.get("code") if isinstance(error,dict) else None
    return candidate if isinstance(candidate,str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}",candidate) else "PROCESS_FAILED"

def _redacted_process_error_code(stderr):
    child=_redacted_child_error_code(stderr)
    if child!="PROCESS_FAILED": return child
    if not isinstance(stderr,(bytes,bytearray)): return "PROCESS_OUTPUT_TYPE_INVALID"
    if len(stderr)>MAX_WRAPPER_DIAGNOSTIC_BYTES: return "PROCESS_STDERR_OVERSIZED"
    try: lines=bytes(stderr).decode("utf-8","strict").splitlines()
    except UnicodeDecodeError: return "PROCESS_STDERR_ENCODING_INVALID"
    nonempty=[line.strip() for line in lines if line.strip()]
    if not nonempty: return "PROCESS_STDERR_EMPTY"
    final=nonempty[-1]
    if len(final.encode())>MAX_REDACTED_DIAGNOSTIC_LINE_BYTES: return "PROCESS_STDERR_FINAL_LINE_OVERSIZED"
    wrapper=next((code for pattern,code in WRAPPER_ERROR_PATTERNS if pattern.fullmatch(final)),None)
    if wrapper: return wrapper
    return "PROCESS_STDERR_SINGLE_LINE_UNCLASSIFIED" if len(nonempty)==1 else "PROCESS_STDERR_MULTILINE_UNCLASSIFIED"

def _digest_file(path):
    digest=hashlib.sha256()
    with open(path,"rb") as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b""): digest.update(chunk)
    return "sha256:"+digest.hexdigest()
def runtime_digest(path,commit):
    root=Path(path); files=[]
    for item in sorted(root.rglob("*")):
        relative=item.relative_to(root)
        if any(part in RUNTIME_EXCLUDED for part in relative.parts): continue
        if item.is_symlink() or (not item.is_file() and not item.is_dir()): raise ValueError("runtime tree contains unsupported entries")
        if item.is_file(): files.append({"path":relative.as_posix(),"mode":item.stat().st_mode&0o777,"sha256":_digest_file(item)})
    return _object_digest({"version":1,"commit":commit,"files":files})
def capability_digest(commit: str, schemas: Mapping[str, object], provisioning_contract_version: str = PROVISIONING_CONTRACT_VERSION) -> str: return _object_digest({"version":2,"commit":commit,"provisioning_contract_version":provisioning_contract_version,"tools":schemas})
def _object_digest(value): return "sha256:"+hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def _require_contract_identity(arguments):
    version=arguments.get("provisioning_contract_version")
    expected=runtime_artifact_identity(arguments.get("commit"),EXPECTED_BACKUP_TOOL_SCHEMAS) if isinstance(arguments.get("commit"),str) else None
    if version!=PROVISIONING_CONTRACT_VERSION or arguments.get("runtime_artifact_identity")!=expected: raise RuntimeError("published contract identity mismatch")
def _normalize_schema(value):
    if not isinstance(value,Mapping) or value.get("type")!="object" or value.get("additionalProperties") is not False or not isinstance(value.get("properties"),Mapping) or not isinstance(value.get("required"),list): raise ValueError("tool schema is not strict")
    return _normalize_schema_value(value)
def _normalize_schema_value(value):
    if isinstance(value,Mapping):
        normalized={str(name):_normalize_schema_value(child) for name,child in value.items() if name!="title"}
        if isinstance(normalized.get("required"),list): normalized["required"]=sorted(normalized["required"])
        return normalized
    if isinstance(value,list): return [_normalize_schema_value(child) for child in value]
    return value
def _load_mcp_tools(url):
    session=None
    def post(payload):
        nonlocal session
        headers={"content-type":"application/json","accept":"application/json, text/event-stream"}
        if session: headers["mcp-session-id"]=session
        request=urllib.request.Request(url,data=json.dumps(payload,separators=(",",":")).encode(),headers=headers,method="POST")
        with urllib.request.urlopen(request,timeout=10) as response:
            session=response.headers.get("mcp-session-id") or session; body=response.read(2_097_153).decode()
        data=next((line[5:].strip() for line in body.splitlines() if line.startswith("data:")),None)
        return json.loads(data if data is not None else body) if body else {}
    initialized=post({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"overseer-provisioner","version":"1"}}})
    if "result" not in initialized: raise RuntimeError("MCP initialize failed")
    post({"jsonrpc":"2.0","method":"notifications/initialized","params":{}})
    listed=post({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}); tools=listed.get("result",{}).get("tools") if isinstance(listed,Mapping) else None
    if not isinstance(tools,list): raise RuntimeError("MCP tools/list failed")
    return tools
def _unit(p):
    return "[Service]\nUser="+p["user"]+"\nExecStart="+" ".join(_sd_quote(value) for value in p["exec_start"])+"\nUMask="+p["umask"]+"\nPrivateTmp=yes\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=read-only\nReadOnlyPaths="+" ".join(_sd_quote(value) for value in p["read_only_paths"])+"\nReadWritePaths="+" ".join(_sd_quote(value) for value in p["read_write_paths"])+"\nRestrictAddressFamilies="+" ".join(p["restrict_address_families"])+"\n[Install]\nWantedBy=multi-user.target\n"
def _sd_quote(value): return '"'+str(value).replace("\\","\\\\").replace('"','\\"')+'"'

__all__=["ConcreteHostProvisioningAdapter","EXPECTED_BACKUP_TOOL_SCHEMAS","PRIVILEGED_CONFIRMATION","RUNTIME_EXCLUDED","RedactedHostOperationError","capability_digest","runtime_digest"]
