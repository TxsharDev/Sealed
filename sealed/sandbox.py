"""Behavioral sandbox: import packages in isolation, monitor behavior."""

from __future__ import annotations
import json, os, subprocess, sys, tempfile, time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from sealed.chain import _hash_bytes

_MONITOR_SCRIPT = """import sys, json, os, importlib
_behaviors = []
_original_socket = None
try:
    import socket as _sm
    _original_socket = _sm.socket
    class _MS(_original_socket):
        def connect(s, addr):
            _behaviors.append({'type':'network_connect','address':str(addr),'severity':'critical'})
            raise ConnectionRefusedError('blocked')
        def connect_ex(s, addr):
            _behaviors.append({'type':'network_connect','address':str(addr),'severity':'critical'})
            return 111
    _sm.socket = _MS
except: pass
try:
    import subprocess as _sub
    class _MP:
        def __init__(s,*a,**k):
            _behaviors.append({'type':'subprocess','command':str(a[0] if a else k.get('args','?'))[:500],'severity':'high'})
            raise PermissionError('blocked')
    _sub.Popen = _MP
except: pass
_oo = open
_sp = ['.ssh','.gnupg','.aws','.env','.netrc','.docker','.kube','id_rsa','id_ed25519','credentials']
def _mo(f,*a,**k):
    ps = str(f).lower().replace(chr(92),'/')
    for s in _sp:
        if s in ps: _behaviors.append({'type':'sensitive_file_read','path':str(f)[:500],'pattern':s,'severity':'critical'})
    return _oo(f,*a,**k)
import builtins; builtins.open = _mo
_og = os.getenv
_sk = ['token','secret','password','api_key','apikey','private_key','access_key']
def _mg(k,d=None):
    for p in _sk:
        if p in k.lower(): _behaviors.append({'type':'env_secret_access','variable':k,'severity':'high'})
    return _og(k,d)
os.getenv = _mg
pn, of = sys.argv[1], sys.argv[2]
try:
    importlib.import_module(pn)
    _behaviors.append({'type':'import_success','package':pn,'severity':'info'})
except Exception as e:
    _behaviors.append({'type':'import_error','package':pn,'error':str(e)[:500],'severity':'info'})
with _oo(of,'w') as f: json.dump({'behaviors':_behaviors},f)
"""

@dataclass
class SandboxBehavior:
    type: str
    severity: str
    details: dict[str, str] = field(default_factory=dict)
    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "severity": self.severity, **self.details}

@dataclass
class SandboxResult:
    package: str
    version: str
    behaviors: list[SandboxBehavior] = field(default_factory=list)
    timeout: bool = False
    error: str | None = None
    @property
    def safe(self) -> bool:
        return not any(b.severity in ("critical", "high") for b in self.behaviors)
    @property
    def digest(self) -> str:
        data = json.dumps([b.to_dict() for b in self.behaviors], sort_keys=True, separators=(",",":"))
        return _hash_bytes(data.encode())
    def to_dict(self) -> dict[str, Any]:
        return {"package": self.package, "version": self.version, "safe": self.safe,
                "timeout": self.timeout, "error": self.error,
                "behaviors": [b.to_dict() for b in self.behaviors],
                "critical": sum(1 for b in self.behaviors if b.severity == "critical"),
                "high": sum(1 for b in self.behaviors if b.severity == "high")}

class BehavioralSandbox:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    def analyze(self, package: str, version: str, wheel_path: Path | None = None) -> SandboxResult:
        result = SandboxResult(package=package, version=version)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as sf:
            sf.write(_MONITOR_SCRIPT)
            script_path = sf.name
        output_path = tempfile.mktemp(suffix=".json")
        try:
            import_name = package.replace("-", "_").replace(".", "_")
            env = self._restricted_env()
            if wheel_path:
                install_dir = tempfile.mkdtemp(prefix="sealed_sandbox_")
                subprocess.run([sys.executable, "-m", "pip", "install", str(wheel_path),
                    "--target", install_dir, "--quiet", "--no-deps"],
                    capture_output=True, timeout=60, env=env)
                env["PYTHONPATH"] = install_dir
            proc = subprocess.run([sys.executable, script_path, import_name, output_path],
                capture_output=True, text=True, timeout=self.timeout, env=env)
            if Path(output_path).exists():
                data = json.loads(Path(output_path).read_text())
                for b in data.get("behaviors", []):
                    bt = b.pop("type", "unknown")
                    sv = b.pop("severity", "info")
                    result.behaviors.append(SandboxBehavior(type=bt, severity=sv, details=b))
            if proc.returncode != 0 and not result.behaviors:
                result.error = proc.stderr[:500] if proc.stderr else "Unknown error"
        except subprocess.TimeoutExpired:
            result.timeout = True
            result.behaviors.append(SandboxBehavior(type="timeout", severity="high", details={"seconds": str(self.timeout)}))
        except Exception as e:
            result.error = str(e)[:500]
        finally:
            Path(script_path).unlink(missing_ok=True)
            Path(output_path).unlink(missing_ok=True)
        return result

    def _restricted_env(self) -> dict[str, str]:
        env = {}
        for var in ["PATH","SYSTEMROOT","TEMP","TMP","HOME","USERPROFILE","PYTHONPATH","VIRTUAL_ENV"]:
            val = os.environ.get(var)
            if val: env[var] = val
        env["SEALED_SANDBOX"] = "1"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return env
