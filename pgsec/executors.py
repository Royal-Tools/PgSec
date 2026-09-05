from __future__ import annotations
import os, subprocess, time, shutil, base64, json
from pathlib import Path
from typing import Optional
from .models import CommandResult
from .util import shell_quote, redact

class Executor:
    kind = "base"
    def run(self, command: str, timeout: int = 20, env: Optional[dict[str,str]] = None) -> CommandResult:
        raise NotImplementedError
    def sql(self, sql: str, timeout: int = 20) -> CommandResult:
        raise NotImplementedError

class LocalExecutor(Executor):
    kind = "local"
    def __init__(self, db_user: str | None = None, db_name: str = "postgres", psql_path: str | None = None):
        self.db_user = db_user
        self.db_name = db_name
        self.psql_path = psql_path or "psql"
        self.sql_prefix: str | None = None

    def run(self, command: str, timeout: int = 20, env: Optional[dict[str,str]] = None) -> CommandResult:
        start=time.monotonic()
        e=os.environ.copy()
        if env:
            e.update({str(k):str(v) for k,v in env.items()})
        try:
            p=subprocess.run(command, shell=True, executable="/bin/sh", text=True, capture_output=True, timeout=timeout, env=e)
            return CommandResult(p.stdout.strip(), p.stderr.strip(), p.returncode, int((time.monotonic()-start)*1000))
        except subprocess.TimeoutExpired as ex:
            return CommandResult((ex.stdout or "").strip() if isinstance(ex.stdout,str) else "", "command timeout", 124, int((time.monotonic()-start)*1000))
        except Exception as ex:
            return CommandResult("", str(ex), 125, int((time.monotonic()-start)*1000))

    def _psql_cmd(self, sql: str, prefix: str = "") -> str:
        user = f" -U {shell_quote(self.db_user)}" if self.db_user else ""
        return f"{prefix}{shell_quote(self.psql_path)} -X -A -t -v ON_ERROR_STOP=1{user} -d {shell_quote(self.db_name)} -c {shell_quote(sql)}"

    def sql(self, sql: str, timeout: int = 20) -> CommandResult:
        # Cache the first working local access method. Avoid interactive password prompts.
        prefixes = [self.sql_prefix] if self.sql_prefix is not None else ["", "sudo -n -u postgres ", "su -s /bin/sh postgres -c "]
        for prefix in prefixes:
            if prefix is None:
                continue
            if prefix.startswith("su "):
                inner = self._psql_cmd(sql, "")
                cmd = f"su -s /bin/sh postgres -c {shell_quote(inner)}"
            else:
                cmd = self._psql_cmd(sql, prefix)
            # Ensure psql cannot stop waiting for a password.
            res = self.run(f"PGCONNECT_TIMEOUT=3 {cmd} </dev/null", timeout=timeout)
            if res.rc == 0:
                if self.sql_prefix is None:
                    self.sql_prefix = prefix
                return res
            if self.sql_prefix is not None:
                return res
        return res

class FakeExecutor(Executor):
    kind="fake"
    def __init__(self, responses: dict[str,CommandResult] | None = None, sql_responses: dict[str,str|CommandResult] | None = None):
        self.responses=responses or {}
        self.sql_responses=sql_responses or {}
        self.commands=[]
    def run(self, command: str, timeout: int = 20, env=None) -> CommandResult:
        self.commands.append(command)
        for k,v in self.responses.items():
            if k in command:
                return v
        return CommandResult("", "fake: command not mapped", 127)
    def sql(self, sql: str, timeout: int = 20) -> CommandResult:
        self.commands.append("SQL:"+sql)
        if sql in self.sql_responses:
            v=self.sql_responses[sql]
            return v if isinstance(v,CommandResult) else CommandResult(str(v),"",0)
        # fuzzy exact stripped fallback
        key=sql.strip()
        for k,v in self.sql_responses.items():
            if k.strip()==key:
                return v if isinstance(v,CommandResult) else CommandResult(str(v),"",0)
        return CommandResult("", "fake: sql not mapped", 127)

class SSHExecutor(Executor):
    kind="ssh"
    def __init__(self, host: str, username: str, port: int=22, password: str|None=None, key_file: str|None=None,
                 helper: str|None=None, known_hosts: str|None=None, accept_new_hostkey: bool=False,
                 db_user: str|None=None, db_name: str="postgres"):
        self.host=host; self.username=username; self.port=port; self.password=password; self.key_file=key_file
        self.helper=helper or self._find_helper()
        self.known_hosts=known_hosts or os.path.expanduser("~/.ssh/known_hosts")
        self.accept_new_hostkey=accept_new_hostkey
        self.db_user=db_user; self.db_name=db_name; self.sql_prefix=None
    def _find_helper(self) -> str|None:
        env=os.environ.get("PGSEC_SSH_HELPER")
        if env and Path(env).exists(): return env
        here=Path(__file__).resolve().parent
        for p in [here.parent/"bin"/"pgssh", Path(sys_exe_dir())/"pgssh", Path.cwd()/"bin"/"pgssh"]:
            if p.exists(): return str(p)
        return shutil.which("pgssh")
    def run(self, command: str, timeout: int = 20, env=None) -> CommandResult:
        if env:
            # Remote env values are shell-quoted. Caller must not place report secrets here.
            exports=" ".join(f"{k}={shell_quote(v)}" for k,v in env.items())
            command=f"env {exports} {command}"
        if self.helper:
            args=[self.helper,"--host",self.host,"--port",str(self.port),"--user",self.username,
                  "--known-hosts",self.known_hosts,"--command-b64",base64.b64encode(command.encode()).decode()]
            if self.accept_new_hostkey: args.append("--accept-new")
            if self.key_file:
                args += ["--key",self.key_file]
            elif self.password is not None:
                args.append("--password-stdin")
            start=time.monotonic()
            try:
                input_data=(self.password or "")+"\n" if self.password is not None and not self.key_file else ""
                p=subprocess.run(args,input=input_data,text=True,capture_output=True,timeout=timeout+5)
                err=(p.stderr or "")
                glibc_incompat=("GLIBC_" in err and "not found" in err) or ("version `" in err and "not found" in err)
                if glibc_incompat and not (self.password is not None and not self.key_file):
                    self.helper=None
                else:
                    return CommandResult(p.stdout.strip(),err.strip(),p.returncode,int((time.monotonic()-start)*1000))
            except subprocess.TimeoutExpired:
                return CommandResult("","ssh timeout",124,int((time.monotonic()-start)*1000))
            except OSError:
                if self.password is not None and not self.key_file:
                    return CommandResult("","bundled pgssh helper could not be executed",125,int((time.monotonic()-start)*1000))
                self.helper=None
            except Exception as ex:
                return CommandResult("",str(ex),125,int((time.monotonic()-start)*1000))
        # Key-auth fallback to system ssh. Password mode deliberately does not expose password on argv.
        ssh=shutil.which("ssh")
        if not ssh:
            return CommandResult("","No bundled pgssh helper or system ssh client available",127)
        if self.password is not None and not self.key_file:
            return CommandResult("","Password SSH requires bundled pgssh helper",126)
        args=[ssh,"-p",str(self.port),"-o","BatchMode=yes","-o","ConnectTimeout=8","-o","StrictHostKeyChecking=yes"]
        if self.key_file: args += ["-i",self.key_file]
        args += [f"{self.username}@{self.host}",command]
        start=time.monotonic()
        try:
            p=subprocess.run(args,text=True,capture_output=True,timeout=timeout+5)
            return CommandResult(p.stdout.strip(),p.stderr.strip(),p.returncode,int((time.monotonic()-start)*1000))
        except Exception as ex:
            return CommandResult("",str(ex),125,int((time.monotonic()-start)*1000))
    def _psql_cmd(self, sql: str, prefix: str="") -> str:
        user=f" -U {shell_quote(self.db_user)}" if self.db_user else ""
        return f"{prefix}psql -X -A -t -v ON_ERROR_STOP=1{user} -d {shell_quote(self.db_name)} -c {shell_quote(sql)}"
    def sql(self, sql: str, timeout: int=20) -> CommandResult:
        prefixes=[self.sql_prefix] if self.sql_prefix is not None else ["", "sudo -n -u postgres "]
        for prefix in prefixes:
            res=self.run(f"PGCONNECT_TIMEOUT=3 {self._psql_cmd(sql,prefix)} </dev/null",timeout)
            if res.rc==0:
                if self.sql_prefix is None: self.sql_prefix=prefix
                return res
            if self.sql_prefix is not None: return res
        return res

class ContainerExecutor(Executor):
    kind="container"
    def __init__(self, base: Executor, runtime: str, container: str, db_user: str|None=None, db_name: str="postgres"):
        self.base=base; self.runtime=runtime; self.container=container; self.db_user=db_user; self.db_name=db_name; self.sql_prefix=None
    def build_command(self, command: str) -> str:
        return f"{self.runtime} exec {shell_quote(self.container)} sh -lc {shell_quote(command)}"
    def run(self, command: str, timeout: int=20, env=None) -> CommandResult:
        if env:
            exports=" ".join(f"{k}={shell_quote(v)}" for k,v in env.items())
            command=f"env {exports} {command}"
        return self.base.run(self.build_command(command),timeout)
    def sql(self, sql: str, timeout: int=20) -> CommandResult:
        user=f" -U {shell_quote(self.db_user)}" if self.db_user else ""
        candidates=[]
        if self.sql_prefix is not None:
            candidates=[self.sql_prefix]
        else:
            candidates=["", "runuser -u postgres -- ", "su -s /bin/sh postgres -c "]
        for prefix in candidates:
            base=f"psql -X -A -t -v ON_ERROR_STOP=1{user} -d {shell_quote(self.db_name)} -c {shell_quote(sql)}"
            if prefix.startswith("su "):
                cmd=f"su -s /bin/sh postgres -c {shell_quote(base)}"
            else:
                cmd=prefix+base
            res=self.run(f"PGCONNECT_TIMEOUT=3 {cmd} </dev/null",timeout)
            if res.rc==0:
                if self.sql_prefix is None:self.sql_prefix=prefix
                return res
            if self.sql_prefix is not None:return res
        return res

def sys_exe_dir() -> str:
    import sys
    return str(Path(sys.executable).resolve().parent)
