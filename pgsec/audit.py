from __future__ import annotations
import json, re, time, os, fnmatch
from pathlib import Path
from typing import Callable, Iterable
from .models import Result, Evidence, Target, CommandResult
from .rules import CIS_RULES_BY_MAJOR, ESA_RULES, BENCHMARKS
from .util import bool_on, bool_off, truncate, version_tuple, shell_quote

LOG_LEVELS = ['debug5','debug4','debug3','debug2','debug1','info','notice','warning','error','log','fatal','panic']
TLS_ALLOWED = {
'TLS_AES_256_GCM_SHA384','TLS_AES_128_GCM_SHA256','TLS_AES_128_CCM_SHA256','TLS_CHACHA20_POLY1305_SHA256',
'ECDHE-ECDSA-AES256-CCM','ECDHE-ECDSA-AES128-CCM','DHE-RSA-AES256-CCM','DHE-RSA-AES128-CCM',
'ECDHE-RSA-AES256-GCM-SHA384','ECDHE-RSA-AES128-GCM-SHA256','ECDHE-ECDSA-AES256-GCM-SHA384','ECDHE-ECDSA-AES128-GCM-SHA256',
'DHE-DSS-AES256-GCM-SHA384','DHE-DSS-AES128-GCM-SHA256','DHE-RSA-AES256-GCM-SHA384','DHE-RSA-AES128-GCM-SHA256',
'ECDHE-ECDSA-CHACHA20-POLY1305','ECDHE-RSA-CHACHA20-POLY1305','DHE-RSA-CHACHA20-POLY1305'
}

class Auditor:
    def __init__(self, executor, target: Target, current_pg: str='16.15', context: dict|None=None, benchmark: int=16):
        self.ex=executor; self.target=target; self.current_pg=current_pg; self.benchmark=benchmark; self.context=context or {}
        self.policy=self.context.get('policy') or {}
        self._setting_cache={}; self._sql_cache={}; self._shell_cache={}

    def _ev(self, source, detail, command='', rc=None):
        # Calculate hash for discovered paths/files in the evidence detail
        path_hash = ''
        if detail and (source in ('OS','SQL')):
            # Common pattern: find absolute paths in the evidence text
            paths=re.findall(r'(/[^\s|]+)', detail)
            for p in paths:
                if p.endswith('/') or not ('.' in p or 'postgres' in p or 'log' in p or 'conf' in p):continue
                h=self._shell(f"sha256sum {shell_quote(p)} 2>/dev/null | cut -d' ' -f1",5)
                if h.rc==0 and len(h.stdout.strip())==64:
                    path_hash=h.stdout.strip();break
        return Evidence(source, truncate(detail,5000), truncate(command,1000), rc, path_hash=path_hash)

    def _sql(self, sql: str, timeout=20) -> CommandResult:
        if sql not in self._sql_cache:
            self._sql_cache[sql]=self.ex.sql(sql,timeout)
        return self._sql_cache[sql]

    def _shell(self, cmd: str, timeout=20) -> CommandResult:
        if cmd not in self._shell_cache:
            self._shell_cache[cmd]=self.ex.run(cmd,timeout)
        return self._shell_cache[cmd]

    def _setting(self, name: str) -> CommandResult:
        if name not in self._setting_cache:
            self._setting_cache[name]=self._sql(f'SHOW {name};')
        return self._setting_cache[name]

    REVIEW_REQUIRED_INPUT = {
        '1.1': 'Confirm whether each discovered PostgreSQL package repository/mirror is organization-approved. Provide the approved repository name/URL list and, for internal mirrors, the expected package-signing/GPG key fingerprint or other package-provenance trust evidence.',
        '1.2': 'For every optional PostgreSQL package/add-on reported by this check, state whether it is required for the business/application. Provide the approved package name, business purpose/use case, and owner/approver (including documentation, administration, development, debug, or test packages).',
        '4.4': 'For every LOGIN-enabled PostgreSQL role listed in Test Result, provide the account owner, business/application purpose, whether the account is currently active or should be disabled/decommissioned, and any approved expiration/exception.',
        '4.6': 'Provide the approved DML authorization matrix for the reported grants: role/grantee | schema | table | business purpose | required INSERT/UPDATE/DELETE/TRUNCATE privileges. Identify any grant that should be revoked.',
        '4.7': 'Identify the tables/data domains that require Row Level Security (RLS) for this application. For each required table provide the intended protected roles/tenant rule, and list any explicitly approved BYPASSRLS role exceptions.',
        '6.7': 'State the FIPS requirement for this host/workload and whether FIPS mode is mandatory under organization or regulatory policy. If required, provide host-level evidence of OS FIPS mode and the validated cryptographic module/provider; if not required, provide the approved policy/exception stating that FIPS is not mandatory.',
        '4.10': 'For every login-enabled PostgreSQL role reported without a stored password, state the account owner and purpose and whether it authenticates with SSL client certificates (provide certificate/issuer evidence). Roles that do not use certificates require a password.',
    }

    def _review_required_input(self, rule):
        cid=rule.get('id','')
        if cid in self.REVIEW_REQUIRED_INPUT:
            return self.REVIEW_REQUIRED_INPUT[cid]
        if str(cid).startswith('ESA-'):
            return 'Provide the organization policy, business requirement, or external-system evidence needed to decide this enhanced security check.'
        return 'Provide the organization policy/business requirement and the requested evidence needed to decide whether this control is compliant.'

    def _attach_output(self, test_result: str, evidence) -> str:
        # Test Result must carry the real command output, not only our verdict sentence.
        # Evidence rows that are descriptive (no command) or already quoted are skipped.
        for e in evidence or []:
            detail=(e.detail or '').strip()
            if not e.command or not detail:continue
            if detail[:120] and detail[:120] in test_result:continue
            test_result+=f"\n[{e.source}] {truncate(e.command,300)} (rc={e.rc})\n{truncate(detail,900)}"
        return test_result

    def _mk(self, rule, status, test_result, evidence=None, comments=None, solution=None, source='CIS', required_input=None):
        req = required_input if required_input is not None else (self._review_required_input(rule) if status == 'REVIEW' else '')
        return Result(status, f"{rule['id']} {rule['title']}", rule['description'], truncate(self._attach_output(truncate(test_result,4500),evidence or []),6000), solution or rule['solution'], comments or rule['comments'], rule['id'], source, evidence or [], req)

    def _setting_result(self, rule, name, pred: Callable[[str],bool], expected: str, comments=None):
        r=self._setting(name); ev=[self._ev('SQL',r.stdout or r.stderr,f'SHOW {name};',r.rc)]
        if r.rc!=0:
            return self._mk(rule,'ERROR',f"Unable to read {name}: {truncate(r.stderr or r.stdout,800)}",ev)
        v=r.stdout.strip()
        return self._mk(rule,'PASS' if pred(v) else 'FAIL',f"{name} = {v}; expected {expected}",ev,comments)

    def run_cis(self, control_ids: Iterable[str]|None=None, callback=None) -> list[Result]:
        wanted=set(control_ids) if control_ids else None
        catalog=CIS_RULES_BY_MAJOR[self.benchmark]
        selected=[r for r in catalog if not wanted or r['id'] in wanted]
        # A CIS score is only meaningful on the matching PostgreSQL major.  The benchmark
        # itself warns that applying it to a different product version can produce invalid
        # pass/fail results. Discovery and ESA may still run on other majors.
        sv=self._setting('server_version')
        vt=version_tuple(sv.stdout) if sv.rc==0 else ()
        if vt and vt[0] != self.benchmark and not self.context.get('force_cis_major_mismatch', False):
            out=[]
            for rule in selected:
                res=self._mk(rule,'N/A',f"Detected PostgreSQL {sv.stdout.strip()}; CIS PostgreSQL {self.benchmark} benchmark is not scored against a non-{self.benchmark} server. Use PostgreSQL {self.benchmark} or explicitly force compatibility diagnostics.",[self._ev('SQL',sv.stdout,'SHOW server_version;',sv.rc)])
                out.append(res)
                if callback: callback(res,len(out))
            return out
        out=[]
        for rule in selected:
            try: res=self._check_cis(rule)
            except Exception as ex: res=self._mk(rule,'ERROR',f"Internal check error: {ex}")
            out.append(res)
            if callback: callback(res, len(out))
        return out

    def run_esa(self, control_ids: Iterable[str]|None=None, callback=None) -> list[Result]:
        wanted=set(control_ids) if control_ids else None
        out=[]
        for rule in ESA_RULES:
            if wanted and rule['id'] not in wanted: continue
            try: res=self._check_esa(rule)
            except Exception as ex: res=self._mk(rule,'ERROR',f"Internal check error: {ex}",source='ESA')
            out.append(res)
            if callback: callback(res, len(out))
        return out

    # ---- CIS dispatch ----
    def _check_cis(self, rule):
        cid=rule['id']
        fn=getattr(self,'cis_'+cid.replace('.','_'),None)
        if fn: return fn(rule)
        return self._manual_review(rule)

    def _manual_review(self, rule):
        cid=rule['id']; ev=[]; detail='Manual validation required; automated evidence collection was not conclusive.'
        # Add targeted evidence for manual controls so REVIEW is useful rather than empty.
        evidence_sql={
          '1.1':None,'1.2':None,'2.1':None,'2.4':None,'3.1.10':'SHOW syslog_facility;',
          '4.2':None,'4.4':"SELECT rolname,rolcanlogin,rolvaliduntil FROM pg_roles WHERE rolname !~ '^pg_' ORDER BY 1;",
          '4.6':"SELECT grantee,table_schema,table_name,privilege_type FROM information_schema.role_table_grants WHERE table_schema NOT IN ('pg_catalog','information_schema') ORDER BY 1,2,3,4;",
          '4.7':"SELECT n.nspname,c.relname,c.relrowsecurity,c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='r' AND n.nspname NOT IN ('pg_catalog','information_schema') ORDER BY 1,2;",
          '4.9':"SELECT r.rolname, r.rolsuper FROM pg_roles r WHERE r.rolsuper OR r.rolname !~ '^pg_' ORDER BY 1;",
          '5.1':None,'5.2':'SHOW listen_addresses;','5.3':"SELECT type,database,user_name,address,auth_method,error FROM pg_hba_file_rules ORDER BY rule_number;",
          '5.4':"SELECT type,database,user_name,address,auth_method,error FROM pg_hba_file_rules ORDER BY rule_number;",
          '5.6':'SHOW shared_preload_libraries;','6.1':"SELECT name,setting,source,sourcefile,sourceline FROM pg_settings WHERE source <> 'default' ORDER BY name;",
          '6.3':"SELECT name,setting,source FROM pg_settings WHERE context='postmaster' ORDER BY name;",
          '6.4':"SELECT name,setting,source FROM pg_settings WHERE context='sighup' ORDER BY name;",
          '6.5':"SELECT name,setting,source FROM pg_settings WHERE context='superuser' ORDER BY name;",
          '6.6':"SELECT d.datname,r.rolname,s.setconfig FROM pg_db_role_setting s LEFT JOIN pg_database d ON d.oid=s.setdatabase LEFT JOIN pg_roles r ON r.oid=s.setrole ORDER BY 1,2;",
          '6.11':"SELECT name,default_version,installed_version FROM pg_available_extensions WHERE name='pgcrypto';",
          '7.1':"SELECT rolname,rolsuper,rolreplication,rolcanlogin FROM pg_roles WHERE rolreplication ORDER BY 1;",
          '7.2':'SHOW log_replication_commands;','7.3':None,'7.5':"SELECT pid,usename,client_addr,state,sync_state FROM pg_stat_replication ORDER BY pid;",
          '8.1':"SELECT name,setting FROM pg_settings WHERE name ~ '_directory$' OR name ~ '_tablespace' OR name='temp_file_limit' ORDER BY name;",
          '8.3':"SELECT name,setting FROM pg_settings WHERE name IN ('external_pid_file','unix_socket_directories','unix_socket_permissions','shared_preload_libraries','dynamic_library_path','local_preload_libraries','session_preload_libraries') ORDER BY name;",
        }
        sql=evidence_sql.get(cid)
        if sql:
            r=self._sql(sql); ev.append(self._ev('SQL',r.stdout or r.stderr,sql,r.rc)); detail=truncate(r.stdout or r.stderr,3500)
        shell_map={
          '1.1':"(dnf repolist --enabled 2>/dev/null || yum repolist enabled 2>/dev/null || grep -RhsE '^[[:space:]]*deb ' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null) | head -200",
          '1.2':"(rpm -qa 2>/dev/null || dpkg-query -W -f='${binary:Package} ${Version}\\n' 2>/dev/null) | grep -Ei 'postgres|pgadmin|phppgadmin' | head -300",
          '2.1':"(sudo -n -u postgres sh -lc 'umask' 2>/dev/null || su -s /bin/sh postgres -c umask 2>/dev/null || true)",
          '2.4':"find /root /home /etc -type f -name '.pg_service.conf' -o -name 'pg_service.conf' 2>/dev/null | head -100",
          '4.2':"grep -RhsE 'postgres|%dba' /etc/sudoers /etc/sudoers.d 2>/dev/null | head -200",
          '5.1':"ps -eww -o pid,args 2>/dev/null | grep -Ei '[p]sql|[p]ostgres' | head -200",
          '7.3':"(pgbackrest info --output=json 2>/dev/null || pgbackrest info 2>/dev/null || find /var/lib/pgsql /var/lib/postgresql /backup /backups -maxdepth 4 -type f -mtime -30 2>/dev/null | head -100)",
        }
        if cid in shell_map:
            r=self._shell(shell_map[cid],25); ev.append(self._ev('OS',r.stdout or r.stderr,shell_map[cid],r.rc)); detail=truncate(r.stdout or r.stderr,3500) or detail
        return self._mk(rule,'REVIEW',detail,ev)

    # Installation / patches
    def cis_1_1(self,rule):
        # Fully automate when package provenance is machine-readable.  Internal/mirror
        # repositories that cannot be tied to a recognized signed source remain REVIEW.
        pkg=self._shell("(rpm -qa 2>/dev/null | grep -Ei '^postgresql|^postgres' || dpkg-query -W -f='${binary:Package} ${Version}\\n' 2>/dev/null | grep -Ei '^postgres') | head -200",15)
        repo=self._shell("(dnf repolist --enabled -v 2>/dev/null || yum repolist enabled -v 2>/dev/null || grep -RhsE '^[[:space:]]*deb ' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null) | head -400",20)
        ev=[self._ev('OS',pkg.stdout or pkg.stderr,'PostgreSQL package inventory',pkg.rc),self._ev('OS',repo.stdout or repo.stderr,'Enabled repository inventory',repo.rc)]
        if not pkg.stdout:
            # Common for the official container image/source installs: no package-managed
            # PostgreSQL package exists, so this package-repository recommendation is N/A.
            return self._mk(rule,'N/A','No package-managed PostgreSQL installation was detected on this execution target.',ev)
        text=(repo.stdout or '').lower()
        recognized=('apt.postgresql.org','yum.postgresql.org','download.postgresql.org','redhat.com','ubuntu.com','debian.org','rockylinux','almalinux','rhel-','baseos','appstream')
        if any(x in text for x in recognized):
            return self._mk(rule,'PASS','PostgreSQL packages are installed and enabled repository metadata contains a recognized PostgreSQL/vendor/distribution source.\n'+truncate(repo.stdout,2500),ev)
        approved_patterns=[str(x).lower() for x in self.policy.get('approved_repository_patterns',[]) if str(x).strip()]
        if repo.stdout and approved_patterns:
            # Prefer concrete origin/base-URL lines. Repository IDs are labels and may not
            # themselves contain an approved domain even when their base URL is approved.
            concrete=[]; labels=[]
            for line in repo.stdout.splitlines():
                stripped=line.strip(); low=stripped.lower()
                if not low: continue
                if low.startswith('deb ') or re.search(r'(?i)repo[-_ ]?baseurl|from repo', stripped):
                    concrete.append(stripped)
                elif re.search(r'(?i)repo[-_ ]?id|enabled$', stripped):
                    labels.append(stripped)
            source_lines=concrete or labels or [repo.stdout.strip()]
            def approved_line(line):
                low=line.lower()
                return any(x in low for x in recognized) or any((p in low) or fnmatch.fnmatch(low,p) for p in approved_patterns)
            unapproved=[line for line in source_lines if not approved_line(line)]
            return self._mk(rule,'FAIL' if unapproved else 'PASS',('Repository source(s) outside approved_repository_patterns:\n'+'\n'.join(unapproved[:100])) if unapproved else 'All machine-readable repository source lines match built-in trusted sources or policy.approved_repository_patterns.\n'+truncate(repo.stdout,2500),ev)
        if repo.stdout:
            return self._mk(rule,'REVIEW','Package repository metadata was collected but the source is not in the built-in trusted-source recognizer; an organization-approved internal mirror may be legitimate.\n'+truncate(repo.stdout,2500),ev)
        return self._mk(rule,'REVIEW','PostgreSQL packages were detected but package origin/repository metadata could not be determined.',ev)

    def cis_1_2(self,rule):
        cmd="(rpm -qa 2>/dev/null || dpkg-query -W -f='${binary:Package} ${Version}\\n' 2>/dev/null) | grep -Ei 'postgres|pgadmin|phppgadmin' | head -400"
        r=self._shell(cmd,20); ev=[self._ev('OS',r.stdout or r.stderr,cmd,r.rc)]
        if not r.stdout:
            return self._mk(rule,'N/A','No package-managed PostgreSQL/add-on packages were detected on this target.',ev)
        # Only flag packages whose purpose is normally optional/admin/development. Core
        # server/client/libs/contrib packages do not need a human review.
        optional=[]
        for line in r.stdout.splitlines():
            low=line.lower()
            versioned_optional=bool(re.search(r'postgresql\d*[-_](docs?|devel|dev|debug|debuginfo|test)(?:[-_.]|$)',low))
            if versioned_optional or any(x in low for x in ('phppgadmin','pgadmin','postgresql-doc','postgresql-docs','-devel','-dev ','debug','debuginfo')) or re.search(r'(^|[-_])test(s)?($|[-_.])',low):
                optional.append(line)
        if optional:
            if 'required_packages' in self.policy:
                patterns=[str(x).lower() for x in self.policy.get('required_packages',[]) if str(x).strip()]
                def is_required(line):
                    low=line.lower()
                    return any((p in low) or fnmatch.fnmatch(low,p) for p in patterns)
                unauthorized=[line for line in optional if not is_required(line)]
                if unauthorized:
                    return self._mk(rule,'FAIL','Optional/administrative/development PostgreSQL package(s) are not present in policy.required_packages:\n'+'\n'.join(unauthorized[:100]),ev)
                return self._mk(rule,'PASS','All optional PostgreSQL packages detected by the classifier are explicitly approved in policy.required_packages:\n'+'\n'.join(optional[:100]),ev)
            return self._mk(rule,'REVIEW','Optional/administrative/development PostgreSQL packages detected; business necessity cannot be inferred safely without an approved package/build allowlist:\n'+'\n'.join(optional[:100]),ev)
        return self._mk(rule,'PASS','Only core PostgreSQL-related packages were detected by the built-in package classifier.\n'+truncate(r.stdout,2500),ev)

    def cis_1_3(self,rule):
        if self.target.container_id: return self._mk(rule,'N/A','systemd service enablement is a host control; target is a container.')
        sysd=self._shell("command -v systemctl >/dev/null 2>&1 && [ \"$(ps -p 1 -o comm= 2>/dev/null)\" = systemd ]",5)
        if sysd.rc!=0:return self._mk(rule,'N/A','systemd is not the active init/service manager on this target.')
        r=self._shell("systemctl list-unit-files --no-legend 2>/dev/null | grep -Ei '^postgres.*service'",10); ev=[self._ev('OS',r.stdout or r.stderr,'systemctl list-unit-files',r.rc)]
        if r.rc!=0 or not r.stdout:return self._mk(rule,'FAIL','systemd is active but no PostgreSQL systemd service unit was detected.',ev)
        lines=r.stdout.splitlines(); enabled=[x for x in lines if re.search(r'\benabled\b',x)]
        return self._mk(rule,'PASS' if enabled else 'FAIL',f"Detected services: {len(lines)}; enabled: {len(enabled)}\n"+truncate(r.stdout,1800),ev)
    def cis_1_4(self,rule):
        rd=self._sql('SHOW data_directory;'); ev=[self._ev('SQL',rd.stdout or rd.stderr,'SHOW data_directory;',rd.rc)]
        pgdata=rd.stdout.strip() if rd.rc==0 else self.context.get('postgres',{}).get('pgdata','')
        if not pgdata:return self._mk(rule,'ERROR','Unable to determine PGDATA.',ev)
        cmd=f"stat -c '%U:%G %a %F' {shell_quote(pgdata)} 2>/dev/null; test -f {shell_quote(pgdata+'/PG_VERSION')}"
        r=self._shell(cmd,10);ev.append(self._ev('OS',r.stdout or r.stderr,cmd,r.rc))
        if r.rc!=0:return self._mk(rule,'FAIL',f"PGDATA={pgdata}; PG_VERSION or directory validation failed.",ev)
        mode_m=re.search(r'\b(\d{3,4})\b',r.stdout); mode=mode_m.group(1)[-3:] if mode_m else ''
        okay=mode in {'700','750'} or (mode and int(mode,8)&0o007==0)
        return self._mk(rule,'PASS' if okay else 'FAIL',f"PGDATA={pgdata}; stat={r.stdout}",ev)
    def cis_1_5(self,rule):
        r=self._setting('server_version'); ev=[self._ev('SQL',r.stdout or r.stderr,'SHOW server_version;',r.rc)]
        if r.rc!=0:return self._mk(rule,'ERROR','Unable to determine running PostgreSQL version.',ev)
        v=r.stdout.strip(); cur=self.current_pg
        major=version_tuple(v)[:1]
        if major!=(self.benchmark,):return self._mk(rule,'N/A',f"Detected PostgreSQL {v}; this benchmark implementation is for PostgreSQL {self.benchmark}. Current bundled PG{self.benchmark} minor={cur}.",ev)
        return self._mk(rule,'PASS' if version_tuple(v)>=version_tuple(cur) else 'FAIL',f"Installed={v}; current PostgreSQL {self.benchmark} minor={cur}",ev)
    def cis_1_6(self,rule):
        cmd="grep -RsnI --exclude='*.swp' --exclude='*.bak' 'PGPASSWORD' /root/.profile /root/.bashrc /root/.bash_profile /home/*/.profile /home/*/.bashrc /home/*/.bash_profile /home/*/.zshrc /etc/environment 2>/dev/null | head -100"
        r=self._shell(cmd,15);ev=[self._ev('OS',r.stdout or r.stderr,cmd,r.rc)]
        return self._mk(rule,'FAIL' if r.stdout else 'PASS',r.stdout or 'No persistent PGPASSWORD assignment found in searched profiles.',ev)
    def cis_1_7(self,rule):
        cmd="for f in /proc/[0-9]*/environ; do tr '\\0' '\\n' < \"$f\" 2>/dev/null | grep -H '^PGPASSWORD=' /dev/stdin && echo \"process=$f\"; done | head -100"
        r=self._shell(cmd,15);ev=[self._ev('OS',r.stdout or r.stderr,cmd,r.rc)]
        return self._mk(rule,'FAIL' if 'PGPASSWORD=' in r.stdout else 'PASS',('PGPASSWORD detected in process environment(s).' if 'PGPASSWORD=' in r.stdout else 'No active PGPASSWORD variable found in readable process environments.'),ev)

    # file permissions
    def cis_2_1(self,rule):
        # Prefer the effective umask of the live postgres postmaster from /proc. This is
        # stronger than merely reading a shell profile and works well in containers.
        processes=(self.context.get('postgres') or {}).get('processes','')
        m=re.search(r'^\s*(\d+)\s+.*(?:postgres|postmaster)',processes,re.M)
        pid=m.group(1) if m else ''
        cmds=[]
        if pid:
            cmds.append(f"grep -E '^Umask:' /proc/{pid}/status 2>/dev/null")
        cmds += [
            "pid=$(pgrep -xo postgres 2>/dev/null || pgrep -xo postmaster 2>/dev/null); [ -n \"$pid\" ] && grep -E '^Umask:' /proc/$pid/status 2>/dev/null",
            "sudo -n -u postgres sh -lc 'umask' 2>/dev/null || runuser -u postgres -- sh -lc 'umask' 2>/dev/null || su -s /bin/sh postgres -c umask 2>/dev/null",
        ]
        out=None; used=''
        for cmd in cmds:
            rr=self._shell(cmd,10)
            if rr.rc==0 and rr.stdout.strip(): out=rr;used=cmd;break
        ev=[self._ev('OS',(out.stdout if out else ''),(used or 'effective postgres umask'),out.rc if out else None)]
        if not out:
            return self._mk(rule,'ERROR','Unable to determine the effective postgres process/user umask.',ev)
        mm=re.search(r'(?i)(?:Umask:\s*)?([0-7]{3,4})',out.stdout)
        if not mm:return self._mk(rule,'ERROR',f"Unable to parse postgres umask from: {out.stdout}",ev)
        raw=mm.group(1); val=int(raw,8)
        # CIS requires 0077 or more restrictive. Group and other bits must all be masked.
        ok=(val & 0o077) == 0o077
        return self._mk(rule,'PASS' if ok else 'FAIL',f"effective postgres umask={raw}; expected 0077 or more restrictive",ev)

    def cis_2_2(self,rule):
        cmd="d=$(pg_config --sharedir 2>/dev/null)/extension; test -d \"$d\" && stat -c '%U:%G %a %n' \"$d\""
        r=self._shell(cmd,10);ev=[self._ev('OS',r.stdout or r.stderr,cmd,r.rc)]
        if r.rc!=0:return self._mk(rule,'ERROR','Unable to determine/stat extension directory.',ev)
        m=re.search(r'^(\S+):(\S+)\s+(\d+)\s+',r.stdout)
        ok=bool(m and m.group(1)=='root' and m.group(2)=='root' and m.group(3) in {'755','0755'})
        return self._mk(rule,'PASS' if ok else 'FAIL',r.stdout,ev)
    def cis_2_3(self,rule):
        cmd="find /root /home -xdev -name '.psql_history' -printf '%p -> %l\\n' 2>/dev/null | head -200"
        r=self._shell(cmd,15);ev=[self._ev('OS',r.stdout or r.stderr,cmd,r.rc)]
        bad=[]
        for line in r.stdout.splitlines():
            if '-> /dev/null' not in line:bad.append(line)
        return self._mk(rule,'FAIL' if bad else 'PASS',('\n'.join(bad) if bad else 'No active .psql_history files found; any discovered history links point to /dev/null.'),ev)

    def cis_2_4(self,rule):
        # Values are never returned: only file:line and the key name are emitted.
        cmd=("files=\"\"; [ -n \"$PGSERVICEFILE\" ] && files=\"$files $PGSERVICEFILE\"; "
             "[ -n \"$PGSYSCONFDIR\" ] && files=\"$files $PGSYSCONFDIR/pg_service.conf\"; "
             "files=\"$files /etc/pg_service.conf /etc/postgresql-common/pg_service.conf\"; "
             "for f in /root/.pg_service.conf /home/*/.pg_service.conf $files; do [ -f \"$f\" ] || continue; "
             "awk -F= '/^[[:space:]]*password[[:space:]]*=/{print FILENAME \":\" FNR \":password=<redacted>\"}' \"$f\"; done | head -200")
        r=self._shell(cmd,20);ev=[self._ev('OS',r.stdout or r.stderr,'Search PostgreSQL service files for password= entries (values redacted)',r.rc)]
        if r.rc not in (0,1):return self._mk(rule,'ERROR','Unable to inspect PostgreSQL service files.',ev)
        return self._mk(rule,'FAIL' if r.stdout else 'PASS',r.stdout or 'No password= entries found in discovered PostgreSQL connection service files.',ev)

    # logging settings
    def cis_3_1_2(self,r):return self._setting_result(r,'log_destination',lambda v:any(x.strip() in {'stderr','csvlog','syslog','jsonlog'} for x in v.split(',')),'a supported organization-approved destination')
    def cis_3_1_3(self,r):return self._setting_result(r,'logging_collector',bool_on,'on')
    def cis_3_1_4(self,r):return self._setting_result(r,'log_directory',lambda v:bool(v.strip()) and v.strip()!='/','non-empty protected log directory')
    def cis_3_1_5(self,r):return self._setting_result(r,'log_filename',lambda v:bool(v.strip()) and ('%' in v or v.endswith('.log')),'rotation-friendly log filename')
    def cis_3_1_6(self,r):return self._setting_result(r,'log_file_mode',lambda v:v.strip() in {'0600','600','0640','640'},'0600 (or policy-approved 0640)')
    def cis_3_1_7(self,r):return self._setting_result(r,'log_truncate_on_rotation',bool_on,'on')
    def cis_3_1_8(self,rule):
        r=self._setting('log_rotation_age');ev=[self._ev('SQL',r.stdout or r.stderr,'SHOW log_rotation_age;',r.rc)]
        if r.rc:return self._mk(rule,'ERROR','Unable to read log_rotation_age.',ev)
        v=r.stdout.strip().lower(); minutes=None
        try:
            if v.endswith('min'):minutes=float(v[:-3].strip())
            elif v.endswith('h'):minutes=float(v[:-1])*60
            elif v.endswith('d'):minutes=float(v[:-1])*1440
            elif v.isdigit():minutes=float(v)
        except:pass
        ok=minutes is not None and 0<minutes<=1440
        return self._mk(rule,'PASS' if ok else 'FAIL',f"log_rotation_age={v}; expected >0 and <=1d",ev)
    def cis_3_1_9(self,rule):
        r=self._setting('log_rotation_size');ev=[self._ev('SQL',r.stdout or r.stderr,'SHOW log_rotation_size;',r.rc)]
        if r.rc:return self._mk(rule,'ERROR','Unable to read log_rotation_size.',ev)
        v=r.stdout.strip().lower();zero=v in {'0','0kb','0mb','0gb','0 b','0kb'}
        return self._mk(rule,'FAIL' if zero else 'PASS',f"log_rotation_size={v}",ev)
    def cis_3_1_10(self,rule):
        ld=self._setting('log_destination');sf=self._setting('syslog_facility');ev=[self._ev('SQL',ld.stdout or ld.stderr,'SHOW log_destination;',ld.rc),self._ev('SQL',sf.stdout or sf.stderr,'SHOW syslog_facility;',sf.rc)]
        if ld.rc or sf.rc:return self._mk(rule,'ERROR','Unable to read syslog settings.',ev)
        if 'syslog' not in ld.stdout:return self._mk(rule,'N/A',f"log_destination={ld.stdout.strip()}; syslog not active.",ev)
        allowed=set(str(x).lower() for x in self.policy.get('syslog_facilities',[])) or {f'local{i}' for i in range(8)}
        ok=sf.stdout.strip().lower() in allowed
        return self._mk(rule,'PASS' if ok else 'FAIL',f"syslog_facility={sf.stdout.strip()}; allowed={','.join(sorted(allowed))}",ev)
    def cis_3_1_11(self,r):return self._setting_result(r,'syslog_sequence_numbers',bool_on,'on')
    def cis_3_1_12(self,r):return self._setting_result(r,'syslog_split_messages',bool_on,'on')
    def cis_3_1_13(self,r):return self._setting_result(r,'syslog_ident',lambda v:bool(v.strip()),'non-empty unique identifier')
    def _level_at_least(self,v,threshold):
        try:return LOG_LEVELS.index(v.strip().lower())<=LOG_LEVELS.index(threshold)
        except:return False
    def cis_3_1_14(self,r):return self._setting_result(r,'log_min_messages',lambda v:self._level_at_least(v,'warning'),'WARNING or more verbose')
    def cis_3_1_15(self,r):return self._setting_result(r,'log_min_error_statement',lambda v:self._level_at_least(v,'error'),'ERROR or more verbose')
    def cis_3_1_16(self,r):return self._setting_result(r,'debug_print_parse',bool_off,'off')
    def cis_3_1_17(self,r):return self._setting_result(r,'debug_print_rewritten',bool_off,'off')
    def cis_3_1_18(self,r):return self._setting_result(r,'debug_print_plan',bool_off,'off')
    def cis_3_1_19(self,r):return self._setting_result(r,'debug_pretty_print',bool_on,'on')
    def cis_3_1_20(self,r):return self._setting_result(r,'log_connections',bool_on,'on')
    def cis_3_1_21(self,r):return self._setting_result(r,'log_disconnections',bool_on,'on')
    def cis_3_1_22(self,r):return self._setting_result(r,'log_error_verbosity',lambda v:v.strip().lower()=='verbose','VERBOSE')
    def cis_3_1_23(self,r):return self._setting_result(r,'log_hostname',bool_off,'off')
    def cis_3_1_24(self,rule):
        p=self._setting('log_line_prefix');ld=self._setting('log_destination');ev=[self._ev('SQL',p.stdout or p.stderr,'SHOW log_line_prefix;',p.rc)]
        if p.rc:return self._mk(rule,'ERROR','Unable to read log_line_prefix.',ev)
        val=p.stdout.strip();req=['%u','%d','%a','%h'] if (ld.rc==0 and 'syslog' in ld.stdout) else ['%m','%p','%l','%d','%u','%a','%h']
        missing=[x for x in req if x not in val]
        return self._mk(rule,'PASS' if not missing else 'FAIL',f"log_line_prefix={val}; missing={','.join(missing) or 'none'}",ev)
    def cis_3_1_25(self,r):return self._setting_result(r,'log_statement',lambda v:v.strip().lower() in {'ddl','mod','all'},'ddl/mod/all (benchmark recommends ddl)')
    def cis_3_1_26(self,r):return self._setting_result(r,'log_timezone',lambda v:v.strip().upper() in {'UTC','GMT','ETC/UTC'},'UTC or GMT')
    def cis_3_2(self,rule):
        a=self._setting('shared_preload_libraries');b=self._setting('pgaudit.log');ev=[self._ev('SQL',a.stdout or a.stderr,'SHOW shared_preload_libraries;',a.rc),self._ev('SQL',b.stdout or b.stderr,'SHOW pgaudit.log;',b.rc)]
        ok=a.rc==0 and re.search(r'(^|,)\s*pgaudit\s*(,|$)',a.stdout,re.I) and b.rc==0 and bool(b.stdout.strip())
        return self._mk(rule,'PASS' if ok else 'FAIL',f"shared_preload_libraries={a.stdout.strip() if a.rc==0 else '<error>'}; pgaudit.log={b.stdout.strip() if b.rc==0 else '<unavailable>'}",ev)

    # authorization
    def cis_4_1(self,rule):
        cmd="(getent shadow postgres 2>/dev/null || sudo -n getent shadow postgres 2>/dev/null) | cut -d: -f1-2; getent passwd postgres 2>/dev/null | cut -d: -f1,7; (passwd -S postgres 2>/dev/null || sudo -n passwd -S postgres 2>/dev/null) | head -1"
        r=self._shell(cmd,10);ev=[self._ev('OS',r.stdout or r.stderr,cmd,r.rc)]
        if not r.stdout:
            if self.target.container_id:
                sshd=self._shell("pgrep -x sshd >/dev/null 2>&1",5);ev.append(self._ev('OS',sshd.stdout or sshd.stderr,'sshd process check',sshd.rc))
                if sshd.rc!=0:return self._mk(rule,'N/A','postgres OS account lock state is not readable and the selected container does not run sshd; no interactive OS login service is exposed inside this container.',ev)
            return self._mk(rule,'ERROR','postgres OS account not visible or insufficient privilege to inspect lock state.',ev)
        lines=r.stdout.splitlines(); locked=False
        for line in lines:
            if line.startswith('postgres:') and ':' in line and line.split(':',1)[1].startswith(('!','*')):locked=True
            if re.match(r'^postgres\s+[L!]',line):locked=True
        return self._mk(rule,'PASS' if locked else 'FAIL',r.stdout,ev)
    def cis_4_2(self,rule):
        if self.target.container_id:
            return self._mk(rule,'N/A','sudo configuration is a host administrative-access control; the selected target is a container.')
        has_sudo=self._shell('command -v sudo >/dev/null 2>&1',5)
        if has_sudo.rc!=0:return self._mk(rule,'N/A','sudo is not installed on this host; this sudo-specific recommendation is not applicable to the detected administration model.')
        cmd=r"stat -c '%a %U:%G %n' /etc/sudoers /etc/sudoers.d 2>/dev/null; grep -RhsE '^[[:space:]]*[^#].*\(postgres\)' /etc/sudoers /etc/sudoers.d 2>/dev/null | head -200"
        r=self._shell(cmd,15);ev=[self._ev('OS',r.stdout or r.stderr,cmd,r.rc)]
        if r.rc not in (0,1):return self._mk(rule,'ERROR','Unable to inspect sudo configuration.',ev)
        lines=r.stdout.splitlines(); rules=[x for x in lines if '(postgres)' in x]
        unsafe=[x for x in rules if re.search(r'(?i)NOPASSWD|ALL\s*=\s*\(ALL(:ALL)?\)',x)]
        if unsafe:return self._mk(rule,'FAIL','Unsafe PostgreSQL sudo escalation rule(s):\n'+'\n'.join(unsafe),ev)
        if rules:return self._mk(rule,'PASS','Restricted sudo-to-postgres rule(s) found; no broad/NOPASSWD pattern detected:\n'+'\n'.join(rules),ev)
        return self._mk(rule,'FAIL','sudo is installed but no explicit restricted sudo-to-postgres rule was discovered.',ev)
    def cis_4_3(self,rule):
        sql="SELECT rolname,rolsuper,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls,rolcanlogin FROM pg_roles WHERE rolname !~ '^pg_' ORDER BY rolname;"
        r=self._sql(sql);ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc)]
        if r.rc:return self._mk(rule,'ERROR','Unable to inventory role attributes.',ev)
        elevated=[]
        for line in r.stdout.splitlines():
            p=line.split('|')
            if len(p)<7 or p[0]=='postgres':continue
            # A dedicated replication-only login role is expected by CIS 7.1 and is not
            # treated as excessive administration here. All other broad attributes fail.
            super_,createrole,createdb,repl,bypass,canlogin=p[1:7]
            replication_only=(repl=='t' and super_=='f' and createrole=='f' and createdb=='f' and bypass=='f')
            if not replication_only and any(x=='t' for x in (super_,createrole,createdb,repl,bypass)):
                elevated.append(line)
        return self._mk(rule,'FAIL' if elevated else 'PASS',('Excessive non-postgres administrative attributes detected:\n'+'\n'.join(elevated)) if elevated else 'No non-postgres role with excessive administrative attributes detected (dedicated replication-only roles are allowed).',ev)
    def cis_4_4(self,rule):
        sql="SELECT rolname,rolvaliduntil FROM pg_authid WHERE rolcanlogin AND rolname !~ '^pg_' ORDER BY 1;"
        r=self._sql(sql);ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc)]
        if r.rc:return self._mk(rule,'ERROR','Unable to inspect login-role validity.',ev)
        if not r.stdout.strip():return self._mk(rule,'PASS','No non-system LOGIN roles were returned by pg_authid.',ev)
        active_allow=set(self.policy.get('active_login_roles',[]))
        expired=[];unknown=[]
        now=time.time()
        for line in r.stdout.splitlines():
            role,_,until=line.partition('|')
            if active_allow and role not in active_allow:unknown.append(role)
            if until.strip():
                chk=self._sql("SELECT CASE WHEN %s::timestamptz < now() THEN 'expired' ELSE 'valid' END;" % shell_quote(until.strip()))
                if chk.rc==0 and chk.stdout.strip()=='expired':expired.append(role)
        if expired:return self._mk(rule,'FAIL','Expired-but-login-enabled role(s): '+', '.join(expired),ev)
        if active_allow and unknown:return self._mk(rule,'FAIL','Login-enabled role(s) not present in configured active_login_roles policy: '+', '.join(unknown),ev)
        if active_allow:return self._mk(rule,'PASS','All login-enabled roles are permitted by active_login_roles policy and none are expired.',ev)
        # PostgreSQL does not store a universal last-login timestamp. Keep REVIEW only for
        # the genuinely business-dependent question of whether a valid account is still used.
        return self._mk(rule,'REVIEW',f"Login-enabled roles={len(r.stdout.splitlines())}; none are provably expired. Supply active_login_roles in --policy to make this PASS/FAIL automatically.\n{truncate(r.stdout,2500)}",ev)
    def cis_4_5(self,rule):
        sql="""SELECT n.nspname||'.'||p.proname, r.rolname, p.prosecdef, COALESCE(array_to_string(p.proconfig,','),''), has_function_privilege('public',p.oid,'EXECUTE') FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog','information_schema') ORDER BY 1;"""
        r=self._sql(sql);ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc)]
        if r.rc:return self._mk(rule,'ERROR','Unable to inspect SECURITY DEFINER functions.',ev)
        bad=[l for l in r.stdout.splitlines() if l.rstrip().endswith('|t')]
        return self._mk(rule,'FAIL' if bad else 'PASS',('SECURITY DEFINER functions executable by PUBLIC:\n'+'\n'.join(bad)) if bad else (r.stdout or 'No user SECURITY DEFINER functions found.'),ev)
    def cis_4_6(self,rule):
        sql="SELECT grantee,table_schema,table_name,privilege_type FROM information_schema.role_table_grants WHERE table_schema NOT IN ('pg_catalog','information_schema') AND privilege_type IN ('INSERT','UPDATE','DELETE','TRUNCATE') ORDER BY 1,2,3,4;"
        r=self._sql(sql);ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc)]
        if r.rc:return self._mk(rule,'ERROR','Unable to inventory table DML grants.',ev)
        lines=[x for x in r.stdout.splitlines() if x.strip()]
        public=[x for x in lines if x.split('|',1)[0].upper()=='PUBLIC']
        if public:return self._mk(rule,'FAIL','Write/DML privilege granted to PUBLIC:\n'+'\n'.join(public[:100]),ev)
        allowed=set(self.policy.get('dml_allowlist',[]))
        if allowed:
            extra=[]
            for x in lines:
                p=x.split('|')
                key='|'.join(p[:4]) if len(p)>=4 else x
                if key not in allowed:extra.append(key)
            return self._mk(rule,'FAIL' if extra else 'PASS',('DML grants outside dml_allowlist:\n'+'\n'.join(extra[:100])) if extra else 'All discovered DML grants match dml_allowlist policy.',ev)
        if not lines:return self._mk(rule,'PASS','No explicit non-system INSERT/UPDATE/DELETE/TRUNCATE role grants detected.',ev)
        return self._mk(rule,'REVIEW','Explicit application DML grants exist and no dml_allowlist policy was supplied; business authorization is the only remaining manual decision.\n'+truncate(r.stdout,3000),ev)
    def cis_4_7(self,rule):
        sql="SELECT n.nspname||'.'||c.relname,c.relrowsecurity,c.relforcerowsecurity,(SELECT count(*) FROM pg_policy p WHERE p.polrelid=c.oid) policies FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='r' AND n.nspname NOT IN ('pg_catalog','information_schema') ORDER BY 1;"
        r=self._sql(sql);b=self._sql("SELECT rolname FROM pg_roles WHERE rolbypassrls AND rolname <> 'postgres' ORDER BY 1;");ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc),self._ev('SQL',b.stdout or b.stderr,'BYPASSRLS role inventory',b.rc)]
        if r.rc:return self._mk(rule,'ERROR','Unable to inspect RLS state.',ev)
        rows=[x for x in r.stdout.splitlines() if x.strip()]
        if not rows:return self._mk(rule,'N/A','No user tables were detected; no RLS applicability to assess.',ev)
        allow_bypass=set(self.policy.get('allow_bypassrls_roles',[]))
        bad_bypass=[x for x in b.stdout.splitlines() if x and x not in allow_bypass] if b.rc==0 else []
        broken=[]
        for x in rows:
            p=x.split('|')
            if len(p)>=4 and p[1]=='t' and int(p[3] or 0)==0:broken.append(x)
        if bad_bypass or broken:return self._mk(rule,'FAIL',f"unauthorized BYPASSRLS={bad_bypass or 'none'}; RLS-enabled tables without policies={broken or 'none'}",ev)
        required=set(self.policy.get('rls_required_tables',[]))
        if required:
            state={x.split('|')[0]:x.split('|')[1:] for x in rows}
            missing=[t for t in sorted(required) if t not in state or state[t][0]!='t' or int(state[t][2] or 0)==0]
            return self._mk(rule,'FAIL' if missing else 'PASS',f"rls_required_tables={sorted(required)}; missing_or_unprotected={missing or 'none'}",ev)
        protected=[x for x in rows if '|t|' in x]
        if protected:return self._mk(rule,'PASS',f"RLS is enabled with policies on {len(protected)} table(s); no unauthorized BYPASSRLS role detected.\n"+truncate('\n'.join(protected),2500),ev)
        return self._mk(rule,'REVIEW',f"{len(rows)} user table(s) exist but no rls_required_tables policy was supplied. Which tables require RLS is explicitly business-specific in CIS.",ev)
    def cis_4_8(self,rule):
        sql="SELECT default_version,installed_version FROM pg_available_extensions WHERE name='set_user';"
        r=self._sql(sql);pre=self._setting('shared_preload_libraries');ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc),self._ev('SQL',pre.stdout or pre.stderr,'SHOW shared_preload_libraries;',pre.rc)]
        installed=bool(r.rc==0 and r.stdout and len(r.stdout.split('|'))>1 and r.stdout.split('|')[1].strip())
        preload=pre.rc==0 and 'set_user' in pre.stdout
        return self._mk(rule,'PASS' if installed and preload else 'FAIL',f"extension={r.stdout.strip() or '<not available>'}; preload={'yes' if preload else 'no'}",ev)
    def cis_4_9(self,rule):
        sql="SELECT rolname FROM pg_roles WHERE rolsuper ORDER BY 1;"
        r=self._sql(sql);ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc)]
        if r.rc:return self._mk(rule,'ERROR','Unable to inspect superuser roles.',ev)
        supers=[x.strip() for x in r.stdout.splitlines() if x.strip()]
        allowed=set(self.policy.get('allowed_superusers',['postgres']))
        extra=[x for x in supers if x not in allowed]
        if extra:return self._mk(rule,'FAIL','Unexpected superuser role(s) detected; reduce to predefined roles where possible or explicitly allow them in policy.allowed_superusers: '+', '.join(extra),ev)
        return self._mk(rule,'PASS',f"Superuser roles={supers or 'none'}; no unexpected superuser beyond allowed_superusers={sorted(allowed)}.",ev)
    def cis_4_10(self,rule):
        # CIS 18 4.10: a NULL password verifier means the role can never password-authenticate;
        # any interactive use therefore implies certificate/external auth.  Instead of failing
        # every passwordless role outright, policy.cert_login_roles declares the roles that are
        # known to authenticate with SSL client certificates.
        base="SELECT rolname FROM pg_authid WHERE rolpassword IS NULL AND rolcanlogin AND rolname NOT LIKE 'pg_%' ORDER BY 1;"
        inv="SELECT rolname,CASE WHEN rolpassword IS NULL THEN 'NONE' WHEN rolpassword LIKE 'SCRAM-SHA-256$%' THEN 'SCRAM-SHA-256' WHEN rolpassword LIKE 'md5%' THEN 'MD5' ELSE 'OTHER' END FROM pg_authid WHERE rolcanlogin AND rolname NOT LIKE 'pg_%' ORDER BY 1;"
        r=self._sql(base);i=self._sql(inv);ev=[self._ev('SQL',r.stdout or r.stderr,base,r.rc),self._ev('SQL',i.stdout or i.stderr,'Login-role password-verifier inventory',i.rc)]
        if r.rc:return self._mk(rule,'ERROR','pg_authid requires elevated database privilege; login roles without a stored password could not be audited.',ev)
        nopw=[x.strip() for x in r.stdout.splitlines() if x.strip()]
        cert=set(self.policy.get('cert_login_roles',[]))
        unprotected=[x for x in nopw if x not in cert]
        if unprotected:return self._mk(rule,'FAIL','Login role(s) with no stored password and no certificate-auth policy exception: '+', '.join(unprotected),ev)
        if nopw:return self._mk(rule,'PASS','Login role(s) without a stored password are covered by policy.cert_login_roles (certificate-based authentication): '+', '.join(sorted(nopw)),ev)
        return self._mk(rule,'PASS','Every non-system login-enabled role has a stored password verifier.',ev)

    # connection/login
    def cis_5_1(self,rule):
        cmd="ps -eww -o pid,args 2>/dev/null | grep -E '[p]sql|[p]g_dump|[p]g_basebackup' | head -300"
        r=self._shell(cmd,12);ev=[self._ev('OS',r.stdout or r.stderr,cmd,r.rc)]
        bad=[]
        for line in r.stdout.splitlines():
            if re.search(r'postgres(?:ql)?://[^\s:]+:[^@\s]+@|\bpassword=[^\s]+',line,re.I):bad.append(line)
        return self._mk(rule,'FAIL' if bad else 'PASS',('Potential command-line credentials detected (redacted in evidence).') if bad else 'No obvious PostgreSQL passwords detected in current process arguments.',ev)
    def cis_5_2(self,rule):
        return self._setting_result(rule,'listen_addresses',lambda v:v.strip() not in {'*','0.0.0.0','::','0.0.0.0,::'},'specific required address(es), not wildcard')
    def cis_5_3(self,rule):
        sql="SELECT type,database,user_name,address,auth_method,error FROM pg_hba_file_rules ORDER BY rule_number;"
        r=self._sql(sql);ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc)]
        if r.rc:return self._mk(rule,'ERROR','pg_hba_file_rules unavailable; unable to validate local authentication rules.',ev)
        local=[x for x in r.stdout.splitlines() if x.startswith('local|')]
        bad=[x for x in local if re.search(r'\|(trust|password|md5|ident)\|',x,re.I)]
        peers=[x for x in local if '|peer|' in x.lower()]
        status='FAIL' if bad or (local and not peers) else ('PASS' if peers else 'N/A')
        return self._mk(rule,status,f"local rules={len(local)}, peer={len(peers)}, insecure={len(bad)}\n"+'\n'.join(local[:50]),ev)
    def cis_5_4(self,rule):
        sql="SELECT type,database,user_name,address,auth_method,error FROM pg_hba_file_rules ORDER BY rule_number;"
        r=self._sql(sql);ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc)]
        if r.rc:return self._mk(rule,'ERROR','pg_hba_file_rules unavailable; unable to validate host authentication rules.',ev)
        hosts=[x for x in r.stdout.splitlines() if x.startswith(('host|','hostssl|','hostnossl|'))]
        bad=[x for x in hosts if re.search(r'\|(trust|password|ident|md5)\|',x,re.I) or x.startswith('hostnossl|')]
        review=[x for x in hosts if re.search(r'\|(pam|ldap|radius|gss|sspi)\|',x,re.I)]
        status='FAIL' if bad else ('PASS' if hosts else 'N/A')
        return self._mk(rule,status,f"host rules={len(hosts)}, insecure={len(bad)}, external-auth-methods={len(review)} (external providers are outside this CIS audit's authentication-provider validation)\n"+'\n'.join(hosts[:80]),ev)
    def cis_5_5(self,rule):
        sql="SELECT rolname,rolconnlimit FROM pg_roles WHERE rolcanlogin AND rolname NOT LIKE 'pg_%' ORDER BY rolname;"
        r=self._sql(sql);ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc)]
        if r.rc:return self._mk(rule,'ERROR','Unable to read role connection limits.',ev)
        bad=[l for l in r.stdout.splitlines() if l.endswith('|-1')]
        return self._mk(rule,'FAIL' if bad else 'PASS',('Unlimited login roles:\n'+'\n'.join(bad)) if bad else (r.stdout or 'No login roles found.'),ev)
    def cis_5_6(self,rule):
        p=self._setting('shared_preload_libraries');d=self._setting('dynamic_library_path');ev=[self._ev('SQL',p.stdout or p.stderr,'SHOW shared_preload_libraries;',p.rc),self._ev('SQL',d.stdout or d.stderr,'SHOW dynamic_library_path;',d.rc)]
        if p.rc:return self._mk(rule,'ERROR','Unable to read preload settings.',ev)
        ok='passwordcheck' in p.stdout
        return self._mk(rule,'PASS' if ok else 'FAIL',f"shared_preload_libraries={p.stdout.strip()}; dynamic_library_path={d.stdout.strip() if d.rc==0 else '<unknown>'}",ev)

    # runtime settings
    def _settings_integrity(self, rule, context_name: str, dangerous: dict[str,set[str]]|None=None):
        sql=f"SELECT name,setting,source,COALESCE(sourcefile,''),COALESCE(sourceline,0),pending_restart FROM pg_settings WHERE context='{context_name}' ORDER BY name;"
        r=self._sql(sql)
        errs=self._sql("SELECT sourcefile,sourceline,name,setting,error FROM pg_file_settings WHERE error IS NOT NULL ORDER BY sourcefile,sourceline;")
        ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc),self._ev('SQL',errs.stdout or errs.stderr,'pg_file_settings parse-error inventory',errs.rc)]
        if r.rc:return self._mk(rule,'ERROR',f"Unable to inventory {context_name} runtime parameters.",ev)
        bad=[]
        dangerous=dangerous or {}
        for line in r.stdout.splitlines():
            p=line.split('|')
            if len(p)>=2 and p[0] in dangerous and p[1].lower() in dangerous[p[0]]:bad.append(f"{p[0]}={p[1]}")
        if errs.rc==0 and errs.stdout.strip():bad.append('configuration-file parse errors are present')
        return self._mk(rule,'FAIL' if bad else 'PASS',f"context={context_name}; settings={len(r.stdout.splitlines())}; technical integrity findings={bad or 'none'}"+("\n"+truncate(r.stdout,3000) if not bad else ''),ev)

    def cis_6_1(self,rule):
        # Automates the attack-vector review by checking configuration parser health,
        # non-default sources and known integrity-bypass settings rather than returning an
        # unconditional manual REVIEW.
        sql="SELECT name,setting,context,source,COALESCE(sourcefile,'') FROM pg_settings WHERE source <> 'default' ORDER BY name;"
        r=self._sql(sql);errs=self._sql("SELECT sourcefile,sourceline,name,error FROM pg_file_settings WHERE error IS NOT NULL ORDER BY 1,2;")
        ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc),self._ev('SQL',errs.stdout or errs.stderr,'pg_file_settings error inventory',errs.rc)]
        if r.rc:return self._mk(rule,'ERROR','Unable to review runtime parameter sources.',ev)
        danger=self._sql("SELECT name,setting FROM pg_settings WHERE (name IN ('allow_system_table_mods','ignore_checksum_failure','zero_damaged_pages') AND setting='on') OR (name IN ('debug_print_parse','debug_print_plan','debug_print_rewritten') AND setting='on') ORDER BY name;")
        ev.append(self._ev('SQL',danger.stdout or danger.stderr,'Known dangerous runtime-setting inventory',danger.rc))
        bad=[]
        if errs.rc==0 and errs.stdout.strip():bad.append('configuration parse errors')
        if danger.rc==0 and danger.stdout.strip():bad.append('known dangerous settings: '+danger.stdout.replace('\n',', '))
        return self._mk(rule,'FAIL' if bad else 'PASS',f"non-default settings={len(r.stdout.splitlines())}; findings={bad or 'none'}",ev)

    def cis_6_2(self,rule):
        names=['ignore_system_indexes','jit_debugging_support','jit_profiling_support','log_connections','log_disconnections','post_auth_delay']
        sql="SELECT name,setting FROM pg_settings WHERE name IN ("+','.join("'%s'"%x for x in names)+") ORDER BY name;"
        r=self._sql(sql);ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc)]
        if r.rc:return self._mk(rule,'ERROR','Unable to read backend settings.',ev)
        vals={p[0]:p[1] for l in r.stdout.splitlines() if len((p:=l.split('|',1)))==2}
        expected={'ignore_system_indexes':'off','jit_debugging_support':'off','jit_profiling_support':'off','log_connections':'on','log_disconnections':'on','post_auth_delay':'0'}
        bad={k:(vals.get(k),v) for k,v in expected.items() if vals.get(k)!=v and k in vals}
        return self._mk(rule,'FAIL' if bad else 'PASS',f"settings={vals}; mismatches={bad or 'none'}",ev)
    def cis_6_3(self,rule):
        return self._settings_integrity(rule,'postmaster',{
            'data_sync_retry':{'on'},'ignore_invalid_pages':{'on'},
        })
    def cis_6_4(self,rule):
        return self._settings_integrity(rule,'sighup',{
            'fsync':{'off'},'full_page_writes':{'off'},'restart_after_crash':{'off'},
        })
    def cis_6_5(self,rule):
        sql="SELECT name,setting FROM pg_settings WHERE name IN ('allow_system_table_mods','ignore_checksum_failure','zero_damaged_pages','log_statement','log_error_verbosity') ORDER BY name;"
        r=self._sql(sql);ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc)]
        if r.rc:return self._mk(rule,'ERROR','Unable to read superuser settings.',ev)
        bad=[]
        for l in r.stdout.splitlines():
            k,_,v=l.partition('|')
            if k in {'allow_system_table_mods','ignore_checksum_failure','zero_damaged_pages'} and v=='on':bad.append(l)
        return self._mk(rule,'FAIL' if bad else 'PASS',('Dangerous superuser settings detected:\n'+'\n'.join(bad)) if bad else 'No known dangerous superuser integrity-bypass setting enabled.\n'+r.stdout,ev)
    def cis_6_6(self,rule):
        sql="SELECT COALESCE(d.datname,'*'),COALESCE(r.rolname,'*'),unnest(s.setconfig) FROM pg_db_role_setting s LEFT JOIN pg_database d ON d.oid=s.setdatabase LEFT JOIN pg_roles r ON r.oid=s.setrole ORDER BY 1,2,3;"
        q=self._sql(sql);ev=[self._ev('SQL',q.stdout or q.stderr,sql,q.rc)]
        if q.rc:return self._mk(rule,'ERROR','Unable to inspect per-role/database runtime settings.',ev)
        danger=[]
        for line in q.stdout.splitlines():
            low=line.lower()
            if re.search(r'\|(session_replication_role\s*=\s*replica|row_security\s*=\s*off|local_preload_libraries\s*=|search_path\s*=.*\bpublic\b)',low):danger.append(line)
        return self._mk(rule,'FAIL' if danger else 'PASS',('Risky role/database runtime overrides:\n'+'\n'.join(danger[:100])) if danger else (q.stdout or 'No per-role/database runtime overrides configured.'),ev)
    def cis_6_7(self,rule):
        a=self._shell("fips-mode-setup --check 2>/dev/null || cat /proc/sys/crypto/fips_enabled 2>/dev/null || (test -e /etc/system-fips && echo enabled)",12);b=self._shell("openssl version 2>/dev/null; openssl list -providers 2>/dev/null | head -80",8);ev=[self._ev('OS',a.stdout or a.stderr,'FIPS mode check',a.rc),self._ev('OS',b.stdout or b.stderr,'openssl version/providers',b.rc)]
        if not a.stdout:return self._mk(rule,'REVIEW','FIPS mode tooling/state not available on this platform; validate against organization cryptographic requirements.',ev)
        enabled='enabled' in a.stdout.lower() or a.stdout.strip()=='1'
        return self._mk(rule,'PASS' if enabled else 'FAIL',f"FIPS state: {a.stdout}; OpenSSL: {b.stdout}",ev)
    def cis_6_8(self,rule):
        s=self._setting('ssl');cert=self._setting('ssl_cert_file');key=self._setting('ssl_key_file');ev=[self._ev('SQL',s.stdout or s.stderr,'SHOW ssl;',s.rc),self._ev('SQL',cert.stdout or cert.stderr,'SHOW ssl_cert_file;',cert.rc),self._ev('SQL',key.stdout or key.stderr,'SHOW ssl_key_file;',key.rc)]
        if s.rc:return self._mk(rule,'ERROR','Unable to read TLS settings.',ev)
        ok=bool_on(s.stdout) and cert.rc==0 and key.rc==0 and bool(cert.stdout.strip()) and bool(key.stdout.strip())
        return self._mk(rule,'PASS' if ok else 'FAIL',f"ssl={s.stdout.strip()}; cert={cert.stdout.strip() if cert.rc==0 else '<error>'}; key={key.stdout.strip() if key.rc==0 else '<error>'}",ev)
    def cis_6_9(self,rule):return self._setting_result(rule,'ssl_min_protocol_version',lambda v:v.strip().lower() in {'tlsv1.2','tlsv1.3'},'TLSv1.2 or TLSv1.3')
    def cis_6_10(self,rule):
        r=self._setting('ssl_ciphers');ev=[self._ev('SQL',r.stdout or r.stderr,'SHOW ssl_ciphers;',r.rc)]
        if r.rc:return self._mk(rule,'ERROR','Unable to read ssl_ciphers.',ev)
        raw=r.stdout.strip();parts=[x.strip() for x in re.split(r'[:,]',raw) if x.strip()]
        # OpenSSL expressions like HIGH:!aNULL are not a literal benchmark allowlist and therefore require/fail benchmark validation.
        bad=[x for x in parts if x not in TLS_ALLOWED]
        return self._mk(rule,'PASS' if parts and not bad else 'FAIL',f"ssl_ciphers={raw}; values outside benchmark allowlist={bad or 'none'}",ev)
    def cis_6_11(self,rule):
        sql="SELECT default_version,installed_version FROM pg_available_extensions WHERE name='pgcrypto';"
        r=self._sql(sql);ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc)]
        if r.rc:return self._mk(rule,'ERROR','Unable to inspect pgcrypto.',ev)
        installed=bool(r.stdout and len(r.stdout.split('|'))>1 and r.stdout.split('|')[1].strip())
        return self._mk(rule,'PASS' if installed else 'FAIL',f"pgcrypto={r.stdout.strip() or '<not available>'}; the benchmark's pgcrypto control is not satisfied on this database.",ev)

    # replication / backup
    def cis_7_1(self,rule):
        sql="SELECT rolname,rolsuper,rolreplication,rolcanlogin FROM pg_roles WHERE rolreplication ORDER BY 1;"
        r=self._sql(sql);ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc)]
        if r.rc:return self._mk(rule,'ERROR','Unable to inspect replication roles.',ev)
        dedicated=[]
        for l in r.stdout.splitlines():
            p=l.split('|')
            if len(p)>=4 and p[0]!='postgres' and p[1]=='f' and p[2]=='t' and p[3]=='t':dedicated.append(p[0])
        active=self._sql('SELECT count(*) FROM pg_stat_replication;');slots=self._sql('SELECT count(*) FROM pg_replication_slots;');pc=self._setting('primary_conninfo')
        ev += [self._ev('SQL',active.stdout or active.stderr,'SELECT count(*) FROM pg_stat_replication;',active.rc),self._ev('SQL',slots.stdout or slots.stderr,'SELECT count(*) FROM pg_replication_slots;',slots.rc),self._ev('SQL',pc.stdout or pc.stderr,'SHOW primary_conninfo;',pc.rc)]
        count=int(active.stdout.strip() or 0) if active.rc==0 and active.stdout.strip().isdigit() else None
        slot_count=int(slots.stdout.strip() or 0) if slots.rc==0 and slots.stdout.strip().isdigit() else None
        if dedicated:return self._mk(rule,'PASS',f"Dedicated replication role(s): {', '.join(dedicated)}; active replication sessions={count if count is not None else 'unknown'}",ev)
        replication_used=bool((count or 0)>0 or (slot_count or 0)>0 or (pc.rc==0 and pc.stdout.strip()))
        return self._mk(rule,'FAIL' if replication_used else 'N/A',f"No dedicated non-superuser replication login role detected; active sessions={count}; slots={slot_count}; primary_conninfo={'set' if pc.rc==0 and pc.stdout.strip() else 'unset'}",ev)
    def cis_7_2(self,rule):return self._setting_result(rule,'log_replication_commands',bool_on,'on')
    def cis_7_3(self,rule):
        cmd="pgbackrest info --output=json 2>/dev/null || wal-g backup-list --json 2>/dev/null || barman list-backups all 2>/dev/null || find /var/lib/pgsql /var/lib/postgresql /backup /backups -maxdepth 5 -type f \\( -name backup_manifest -o -name 'base.tar*' -o -name '*.backup' \\) -mtime -8 2>/dev/null | head -200"
        r=self._shell(cmd,20);ev=[self._ev('OS',r.stdout or r.stderr,cmd,r.rc)]
        if r.rc==0 and r.stdout:return self._mk(rule,'PASS','Recent/machine-readable base-backup evidence found. Restore testing is assessed separately by ESA-01.\n'+truncate(r.stdout,3000),ev)
        return self._mk(rule,'FAIL','No recent local/machine-readable base-backup evidence found through pgBackRest, WAL-G, Barman, backup manifests, or common backup paths.',ev)
    def cis_7_4(self,rule):
        sql="SELECT name,setting FROM pg_settings WHERE name IN ('archive_mode','archive_command','archive_library') ORDER BY name;"
        r=self._sql(sql);st=self._sql("SELECT archived_count,failed_count,last_archived_wal,last_archived_time,last_failed_wal,last_failed_time FROM pg_stat_archiver;");ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc),self._ev('SQL',st.stdout or st.stderr,'SELECT ... FROM pg_stat_archiver;',st.rc)]
        if r.rc:return self._mk(rule,'ERROR','Unable to read WAL archive settings.',ev)
        vals={l.split('|',1)[0]:l.split('|',1)[1] for l in r.stdout.splitlines() if '|' in l}
        enabled=vals.get('archive_mode') in {'on','always'} and bool(vals.get('archive_command','').strip() not in {'','(disabled)'} or vals.get('archive_library','').strip())
        return self._mk(rule,'PASS' if enabled else 'FAIL',f"settings={vals}; pg_stat_archiver={truncate(st.stdout,1200)}",ev)
    def cis_7_5(self,rule):
        sql="SELECT a.usename,a.client_addr,s.ssl,s.version,s.cipher FROM pg_stat_activity a LEFT JOIN pg_stat_ssl s ON s.pid=a.pid WHERE a.backend_type='walsender' ORDER BY a.pid;"
        r=self._sql(sql);pc=self._setting('primary_conninfo');ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc),self._ev('SQL',pc.stdout or pc.stderr,'SHOW primary_conninfo;',pc.rc)]
        lines=r.stdout.splitlines() if r.rc==0 else []
        unencrypted=[l for l in lines if '|f|' in l]
        pconn=pc.stdout.strip() if pc.rc==0 else ''
        if unencrypted:return self._mk(rule,'FAIL','Unencrypted walsender connection(s):\n'+'\n'.join(unencrypted),ev)
        if lines:return self._mk(rule,'PASS','Active replication sessions use TLS:\n'+'\n'.join(lines),ev)
        if pconn:
            ok=re.search(r'(?i)sslmode=(require|verify-ca|verify-full)',pconn)
            return self._mk(rule,'PASS' if ok else 'FAIL',f"standby primary_conninfo present; sslmode secure={'yes' if ok else 'no'}",ev)
        return self._mk(rule,'N/A','No active streaming replication or primary_conninfo detected.',ev)
    def cis_8_1(self,rule):
        dg=self._setting('data_directory');ld=self._setting('log_directory');tt=self._setting('temp_tablespaces');tf=self._setting('temp_file_limit');ev=[self._ev('SQL',x.stdout or x.stderr,cmd,x.rc) for x,cmd in [(dg,'SHOW data_directory;'),(ld,'SHOW log_directory;'),(tt,'SHOW temp_tablespaces;'),(tf,'SHOW temp_file_limit;')]]
        if dg.rc or ld.rc:return self._mk(rule,'ERROR','Unable to determine data/log directory.',ev)
        data=dg.stdout.strip().rstrip('/');log=ld.stdout.strip(); temp=tt.stdout.strip() if tt.rc==0 else '';limit=tf.stdout.strip() if tf.rc==0 else ''
        log_outside=log.startswith('/') and not (log==data or log.startswith(data+'/'))
        temp_protected=bool(temp) or (limit not in {'','-1','0'})
        status='PASS' if log_outside and temp_protected else 'FAIL'
        return self._mk(rule,status,f"data_directory={data}; log_directory={log} (outside={log_outside}); temp_tablespaces={temp or '<unset>'}; temp_file_limit={limit or '<unknown>'}",ev)
    def cis_8_2(self,rule):
        r=self._shell("command -v pgbackrest >/dev/null 2>&1 && pgbackrest info --output=json 2>/dev/null",25);ev=[self._ev('OS',r.stdout or r.stderr,'pgbackrest info --output=json',r.rc)]
        if r.rc!=0 or not r.stdout:return self._mk(rule,'FAIL','pgBackRest not installed/configured or no valid stanza information was returned.',ev)
        try:
            j=json.loads(r.stdout); ok=bool(j)
        except:ok=False
        return self._mk(rule,'PASS' if ok else 'FAIL',truncate(r.stdout,3500),ev)
    def cis_8_3(self,rule):
        sql="SELECT name,setting FROM pg_settings WHERE name IN ('external_pid_file','unix_socket_directories','unix_socket_permissions','shared_preload_libraries','dynamic_library_path','local_preload_libraries','session_preload_libraries') ORDER BY name;"
        r=self._sql(sql);ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc)]
        if r.rc:return self._mk(rule,'ERROR','Unable to read miscellaneous settings.',ev)
        vals={l.split('|',1)[0]:l.split('|',1)[1] for l in r.stdout.splitlines() if '|' in l}
        socket_dirs=[x.strip() for x in vals.get('unix_socket_directories','').split(',') if x.strip()]
        risky=[x for x in socket_dirs if x=='/tmp']
        preload=' '.join(vals.get(x,'') for x in ('local_preload_libraries','session_preload_libraries'))
        if preload.strip():risky.append('local/session preload libraries configured')
        # Resolve and stat concrete socket/pid/library directories when possible.
        paths=[]
        paths.extend([x for x in socket_dirs if x and x.startswith('/')])
        if vals.get('external_pid_file','').startswith('/'):paths.append(vals['external_pid_file'])
        dl=vals.get('dynamic_library_path','')
        if dl.startswith('/'):paths.extend(x for x in dl.split(':') if x.startswith('/'))
        stat_out=''
        if paths:
            cmd='for p in '+ ' '.join(shell_quote(x) for x in paths) + "; do [ -e \"$p\" ] && stat -c '%U:%G %a %F %n' \"$p\"; done"
            st=self._shell(cmd,15);ev.append(self._ev('OS',st.stdout or st.stderr,cmd,st.rc));stat_out=st.stdout
            for line in st.stdout.splitlines():
                mm=re.search(r'\s(\d{3,4})\s',line)
                if mm and (int(mm.group(1)[-3:],8)&0o022):risky.append('group/other-writable path: '+line)
        return self._mk(rule,'FAIL' if risky else 'PASS',f"settings={vals}; risk_flags={risky or 'none'}"+("\npath permissions:\n"+stat_out if stat_out else ''),ev)

    # ---- ESA ----
    def _check_esa(self,rule):
        fn=getattr(self,'esa_'+rule['id'].split('-')[1],None)
        if fn:return fn(rule)
        return self._mk(rule,'REVIEW','Enhanced check requires manual validation.',source='ESA')
    def _esa_mk(self,rule,status,test,ev=None,comments=None,solution=None):return self._mk(rule,status,test,ev,comments,solution,'ESA')
    def esa_01(self,rule):
        cmd="pgbackrest info --output=json 2>/dev/null"
        r=self._shell(cmd,25);ev=[self._ev('OS',r.stdout or r.stderr,cmd,r.rc)]
        if r.rc!=0 or not r.stdout:return self._esa_mk(rule,'FAIL','No machine-readable pgBackRest backup evidence found.',ev)
        try:
            data=json.loads(r.stdout); backups=[]
            for stanza in data if isinstance(data,list) else []: backups.extend(stanza.get('backup') or [])
            latest=max((b.get('timestamp',{}).get('stop',0) or 0 for b in backups),default=0)
            age=(time.time()-latest)/3600 if latest else None
            max_age=float(self.policy.get('backup_max_age_hours',168))
            marker=self._shell("for f in /var/lib/pgsec/last_restore_test /etc/pgsec/last_restore_test /var/lib/postgresql/.last_restore_test; do [ -e \"$f\" ] && stat -c %Y \"$f\" && break; done",8)
            ev.append(self._ev('OS',marker.stdout or marker.stderr,'restore-test evidence marker timestamp',marker.rc))
            marker_epoch=int(marker.stdout.splitlines()[0]) if marker.rc==0 and marker.stdout.splitlines() and marker.stdout.splitlines()[0].isdigit() else int(self.policy.get('restore_test_epoch',0) or 0)
            restore_days=(time.time()-marker_epoch)/86400 if marker_epoch else None
            restore_max=float(self.policy.get('restore_test_max_age_days',120))
            problems=[]
            if age is None or age>max_age:problems.append(f'backup age exceeds {max_age:g}h')
            if restore_days is None:problems.append('no restore-test evidence marker')
            elif restore_days>restore_max:problems.append(f'restore test older than {restore_max:g}d')
            status='FAIL' if problems else 'PASS'
            return self._esa_mk(rule,status,f"Backups={len(backups)}; latest_age_hours={age:.1f}" if age is not None else f"Backups={len(backups)}; latest timestamp unavailable",ev,comments=f"Restore-test age days={restore_days:.1f}; findings={problems or 'none'}" if restore_days is not None else f"Restore-test evidence unavailable; findings={problems or 'none'}")
        except Exception as ex:return self._esa_mk(rule,'FAIL',f"pgBackRest output could not be parsed: {ex}",ev)
    def esa_02(self,rule):
        a=self._setting('data_checksums');sql="SELECT datname,checksum_failures,checksum_last_failure FROM pg_stat_database WHERE checksum_failures IS NOT NULL AND checksum_failures>0 ORDER BY checksum_failures DESC;";b=self._sql(sql);ev=[self._ev('SQL',a.stdout or a.stderr,'SHOW data_checksums;',a.rc),self._ev('SQL',b.stdout or b.stderr,sql,b.rc)]
        if a.rc:return self._esa_mk(rule,'ERROR','Unable to read data_checksums.',ev)
        if not bool_on(a.stdout):return self._esa_mk(rule,'FAIL',f"data_checksums={a.stdout.strip()}; page checksums are not enabled.",ev)
        if b.rc==0 and b.stdout:return self._esa_mk(rule,'FAIL','Checksum failures reported:\n'+b.stdout,ev)
        return self._esa_mk(rule,'PASS','data_checksums=on; no checksum failure rows returned.',ev)
    def esa_03(self,rule):
        sql="SELECT rolname,CASE WHEN rolpassword IS NULL THEN 'NONE' WHEN rolpassword LIKE 'SCRAM-SHA-256$%' THEN 'SCRAM-SHA-256' WHEN rolpassword LIKE 'md5%' THEN 'MD5' ELSE 'OTHER' END FROM pg_authid WHERE rolcanlogin ORDER BY 1;"
        r=self._sql(sql);ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc)]
        if r.rc:return self._esa_mk(rule,'ERROR','pg_authid requires elevated database privilege; password hash audit could not be completed.',ev)
        md5=[l for l in r.stdout.splitlines() if l.endswith('|MD5')];other=[l for l in r.stdout.splitlines() if l.endswith('|OTHER')]
        return self._esa_mk(rule,'FAIL' if md5 or other else 'PASS',f"MD5 roles={len(md5)}; other unknown hash roles={len(other)}\n"+r.stdout,ev)
    def esa_04(self,rule):
        sql="SELECT rolname,rolvaliduntil FROM pg_authid WHERE rolcanlogin AND rolname !~ '^pg_' ORDER BY 1;"
        r=self._sql(sql);ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc)]
        if r.rc:return self._esa_mk(rule,'ERROR','Credential lifecycle audit needs pg_authid access.',ev)
        expired_q=self._sql("SELECT rolname FROM pg_authid WHERE rolcanlogin AND rolname !~ '^pg_' AND rolvaliduntil IS NOT NULL AND rolvaliduntil < now() ORDER BY 1;")
        ev.append(self._ev('SQL',expired_q.stdout or expired_q.stderr,'expired login role query',expired_q.rc))
        exp=[x for x in expired_q.stdout.splitlines() if x.strip()] if expired_q.rc==0 else []
        never=[l for l in r.stdout.splitlines() if l.endswith('|')]
        require_expiry=bool(self.policy.get('require_password_expiry',False))
        if exp:return self._esa_mk(rule,'FAIL',f"expired={len(exp)}; no-expiry={len(never)}\nExpired roles: {', '.join(exp)}",ev)
        if require_expiry and never:return self._esa_mk(rule,'FAIL',f"expired=0; no-expiry={len(never)}; policy requires password expiration.\n"+r.stdout,ev)
        return self._esa_mk(rule,'PASS',f"expired=0; no-expiry={len(never)}. No-expiry is informational unless require_password_expiry policy is enabled.\n"+r.stdout,ev)
    def esa_05(self,rule):
        sql="SELECT rule_number,error FROM pg_hba_file_rules WHERE error IS NOT NULL ORDER BY rule_number;";r=self._sql(sql);ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc)]
        if r.rc:return self._esa_mk(rule,'ERROR','pg_hba_file_rules not available.',ev)
        return self._esa_mk(rule,'FAIL' if r.stdout else 'PASS',r.stdout or 'No pg_hba parsing errors reported.',ev)
    def esa_06(self,rule):
        sql="SELECT sourcefile,sourceline,name,setting,applied,error FROM pg_file_settings WHERE error IS NOT NULL OR NOT applied ORDER BY sourcefile,sourceline;";r=self._sql(sql);ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc)]
        if r.rc:return self._esa_mk(rule,'ERROR','pg_file_settings unavailable.',ev)
        return self._esa_mk(rule,'FAIL' if r.stdout else 'PASS',r.stdout or 'No invalid/unapplied configuration rows reported.',ev)
    def esa_07(self,rule):
        sql="""WITH sp AS (SELECT regexp_split_to_table(current_setting('search_path'), '\\s*,\\s*') n) SELECT nspname, has_schema_privilege('public',oid,'CREATE') public_create FROM pg_namespace WHERE nspname IN (SELECT replace(n,'\"','') FROM sp) ORDER BY 1;""";r=self._sql(sql);ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc)]
        if r.rc:return self._esa_mk(rule,'ERROR','Unable to evaluate search_path schema privileges.',ev)
        bad=[l for l in r.stdout.splitlines() if l.endswith('|t')]
        return self._esa_mk(rule,'FAIL' if bad else 'PASS',('PUBLIC can CREATE in search_path schema(s):\n'+'\n'.join(bad)) if bad else (r.stdout or 'No writable PUBLIC search_path schema found.'),ev)
    def esa_08(self,rule):
        sql="""SELECT n.nspname||'.'||p.proname, has_function_privilege('public',p.oid,'EXECUTE') public_exec, COALESCE(array_to_string(p.proconfig,','),'') config FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog','information_schema') ORDER BY 1;""";r=self._sql(sql);ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc)]
        if r.rc:return self._esa_mk(rule,'ERROR','Unable to inspect SECURITY DEFINER functions.',ev)
        bad=[]
        for l in r.stdout.splitlines():
            p=l.split('|',2);cfg=p[2] if len(p)>2 else ''
            if len(p)>1 and (p[1]=='t' or 'search_path=' not in cfg or re.search(r'search_path=[^|]*\$user|search_path=[^|]*public',cfg,re.I)):bad.append(l)
        return self._esa_mk(rule,'FAIL' if bad else 'PASS',('Unsafe SECURITY DEFINER candidates:\n'+'\n'.join(bad)) if bad else (r.stdout or 'No user SECURITY DEFINER functions found.'),ev)
    def esa_09(self,rule):
        sql="""SELECT member.rolname, role.rolname FROM pg_auth_members m JOIN pg_roles role ON role.oid=m.roleid JOIN pg_roles member ON member.oid=m.member WHERE role.rolname IN ('pg_execute_server_program','pg_read_server_files','pg_write_server_files','pg_read_all_data','pg_write_all_data','pg_signal_backend') ORDER BY 1,2;""";r=self._sql(sql);ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc)]
        if r.rc:return self._esa_mk(rule,'ERROR','Unable to inspect predefined role memberships.',ev)
        high=[l for l in r.stdout.splitlines() if any(x in l for x in ('pg_execute_server_program','pg_read_server_files','pg_write_server_files'))]
        return self._esa_mk(rule,'FAIL' if high else 'PASS',r.stdout or 'No high-risk predefined role memberships found.',ev)
    def esa_10(self,rule):
        sql="""SELECT a.usename,a.datname,a.client_addr,COALESCE(s.ssl,false),COALESCE(s.version,''),COALESCE(s.cipher,'') FROM pg_stat_activity a LEFT JOIN pg_stat_ssl s USING(pid) WHERE a.client_addr IS NOT NULL AND a.backend_type='client backend' ORDER BY a.pid;""";r=self._sql(sql);ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc)]
        if r.rc:return self._esa_mk(rule,'ERROR','Unable to inspect TLS session state.',ev)
        plain=[l for l in r.stdout.splitlines() if '|f|' in l]
        return self._esa_mk(rule,'FAIL' if plain else 'PASS',('Unencrypted remote sessions:\n'+'\n'.join(plain)) if plain else (r.stdout or 'No active remote client sessions to evaluate.'),ev)
    def esa_11(self,rule):
        pc=self._setting('primary_conninfo');cmd="grep -RhsE 'sslmode=(disable|allow|prefer|require|verify-ca|verify-full)' /root/.pg_service.conf /home/*/.pg_service.conf /etc/pg_service.conf 2>/dev/null | head -100";s=self._shell(cmd,10);ev=[self._ev('SQL',pc.stdout or pc.stderr,'SHOW primary_conninfo;',pc.rc),self._ev('OS',s.stdout or s.stderr,cmd,s.rc)]
        text='\n'.join([pc.stdout if pc.rc==0 else '',s.stdout])
        weak=re.findall(r'(?i)sslmode=(disable|allow|prefer|require)(\b)',text);strong=re.findall(r'(?i)sslmode=(verify-ca|verify-full)',text)
        return self._esa_mk(rule,'FAIL' if weak else ('PASS' if strong else 'N/A'),f"weak/non-verifying sslmode occurrences={len(weak)}; verifying occurrences={len(strong)}. No local client connection profile => N/A; clients on other hosts are separate targets.",ev)
    def esa_12(self,rule):
        sql="""SELECT slot_name,slot_type,active,wal_status,pg_size_pretty(CASE WHEN restart_lsn IS NULL THEN 0 ELSE pg_wal_lsn_diff(pg_current_wal_lsn(),restart_lsn) END) retained FROM pg_replication_slots ORDER BY active,slot_name;""";r=self._sql(sql);m=self._setting('max_slot_wal_keep_size');ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc),self._ev('SQL',m.stdout or m.stderr,'SHOW max_slot_wal_keep_size;',m.rc)]
        if r.rc:return self._esa_mk(rule,'ERROR','Unable to inspect replication slots.',ev)
        slots=[l for l in r.stdout.splitlines() if l.strip()];inactive=[l for l in slots if '|f|' in l];unbounded=(m.rc==0 and m.stdout.strip() in {'-1','-1MB'})
        if not slots:return self._esa_mk(rule,'PASS',f"slots=0; max_slot_wal_keep_size={m.stdout.strip() if m.rc==0 else '<unknown>'}; unbounded setting has no slot-retention effect while no slots exist.",ev)
        return self._esa_mk(rule,'FAIL' if inactive or unbounded else 'PASS',f"slots={len(slots)}; inactive_slots={len(inactive)}; max_slot_wal_keep_size={m.stdout.strip() if m.rc==0 else '<unknown>'}\n{r.stdout}",ev)
    def esa_13(self,rule):
        meta=self.context.get('container') or {};ev=[self._ev('Container','metadata from runtime inspect')]
        if not meta:return self._esa_mk(rule,'N/A','Target is not a selected container or container inspect metadata is unavailable.',ev)
        flags=[]
        if meta.get('privileged'):flags.append('privileged=true')
        image_user=str(meta.get('user','')).strip()
        cmd="pid=$(pgrep -xo postgres 2>/dev/null || pgrep -xo postmaster 2>/dev/null); if [ -n \"$pid\" ]; then ps -o uid= -o user= -p \"$pid\"; else id -u; id -un; fi"
        actual=self._shell(cmd,8);ev.append(self._ev('OS',actual.stdout or actual.stderr,cmd,actual.rc))
        actual_text=(actual.stdout or '').strip(); actual_root=bool(re.search(r'(^|\s)(0|root)(\s|$)',actual_text))
        if actual_root:flags.append('postgres process/runtime user is root')
        caps=[str(x).upper() for x in meta.get('cap_add',[])];danger=[x for x in caps if x in {'SYS_ADMIN','SYS_PTRACE','DAC_OVERRIDE','SYS_MODULE','NET_ADMIN','ALL'}]
        if danger:flags.append('cap_add='+','.join(danger))
        if any('unconfined' in str(x).lower() for x in meta.get('security_opt',[])):flags.append('security_opt=unconfined')
        return self._esa_mk(rule,'FAIL' if flags else 'PASS',f"risk_flags={flags or 'none'}; image_config_user={image_user or '<image-default>'}; actual_identity={actual_text or '<unavailable>'}; readonly_rootfs={meta.get('readonly_rootfs')}",ev)
    def esa_14(self,rule):
        meta=self.context.get('container') or {};names=meta.get('secret_env_names',[]) if meta else [];ev=[self._ev('Container','Only environment variable names are reported; values are intentionally suppressed.')]
        if not meta:return self._esa_mk(rule,'N/A','No container inspect metadata.',ev)
        return self._esa_mk(rule,'FAIL' if names else 'PASS',f"secret-like environment variable names={names or 'none'} (values not collected)",ev)
    def esa_15(self,rule):
        meta=self.context.get('container') or {};ev=[self._ev('Container','mount metadata from runtime inspect')]
        if not meta:return self._esa_mk(rule,'N/A','No container inspect metadata.',ev)
        sensitive=[]
        for m in meta.get('mounts',[]):
            src=str(m.get('source',''));dst=str(m.get('destination',''))
            if src in {'/','/etc','/var/run/docker.sock','/run/docker.sock'} or 'docker.sock' in src or dst in {'/var/run/docker.sock','/run/docker.sock'}:sensitive.append(f"{src}->{dst}")
        return self._esa_mk(rule,'FAIL' if sensitive else 'PASS',f"sensitive_mounts={sensitive or 'none'}",ev)
    def esa_16(self,rule):
        meta=self.context.get('container') or {};ev=[self._ev('Container','port bindings from runtime inspect')]
        if not meta:return self._esa_mk(rule,'N/A','No container inspect metadata.',ev)
        exposed=[]
        for p in meta.get('port_bindings',[]):
            if str(p.get('container_port','')).startswith('5432/') and p.get('host_ip','') in {'','0.0.0.0','::'}:exposed.append(p)
        return self._esa_mk(rule,'FAIL' if exposed else 'PASS',f"wildcard PostgreSQL port bindings={exposed or 'none'}",ev)
    def esa_17(self,rule):
        sv=self._setting('server_version');ev=[self._ev('SQL',sv.stdout or sv.stderr,'SHOW server_version;',sv.rc)]
        if sv.rc:return self._esa_mk(rule,'ERROR','Unable to determine PostgreSQL version.',ev)
        maj=version_tuple(sv.stdout)[:1]
        minv=(16,15) if maj==(16,) else ((maj+(0,)) if maj else (16,15))
        if version_tuple(sv.stdout)<minv:return self._esa_mk(rule,'FAIL',f"PostgreSQL {sv.stdout.strip()} predates {'.'.join(map(str,minv))}; update first to receive output_plugin_libraries and current security fixes.",ev)
        op=self._setting('output_plugin_libraries');slots=self._sql("SELECT DISTINCT plugin FROM pg_replication_slots WHERE plugin IS NOT NULL ORDER BY 1;");ev += [self._ev('SQL',op.stdout or op.stderr,'SHOW output_plugin_libraries;',op.rc),self._ev('SQL',slots.stdout or slots.stderr,'SELECT DISTINCT plugin FROM pg_replication_slots...',slots.rc)]
        if op.rc:return self._esa_mk(rule,'FAIL','output_plugin_libraries is unavailable despite a version that should support it; verify effective server binaries/version.',ev)
        allowed=[x.strip() for x in op.stdout.split(',') if x.strip()];plugins=[x.strip() for x in slots.stdout.splitlines() if x.strip()] if slots.rc==0 else []
        configured_allow=set(self.policy.get('allowed_output_plugins',['pgoutput','test_decoding']))
        missing=[x for x in plugins if x not in allowed];unexpected=[x for x in allowed if x not in configured_allow and x not in plugins]
        return self._esa_mk(rule,'FAIL' if missing or unexpected else 'PASS',f"output_plugin_libraries={allowed}; slot_plugins={plugins}; missing={missing}; disallowed_extra={unexpected}",ev)
    def esa_18(self,rule):
        sql="""SELECT 'EXT|'||e.extname||'|'||e.extversion||'|'||n.nspname FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace ORDER BY 1; SELECT 'LANG|'||lanname||'|'||lanpltrusted FROM pg_language ORDER BY 1;""";r=self._sql(sql);ev=[self._ev('SQL',r.stdout or r.stderr,sql,r.rc)]
        if r.rc:return self._esa_mk(rule,'ERROR','Unable to inventory extensions/languages.',ev)
        languages=[];extensions=[]
        for l in r.stdout.splitlines():
            if l.startswith('LANG|'):languages.append(l)
            elif l.startswith('EXT|'):extensions.append(l)
        # C and internal are built-in untrusted implementation languages, not user-facing
        # procedural languages. Flag additional untrusted procedural languages decisively.
        unsafe=[]
        for l in languages:
            p=l.split('|')
            if len(p)>=3 and p[2].lower() in {'f','false'} and p[1] not in {'c','internal'}:unsafe.append(l)
        allowed_ext=set(self.policy.get('allowed_extensions',[]))
        disallowed=[]
        if allowed_ext:
            for l in extensions:
                name=l.split('|')[1] if len(l.split('|'))>1 else ''
                if name and name not in allowed_ext and name!='plpgsql':disallowed.append(name)
        return self._esa_mk(rule,'FAIL' if unsafe or disallowed else 'PASS',f"extensions={len(extensions)}; languages={len(languages)}; unsafe_untrusted_languages={unsafe or 'none'}; disallowed_extensions={disallowed or 'none'}\n{truncate(r.stdout,3500)}",ev)
