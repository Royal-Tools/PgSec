from __future__ import annotations
import json, re, os
from .models import CommandResult, Evidence, Target
from .executors import Executor
from .util import parse_version, truncate, shell_quote


def parse_container_listing(raw: str) -> list[dict]:
    rows=[]
    for line in (raw or '').splitlines():
        p=line.split('|',4)
        if len(p)<4: continue
        while len(p)<5:p.append('')
        cid,name,image,status,ports=p
        cand=bool(re.search(r'(?i)(postgres|postgresql|timescale|postgis)', f'{name} {image}'))
        rows.append({'id':cid.strip(),'name':name.strip(),'image':image.strip(),'status':status.strip(),'ports':ports.strip(),'postgres_candidate':cand})
    return rows


def discover_containers(executor: Executor, runtime: str) -> list[dict]:
    fmt='{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}'
    r=executor.run(f"{runtime} ps -a --no-trunc --format {shell_quote(fmt)}", timeout=20)
    if r.rc != 0:
        return []
    rows=parse_container_listing(r.stdout)
    for row in rows:
        if not row['postgres_candidate'] and 'Up' in row['status']:
            chk=executor.run(f"{runtime} exec {shell_quote(row['id'])} sh -lc 'command -v postgres >/dev/null 2>&1 || command -v psql >/dev/null 2>&1'",timeout=8)
            if chk.rc==0: row['postgres_candidate']=True
    return rows


def inspect_container(executor: Executor, runtime: str, cid: str) -> dict:
    r=executor.run(f"{runtime} inspect {shell_quote(cid)}",timeout=20)
    if r.rc!=0 or not r.stdout:
        return {'inspect_error':truncate(r.stderr)}
    try:
        obj=json.loads(r.stdout)
        d=obj[0] if isinstance(obj,list) and obj else obj
    except Exception:
        return {'inspect_error':'invalid inspect JSON'}
    cfg=d.get('Config') or {}; host=d.get('HostConfig') or {}; net=d.get('NetworkSettings') or {}
    env_names=[]
    secret_names=[]
    env_map={}
    for item in cfg.get('Env') or []:
        if '=' in item:
            k,v=item.split('=',1)
            env_map[k]=v
            env_names.append(k)
            if re.search(r'(?i)(password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|pgpassword)',k):
                secret_names.append(k)
    mounts=[]
    for m in d.get('Mounts') or []:
        mounts.append({'source':m.get('Source',''),'destination':m.get('Destination',''),'rw':m.get('RW',False),'type':m.get('Type','')})
    port_bindings=[]
    for container_port, bindings in (host.get('PortBindings') or {}).items():
        for b in bindings or []:
            port_bindings.append({'container_port':container_port,'host_ip':b.get('HostIp',''),'host_port':b.get('HostPort','')})

    # Discover container Postgres credentials from env or docker-compose
    pg_user=env_map.get('POSTGRES_USER') or env_map.get('PGUSER') or ''
    pg_db=env_map.get('POSTGRES_DB') or env_map.get('PGDATABASE') or ''
    pg_pass=env_map.get('POSTGRES_PASSWORD') or env_map.get('PGPASSWORD') or ''
    if not (pg_user and pg_pass and pg_db):
        # Scan common docker-compose locations on the host for this container/service name
        cname=(d.get('Name') or '').lstrip('/')
        cmp=executor.run(f"find /etc /opt /srv /var /home /root -maxdepth 4 -type f \\( -name 'docker-compose.yml' -o -name 'docker-compose.yaml' -o -name 'compose.yml' -o -name 'compose.yaml' \\) -exec grep -H -E -i 'POSTGRES_USER|POSTGRES_PASSWORD|POSTGRES_DB' {{}} + 2>/dev/null | head -100",12)
        if cmp.rc==0 and cmp.stdout:
            for line in cmp.stdout.splitlines():
                if not pg_user and 'POSTGRES_USER' in line:
                    m=re.search(r'POSTGRES_USER[=\s:]+([^\s"\'#]+)',line)
                    if m:pg_user=m.group(1)
                if not pg_pass and 'POSTGRES_PASSWORD' in line:
                    m=re.search(r'POSTGRES_PASSWORD[=\s:]+([^\s"\'#]+)',line)
                    if m:pg_pass=m.group(1)
                if not pg_db and 'POSTGRES_DB' in line:
                    m=re.search(r'POSTGRES_DB[=\s:]+([^\s"\'#]+)',line)
                    if m:pg_db=m.group(1)

    return {
        'id': d.get('Id',''), 'name': (d.get('Name') or '').lstrip('/'), 'image': cfg.get('Image',''),
        'user': cfg.get('User',''), 'privileged': bool(host.get('Privileged',False)),
        'cap_add': host.get('CapAdd') or [], 'security_opt': host.get('SecurityOpt') or [],
        'readonly_rootfs': bool(host.get('ReadonlyRootfs',False)), 'env_names':env_names,
        'secret_env_names':secret_names, 'mounts':mounts,'port_bindings':port_bindings,
        'network_mode':host.get('NetworkMode',''), 'pid_mode':host.get('PidMode',''),
        'discovered_db_user':pg_user, 'discovered_db_name':pg_db, 'discovered_db_pass':pg_pass,
    }


def discover_host(executor: Executor) -> dict:
    facts={}
    cmds={
        'hostname':'hostname 2>/dev/null || uname -n',
        'os_release':'cat /etc/os-release 2>/dev/null',
        'kernel':'uname -r 2>/dev/null',
        'architecture':'uname -m 2>/dev/null',
        'whoami':'id -un 2>/dev/null',
    }
    for k,c in cmds.items():
        r=executor.run(c,timeout=8); facts[k]=truncate(r.stdout,1500) if r.rc==0 else ''
    runtimes=[]
    for rt in ('docker','podman'):
        r=executor.run(f'command -v {rt} >/dev/null 2>&1 && {rt} version >/dev/null 2>&1',timeout=8)
        if r.rc==0:runtimes.append(rt)
        else:
            r=executor.run(f'sudo -n {rt} version >/dev/null 2>&1',timeout=8)
            if r.rc==0:runtimes.append('sudo '+rt)
    facts['container_runtimes']=runtimes
    return facts


def discover_db_users(executor: Executor) -> list[dict]:
    # Full inventory needs pg_authid (superuser).  Non-privileged sessions fall back to
    # the readable pg_roles view; the password-verifier column then reports unknown.
    rich=("SELECT r.rolname,r.rolcanlogin,r.rolsuper,r.rolcreaterole,r.rolcreatedb,r.rolreplication,r.rolbypassrls,"
          "r.rolconnlimit,COALESCE(to_char(r.rolvaliduntil,'YYYY-MM-DD HH24:MI:SS'),'never'),"
          "CASE WHEN r.rolpassword IS NULL THEN 'NONE' WHEN r.rolpassword LIKE 'SCRAM-SHA-256$%' THEN 'SCRAM-SHA-256' "
          "WHEN r.rolpassword LIKE 'md5%' THEN 'MD5' ELSE 'OTHER' END,"
          "COALESCE(array_to_string(r.rolmemberof,','),'') FROM pg_authid r ORDER BY 1;")
    plain=("SELECT rolname,rolcanlogin,rolsuper,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls,"
           "rolconnlimit,COALESCE(to_char(rolvaliduntil,'YYYY-MM-DD HH24:MI:SS'),'never') FROM pg_roles ORDER BY 1;")
    def yn(v):return 'Yes' if v.strip()=='t' else 'No'
    for sql,privileged in ((rich,True),(plain,False)):
        r=executor.sql(sql,20)
        if r.rc!=0 or not r.stdout.strip():continue
        rows=[]
        for line in r.stdout.splitlines():
            p=line.split('|')
            if len(p)<(11 if privileged else 9):continue
            name=p[0].strip()
            kind='System' if name.startswith('pg_') else ('Login' if yn(p[1])=='Yes' else 'No-Login')
            rows.append({
                'Role':name,'Type':kind,'Login':yn(p[1]),'Superuser':yn(p[2]),'CreateRole':yn(p[3]),
                'CreateDB':yn(p[4]),'Replication':yn(p[5]),'BypassRLS':yn(p[6]),
                'Connection Limit':p[7].strip(),'Valid Until':p[8].strip(),
                'Password Verifier':p[9].strip() if privileged else 'Unknown (needs privilege)',
                'Member Of':p[10].strip() if privileged and len(p)>10 else '',
            })
        if rows:return rows
    return []


def discover_postgres(executor: Executor) -> dict:
    d={'detected':False,'versions':[],'binaries':[],'services':[],'config_files':[],'pgdata':'','sql_access':False}
    for cmd in ('command -v postgres 2>/dev/null','command -v psql 2>/dev/null'):
        r=executor.run(cmd,8)
        if r.rc==0 and r.stdout:
            d['binaries'] += [x for x in r.stdout.splitlines() if x]
    for cmd in ('postgres --version 2>/dev/null','psql --version 2>/dev/null'):
        r=executor.run(cmd,8)
        v=parse_version(r.stdout)
        if v and v not in d['versions']:d['versions'].append(v)
    r=executor.run("ps -eo pid,args 2>/dev/null | grep -E '[p]ostgres( |$)|[p]ostmaster( |$)'",8)
    if r.rc==0 and r.stdout:
        d['detected']=True; d['processes']=truncate(r.stdout,3000)
        m=re.search(r'(?:^|\s)-D\s+([^\s]+)',r.stdout)
        if m:d['pgdata']=m.group(1)
    r=executor.run("systemctl list-unit-files --no-legend 2>/dev/null | grep -i postgres",8)
    if r.rc==0 and r.stdout:d['services']=r.stdout.splitlines()[:50];d['detected']=True
    # Fast bounded config search; includes common package, source, and container paths.
    r=executor.run("find /etc /var/lib /usr/local /opt /data /srv -xdev -type f \\( -name postgresql.conf -o -name pg_hba.conf \\) 2>/dev/null | head -200",20)
    if r.rc==0 and r.stdout:d['config_files']=r.stdout.splitlines();d['detected']=True
    sv=executor.sql('SHOW server_version;',10)
    if sv.rc==0 and sv.stdout:
        d['sql_access']=True;d['detected']=True
        v=parse_version(sv.stdout)
        if v and v not in d['versions']:d['versions'].insert(0,v)
        for sql,key in [('SHOW data_directory;','pgdata'),('SHOW config_file;','config_file'),('SHOW hba_file;','hba_file')]:
            x=executor.sql(sql,10)
            if x.rc==0 and x.stdout:d[key]=x.stdout.strip()
    if d['binaries']:d['detected']=True
    return d
