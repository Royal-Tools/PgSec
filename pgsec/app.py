from __future__ import annotations
import argparse, getpass, ipaddress, os, sys, time, socket, json
from pathlib import Path
from .models import Target
from .executors import LocalExecutor, SSHExecutor, ContainerExecutor
from .discovery import discover_host, discover_postgres, discover_containers, inspect_container
from .audit import Auditor
from .rules import CIS_RULES, ESA_RULES
from .versioning import get_current_pg16
from .reporting import build_report, save_reports
from . import terminal as ui

VERSION='1.1.2'

def load_targets(value: str) -> list[str]:
    p=Path(value)
    raw=[]
    if p.is_file():
        raw=[x.strip() for x in p.read_text(encoding='utf-8').splitlines() if x.strip() and not x.lstrip().startswith('#')]
    else: raw=[value]
    out=[]
    for item in raw:
        if '/' in item:
            try:
                net=ipaddress.ip_network(item,strict=False)
                # Guard accidental huge ranges in an interactive audit utility.
                if net.num_addresses>4096: raise ValueError('CIDR contains more than 4096 addresses; use an explicit list or smaller range')
                out.extend(str(x) for x in net.hosts());continue
            except ValueError as ex:
                if 'more than 4096' in str(ex): raise
        out.append(item)
    return list(dict.fromkeys(out))

def _choice(prompt, options, default=None):
    opts=' / '.join(options)
    while True:
        v=input(f'{prompt} [{opts}]'+(f' ({default})' if default else '')+': ').strip()
        if not v and default:return default
        for o in options:
            if v.lower()==o.lower() or v.lower()==o[0].lower():return o
        ui.warn('Invalid selection.')

def _prompt_nonempty(prompt: str) -> str:
    while True:
        v=input(f'{prompt}: ').strip()
        if v: return v
        ui.warn('This field is required.')

def _prompt_password(prompt: str='SSH password') -> str:
    while True:
        v=getpass.getpass(f'{prompt}: ')
        if v: return v
        ui.warn('Password is required for SSH password authentication.')

def _wizard(args):
    ui.banner()
    ui.section('Target')
    print('Local = this machine (no SSH).  Single IP / IP List = remote SSH (username and password or key are required).')
    t=_choice('Target mode',['Local','Single IP','IP List'])
    if t=='Local':
        args.local=True
        db=input('Database user for psql (blank = default): ').strip()
        if db: args.db_user=db
        name=input('Database name (postgres): ').strip()
        if name: args.db_name=name
    elif t=='Single IP':
        args.ip=_prompt_nonempty('IP / hostname')
    else:
        args.file=_prompt_nonempty('IP list file')
    if not args.local:
        args.user=args.user or _prompt_nonempty('SSH username')
        a=_choice('SSH authentication',['Password','SSH Key'])
        if a=='SSH Key':
            args.key=_prompt_nonempty('SSH private key path')
            args.key=os.path.expanduser(args.key)
        else:
            args.password_prompt=True
            args.ssh_password=_prompt_password('SSH password')
        args.accept_new_hostkey=_choice('Unknown host keys',['Reject','Accept new (TOFU)'],'Reject').startswith('Accept')
        port=input(f'SSH port ({args.port}): ').strip()
        if port.isdigit(): args.port=int(port)
    ui.section('Assessment')
    m=_choice('Assessment',['Discovery','CIS + ESA','Discovery + CIS + ESA'],'Discovery + CIS + ESA')
    args.mode={'Discovery':'discovery','CIS + ESA':'cis','Discovery + CIS + ESA':'all'}[m]
    if not args.local:
        args.container_policy=_choice('Container selection',['Interactive per host','Auto all PostgreSQL containers','Host only'],'Interactive per host')
    else:
        args.container_policy=_choice('Container selection',['Interactive','Auto all PostgreSQL containers','Host only'],'Interactive')
        if args.container_policy=='Host only': args.host_only=True
        elif args.container_policy=='Auto all PostgreSQL containers': args.all_postgres_containers=True
    return args

def _parse_args(argv=None):
    p=argparse.ArgumentParser(description='PostgreSQL 16 CIS + Enhanced Security Assessment')
    g=p.add_mutually_exclusive_group()
    g.add_argument('--local',action='store_true',help='audit this local environment')
    g.add_argument('--ip',help='single IP/hostname/CIDR')
    g.add_argument('--file',help='file containing IPs/hostnames/CIDRs')
    p.add_argument('-u','--user',help='SSH username')
    p.add_argument('-k','--key',help='SSH private key file')
    p.add_argument('--password-stdin',action='store_true',help='read SSH password from stdin (first line)')
    p.add_argument('--port',type=int,default=22)
    p.add_argument('--container',help='container ID or name to audit on each remote host')
    p.add_argument('--all-postgres-containers',action='store_true')
    p.add_argument('--host-only',action='store_true')
    p.add_argument('--runtime',choices=['auto','docker','podman'],default='auto')
    p.add_argument('--accept-new-hostkey',action='store_true',help='trust unknown host keys on first use')
    p.add_argument('--known-hosts',default=os.path.expanduser('~/.ssh/known_hosts'))
    p.add_argument('--mode',choices=['discovery','cis','all'],default='all')
    p.add_argument('--db-user')
    p.add_argument('--db-name',default='postgres')
    p.add_argument('--output-dir',default='.')
    p.add_argument('--prefix',default='postgres-security-report')
    p.add_argument('--policy',help='optional JSON policy file to resolve organization-specific controls automatically')
    p.add_argument('--force-cis-major-mismatch',action='store_true',help='run CIS16 compatibility diagnostics even when detected PostgreSQL major is not 16 (not an official CIS16 score)')
    p.add_argument('--no-network',action='store_true',help='disable one-shot PostgreSQL current-version lookup')
    p.add_argument('--non-interactive',action='store_true')
    p.add_argument('--version',action='version',version=f'%(prog)s {VERSION}')
    args=p.parse_args(argv)
    args.password_prompt=False;args.container_policy=None;args.ssh_password=None
    return args

def _container_menu(host, rows):
    ui.section(f'Containers on {host}')
    print(f"{'#':>3}  {'NAME':<24} {'ID':<16} {'IMAGE':<32} STATUS")
    for i,r in enumerate(rows,1):
        mark='*' if r['postgres_candidate'] else ' '
        print(f"{i:>3}{mark} {r['name'][:23]:<24} {r['id'][:15]:<16} {r['image'][:31]:<32} {r['status'][:24]}")
    print('  * PostgreSQL candidate')
    while True:
        v=input('Select number, A=all PostgreSQL, H=host, S=skip: ').strip().lower()
        if v=='a':return [r for r in rows if r['postgres_candidate']]
        if v=='h':return ['HOST']
        if v=='s':return []
        try:
            i=int(v);return [rows[i-1]]
        except:ui.warn('Invalid selection.')

def _scan_one(ex, target: Target, current_pg16: str, mode: str, container_meta=None):
    label=target.label();ui.section(f'Target: {label}')
    ui.step('Discovery')
    host=discover_host(ex);pg=discover_postgres(ex);discovery={'host':host,'postgres':pg}
    if container_meta:discovery['container']=container_meta
    ui.info(f"PostgreSQL detected={pg.get('detected')} version={','.join(pg.get('versions',[])) or 'unknown'} SQL-access={pg.get('sql_access')}")
    cis=[];esa=[]
    if mode in {'cis','all'}:
        if not pg.get('detected'):
            ui.warn('PostgreSQL was not detected on this execution target; CIS/ESA assessment skipped.')
            return {'target':{**target.__dict__,'label':label},'discovery':discovery,'cis':cis,'esa':esa}
        aud=Auditor(ex,target,current_pg16,{'host':host,'postgres':pg,'container':container_meta or {},'policy':getattr(_scan_one,'policy',{}),'force_cis_major_mismatch':getattr(_scan_one,'force_cis_major_mismatch',False)})
        ui.section('CIS PostgreSQL 16 Benchmark v1.1.0')
        cis=aud.run_cis(callback=lambda r,n:ui.print_control(r,n,len(CIS_RULES)))
        ui.section('Enhanced Security Assessment (ESA)')
        esa=aud.run_esa(callback=lambda r,n:ui.print_control(r,n,len(ESA_RULES)))
    return {'target':{**target.__dict__,'label':label},'discovery':discovery,'cis':cis,'esa':esa}

def main(argv=None):
    args=_parse_args(argv)
    if not (args.local or args.ip or args.file):
        if args.non_interactive:
            print('ERROR: choose --local, --ip or --file',file=sys.stderr);return 2
        args=_wizard(args)
    else:
        ui.banner()
    ssh_password=getattr(args,'ssh_password',None)
    if not args.local:
        if not args.user:
            if args.non_interactive:print('ERROR: --user required for SSH',file=sys.stderr);return 2
            args.user=_prompt_nonempty('SSH username')
        if args.password_stdin:
            ssh_password=sys.stdin.readline().rstrip('\n')
        elif args.key:
            ssh_password=None
        elif ssh_password:
            pass
        else:
            envpw=os.environ.get('PGSEC_SSH_PASSWORD')
            ssh_password=envpw if envpw is not None else _prompt_password('SSH password')
    current,version_source=get_current_pg16(not args.no_network,2.0)
    ui.info(f'PostgreSQL 16 patch baseline: {current} ({version_source})')
    policy={}
    if args.policy:
        try:
            policy=json.loads(Path(args.policy).read_text(encoding='utf-8'))
            if not isinstance(policy,dict):raise ValueError('policy root must be a JSON object')
            ui.info(f'Policy loaded: {args.policy}')
        except Exception as ex:
            print(f'ERROR: unable to load --policy: {ex}',file=sys.stderr);return 2
    _scan_one.policy=policy
    _scan_one.force_cis_major_mismatch=args.force_cis_major_mismatch
    reports=[]
    if args.local:
        base=LocalExecutor(args.db_user,args.db_name)
        hostfacts=discover_host(base)
        runtimes=[] if args.host_only else [x for x in hostfacts.get('container_runtimes',[]) if args.runtime=='auto' or args.runtime in x]
        chosen=None
        if runtimes and not args.host_only:
            rt=runtimes[0];rows=discover_containers(base,rt)
            pgrows=[r for r in rows if r['postgres_candidate']]
            if args.container:chosen=[r for r in rows if r['id'].startswith(args.container) or r['name']==args.container]
            elif args.all_postgres_containers or args.container_policy=='Auto all PostgreSQL containers':chosen=pgrows
            elif args.host_only or args.container_policy=='Host only':chosen=['HOST']
            elif pgrows and not args.non_interactive:chosen=_container_menu('local',rows)
        if chosen and chosen!=['HOST']:
            for row in chosen:
                meta=inspect_container(base,rt,row['id']);ce=ContainerExecutor(base,rt,row['id'],args.db_user,args.db_name)
                t=Target('local-container','local',container_runtime=rt,container_id=row['id'],container_name=row['name'],container_image=row['image'],db_user=args.db_user,db_name=args.db_name)
                reports.append(_scan_one(ce,t,current,args.mode,meta))
        else:
            t=Target('local','local',db_user=args.db_user,db_name=args.db_name);reports.append(_scan_one(base,t,current,args.mode))
    else:
        hosts=load_targets(args.ip or args.file)
        ui.info(f'Target hosts: {len(hosts)}')
        for idx,host in enumerate(hosts,1):
            ui.section(f'Host {idx}/{len(hosts)}: {host}')
            base=SSHExecutor(host,args.user,args.port,ssh_password,args.key,known_hosts=args.known_hosts,accept_new_hostkey=args.accept_new_hostkey,db_user=args.db_user,db_name=args.db_name)
            probe=base.run('printf PGSEC_SSH_OK',12)
            if probe.rc!=0:
                ui.error(f'SSH failed: {probe.stderr or probe.stdout}')
                reports.append({'target':{'mode':'ssh','host':host,'label':host},'discovery':{'ssh_error':probe.stderr or probe.stdout},'cis':[],'esa':[]});continue
            ui.info('SSH connected')
            hf=discover_host(base)
            runtimes=[] if args.host_only else [x for x in hf.get('container_runtimes',[]) if args.runtime=='auto' or args.runtime in x]
            selected=None;rt=None
            if runtimes:
                rt=runtimes[0];rows=discover_containers(base,rt);pgrows=[r for r in rows if r['postgres_candidate']]
                if args.container:selected=[r for r in rows if r['id'].startswith(args.container) or r['name']==args.container]
                elif args.all_postgres_containers or args.container_policy=='Auto all PostgreSQL containers':selected=pgrows
                elif args.host_only or args.container_policy=='Host only':selected=['HOST']
                elif rows and not args.non_interactive:selected=_container_menu(host,rows)
            if selected and selected!=['HOST']:
                for row in selected:
                    meta=inspect_container(base,rt,row['id']);ce=ContainerExecutor(base,rt,row['id'],args.db_user,args.db_name)
                    t=Target('remote-container',host,args.port,args.user,'key' if args.key else 'password',args.key,rt,row['id'],row['name'],row['image'],args.db_user,args.db_name)
                    reports.append(_scan_one(ce,t,current,args.mode,meta))
            elif selected==[]:
                ui.warn('Host skipped by selection.')
            else:
                t=Target('remote-host',host,args.port,args.user,'key' if args.key else 'password',args.key,db_user=args.db_user,db_name=args.db_name)
                reports.append(_scan_one(base,t,current,args.mode))
    report=build_report(reports,version_source,current)
    j,x=save_reports(report,args.output_dir,args.prefix)
    ui.section('Output')
    ui.info(f'JSON : {j}')
    ui.info(f'Excel: {x}')
    return 0
