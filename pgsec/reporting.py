from __future__ import annotations
import json, re, time, platform, os
from pathlib import Path
from .xlsx_writer import write_xlsx
from .rules import BENCHMARKS
from .util import atomic_write, redact, sha256_file

STATUSES=('PASS','FAIL','WARN','REVIEW','ERROR','N/A','SKIPPED')
TOOL_VERSION='1.2.0'


def _os_pretty(os_release: str) -> str:
    m=re.search(r'(?m)^PRETTY_NAME=["\']?([^"\'\r\n]+)',os_release or '')
    if m:return m.group(1).strip()
    return next((l.strip() for l in (os_release or '').splitlines() if l.strip()),'')


def _os_pretty(os_release: str) -> str:
    m=re.search(r'(?m)^PRETTY_NAME=["\']?([^"\'\r\n]+)',os_release or '')
    if m:return m.group(1).strip()
    return next((l.strip() for l in (os_release or '').splitlines() if l.strip()),'')


def _is_local_target(target: dict) -> bool:
    mode=str(target.get('mode') or '')
    return mode.startswith('local')


def target_scope_and_host(target: dict) -> tuple[str,str]:
    if _is_local_target(target):
        return 'Local','local'
    return 'Remote', str(target.get('host') or target.get('label') or '')


def _target_label(target: dict) -> str:
    scope, host = target_scope_and_host(target)
    label=target.get('label')
    if label:
        if _is_local_target(target):
            rest=str(label).split('/',1)
            return f"local/{rest[1]}" if len(rest)==2 and rest[1] else 'local'
        return str(label)
    container=target.get('container_name') or target.get('container_id')
    return f"{host}/{container}" if container else host


def _pct(n: int, d: int) -> str:
    if d<=0: return 'n/a'
    return f"{round(100.0*n/d)}%"


def _assessed(counts: dict, sec: str) -> int:
    return sum(counts.get((sec,s),0) for s in ('PASS','FAIL','WARN','REVIEW','ERROR'))


def _posture(fail: int, error: int, review: int) -> str:
    if fail>=5 or error>=10: return 'Critical'
    if fail>=1 or error>=1: return 'Attention'
    if review>=1: return 'Review'
    return 'Healthy'


def build_report(target_reports: list[dict], baselines: dict|None=None) -> dict:
    # baselines maps PostgreSQL major -> (current minor, version-intelligence source).
    baselines={int(k):tuple(v) for k,v in (baselines or {}).items()}
    used=sorted({tr.get('benchmark') for tr in target_reports if tr.get('benchmark')})
    all_cis=[];all_esa=[];all_ev=[];all_users=[];discovery=[];scoreboard=[]
    counts={}
    scopes=set()
    for tr in target_reports:
        target=tr['target']; label=_target_label(target)
        scope, host = target_scope_and_host(target)
        scopes.add(scope)
        d=tr.get('discovery') or {}
        pg=d.get('postgres') or {}
        hf=d.get('host') or {}
        cm=d.get('container') or {}
        os_hostname='' if _is_local_target(target) else str(hf.get('hostname') or '')
        sql_access=bool(pg.get('sql_access'))
        for u in tr.get('users') or []:
            all_users.append({'Target':label,**u})
        discovery.append({
            'Target':label,'Scope':scope,'Host':host,'OS Hostname':os_hostname,
            'Mode':target.get('mode',''),
            'Container':target.get('container_name') or target.get('container_id') or '',
            'Container Image':cm.get('image',''),
            'Container User':str(cm.get('user') or ''),
            'Container Privileged':'Yes' if cm.get('privileged') else ('No' if cm else ''),
            'Container Ports':'; '.join(f"{p.get('host_ip') or '*'}:{p.get('host_port')}->{p.get('container_port')}" for p in cm.get('port_bindings',[])),
            'OS Release':_os_pretty(hf.get('os_release','')),
            'Kernel':hf.get('kernel',''),
            'Architecture':hf.get('architecture',''),
            'Audit User':hf.get('whoami',''),
            'Container Runtimes':','.join(hf.get('container_runtimes',[])),
            'PostgreSQL Detected': 'Yes' if pg.get('detected') else 'No',
            'Version':','.join(pg.get('versions',[])),
            'SQL Access': 'Yes' if sql_access else 'No',
            'Data Directory':pg.get('pgdata',''),
            'Config File':pg.get('config_file',''),
            'HBA File':pg.get('hba_file',''),
            'PostgreSQL Binaries':','.join(pg.get('binaries',[]))[:200],
            'Systemd Services':'; '.join(pg.get('services',[]))[:300],
            'Config Files Found':len(pg.get('config_files',[]) or []),
            'CIS Benchmark':BENCHMARKS[tr['benchmark']]['label'] if tr.get('benchmark') in BENCHMARKS else target.get('cis_benchmark',''),
        })
        t_counts={}
        for sec,key in [('CIS','cis'),('ESA','esa')]:
            for r in tr.get(key,[]):
                if key == 'cis':
                    row={**r.as_report_dict(),
                         'Required Customer Input': r.required_input if r.status.upper() == 'REVIEW' else '',
                         'Customer Response / Evidence':'',
                         'Auditor Decision':'',
                         'Target':label}
                    all_cis.append(row)
                else:
                    row={**r.as_report_dict(), 'Target':label}
                    all_esa.append(row)
                counts[(sec,r.status)]=counts.get((sec,r.status),0)+1
                t_counts[(sec,r.status)]=t_counts.get((sec,r.status),0)+1
                for e in r.evidence:
                    all_ev.append({'Target':label,'Section':sec,'Control':r.control_id, **e.as_dict()})
        ssh_err=(d.get('ssh_error') or '')
        scoreboard.append({
            'Target':label,'Scope':scope,'Host':host,
            'PostgreSQL': 'Yes' if pg.get('detected') else ('SSH failed' if ssh_err else 'No'),
            'Version':','.join(pg.get('versions',[])),
            'SQL Access': 'Yes' if sql_access else 'No',
            'CIS PASS': t_counts.get(('CIS','PASS'),0),
            'CIS FAIL': t_counts.get(('CIS','FAIL'),0),
            'CIS ERROR': t_counts.get(('CIS','ERROR'),0),
            'ESA FAIL': t_counts.get(('ESA','FAIL'),0),
            'Posture': 'Unreachable' if ssh_err else _posture(t_counts.get(('CIS','FAIL'),0)+t_counts.get(('ESA','FAIL'),0), t_counts.get(('CIS','ERROR'),0)+t_counts.get(('ESA','ERROR'),0), t_counts.get(('CIS','REVIEW'),0)),
        })
    cis_assessed=_assessed(counts,'CIS'); esa_assessed=_assessed(counts,'ESA')
    fail=counts.get(('CIS','FAIL'),0)+counts.get(('ESA','FAIL'),0)
    error=counts.get(('CIS','ERROR'),0)+counts.get(('ESA','ERROR'),0)
    review=counts.get(('CIS','REVIEW'),0)+counts.get(('ESA','REVIEW'),0)
    if scopes=={'Local'}: scope_value='Local'
    elif scopes=={'Remote'}: scope_value='Remote'
    elif scopes: scope_value='Mixed'
    else: scope_value='Unknown'
    bench_labels=[BENCHMARKS[m]['label'] for m in used if m in BENCHMARKS]
    bench_value=' + '.join(bench_labels) if bench_labels else ' / '.join(BENCHMARKS[m]['label'] for m in sorted(BENCHMARKS))
    source_value=', '.join(sorted({src for _,src in baselines.values()})) or 'bundled'
    summary=[
      {'Metric':'Generated At','Value':time.strftime('%Y-%m-%d %H:%M:%S %z')},
      {'Metric':'Assessment Scope','Value':scope_value},
      {'Metric':'Targets','Value':len(target_reports)},
      {'Metric':'CIS Pass Rate','Value':_pct(counts.get(('CIS','PASS'),0), cis_assessed)},
      {'Metric':'ESA Pass Rate','Value':_pct(counts.get(('ESA','PASS'),0), esa_assessed)},
      {'Metric':'Assessment Posture','Value':_posture(fail,error,review)},
      {'Metric':'CIS Benchmark','Value':bench_value},
    ]
    for major in sorted(baselines):
        summary.append({'Metric':f'Current PostgreSQL {major} Minor','Value':baselines[major][0]})
    summary.append({'Metric':'Version Intelligence Source','Value':source_value})
    for sec in ('CIS','ESA'):
        for status in STATUSES:
            summary.append({'Metric':f'{sec} {status}','Value':counts.get((sec,status),0)})
    json_targets=[]
    for tr in target_reports:
        json_targets.append({
          'target':tr['target'], 'discovery':tr.get('discovery',{}),
          'users':tr.get('users',[]),
          'cis':[x.as_json_dict() for x in tr.get('cis',[])],
          'esa':[x.as_json_dict() for x in tr.get('esa',[])],
          'benchmark':tr.get('benchmark'),
        })
    primary=used[0] if used and used[0] in BENCHMARKS else 16
    return {
      'metadata':{
        'tool':'pg-sec-audit','tool_version':TOOL_VERSION,
        'cis_benchmark':BENCHMARKS[primary]['label'],'benchmark_date':BENCHMARKS[primary]['date'],
        'cis_benchmarks':{str(m):BENCHMARKS[m]['label'] for m in used if m in BENCHMARKS},
        **{f'current_postgresql{m}_minor':baselines[m][0] for m in sorted(baselines)},
        'version_intelligence_source':source_value,
        'generated_at':time.strftime('%Y-%m-%dT%H:%M:%S%z'),'platform':platform.platform(),
      },
      'targets':json_targets,
      '_xlsx':{'summary':summary,'scoreboard':scoreboard,'discovery':discovery,'users':all_users,'cis':all_cis,'esa':all_esa,'evidence':all_ev},
    }

def save_reports(report: dict, output_dir: str|Path, prefix: str='postgres-security-report') -> tuple[Path,Path]:
    out=Path(output_dir);out.mkdir(parents=True,exist_ok=True)
    jpath=out/f'{prefix}.json';xpath=out/f'{prefix}.xlsx'
    payload={k:v for k,v in report.items() if k!='_xlsx'}
    atomic_write(jpath,json.dumps(payload,indent=2,ensure_ascii=False),0o600)
    write_xlsx(report['_xlsx'],xpath)
    try: os.chmod(xpath,0o600)
    except: pass
    return jpath,xpath
