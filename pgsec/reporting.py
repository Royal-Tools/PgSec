from __future__ import annotations
import json, time, platform, os
from pathlib import Path
from .xlsx_writer import write_xlsx
from .util import atomic_write, redact, sha256_file

STATUSES=('PASS','FAIL','WARN','REVIEW','ERROR','N/A','SKIPPED')


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


def build_report(target_reports: list[dict], version_source: str, current_pg16: str) -> dict:
    all_cis=[];all_esa=[];all_ev=[];discovery=[];scoreboard=[]
    counts={}
    scopes=set()
    for tr in target_reports:
        target=tr['target']; label=_target_label(target)
        scope, host = target_scope_and_host(target)
        scopes.add(scope)
        d=tr.get('discovery') or {}
        pg=d.get('postgres') or {}
        os_hostname='' if _is_local_target(target) else str((d.get('host') or {}).get('hostname') or '')
        sql_access=bool(pg.get('sql_access'))
        discovery.append({
            'Target':label,'Scope':scope,'Host':host,'OS Hostname':os_hostname,
            'Mode':target.get('mode',''),
            'Container':target.get('container_name') or target.get('container_id') or '',
            'PostgreSQL Detected': 'Yes' if pg.get('detected') else 'No',
            'Version':','.join(pg.get('versions',[])),
            'SQL Access': 'Yes' if sql_access else 'No',
            'OS':(d.get('host') or {}).get('os_release','')[:1000],
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
    summary=[
      {'Metric':'Generated At','Value':time.strftime('%Y-%m-%d %H:%M:%S %z')},
      {'Metric':'Assessment Scope','Value':scope_value},
      {'Metric':'Targets','Value':len(target_reports)},
      {'Metric':'CIS Pass Rate','Value':_pct(counts.get(('CIS','PASS'),0), cis_assessed)},
      {'Metric':'ESA Pass Rate','Value':_pct(counts.get(('ESA','PASS'),0), esa_assessed)},
      {'Metric':'Assessment Posture','Value':_posture(fail,error,review)},
      {'Metric':'CIS Benchmark','Value':'CIS PostgreSQL 16 Benchmark v1.1.0 (2025-06-30)'},
      {'Metric':'Current PostgreSQL 16 Minor','Value':current_pg16},
      {'Metric':'Version Intelligence Source','Value':version_source},
    ]
    for sec in ('CIS','ESA'):
        for status in STATUSES:
            summary.append({'Metric':f'{sec} {status}','Value':counts.get((sec,status),0)})
    json_targets=[]
    for tr in target_reports:
        json_targets.append({
          'target':tr['target'], 'discovery':tr.get('discovery',{}),
          'cis':[x.as_json_dict() for x in tr.get('cis',[])],
          'esa':[x.as_json_dict() for x in tr.get('esa',[])],
        })
    return {
      'metadata':{
        'tool':'pg-sec-audit','tool_version':'1.1.2','cis_benchmark':'CIS PostgreSQL 16 Benchmark v1.1.0',
        'benchmark_date':'2025-06-30','current_postgresql16_minor':current_pg16,'version_intelligence_source':version_source,
        'generated_at':time.strftime('%Y-%m-%dT%H:%M:%S%z'),'platform':platform.platform(),
      },
      'targets':json_targets,
      '_xlsx':{'summary':summary,'scoreboard':scoreboard,'discovery':discovery,'cis':all_cis,'esa':all_esa,'evidence':all_ev},
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
