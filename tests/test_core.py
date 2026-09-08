import re
import pytest
import json, os, sys, tempfile, zipfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pgsec.models import Result, CommandResult, Target
from pgsec.executors import LocalExecutor, ContainerExecutor, FakeExecutor
from pgsec.xlsx_writer import write_xlsx
from pgsec.rules import CIS16_RULES, CIS18_RULES, ESA_RULES
from pgsec.audit import Auditor
from pgsec.discovery import parse_container_listing


def test_rule_catalog_complete_and_unique():
    for catalog, total in ((CIS16_RULES,71),(CIS18_RULES,72)):
        ids = [r['id'] for r in catalog]
        assert len(ids) == total, len(ids)
        assert len(ids) == len(set(ids))
        assert ids[0] == '1.1'
        assert ids[-1] == '8.3'
    assert '4.10' not in {r['id'] for r in CIS16_RULES}
    assert '4.10' in {r['id'] for r in CIS18_RULES}
    assert [r['id'] for r in CIS16_RULES] == [r['id'] for r in CIS18_RULES if r['id']!='4.10']
    esa_ids = [r['id'] for r in ESA_RULES]
    assert len(esa_ids) >= 17
    assert len(esa_ids) == len(set(esa_ids))


def test_result_six_required_fields():
    r = Result('PASS','X','D','T','S','C')
    d = r.as_report_dict()
    assert list(d) == ['Status','Name','Description','Test Result','Solution','Security Comments']


def test_container_listing_parser():
    raw = 'abc123|pg-prod|postgres:16.15|Up 2 days|0.0.0.0:5432->5432/tcp\nxyz|api|app:1|Up|8080/tcp'
    rows = parse_container_listing(raw)
    assert rows[0]['id'] == 'abc123'
    assert rows[0]['postgres_candidate'] is True
    assert rows[1]['postgres_candidate'] is False


def test_container_executor_wraps_commands():
    base = FakeExecutor({'docker exec pg-prod sh -lc': CommandResult('', '', 0)})
    ex = ContainerExecutor(base, 'docker', 'pg-prod')
    cmd = ex.build_command('echo hello')
    assert cmd.startswith("docker exec")
    assert 'pg-prod' in cmd
    assert 'echo hello' in cmd


def test_xlsx_writer_creates_expected_sheets(tmp_path):
    data = {
      'summary': [{'Metric':'Targets','Value':1}],
      'discovery': [{'Host':'local','Value':'x'}],
      'cis': [Result('PASS','1.1 Test','D','T','S','C').as_report_dict()],
      'esa': [Result('WARN','ESA-01 Test','D','T','S','C').as_report_dict()],
      'evidence': [{'Source':'sql','Detail':'ok'}],
    }
    out = tmp_path/'report.xlsx'
    write_xlsx(data, out)
    assert out.exists() and out.stat().st_size > 1000
    with zipfile.ZipFile(out) as z:
        wb = z.read('xl/workbook.xml').decode()
        for name in ['Summary','Discovery','CIS','ESA','Evidence']:
            assert f'name="{name}"' in wb


def test_auditor_runs_with_fake_postgres():
    responses = {
      'SHOW server_version;': '16.15',
      'SHOW log_connections;': 'on',
      'SHOW log_disconnections;': 'on',
      'SHOW ssl;': 'on',
      'SHOW ssl_cert_file;': 'server.crt',
      'SHOW ssl_key_file;': 'server.key',
      'SHOW ssl_min_protocol_version;': 'TLSv1.3',
    }
    fake = FakeExecutor({}, sql_responses=responses)
    target = Target(mode='local', host='local')
    auditor = Auditor(fake, target, current_pg='16.15')
    results = auditor.run_cis(control_ids=['1.5','3.1.20','3.1.21','6.8','6.9'])
    by = {r.control_id:r.status for r in results}
    assert by['1.5'] == 'PASS'
    assert by['3.1.20'] == 'PASS'
    assert by['3.1.21'] == 'PASS'
    assert by['6.8'] == 'PASS'
    assert by['6.9'] == 'PASS'

from pgsec.app import load_targets

class PermissiveExecutor:
    kind='simulation'
    def __init__(self): self.commands=[]
    def run(self, command, timeout=20, env=None):
        self.commands.append(command)
        samples = [
          ('systemctl list-unit-files', 'postgresql-16.service enabled'),
          ('command -v docker', ''), ('command -v podman',''),
          ('hostname', 'sim-db-01'), ('uname -r','6.8.0-sim'), ('uname -m','x86_64'), ('id -un','audit'),
          ('cat /etc/os-release','NAME=Simulation\nID=sim'),
          ('command -v postgres','/usr/bin/postgres'), ('command -v psql','/usr/bin/psql'),
          ('postgres --version','postgres (PostgreSQL) 16.15'), ('psql --version','psql (PostgreSQL) 16.15'),
          ('ps -eo pid,args','100 postgres -D /var/lib/postgresql/16/data'),
          ('find /etc /var/lib','/etc/postgresql/16/main/postgresql.conf\n/etc/postgresql/16/main/pg_hba.conf'),
          ('stat -c', 'postgres:postgres 700 directory'),
          ('fips-mode-setup --check','FIPS mode is enabled.'), ('openssl version','OpenSSL 3.0.0 FIPS'),
          ('pgbackrest','stanza: main\nstatus: ok'),
        ]
        for needle, out in samples:
            if needle in command: return CommandResult(out,'',0)
        return CommandResult('', '', 0)
    def sql(self, sql, timeout=20):
        self.commands.append('SQL:'+sql)
        settings={
          'server_version':'16.15','data_directory':'/var/lib/postgresql/16/data','config_file':'/etc/postgresql/16/main/postgresql.conf','hba_file':'/etc/postgresql/16/main/pg_hba.conf',
          'log_destination':'stderr','logging_collector':'on','log_directory':'/var/log/postgresql','log_filename':'postgresql-%Y%m%d.log','log_file_mode':'0600',
          'log_truncate_on_rotation':'on','log_rotation_age':'1d','log_rotation_size':'1GB','syslog_facility':'LOCAL0','syslog_sequence_numbers':'on','syslog_split_messages':'on','syslog_ident':'postgres',
          'log_min_messages':'warning','log_min_error_statement':'error','debug_print_parse':'off','debug_print_rewritten':'off','debug_print_plan':'off','debug_pretty_print':'on',
          'log_connections':'on','log_disconnections':'on','log_error_verbosity':'verbose','log_hostname':'off','log_line_prefix':'%m [%p]: [%l-1] db=%d,user=%u,app=%a,client=%h ','log_statement':'ddl','log_timezone':'UTC',
          'shared_preload_libraries':'pgaudit,set_user','pgaudit.log':'ddl,write','listen_addresses':'127.0.0.1','ssl':'on','ssl_cert_file':'server.crt','ssl_key_file':'server.key','ssl_min_protocol_version':'TLSv1.3',
          'ssl_ciphers':'ECDHE-RSA-AES256-GCM-SHA384','password_encryption':'scram-sha-256','log_replication_commands':'on','archive_mode':'on','archive_command':'cp %p /archive/%f','archive_library':'',
          'dynamic_library_path':'$libdir','temp_file_limit':'1GB','unix_socket_directories':'/var/run/postgresql','unix_socket_permissions':'0770','output_plugin_libraries':'pgoutput,test_decoding'
        }
        st=sql.strip()
        m=re.match(r'^SHOW\s+([A-Za-z0-9_.]+);$',st,re.I)
        if m: return CommandResult(settings.get(m.group(1).lower(),'on'),' ',0)
        if 'pg_available_extensions' in sql and "pgcrypto" in sql: return CommandResult('pgcrypto|1.3|1.3','',0)
        if 'pg_available_extensions' in sql and "set_user" in sql: return CommandResult('set_user|4.1.0|4.1.0','',0)
        if 'pg_available_extensions' in sql: return CommandResult('pgcrypto|1.3|1.3\npgaudit|1.7|1.7','',0)
        if 'pg_hba_file_rules' in sql: return CommandResult('hostssl|{all}|{all}|127.0.0.1/32|scram-sha-256|','',0)
        if 'pg_file_settings' in sql: return CommandResult('/etc/postgresql.conf|1|ssl|on|t|','',0)
        if 'pg_stat_archiver' in sql: return CommandResult('10|00000001000000000000000A|2026-09-02|0||','',0)
        if 'pg_stat_database' in sql and 'checksum' in sql: return CommandResult('postgres|0|','',0)
        if 'pg_replication_slots' in sql: return CommandResult('slot1|t|physical|0/100|0/100|','',0)
        if 'pg_stat_ssl' in sql: return CommandResult('123|t|TLSv1.3|TLS_AES_256_GCM_SHA384','',0)
        if 'rolconnlimit' in sql: return CommandResult('app|20','',0)
        if 'rolpassword' in sql: return CommandResult('app|SCRAM','',0)
        if 'rolsuper' in sql: return CommandResult('postgres|t','',0)
        if 'prosecdef' in sql: return CommandResult('', '',0)
        return CommandResult('', '', 0)

def test_full_catalog_executes_without_internal_errors():
    ex=PermissiveExecutor(); target=Target(mode='local',host='local')
    aud=Auditor(ex,target,current_pg='16.15',context={'postgres':{'pgdata':'/var/lib/postgresql/16/data'},'host':{},'container':{}})
    cis=aud.run_cis(); esa=aud.run_esa()
    assert len(cis)==71
    assert len(esa)>=18
    assert all('Internal check error' not in r.test_result for r in cis+esa)
    assert all(r.status in {'PASS','FAIL','WARN','REVIEW','ERROR','N/A','SKIPPED'} for r in cis+esa)

def test_ip_list_and_cidr_loader(tmp_path):
    f=tmp_path/'targets.txt'; f.write_text('# comment\n10.0.0.1\n10.0.0.4/30\ndb.example\n')
    assert load_targets(str(f)) == ['10.0.0.1','10.0.0.5','10.0.0.6','db.example']

@pytest.mark.skipif(os.name=='nt',reason='executing a .py helper directly requires a POSIX exec layer')
def test_ssh_password_not_exposed_in_argv(tmp_path, monkeypatch):
    helper=tmp_path/'helper.py'; arglog=tmp_path/'args.txt'; stdinlog=tmp_path/'stdin.txt'
    helper.write_text("#!/usr/bin/env python3\nimport sys, pathlib\npathlib.Path(%r).write_text('\\n'.join(sys.argv[1:]))\npathlib.Path(%r).write_text(sys.stdin.read())\nprint('ok')\n" % (str(arglog),str(stdinlog)))
    helper.chmod(0o755)
    from pgsec.executors import SSHExecutor
    pw='UltraSecret-DoNotLeak-9921'
    ex=SSHExecutor('127.0.0.1','audit',password=pw,helper=str(helper),known_hosts=str(tmp_path/'known_hosts'))
    r=ex.run('printf hello')
    assert r.rc==0
    assert pw not in arglog.read_text()
    assert '--password-stdin' in arglog.read_text()
    assert stdinlog.read_text().strip()==pw

def test_terminal_handles_empty_failure_result(capsys):
    from pgsec import terminal
    r=Result('FAIL','X','D','','S','C')
    terminal.print_control(r,1,1)
    assert 'FAIL' in capsys.readouterr().out


def test_full_catalog_pg18_executes_without_internal_errors():
    class PermissiveExecutor18(PermissiveExecutor):
        def sql(self, sql, timeout=20):
            if re.match(r'^SHOW\s+server_version;$',sql.strip(),re.I): return CommandResult('18.6',' ',0)
            return super().sql(sql,timeout)
    ex=PermissiveExecutor18(); target=Target(mode='local',host='local')
    aud=Auditor(ex,target,current_pg='18.6',benchmark=18,context={'postgres':{'pgdata':'/var/lib/postgresql/16/data'},'host':{},'container':{}})
    cis=aud.run_cis(); esa=aud.run_esa()
    assert len(cis)==72
    assert len(esa)>=18
    assert all('Internal check error' not in r.test_result for r in cis+esa)
    assert all(r.status in {'PASS','FAIL','WARN','REVIEW','ERROR','N/A','SKIPPED'} for r in cis+esa)


def test_resolve_benchmark_selection_modes():
    from pgsec.app import resolve_benchmark
    assert resolve_benchmark(18,16)==18          # forced preference wins
    assert resolve_benchmark(16,18)==16
    assert resolve_benchmark(None,16)==16        # auto-detect
    assert resolve_benchmark(None,18)==18
    assert resolve_benchmark(None,None)=='ASK'   # undetectable -> interactive ask
    assert resolve_benchmark(None,17) is None    # unsupported major -> no CIS score
