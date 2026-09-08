import zipfile
from pathlib import Path

from pgsec.audit import Auditor
from pgsec.executors import FakeExecutor
from pgsec.models import CommandResult, Result, Target
from pgsec.reporting import build_report
from pgsec.xlsx_writer import write_xlsx


def _result_status(aud, cid):
    return aud.run_cis(control_ids=[cid])[0]


def _esa_status(aud, cid):
    return aud.run_esa(control_ids=[cid])[0]


def test_cis_major_mismatch_is_not_scored_as_cis16():
    fake = FakeExecutor(sql_responses={'SHOW server_version;': '18.6'})
    aud = Auditor(fake, Target('local'), current_pg='16.15')
    rows = aud.run_cis(control_ids=['3.1.20','6.8'])
    assert [x.status for x in rows] == ['N/A','N/A']
    assert all('PostgreSQL 16' in x.test_result for x in rows)


def test_cis_2_1_umask_is_fully_automated_pass_and_fail():
    good = FakeExecutor({'/proc/': CommandResult('Umask:\t0077', '', 0)})
    aud = Auditor(good, Target('local'), context={'postgres': {'processes': '101 postgres -D /data'}})
    assert _result_status(aud,'2.1').status == 'PASS'

    bad = FakeExecutor({'/proc/': CommandResult('Umask:\t0022', '', 0)})
    aud = Auditor(bad, Target('local'), context={'postgres': {'processes': '101 postgres -D /data'}})
    r = _result_status(aud,'2.1')
    assert r.status == 'FAIL'
    assert '0022' in r.test_result


def test_cis_2_4_service_file_password_is_fully_automated():
    clean = FakeExecutor({'pg_service.conf': CommandResult('', '', 0)})
    aud = Auditor(clean, Target('local'))
    assert _result_status(aud,'2.4').status == 'PASS'

    exposed = FakeExecutor({'pg_service.conf': CommandResult('/etc/pg_service.conf:7:password=<redacted>', '', 0)})
    aud = Auditor(exposed, Target('local'))
    assert _result_status(aud,'2.4').status == 'FAIL'


def test_syslog_facility_valid_is_pass_not_review():
    fake = FakeExecutor(sql_responses={'SHOW server_version;':'16.15','SHOW log_destination;':'syslog','SHOW syslog_facility;':'local1'})
    aud = Auditor(fake, Target('local'))
    assert _result_status(aud,'3.1.10').status == 'PASS'


def test_container_sudo_control_is_not_applicable():
    fake = FakeExecutor(sql_responses={'SHOW server_version;':'16.15'})
    aud = Auditor(fake, Target('local-container', container_id='abc'))
    assert _result_status(aud,'4.2').status == 'N/A'


def test_admin_privilege_check_allows_replication_only_but_fails_bypassrls():
    sql = "SELECT rolname,rolsuper,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls,rolcanlogin FROM pg_roles WHERE rolname !~ '^pg_' ORDER BY rolname;"
    good = FakeExecutor(sql_responses={'SHOW server_version;':'16.15', sql: 'postgres|t|t|t|t|t|t\nrepl|f|f|f|t|f|t'})
    assert _result_status(Auditor(good,Target('local')),'4.3').status == 'PASS'
    bad = FakeExecutor(sql_responses={'SHOW server_version;':'16.15', sql: 'postgres|t|t|t|t|t|t\napp|f|f|f|f|t|t'})
    assert _result_status(Auditor(bad,Target('local')),'4.3').status == 'FAIL'


def test_replication_only_control_is_na_when_replication_unused():
    role_sql = "SELECT rolname,rolsuper,rolreplication,rolcanlogin FROM pg_roles WHERE rolreplication ORDER BY 1;"
    fake = FakeExecutor(sql_responses={
        'SHOW server_version;':'16.15', role_sql:'postgres|t|t|t',
        "SELECT count(*) FROM pg_stat_replication;": '0',
        "SELECT count(*) FROM pg_replication_slots;": '0',
        "SHOW primary_conninfo;": '',
    })
    assert _result_status(Auditor(fake,Target('local')),'7.1').status == 'N/A'


def test_esa_no_expiry_is_information_not_warning():
    sql="SELECT rolname,rolvaliduntil FROM pg_authid WHERE rolcanlogin AND rolname !~ '^pg_' ORDER BY 1;"
    fake=FakeExecutor(sql_responses={sql:'app|', 'SHOW server_version;':'16.15'})
    r=_esa_status(Auditor(fake,Target('local')),'ESA-04')
    assert r.status == 'PASS'
    assert 'no-expiry=1' in r.test_result


def test_esa_replication_slot_unbounded_is_pass_when_no_slots():
    slot_sql="SELECT slot_name,slot_type,active,wal_status,pg_size_pretty(CASE WHEN restart_lsn IS NULL THEN 0 ELSE pg_wal_lsn_diff(pg_current_wal_lsn(),restart_lsn) END) retained FROM pg_replication_slots ORDER BY active,slot_name;"
    fake=FakeExecutor(sql_responses={slot_sql:'','SHOW max_slot_wal_keep_size;':'-1','SHOW server_version;':'16.15'})
    assert _esa_status(Auditor(fake,Target('local')),'ESA-12').status == 'PASS'


def test_esa_container_identity_uses_actual_postgres_process_not_empty_image_user():
    meta={'privileged':False,'user':'','cap_add':[],'security_opt':[],'readonly_rootfs':False}
    fake=FakeExecutor({'ps -o uid=':CommandResult('999 postgres','',0)},sql_responses={'SHOW server_version;':'16.15'})
    aud=Auditor(fake,Target('local-container',container_id='x'),context={'container':meta})
    assert _esa_status(aud,'ESA-13').status == 'PASS'


def test_esa_secret_env_and_wildcard_port_are_fail_not_warn():
    meta={'secret_env_names':['POSTGRES_PASSWORD'],'port_bindings':[{'container_port':'5432/tcp','host_ip':'','host_port':'5432'}]}
    aud=Auditor(FakeExecutor(sql_responses={'SHOW server_version;':'16.15'}),Target('local-container',container_id='x'),context={'container':meta})
    assert _esa_status(aud,'ESA-14').status == 'FAIL'
    assert _esa_status(aud,'ESA-16').status == 'FAIL'


def test_esa_extension_inventory_does_not_review_builtins_only():
    sql="SELECT 'EXT|'||e.extname||'|'||e.extversion||'|'||n.nspname FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace ORDER BY 1; SELECT 'LANG|'||lanname||'|'||lanpltrusted FROM pg_language ORDER BY 1;"
    fake=FakeExecutor(sql_responses={sql:'EXT|plpgsql|1.0|pg_catalog\nLANG|c|f\nLANG|internal|f\nLANG|plpgsql|t\nLANG|sql|t','SHOW server_version;':'16.15'})
    assert _esa_status(Auditor(fake,Target('local')),'ESA-18').status == 'PASS'


def test_reporting_keeps_requested_six_columns_first():
    tr={'target':{'label':'local','host':'local','mode':'local'},'discovery':{},'cis':[Result('PASS','X','D','T','S','C')],'esa':[]}
    report=build_report([tr],{16:('16.15','cache')})
    keys=list(report['_xlsx']['cis'][0].keys())
    assert keys[:6] == ['Status','Name','Description','Test Result','Solution','Security Comments']
    assert keys[6:9] == ['Required Customer Input','Customer Response / Evidence','Auditor Decision']
    assert keys[9] == 'Target'


def test_xlsx_has_title_header_freeze_and_status_style(tmp_path):
    data={
      'summary':[{'Metric':'Targets','Value':1}], 'discovery':[{'Target':'local','Mode':'local'}],
      'cis':[{'Status':'FAIL','Name':'1.1 X','Description':'D','Test Result':'T','Solution':'S','Security Comments':'C','Target':'local'}],
      'esa':[{'Status':'PASS','Name':'ESA-01 X','Description':'D','Test Result':'T','Solution':'S','Security Comments':'C','Target':'local'}],
      'evidence':[{'Target':'local','Section':'CIS','Control':'1.1','Source':'OS','Detail':'x','Command':'cmd','Return Code':0,'Timestamp':'now'}],
    }
    out=tmp_path/'r.xlsx'; write_xlsx(data,out)
    with zipfile.ZipFile(out) as z:
        cis=z.read('xl/worksheets/sheet4.xml').decode()
        assert '<mergeCell ref="A1:G1"/>' in cis
        assert 'ySplit="2"' in cis
        assert 'r="A3" s="3"' in cis  # FAIL status is colored after title/header
        assert 'autoFilter ref="A2:G3"' in cis


def test_review_result_explains_exact_required_customer_input_for_optional_packages():
    fake = FakeExecutor({
        "rpm -qa": CommandResult("postgresql16-server-16.15\npostgresql16-docs-16.15", "", 0),
    }, sql_responses={'SHOW server_version;':'16.15'})
    r = _result_status(Auditor(fake, Target('local')),'1.2')
    assert r.status == 'REVIEW'
    assert r.required_input
    assert 'business' in r.required_input.lower()
    assert 'package' in r.required_input.lower()
    assert 'Required input from customer/employer:' not in r.security_comments


def test_optional_packages_become_deterministic_with_required_packages_policy():
    responses={"rpm -qa": CommandResult("postgresql16-server-16.15\npostgresql16-docs-16.15", "", 0)}
    allowed = Auditor(FakeExecutor(responses, sql_responses={'SHOW server_version;':'16.15'}), Target('local'), context={'policy':{'required_packages':['postgresql16-docs']}})
    denied = Auditor(FakeExecutor(responses, sql_responses={'SHOW server_version;':'16.15'}), Target('local'), context={'policy':{'required_packages':[],'required_packages_policy_enforced':True}})
    assert _result_status(allowed,'1.2').status == 'PASS'
    assert _result_status(denied,'1.2').status == 'FAIL'


def test_every_review_is_actionable_and_json_contains_required_input():
    # DML authorization is one of the truly business-dependent CIS cases.
    sql="SELECT grantee,table_schema,table_name,privilege_type FROM information_schema.role_table_grants WHERE table_schema NOT IN ('pg_catalog','information_schema') AND privilege_type IN ('INSERT','UPDATE','DELETE','TRUNCATE') ORDER BY 1,2,3,4;"
    fake=FakeExecutor(sql_responses={'SHOW server_version;':'16.15', sql:'app_user|public|orders|UPDATE'})
    r=_result_status(Auditor(fake,Target('local')),'4.6')
    assert r.status == 'REVIEW'
    assert r.required_input
    assert 'Required input from customer/employer:' not in r.security_comments
    jd=r.as_json_dict()
    assert jd['required_input'] == r.required_input


def test_review_required_input_is_visible_in_excel_security_comments(tmp_path):
    r=Result('REVIEW','1.2 Install only required packages','D','optional package found','S','C',required_input='Provide the packages required for the business/application.')
    tr={'target':{'label':'local','host':'local','mode':'local'},'discovery':{},'cis':[r],'esa':[]}
    report=build_report([tr],{16:('16.15','cache')})
    assert report['_xlsx']['cis'][0]['Required Customer Input'] == r.required_input
    assert 'Required input from customer/employer:' not in report['_xlsx']['cis'][0]['Security Comments']
    out=tmp_path/'review.xlsx'; write_xlsx(report['_xlsx'],out)
    with zipfile.ZipFile(out) as z:
        cis=z.read('xl/worksheets/sheet4.xml').decode()
        assert 'Required Customer Input' in cis
        assert 'Provide the packages required for the business/application.' in cis


def test_internal_repository_becomes_deterministic_with_approved_repository_pattern():
    fake=FakeExecutor({
        'rpm -qa':CommandResult('postgresql16-server-16.15','',0),
        'dnf repolist':CommandResult('Repo-id : corp-pgdg\nRepo-baseurl : https://repo.company.example/postgresql/16','',0),
    },sql_responses={'SHOW server_version;':'16.15'})
    aud=Auditor(fake,Target('local'),context={'policy':{'approved_repository_patterns':['repo.company.example/postgresql']}})
    r=_result_status(aud,'1.1')
    assert r.status == 'PASS'


def test_cis_sheet_has_dedicated_customer_review_workflow_columns():
    r=Result('REVIEW','1.2 Install only required packages','D','optional package found','S','Attack surface concern.',required_input='Provide the exact business-required PostgreSQL packages and approved purpose for each optional package.')
    tr={'target':{'label':'local','host':'local','mode':'local'},'discovery':{},'cis':[r],'esa':[]}
    report=build_report([tr],{16:('16.15','cache')})
    row=report['_xlsx']['cis'][0]
    assert list(row.keys()) == [
        'Status','Name','Description','Test Result','Solution','Security Comments',
        'Required Customer Input','Customer Response / Evidence','Auditor Decision','Target'
    ]
    assert row['Required Customer Input'] == r.required_input
    assert row['Customer Response / Evidence'] == ''
    assert row['Auditor Decision'] == ''
    assert 'Required input from customer/employer:' not in row['Security Comments']


def test_non_review_cis_row_has_blank_customer_review_fields():
    r=Result('PASS','1.4 Data Cluster','D','ok','S','C')
    tr={'target':{'label':'local','host':'local','mode':'local'},'discovery':{},'cis':[r],'esa':[]}
    row=build_report([tr],{16:('16.15','cache')})['_xlsx']['cis'][0]
    assert row['Required Customer Input'] == ''
    assert row['Customer Response / Evidence'] == ''
    assert row['Auditor Decision'] == ''


def test_all_known_cis_review_inputs_are_specific_not_generic():
    aud=Auditor(FakeExecutor(sql_responses={'SHOW server_version;':'16.15'}),Target('local'))
    expected={
      '1.1':('repository','sign'),
      '1.2':('package','business'),
      '4.4':('login','owner'),
      '4.6':('dml','schema'),
      '4.7':('row level security','table'),
      '6.7':('fips','requirement'),
    }
    for cid, needles in expected.items():
        req=aud.REVIEW_REQUIRED_INPUT[cid].lower()
        assert all(n in req for n in needles), (cid,req)
        assert 'organization policy/business requirement and the requested evidence' not in req


def test_xlsx_cis_sheet_contains_review_workflow_headers(tmp_path):
    data={
      'summary':[{'Metric':'Targets','Value':1}], 'discovery':[{'Target':'local','Mode':'local'}],
      'cis':[{
          'Status':'REVIEW','Name':'1.2 X','Description':'D','Test Result':'T','Solution':'S','Security Comments':'C',
          'Required Customer Input':'Provide package business justification.','Customer Response / Evidence':'','Auditor Decision':'','Target':'local'
      }],
      'esa':[], 'evidence':[],
    }
    out=tmp_path/'review-workflow.xlsx'; write_xlsx(data,out)
    with zipfile.ZipFile(out) as z:
        cis=z.read('xl/worksheets/sheet4.xml').decode()
        assert 'Required Customer Input' in cis
        assert 'Customer Response / Evidence' in cis
        assert 'Auditor Decision' in cis
        assert 'Provide package business justification.' in cis


def test_summary_sheet_contains_status_chart_parts(tmp_path):
    data={
      'summary':[
        {'Metric':'Targets','Value':1},
        {'Metric':'CIS PASS','Value':50},{'Metric':'CIS FAIL','Value':10},{'Metric':'CIS WARN','Value':0},{'Metric':'CIS REVIEW','Value':6},{'Metric':'CIS ERROR','Value':0},{'Metric':'CIS N/A','Value':5},{'Metric':'CIS SKIPPED','Value':0},
        {'Metric':'ESA PASS','Value':14},{'Metric':'ESA FAIL','Value':3},{'Metric':'ESA WARN','Value':0},{'Metric':'ESA REVIEW','Value':1},{'Metric':'ESA ERROR','Value':0},{'Metric':'ESA N/A','Value':0},{'Metric':'ESA SKIPPED','Value':0},
      ],
      'discovery':[], 'cis':[], 'esa':[], 'evidence':[],
    }
    out=tmp_path/'summary-chart.xlsx'; write_xlsx(data,out)
    with zipfile.ZipFile(out) as z:
        names=set(z.namelist())
        assert 'xl/charts/chart1.xml' in names
        assert 'xl/drawings/drawing1.xml' in names
        assert 'xl/drawings/_rels/drawing1.xml.rels' in names
        assert 'xl/worksheets/_rels/sheet1.xml.rels' in names
        summary=z.read('xl/worksheets/sheet1.xml').decode()
        chart=z.read('xl/charts/chart1.xml').decode()
        assert '<drawing r:id="rId1"/>' in summary
        assert 'Assessment Status Distribution' in chart
        assert "Summary!$D$4:$D$10" in chart
        assert "Summary!$E$4:$E$10" in chart
        assert "Summary!$F$4:$F$10" in chart


def test_summary_chart_has_named_series_and_cached_status_labels(tmp_path):
    data={
      'summary':[{'Metric':'CIS PASS','Value':3},{'Metric':'ESA PASS','Value':2}],
      'discovery':[], 'cis':[], 'esa':[], 'evidence':[],
    }
    out=tmp_path/'named-chart.xlsx'; write_xlsx(data,out)
    with zipfile.ZipFile(out) as z:
        chart=z.read('xl/charts/chart1.xml').decode()
        assert '<c:v>CIS</c:v>' in chart
        assert '<c:v>ESA</c:v>' in chart
        assert '<c:v>PASS</c:v>' in chart
        assert '<c:ptCount val="7"/>' in chart


def test_local_report_host_is_local_not_os_hostname():
    tr={'target':{'label':'local/pg','host':'local','mode':'local-container','container_name':'pg'},
        'discovery':{'host':{'hostname':'DESKTOP-I6RJHHQ','os_release':'Ubuntu'},'postgres':{'detected':True,'versions':['16.14'],'sql_access':False}},
        'cis':[],'esa':[]}
    report=build_report([tr],{16:('16.15','bundled')})
    row=report['_xlsx']['discovery'][0]
    assert row['Host']=='local'
    assert row['Scope']=='Local'
    assert row['OS Hostname']==''
    assert row['Target'].startswith('local/')
    assert report['_xlsx']['summary'][1]['Value']=='Local'


def test_remote_report_host_is_entered_ip():
    tr={'target':{'label':'10.0.0.11','host':'10.0.0.11','mode':'remote-host'},
        'discovery':{'host':{'hostname':'db-prod-01','os_release':'RHEL'},'postgres':{'detected':True,'versions':['16.15'],'sql_access':True}},
        'cis':[Result('PASS','X','D','T','S','C')],'esa':[]}
    report=build_report([tr],{16:('16.15','cache')})
    row=report['_xlsx']['discovery'][0]
    assert row['Host']=='10.0.0.11'
    assert row['Scope']=='Remote'
    assert row['OS Hostname']=='db-prod-01'
    board=report['_xlsx']['scoreboard'][0]
    assert board['Host']=='10.0.0.11'
    assert 'CIS Pass Rate' in {x['Metric'] for x in report['_xlsx']['summary']}


def test_summary_scoreboard_and_pass_rate_in_xlsx(tmp_path):
    tr={'target':{'label':'local','host':'local','mode':'local'},'discovery':{},'cis':[Result('PASS','X','D','T','S','C')],'esa':[]}
    report=build_report([tr],{16:('16.15','cache')})
    out=tmp_path/'summary-modern.xlsx'; write_xlsx(report['_xlsx'],out)
    with zipfile.ZipFile(out) as z:
        summary=z.read('xl/worksheets/sheet1.xml').decode()
        assert 'Executive Summary' in summary
        assert 'Target Scoreboard' in summary
        assert 'CIS Pass Rate' in summary
        assert 'Assessment Posture' in summary
        chart=z.read('xl/charts/chart1.xml').decode()
        assert "Summary!$D$4:$D$10" in chart



def test_users_sheet_lists_database_roles_with_target(tmp_path):
    users=[{'Role':'postgres','Type':'Login','Login':'Yes','Superuser':'Yes','CreateRole':'Yes','CreateDB':'Yes','Replication':'Yes','BypassRLS':'Yes','Connection Limit':'-1','Valid Until':'never','Password Verifier':'SCRAM-SHA-256','Member Of':''},
           {'Role':'app_user','Type':'Login','Login':'Yes','Superuser':'No','CreateRole':'No','CreateDB':'No','Replication':'No','BypassRLS':'No','Connection Limit':'20','Valid Until':'never','Password Verifier':'SCRAM-SHA-256','Member Of':''}]
    tr={'target':{'label':'local','host':'local','mode':'local','cis_benchmark':'CIS PostgreSQL 16 Benchmark v1.1.0'},'discovery':{},'users':users,'cis':[],'esa':[],'benchmark':16}
    report=build_report([tr],{16:('16.15','cache')})
    assert report['_xlsx']['users'][0]['Target']=='local'
    assert report['_xlsx']['users'][0]['Role']=='postgres'
    assert list(report['_xlsx']['users'][0])[0]=='Target'
    out=tmp_path/'users.xlsx'; write_xlsx(report['_xlsx'],out)
    with zipfile.ZipFile(out) as z:
        wb=z.read('xl/workbook.xml').decode()
        assert 'name="Users"' in wb
        sheet3=z.read('xl/worksheets/sheet3.xml').decode()
        assert 'postgres' in sheet3 and 'app_user' in sheet3 and 'Password Verifier' in sheet3


def test_discovery_sheet_is_enriched_with_environment_and_postgres_details():
    tr={'target':{'label':'10.0.0.11','host':'10.0.0.11','mode':'remote-host'},
        'discovery':{'host':{'hostname':'db-prod-01','os_release':'NAME="Red Hat Enterprise Linux"\nPRETTY_NAME="Red Hat Enterprise Linux 9.4"\n','kernel':'5.14.0','architecture':'x86_64','whoami':'audit','container_runtimes':['docker']},
                     'postgres':{'detected':True,'versions':['16.15'],'sql_access':True,'pgdata':'/var/lib/pgsql/16/data','config_file':'/etc/postgresql.conf','hba_file':'/etc/pg_hba.conf','binaries':['/usr/bin/postgres'],'services':['postgresql-16.service enabled'],'config_files':['/etc/postgresql.conf']}},
        'cis':[],'esa':[],'benchmark':16}
    row=build_report([tr],{16:('16.15','cache')})['_xlsx']['discovery'][0]
    assert row['OS Release']=='Red Hat Enterprise Linux 9.4'
    assert row['Kernel']=='5.14.0' and row['Architecture']=='x86_64' and row['Audit User']=='audit'
    assert row['Data Directory']=='/var/lib/pgsql/16/data'
    assert row['Config File']=='/etc/postgresql.conf' and row['HBA File']=='/etc/pg_hba.conf'
    assert row['PostgreSQL Binaries']=='/usr/bin/postgres'
    assert row['Systemd Services']=='postgresql-16.service enabled'
    assert row['Config Files Found']==1
    assert row['CIS Benchmark']=='CIS PostgreSQL 16 Benchmark v1.1.0'


def test_discovery_container_metadata_columns():
    tr={'target':{'label':'local/pg-prod','host':'local','mode':'local-container','container_name':'pg-prod'},
        'discovery':{'container':{'image':'postgres:16.15','user':'postgres','privileged':False,'port_bindings':[{'container_port':'5432/tcp','host_ip':'','host_port':'5432'}]},'postgres':{'detected':True,'versions':['16.15']}},
        'cis':[],'esa':[],'benchmark':16}
    row=build_report([tr],{})['_xlsx']['discovery'][0]
    assert row['Container Image']=='postgres:16.15'
    assert row['Container Privileged']=='No'
    assert row['Container Ports']=='*:5432->5432/tcp'


def test_test_result_embeds_real_command_output_redacted():
    fake=FakeExecutor({'environ':CommandResult('PGPASSWORD=UltraSecret123','/proc/4242/environ',0)},sql_responses={'SHOW server_version;':'16.15'})
    r=_result_status(Auditor(fake,Target('local')),'1.7')
    assert r.status=='FAIL'
    assert '/proc/' in r.test_result           # the command context is present
    assert 'UltraSecret123' not in r.test_result  # secret redacted
    assert 'PGPASSWORD=<REDACTED>' in r.test_result


def test_setting_result_includes_raw_show_output():
    fake=FakeExecutor(sql_responses={'SHOW server_version;':'16.15','SHOW log_hostname;':'off'})
    r=_result_status(Auditor(fake,Target('local')),'3.1.23')
    assert r.status=='PASS'
    assert 'log_hostname' in r.test_result and ('off' in r.test_result or 'log_hostname=off' in r.test_result)
