from __future__ import annotations
import os, sys, shutil, re

USE_COLOR = sys.stdout.isatty() and os.environ.get('NO_COLOR') is None
C = {
 'reset':'\033[0m','bold':'\033[1m','dim':'\033[2m','blue':'\033[94m','cyan':'\033[96m',
 'green':'\033[92m','red':'\033[91m','yellow':'\033[93m','magenta':'\033[95m','gray':'\033[90m','white':'\033[97m'
}

def color(text, name):
    return (C.get(name,'')+str(text)+C['reset']) if USE_COLOR else str(text)

def clear_line():
    if USE_COLOR: print('\r\033[K',end='')

def banner():
    w=min(86,shutil.get_terminal_size((100,24)).columns)
    title=' PostgreSQL Security Assessment Engine '
    print(color('╭'+'─'*(w-2)+'╮','cyan'))
    print(color('│','cyan')+color(title.center(w-2),'bold')+color('│','cyan'))
    print(color('│','cyan')+(' CIS PostgreSQL 16 v1.1.0  •  Enhanced Security Assessment (ESA) ').center(w-2)+color('│','cyan'))
    print(color('╰'+'─'*(w-2)+'╯','cyan'))

def status_badge(status):
    s=status.upper(); cmap={'PASS':'green','FAIL':'red','WARN':'yellow','REVIEW':'blue','ERROR':'red','N/A':'gray','SKIPPED':'gray'}
    return color(f'{s:<7}',cmap.get(s,'white'))

def print_control(res, current=None, total=None):
    prog=f'[{current:>2}/{total:<2}] ' if current and total else ''
    name=re.sub(r'\s+',' ',res.name)
    print(f"{color(prog,'dim')}{status_badge(res.status)} {name}")
    if res.status in {'FAIL','WARN','ERROR'}:
        lines=(res.test_result or '').splitlines()
        first=(lines[0] if lines else '')[:170]
        if first: print(color('          ↳ '+first,'dim'))
    elif res.status == 'REVIEW':
        req=getattr(res,'required_input','') or ''
        if req: print(color('          ↳ Required input: '+req[:165],'dim'))

def section(title):
    print('\n'+color('── '+title+' '+('─'*max(0,70-len(title))),'bold'))

def info(msg): print(color('[+] ','green')+msg)
def warn(msg): print(color('[!] ','yellow')+msg)
def error(msg): print(color('[-] ','red')+msg)
def step(msg): print(color('[*] ','cyan')+msg)
