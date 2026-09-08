from __future__ import annotations
import json, re, time, os
from pathlib import Path
from urllib.request import Request, urlopen
from .util import atomic_write

DEFAULTS = {16: "16.15", 18: "18.6"}
SUPPORTED_MAJORS = tuple(DEFAULTS)
VERSION_URL = "https://www.postgresql.org/support/versioning/"

def cache_path() -> Path:
    base=Path(os.environ.get('XDG_CACHE_HOME',Path.home()/'.cache'))/'pg-sec-audit'
    return base/'versions.json'

def _read_cache() -> dict:
    p=cache_path()
    try:
        data=json.loads(p.read_text(encoding='utf-8'))
        return data if isinstance(data,dict) else {}
    except Exception:
        return {}

def _write_cache(values: dict[int,str]) -> None:
    try:
        merged={k:v for k,v in _read_cache().items() if not k.startswith('postgresql')}
        for major,v in values.items():merged[f'postgresql{major}']=v
        merged['updated_at']=int(time.time());merged['source']=VERSION_URL
        atomic_write(cache_path(),json.dumps(merged,indent=2),0o600)
    except Exception:
        pass

def _parse_minor(html: str, major: int) -> str|None:
    # The versioning page lists one row per supported major with its current minor.
    m=re.search(rf'(?is)>\s*{major}\s*<.*?>\s*({major}\.\d+)\s*<',html)
    if not m:
        m=re.search(rf'\b{major}\s*\|\s*({major}\.\d+)\b',re.sub(r'<[^>]+>','|',html))
    return m.group(1) if m else None

def get_current_pgs(majors, allow_network: bool=True, timeout: float=2.0) -> dict[int,tuple[str,str]]:
    majors=[int(x) for x in dict.fromkeys(majors) if int(x) in DEFAULTS]
    out={m:(DEFAULTS[m],'bundled') for m in majors}
    if not majors:return out
    cache=_read_cache()
    if allow_network:
        try:
            req=Request(VERSION_URL,headers={'User-Agent':'pg-sec-audit/1.2 (+security-assessment)'})
            with urlopen(req,timeout=timeout) as r:
                html=r.read(400000).decode('utf-8','replace')
            found={m:v for m in majors if (v:=_parse_minor(html,m))}
            if found:
                _write_cache(found)
                for m,v in found.items():out[m]=(v,'online')
                return out
        except Exception:
            pass
    for m in majors:
        cached=cache.get(f'postgresql{m}')
        if cached and re.fullmatch(rf'{m}\.\d+',str(cached)):out[m]=(str(cached),'cache')
    return out

def get_current_pg16(allow_network: bool=True, timeout: float=2.0) -> tuple[str,str]:
    return get_current_pgs([16],allow_network,timeout)[16]
