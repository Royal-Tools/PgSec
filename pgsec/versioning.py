from __future__ import annotations
import json, re, time, os
from pathlib import Path
from urllib.request import Request, urlopen
from .util import atomic_write

DEFAULT_PG16 = "16.15"
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

def _write_cache(v: str) -> None:
    try:
        atomic_write(cache_path(),json.dumps({'postgresql16':v,'updated_at':int(time.time()),'source':VERSION_URL},indent=2),0o600)
    except Exception:
        pass

def get_current_pg16(allow_network: bool=True, timeout: float=2.0) -> tuple[str,str]:
    cache=_read_cache()
    cached=cache.get('postgresql16')
    if allow_network:
        try:
            req=Request(VERSION_URL,headers={'User-Agent':'pg-sec-audit/1.0 (+security-assessment)'})
            with urlopen(req,timeout=timeout) as r:
                html=r.read(400000).decode('utf-8','replace')
            # Current versioning page contains a row with major 16 and current minor.
            m=re.search(r'(?is)>\s*16\s*<.*?>\s*(16\.\d+)\s*<',html)
            if not m:
                m=re.search(r'\b16\s*\|\s*(16\.\d+)\b',re.sub(r'<[^>]+>','|',html))
            if m:
                v=m.group(1); _write_cache(v); return v,'online'
        except Exception:
            pass
    if cached and re.fullmatch(r'16\.\d+',str(cached)):
        return str(cached),'cache'
    return DEFAULT_PG16,'bundled'
