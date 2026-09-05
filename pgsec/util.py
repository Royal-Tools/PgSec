from __future__ import annotations
import re, shlex, os, json, hashlib, time
from pathlib import Path
from typing import Any, Iterable

SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key)\s*[=:]\s*([^\s,;]+)"),
    re.compile(r"(?i)(postgres(?:ql)?://[^:\s/@]+:)([^@\s]+)(@)"),
]

def shell_quote(v: str) -> str:
    return shlex.quote(str(v))

def redact(text: str | None) -> str:
    if not text:
        return ""
    s = str(text)
    s = SECRET_PATTERNS[0].sub(lambda m: f"{m.group(1)}=<REDACTED>", s)
    s = SECRET_PATTERNS[1].sub(lambda m: f"{m.group(1)}<REDACTED>{m.group(3)}", s)
    return s

def truncate(text: str, n: int = 4000) -> str:
    text = redact(text)
    if len(text) <= n:
        return text
    return text[:n] + f"... <truncated {len(text)-n} chars>"

def parse_version(text: str) -> str | None:
    m = re.search(r"(?i)(?:PostgreSQL\s*)?(\d{1,2}(?:\.\d+){0,2})", text or "")
    return m.group(1) if m else None

def version_tuple(v: str | None) -> tuple[int, ...]:
    if not v:
        return ()
    try:
        return tuple(int(x) for x in re.findall(r"\d+", v))
    except Exception:
        return ()

def bool_on(v: str | None) -> bool:
    return (v or "").strip().lower() in {"on", "true", "t", "1", "yes"}

def bool_off(v: str | None) -> bool:
    return (v or "").strip().lower() in {"off", "false", "f", "0", "no"}

def status_rank(status: str) -> int:
    order = {"FAIL":0,"ERROR":1,"WARN":2,"REVIEW":3,"PASS":4,"N/A":5,"SKIPPED":6}
    return order.get(status, 99)

def atomic_write(path: str | Path, data: str, mode: int = 0o600) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + f".tmp-{os.getpid()}")
    tmp.write_text(data, encoding="utf-8")
    os.chmod(tmp, mode)
    os.replace(tmp, p)

def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()
