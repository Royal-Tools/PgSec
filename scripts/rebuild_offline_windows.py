# Rebuild the Linux offline tree on Windows: portable CPython + POSIX launcher.
from __future__ import annotations

import hashlib
import os
import shutil
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "PGSEC_OFFLINE_LINUX_X86_64_PRODUCTION_v1.1.2"
PY_RELEASE = "20260325"
PY_VER = "3.13.12"
ARCHIVE = f"cpython-{PY_VER}+{PY_RELEASE}-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"
URL = f"https://github.com/astral-sh/python-build-standalone/releases/download/{PY_RELEASE}/{ARCHIVE}"
BUILD = ROOT / "build"
TAR = BUILD / ARCHIVE


def write_lf(path: Path, text: str) -> None:
    path.write_bytes(text.encode("utf-8").replace(b"\r\n", b"\n").replace(b"\r", b"\n"))


def main() -> None:
    BUILD.mkdir(parents=True, exist_ok=True)
    if not TAR.exists():
        print(f"Downloading {URL}")
        urllib.request.urlretrieve(URL, TAR)
    print(f"Archive {TAR.stat().st_size} bytes")

    extract = BUILD / "python-extract"
    if extract.exists():
        shutil.rmtree(extract)
    extract.mkdir()
    with tarfile.open(TAR, "r:gz") as tf:
        tf.extractall(extract)
    py_src = extract / "python"
    if not py_src.is_dir():
        raise SystemExit(f"unexpected archive layout: {list(extract.iterdir())}")

    runtime = OUT / "runtime"
    if runtime.exists():
        shutil.rmtree(runtime)
    shutil.copytree(py_src, runtime)

    # Ubuntu host libs require GLIBC_2.34; portable CPython ships its own.
    libdir = OUT / "lib"
    if libdir.exists():
        for p in libdir.iterdir():
            if p.is_file() or p.is_symlink():
                p.unlink()

    for sh in (ROOT / "native" / "pg-sec-audit.sh", ROOT / "scripts" / "build_offline.sh"):
        write_lf(sh, sh.read_text(encoding="utf-8"))
    write_lf(OUT / "pg-sec-audit", (ROOT / "native" / "pg-sec-audit.sh").read_text(encoding="utf-8"))

    app_pgsec = OUT / "app" / "pgsec"
    if app_pgsec.exists():
        shutil.rmtree(app_pgsec)
    shutil.copytree(ROOT / "pgsec", app_pgsec)
    shutil.copy2(ROOT / "pg-sec-audit.py", OUT / "app" / "pg-sec-audit.py")
    shutil.copy2(ROOT / "README.md", OUT / "docs" / "README_SOURCE.md")
    policy = ROOT / "config" / "policy.example.json"
    if policy.exists():
        (OUT / "config").mkdir(exist_ok=True)
        shutil.copy2(policy, OUT / "config" / "policy.example.json")

    # SHA256SUMS for files (not the sums file itself)
    files = []
    for dirpath, dirnames, filenames in os.walk(OUT):
        dirnames[:] = [d for d in dirnames if d not in {".git", "__pycache__"}]
        for name in filenames:
            if name == "SHA256SUMS":
                continue
            p = Path(dirpath) / name
            if p.suffix == ".pyc":
                continue
            files.append(p)
    files.sort(key=lambda p: p.relative_to(OUT).as_posix())
    lines = []
    for p in files:
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        rel = p.relative_to(OUT).as_posix()
        lines.append(f"{h}  {rel}\n")
    (OUT / "SHA256SUMS").write_text("".join(lines), encoding="ascii")
    print(f"Wrote {len(files)} hashes to {OUT / 'SHA256SUMS'}")
    print("OK")


if __name__ == "__main__":
    main()
