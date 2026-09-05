#!/bin/sh
# POSIX launcher: no glibc version dependency (works on RHEL 8 / glibc 2.28+).
# Prefers the bundled CPython. If that interpreter was built against a newer
# glibc than this host provides, fall back to system Python 3.10+.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SCRIPT="$ROOT/app/pg-sec-audit.py"
export PGSEC_SSH_HELPER="$ROOT/bin/pgssh"
export PYTHONNOUSERSITE=1
export PYTHONDONTWRITEBYTECODE=1

pyhome="$ROOT/runtime"
python="$pyhome/bin/python3.13"
if [ ! -f "$python" ]; then
  python="$pyhome/bin/python3"
fi
if [ -f "$python" ] && [ ! -x "$python" ]; then
  chmod u+x "$python" "$pyhome/bin/python3" "$pyhome/bin/python" 2>/dev/null || true
fi
if [ -f "$ROOT/bin/pgssh" ] && [ ! -x "$ROOT/bin/pgssh" ]; then
  chmod u+x "$ROOT/bin/pgssh" 2>/dev/null || true
fi
if [ -f "$python" ]; then
  if LD_LIBRARY_PATH="$pyhome/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" PYTHONHOME="$pyhome" "$python" -c 'import sys' >/dev/null 2>&1; then
    export PYTHONHOME="$pyhome"
    export LD_LIBRARY_PATH="$pyhome/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    if [ -d "$ROOT/lib" ]; then
      export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$ROOT/lib"
    fi
    exec "$python" "$SCRIPT" "$@"
  fi
fi

unset PYTHONHOME || true
for python in python3.13 python3.12 python3.11 python3.10 python3; do
  command -v "$python" >/dev/null 2>&1 || continue
  "$python" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1 || continue
  exec "$python" "$SCRIPT" "$@"
done

printf '%s\n' "pg-sec-audit: bundled Python cannot start on this libc (needs glibc 2.17+) and no system Python 3.10+ was found." >&2
printf '%s\n' "Rebuild with scripts/build_offline.sh, or install Python 3.10+ on this host." >&2
exit 70
