#!/bin/sh
# Build a Linux x86_64 offline bundle that runs on glibc 2.17+ (RHEL/CentOS/Rocky 7+,
# RHEL 8 / glibc 2.28 included). Do not copy a host Python from Ubuntu 22.04+; that
# interpreter requires GLIBC_2.34 and fails on RHEL 8.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${1:-"$ROOT/dist/pg-sec-audit-linux-x86_64"}
PY_RELEASE=${PY_RELEASE:-20260325}
PY_VER=${PY_VER:-3.13.12}
PY_TRIPLE=${PY_TRIPLE:-x86_64-unknown-linux-gnu}
PY_ARCHIVE="cpython-${PY_VER}+${PY_RELEASE}-${PY_TRIPLE}-install_only_stripped.tar.gz"
PY_URL=${PY_URL:-"https://github.com/astral-sh/python-build-standalone/releases/download/${PY_RELEASE}/${PY_ARCHIVE}"}
mkdir -p "$OUT/app" "$OUT/bin" "$OUT/lib" "$OUT/docs" "$OUT/config" "$ROOT/build"

# POSIX shell entrypoint: no glibc symbol versions.
cp "$ROOT/native/pg-sec-audit.sh" "$OUT/pg-sec-audit"
# Strip CRLF if the tree was edited on Windows.
if command -v sed >/dev/null 2>&1; then
  sed -i 's/\r$//' "$OUT/pg-sec-audit" 2>/dev/null || sed 's/\r$//' "$ROOT/native/pg-sec-audit.sh" > "$OUT/pg-sec-audit"
fi

# Portable CPython built against glibc 2.17.
PY_TAR="$ROOT/build/$PY_ARCHIVE"
if [ ! -f "$PY_TAR" ]; then
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$PY_TAR" "$PY_URL"
  else
    wget -O "$PY_TAR" "$PY_URL"
  fi
fi
rm -rf "$ROOT/build/python" "$OUT/runtime"
tar -xzf "$PY_TAR" -C "$ROOT/build"
cp -a "$ROOT/build/python" "$OUT/runtime"
if [ -x "$OUT/runtime/bin/python3" ] && [ ! -e "$OUT/runtime/bin/python3.13" ]; then
  ln -s python3 "$OUT/runtime/bin/python3.13"
fi
rm -rf "$OUT/runtime/lib/python3.13/test" "$OUT/runtime/lib/python3.13/idlelib" "$OUT/runtime/lib/python3.13/tkinter" "$OUT/runtime/lib/python3.13/ensurepip" 2>/dev/null || true
find "$OUT/runtime/lib/python3.13" -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true

# Native SSH helper: static musl via Alpine so it does not need host glibc 2.34.
build_pgssh() {
  if command -v docker >/dev/null 2>&1; then
    docker run --rm --network=host \
      -v "$ROOT/native/pgssh.c:/src/pgssh.c:ro" \
      -v "$OUT/bin:/out" \
      alpine:3.20 sh -c '
        set -eu
        apk add --no-cache gcc musl-dev libssh2-dev libssh2-static openssl-dev openssl-libs-static zlib-dev zlib-static
        cc -O2 -static /src/pgssh.c -o /out/pgssh -lssh2 -lssl -lcrypto -lz
        strip /out/pgssh
      '
    return 0
  fi
  if [ -n "${CC:-}" ] || command -v cc >/dev/null 2>&1; then
    CC=${CC:-cc}
    "$CC" -O2 "$ROOT/native/pgssh.c" -o "$OUT/bin/pgssh" -Wl,-Bstatic -lssh2 -lssl -lcrypto -lz ${ZSTD_STATIC:-} -Wl,-Bdynamic -lpthread -ldl
    strip "$OUT/bin/pgssh" 2>/dev/null || true
    return 0
  fi
  return 1
}
if ! build_pgssh; then
  printf '%s\n' "pgssh: docker/cc unavailable; bundle will use system ssh for key auth" >&2
fi

rm -rf "$OUT/app/pgsec"
cp -a "$ROOT/pgsec" "$OUT/app/pgsec"
cp "$ROOT/pg-sec-audit.py" "$OUT/app/"
find "$OUT/app" -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
find "$OUT/app" -type f -name '*.pyc' -delete
# Do not copy host Ubuntu OpenSSL/zlib into lib/: those .so files require GLIBC_2.34.
# The portable CPython already ships compatible OpenSSL under runtime/lib.
cp "$ROOT/README.md" "$OUT/docs/README_SOURCE.md"
[ -f "$ROOT/config/policy.example.json" ] && cp "$ROOT/config/policy.example.json" "$OUT/config/"
chmod 755 "$OUT/pg-sec-audit" "$OUT/runtime/bin/python3" "$OUT/runtime/bin/python3.13" 2>/dev/null || true
[ -f "$OUT/bin/pgssh" ] && chmod 755 "$OUT/bin/pgssh"
(cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
printf 'Built %s (glibc 2.17+ portable runtime)\n' "$OUT"
