# Verification Matrix — PgSec v1.2.0

The sandbox verification includes:

## Unit Tests (pytest)

- **Catalog validation**: CIS16 (71 controls), CIS18 (72 controls including new 4.10), ESA (18 controls) — no duplicates, correct ordering
- **Benchmark selection logic**: `resolve_benchmark()` correctly handles forced preference, auto-detection, undetectable versions, and unsupported majors
- **Report field structure**: Six audit columns, Required Customer Input, Customer Response / Evidence, Auditor Decision, Target ordering
- **Discovery enrichment**: OS Release, Kernel, Architecture, Audit User, Data Directory, Config/HBA files, Binaries, Systemd Services, Config Files Found, CIS Benchmark
- **Users worksheet**: Role inventory with 12 columns (Target, Role, Type, Login, Superuser, CreateRole, CreateDB, Replication, BypassRLS, Connection Limit, Valid Until, Password Verifier, Member Of)
- **Test Result embedding**: Command output is embedded with secret redaction
- **CIDR/IP-list loading**: Deduplication, comment stripping, 4096-address limit
- **Container listing parsing**: Image-based PostgreSQL candidate detection
- **SSH secret handling**: Password never exposed in argv (skip on Windows due to platform limitation)
- **XLSX structure**: Title row, frozen header, filters, sheet ordering (Summary → Discovery → Users → CIS → ESA → Evidence)

## CIS/ESA Checks

- **PG16 full catalog**: All 71 CIS + 18 ESA checks execute through a deterministic in-process PostgreSQL simulation with no internal-check exception
- **PG18 full catalog**: All 72 CIS + 18 ESA checks (including 4.10) execute cleanly
- **Major version gate**: PostgreSQL 16 scanned with CIS 18 → N/A; PostgreSQL 18 scanned with CIS 16 → N/A
- **Policy integration**: `approved_repository_patterns`, `cert_login_roles`, `allowed_superusers`, `dml_allowlist`, `rls_required_tables` all produce deterministic results when provided

## Integration

- **Local source execution**: Produces JSON + XLSX in `--output-dir`
- **Docker container scan**: Credentials auto-discovered from POSTGRES_* environment variables
- **Remote SSH execution**: Native `pgssh` helper with libssh2 or system `ssh` fallback
- **Offline bundle**: `PGSEC_OFFLINE_LINUX_X86_64_PRODUCTION_v1.2.0.zip` built with portable CPython 3.13, glibc 2.17+ compatible

## Notes

- A real external SSH/PostgreSQL server is not present in the sandbox, so live authentication cannot be certified from this environment
- The native SSH implementation is compiled into the offline bundle; network paths are tested using deterministic shims
- CIS REVIEW workflow verified: Required Customer Input, Customer Response / Evidence, Auditor Decision columns; Summary status distribution chart verified
