# Changelog

All notable changes to this project will be documented in this file.

Format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.2.0] - 2026-09-07

### Added
- **CIS PostgreSQL 18 Benchmark v1.0.0** support (72 controls, new control 4.10)
- `--benchmark auto|16|18` flag for explicit benchmark selection
- **Users worksheet** in Excel report with 12 columns (Role, Type, Login, Superuser, CreateRole, CreateDB, Replication, BypassRLS, Connection Limit, Valid Until, Password Verifier, Member Of)
- **Discovery enrichment**: OS Release, Kernel, Architecture, Audit User, Container Image/Privileged/Ports, Data/Config/HBA File paths, PostgreSQL Binaries, Systemd Services, Config Files Found, CIS Benchmark
- Auto-discovery of `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` from Docker/Podman container environment and `docker-compose.yml` files
- `PGPASSWORD` auto-injection in ContainerExecutor
- SHA256 hash of discovered file paths in Evidence worksheet
- Real command output embedded in Test Result (with secret redaction)
- `policy.example.json` — `cert_login_roles` key for CIS 4.10
- Updated interactive wizard with all options (Target → Credentials → SSH → Benchmark → Container → Policy → Output → Diagnostics)

### Changed
- `CIS_RULES` split into `CIS16_RULES` (71) and `CIS18_RULES` (72)
- `build_report()` now accepts `baselines: dict[int, tuple[str,str]]` instead of `(version_source, current_pg16)`
- `Auditor.__init__()` requires `benchmark: int` parameter
- Excel report now has 6 sheets: Summary → Discovery → Users → CIS → ESA → Evidence
- Version bumped to 1.2.0 (`pgsec/app.py`, `pgsec/__init__.py`, `pgsec/__main__.py`)

### Fixed
- `esa_17` now correctly thresholds based on detected PostgreSQL major
- `versioning.py` now fetches multiple majors in a single network request
- Test suite passes on Windows (PGTLS-era skip for SSH helper test)
- Offline bundle build script updated for v1.2.0 directory layout

## [1.1.2] - 2026-09-05

### Added
- Initial public release
- CIS PostgreSQL 16 Benchmark v1.1.0 (71 controls)
- Enhanced Security Assessment (ESA) with 18 checks
- Local / Remote SSH / Container execution modes
- Excel report with Summary, Discovery, CIS, ESA, Evidence sheets
- Offline bundle for Linux x86_64 (glibc 2.17+)
