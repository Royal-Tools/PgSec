# PgSec — PostgreSQL Security Assessment Engine

<p align="center">
  <img src="docs/banner.png" alt="PgSec — PostgreSQL Security Assessment Engine" width="720">
</p>

**Version 1.2.0** — CIS PostgreSQL 16 & 18 Security Assessment Tool

---

## What’s New in v1.2.0

| Feature | Description |
|---|---|
| **CIS PostgreSQL 18 Support** | Full catalog of 72 CIS controls (v1.0.0, 2026-03-27) plus 71 CIS 16 controls. Automatic benchmark selection based on detected PostgreSQL major version. |
| **Users Worksheet** | New **Users** tab in the Excel report listing every database login role with attributes: Type, Superuser, Replication, Password Verifier (SCRAM/MD5), Connection Limit, Valid Until, Member Of, etc. |
| **Discovery Enrichment** | System details expanded: OS Release, Kernel, Architecture, Audit User, Container Image, Privileged status, Ports, Data/Config/HBA file paths, PostgreSQL Binaries, Systemd Services. |
| **Auto-Credential Discovery** | For Docker/Podman containers: `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` are detected from container environment and adjacent `docker-compose.yml` files. |
| **Real Command Output** | Test Result column now embeds the actual command output (redacted for secrets), making debugging and validation easier. |
| **Evidence Path Hash** | SHA256 hash of file system paths discovered during evidence collection is now included in the Evidence worksheet. |
| **Interactive Wizard Modernized** | Comprehensive non-interactive mode with `--benchmark auto|16|18` and improved interactive prompts for policy, output directory, and diagnostics flags. |

---

## Quick Start

```bash
# Local scan (auto-detects CIS 16 or 18)
python3 pg-sec-audit.py --local --mode all --non-interactive

# Force CIS 18 benchmark
python3 pg-sec-audit.py --local --benchmark 18 --mode all

# Remote scan
python3 pg-sec-audit.py --ip 10.0.0.10 -u audit -k ~/.ssh/id_ed25519 \
    --all-postgres-containers --mode all --no-network

# Interactive wizard
python3 pg-sec-audit.py
```

---

## Execution targets

- Local Linux host
- Local Docker/Podman container (POSTGRES env auto-detected)
- Remote Linux host over SSH
- Remote Docker/Podman container through SSH + runtime exec
- Single IP/hostname, CIDR, or file of IPs

---

## Assessment outputs

- **Discovery** worksheet (enriched with OS, container, PostgreSQL details)
- **Users** worksheet (complete role inventory)
- **CIS Benchmark** (8.1.0 for v16, v1.0.0 for v18)
- **Enhanced Security Assessment (ESA)** – 18 checks
- Live terminal status stream
- JSON and XLSX reports with 71/72 controls + Evidence including path hashes

---

## Offline Use

> **Download:** [v1.2.0 Release](https://github.com/Royal-Tools/PgSec/releases/download/v1.2.0/PGSEC_OFFLINE_LINUX_X86_64_PRODUCTION_v1.2.0.zip)

The `PGSEC_OFFLINE_LINUX_X86_64_PRODUCTION_v1.2.0.zip` bundle includes its own Python 3.13 runtime and native SSH helper (`pgssh`). It runs on any Linux host with **glibc 2.17+** (RHEL/CentOS/Rocky 7+, Ubuntu 18.04+). No `pip install`, internet access, or package-manager access is required.

Extract and run:

```bash
unzip PGSEC_OFFLINE_LINUX_X86_64_PRODUCTION_v1.2.0.zip
cd PGSEC_OFFLINE_LINUX_X86_64_PRODUCTION_v1.2.0
./pg-sec-audit --local --mode discovery
```

---

## Changelog

### v1.2.0 (2024-09-07)

**Major Features**
- Added CIS PostgreSQL 18 Benchmark v1.0.0 support (72 controls, new control 4.10)
- New `Users` worksheet showing all login roles with password verifier types
- Auto-discovery of PostgreSQL credentials from Docker container environment and docker-compose files

**Improvements**
- Discovery worksheet expanded with 10 additional columns (OS, Kernel, Architecture, etc.)
- Test Result now embeds real command output (with secret redaction)
- Evidence items include SHA256 hash of discovered file paths
- Updated interactive wizard with comprehensive options
- Added `--benchmark auto|16|18` flag for explicit benchmark selection

**Code Quality**
- All Python code is compatible with Python 3.10+
- Full test suite passes (44 tests)
- Updated offline build process for v1.2.0

---

## CIS Benchmarks

| Benchmark | Version | Date |
|---|---|---|
| CIS PostgreSQL 16 | v1.1.0 | 2025-06-30 |
| CIS PostgreSQL 18 | v1.0.0 | 2026-03-27 |

Both benchmarks are referenced but **not redistributed**; use your authorized CIS copy for validation/review.

---

## License & Attribution

_pgsec-audit is provided under the terms of its source repository. CIS benchmarks are proprietary CIS material requiring membership for redistribution._