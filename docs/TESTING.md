# Verification matrix

The sandbox verification includes:

- unit tests for catalog shape, report fields, XLSX sheet structure, CIDR/IP-list loading, container parsing, execution wrapping, patch/TLS controls, empty terminal results, and SSH secret argv handling;
- all 71 CIS + 18 ESA checks executed through an in-process deterministic PostgreSQL simulation with no internal-check exception;
- local source execution producing JSON/XLSX;
- remote SSH + remote Docker container discovery through a deterministic SSH/runtime shim;
- complete remote-container CIS+ESA execution through the same execution abstraction, producing all 71 + 18 results;
- Linux x86_64 offline portable launcher from a clean environment with no target Python/pip requirement;
- native libssh2 SSH helper compilation, help path, and deterministic connection-failure path;
- XLSX imported and inspected with the spreadsheet verification tooling for required sheets/columns and formula errors.

A real external SSH/PostgreSQL server is not present in the sandbox, so a live handshake/authentication to a production server cannot be certified from this environment. The real native SSH implementation is compiled into the offline bundle; network execution paths are additionally tested using deterministic sandbox shims.

- CIS REVIEW Excel workflow verified: dedicated Required Customer Input, Customer Response / Evidence, and Auditor Decision columns; Summary status chart verified through spreadsheet import/render.
