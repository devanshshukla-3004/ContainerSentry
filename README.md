# ContainerSentry

**A lightweight static security auditor for Dockerfiles and Docker Compose configurations.**

ContainerSentry reviews container build and deployment configuration for common security misconfigurations and produces actionable terminal or JSON findings.

> **Scope:** static configuration analysis only. It does not execute containers, pull images, inspect a live Docker daemon, or prove that a runtime is secure.

## Checks included

| Rule | Severity | What it checks |
|---|---|---|
| CTR001 | HIGH | No non-root `USER` instruction in Dockerfile |
| CTR002 | MEDIUM | Review of `ADD` usage |
| CTR003 | MEDIUM | Mutable `:latest` base image tag |
| CTR004 | HIGH | Remote script piped directly to a shell |
| CTR005 | MEDIUM | Broad `chmod 777` permissions |
| CMP001 | CRITICAL | Compose service uses privileged mode |
| CMP002 | HIGH | Compose service does not declare a non-root user |
| CMP003 | LOW | Writable container root filesystem |
| CMP004 | HIGH | Host network namespace |
| CMP005 | HIGH | All Linux capabilities added |
| CMP006 | LOW | Missing no-new-privileges setting |
| CMP007 | HIGH | Host path bind mount |
| CMP008 | MEDIUM | Port published on all host interfaces |

Rules are heuristic signals. Validate findings against the application's operational requirements before changing production configuration.

## Requirements

- Python 3.9+
- Docker is **not** required; this version analyzes files offline.
- PyYAML is used to parse Compose YAML.

## Quick start

```bash
git clone https://github.com/devanshshukla-3004/ContainerSentry.git
cd ContainerSentry
python -m venv .venv
```

Activate the environment:

```powershell
# Windows PowerShell
.venv\Scripts\Activate.ps1
```

```bash
# Linux / macOS
source .venv/bin/activate
```

Install and scan:

```bash
python -m pip install -r requirements.txt
python containersentry.py samples/
python containersentry.py samples/compose.yaml --format json --output report.json
```

Scan a project directory:

```bash
python containersentry.py ./path/to/project
```

Exit codes: `0` = no critical/high findings, `1` = at least one critical/high finding, `2` = input or execution error.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Project layout

```text
ContainerSentry/
├── containersentry.py
├── requirements.txt
├── samples/
│   ├── Dockerfile
│   └── compose.yaml
├── tests/
│   └── test_containersentry.py
└── .github/
    └── workflows/
        └── tests.yml
```

## Responsible use

Use ContainerSentry to review configurations you own or are authorized to assess. It is a configuration review aid, not a compliance certification or substitute for image scanning, runtime monitoring, threat modeling, or a professional security review.

## Roadmap

- Image metadata and digest policy checks
- More robust Dockerfile parsing and multi-stage build context
- SARIF output for code-scanning workflows
- Additional Compose hardening checks with clear false-positive handling

## License

MIT
