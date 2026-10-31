# ContainerSentry

**A lightweight static security analyzer for Dockerfiles and Docker Compose configurations.**

ContainerSentry helps developers identify common container security misconfigurations before deployment. It analyzes configuration files offline and reports actionable findings with severity levels, explanations, and remediation guidance.

<p align="center">
  <strong>Scan · Detect · Review · Harden</strong>
</p>

---

## Overview

Container security starts with secure build and deployment configuration. Risky defaults—such as privileged execution, excessive Linux capabilities, host networking, or broad filesystem permissions—can increase the impact of a compromise.

ContainerSentry provides a focused, command-line way to review these configurations as part of a development or security-review workflow.

### Current capabilities

- Static analysis of Dockerfiles.
- Static analysis of Docker Compose YAML files.
- Rule-based findings with severity, file location, explanation, and remediation advice.
- Human-readable terminal output.
- JSON report export for further processing.
- Automated unit tests and GitHub Actions workflow.

## Detection rules

### Dockerfile rules

| Rule ID | Severity | Detection |
|---|---|---|
| CTR001 | HIGH | No non-root `USER` instruction found |
| CTR002 | MEDIUM | `ADD` instruction flagged for review |
| CTR003 | MEDIUM | Base image uses the mutable `:latest` tag |
| CTR004 | HIGH | Remote script is piped directly to a shell |
| CTR005 | MEDIUM | Broad `chmod 777` permissions |

### Docker Compose rules

| Rule ID | Severity | Detection |
|---|---|---|
| CMP001 | CRITICAL | Service enables privileged mode |
| CMP002 | HIGH | Service does not explicitly declare a non-root user |
| CMP003 | LOW | Writable container root filesystem |
| CMP004 | HIGH | Host network mode is enabled |
| CMP005 | HIGH | All Linux capabilities are added |
| CMP006 | LOW | `no-new-privileges` is not configured |
| CMP007 | HIGH | Host-path bind mount is configured |
| CMP008 | MEDIUM | Published port is bound to all host interfaces |

**Important:** Rules are heuristic checks, not definitive vulnerability proofs. For example, a Compose service may inherit a non-root user from its image even when the Compose file does not declare one. Review findings in the context of the actual image and deployment requirements.

## Requirements

- Python 3.9 or newer
- PyYAML (installed through `requirements.txt`)
- Docker is not required for the current static-analysis workflow.

## Installation

Clone the repository:

```bash
git clone https://github.com/devanshshukla-3004/ContainerSentry.git
cd ContainerSentry
```

Create and activate a virtual environment.

**Windows PowerShell**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**Linux / macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Usage

### Scan the included sample configurations

```bash
python containersentry.py samples/
```

The sample Dockerfile and Compose file intentionally contain insecure configuration patterns so you can observe the analyzer's findings.

### Scan a specific configuration

```bash
python containersentry.py samples/compose.yaml
```

### Export findings as JSON

```bash
python containersentry.py samples/ --format json --output report.json
```

### Scan your own project

Pass a file or directory path to the CLI:

```bash
python containersentry.py ./path/to/project
```

Use the CLI's help option to inspect the available arguments:

```bash
python containersentry.py --help
```

## Example output

The following is a shortened illustration of the terminal report format:

```text
ContainerSentry — 14 finding(s)
----------------------------------------------------------
[CRITICAL] CMP001 Privileged container
  Service 'web' enables privileged mode.
  Fix: Remove privileged mode; grant only the specific capabilities required.

[HIGH] CMP004 Host network mode
  Service 'web' shares the host network namespace.
  Fix: Use an isolated Compose network unless host networking is essential.

[MEDIUM] CTR003 Floating image tag
  The base image uses the mutable latest tag.
  Fix: Pin an explicit version and, for stronger reproducibility, an image digest.
```

The included sample configurations currently produce **14 findings** in the local verification run. This count describes those intentionally vulnerable samples; it is not a benchmark or a result for arbitrary projects.

## Running tests

Run the unit test suite from the repository root:

```bash
python -m unittest discover -s tests -v
```

The current test suite covers selected Dockerfile and Compose detection behavior. The verified local run completed **3 tests successfully**.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No critical or high-severity findings |
| `1` | At least one critical or high-severity finding |
| `2` | Input or execution error |

## Repository structure

```text
ContainerSentry/
├── .github/
│   └── workflows/
│       └── tests.yml
├── samples/
│   ├── Dockerfile
│   └── compose.yaml
├── tests/
│   └── test_containersentry.py
├── containersentry.py
├── requirements.txt
└── README.md
```

## Scope and limitations

ContainerSentry currently performs **static configuration analysis**. It does not:

- Start, stop, or execute containers.
- Connect to a Docker daemon or inspect running workloads.
- Pull images or scan image layers for vulnerabilities.
- Verify whether a finding is exploitable in a particular environment.
- Provide compliance certification or replace a full container-security program.

Findings should be validated before changing production configurations. Apply remediation in a test environment first and confirm that application functionality is preserved.

## Roadmap

Planned areas for future development:

- More robust Dockerfile parsing and multi-stage build awareness.
- Improved non-root user analysis to reduce false positives.
- Source-line reporting for Compose findings.
- Image digest and image metadata policy checks.
- SARIF export for code-scanning integrations.
- Expanded test coverage and additional Compose hardening rules.

## Responsible use

Use ContainerSentry to assess configurations you own or are explicitly authorized to review. Treat its output as a security-review aid and validate recommendations against your environment.

## License

This project is released under the MIT License. See the repository's license file for details.

---

**Project:** [ContainerSentry](https://github.com/devanshshukla-3004/ContainerSentry)  
**Part of:** 100 Days · 100 Cybersecurity Projects
