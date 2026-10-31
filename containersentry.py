#!/usr/bin/env python3
"""ContainerSentry: static security checks for Dockerfiles and Compose files."""
from __future__ import annotations
import argparse
import json
import re
import sys
from pathlib import Path

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

def finding(rule_id, severity, title, message, file_path, line=None, recommendation=""):
    return {"rule_id": rule_id, "severity": severity, "title": title, "message": message,
            "file": str(file_path), "line": line, "recommendation": recommendation}

def analyze_dockerfile(path: Path):
    findings = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        return [finding("IO001", "HIGH", "Unable to read file", str(exc), path)]
    instructions = []
    for number, raw in enumerate(lines, 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = re.match(r"^(\w+)\s+(.*)$", stripped)
        if match:
            instructions.append((number, match.group(1).upper(), match.group(2).strip()))
    user_set = any(op == "USER" and arg and arg.upper() not in {"ROOT", "0"} for _, op, arg in instructions)
    if not user_set:
        findings.append(finding("CTR001", "HIGH", "Container may run as root",
            "No non-root USER instruction was found.", path,
            recommendation="Create an unprivileged user and finish the Dockerfile with USER <uid-or-name>."))
    for number, op, arg in instructions:
        if op == "ADD":
            findings.append(finding("CTR002", "MEDIUM", "Review ADD instruction",
                "ADD can fetch remote resources or unpack archives implicitly.", path, number,
                "Prefer COPY for local files; fetch remote artifacts in a controlled, verified build step."))
        if op == "FROM" and re.search(r":latest(?:\s|$)", arg, re.I):
            findings.append(finding("CTR003", "MEDIUM", "Floating image tag",
                "The base image uses the mutable latest tag.", path, number,
                "Pin an explicit version and, for stronger reproducibility, an image digest."))
        if op == "RUN" and re.search(r"(curl|wget).*(\|\s*(sh|bash)|\|\s*sh)", arg, re.I):
            findings.append(finding("CTR004", "HIGH", "Remote script piped to shell",
                "A remote download appears to be executed directly by a shell.", path, number,
                "Verify signatures/checksums and avoid piping untrusted remote content into a shell."))
        if op == "RUN" and re.search(r"chmod\s+777", arg, re.I):
            findings.append(finding("CTR005", "MEDIUM", "World-writable permissions",
                "RUN instruction grants broad write permissions with chmod 777.", path, number,
                "Apply least-privilege ownership and permission bits."))
    return findings

def analyze_compose(path: Path):
    try:
        import yaml
    except ImportError:
        return [finding("DEP001", "INFO", "Compose parser unavailable",
            "Install PyYAML to analyze Compose files: pip install -r requirements.txt.", path,
            recommendation="Install the project dependencies and rerun the audit.")]
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        return [finding("CMP000", "HIGH", "Invalid Compose file", str(exc), path)]
    findings = []
    services = data.get("services", {}) if isinstance(data, dict) else {}
    if not isinstance(services, dict):
        return [finding("CMP000", "HIGH", "Invalid services section",
            "Compose services must be a mapping.", path)]
    for name, service in services.items():
        if not isinstance(service, dict):
            continue
        if service.get("privileged") is True:
            findings.append(finding("CMP001", "CRITICAL", "Privileged container",
                f"Service '{name}' enables privileged mode.", path,
                recommendation="Remove privileged mode; grant only the specific capabilities required."))
        user = str(service.get("user", "")).strip().lower()
        if user in {"", "0", "root", "0:0", "root:root"}:
            findings.append(finding("CMP002", "HIGH", "No non-root user configured",
                f"Service '{name}' does not declare a non-root user.", path,
                recommendation="Set user to an unprivileged UID/GID, or ensure the image defines a safe USER."))
        if service.get("read_only") is not True:
            findings.append(finding("CMP003", "LOW", "Writable root filesystem",
                f"Service '{name}' does not enable read_only.", path,
                recommendation="Set read_only: true and mount only required writable paths."))
        if service.get("network_mode") == "host":
            findings.append(finding("CMP004", "HIGH", "Host network mode",
                f"Service '{name}' shares the host network namespace.", path,
                recommendation="Use an isolated Compose network unless host networking is essential."))
        cap_add = service.get("cap_add", []) or []
        if isinstance(cap_add, list) and any(str(cap).upper() == "ALL" for cap in cap_add):
            findings.append(finding("CMP005", "HIGH", "All Linux capabilities added",
                f"Service '{name}' adds every Linux capability.", path,
                recommendation="Drop all capabilities and add back only the minimum required."))
        if service.get("privileged") is not True and "no-new-privileges:true" not in str(service.get("security_opt", [])):
            findings.append(finding("CMP006", "LOW", "No no-new-privileges setting",
                f"Service '{name}' does not declare no-new-privileges.", path,
                recommendation="Consider security_opt: [no-new-privileges:true]."))
        for volume in service.get("volumes", []) or []:
            if isinstance(volume, str) and re.match(r"^/[^:]+:/", volume):
                findings.append(finding("CMP007", "HIGH", "Host path bind mount",
                    f"Service '{name}' bind-mounts a host path: {volume}.", path,
                    recommendation="Avoid sensitive host paths; use narrow, read-only mounts where possible."))
            elif isinstance(volume, dict) and volume.get("type") == "bind":
                source = str(volume.get("source", ""))
                if source.startswith("/"):
                    findings.append(finding("CMP007", "HIGH", "Host path bind mount",
                        f"Service '{name}' bind-mounts host path: {source}.", path,
                        recommendation="Avoid sensitive host paths; use narrow, read-only mounts where possible."))
        ports = service.get("ports", []) or []
        for port in ports:
            if isinstance(port, str) and re.match(r"^(?:0\.0\.0\.0|\[::\]):", port):
                findings.append(finding("CMP008", "MEDIUM", "Service bound to all interfaces",
                    f"Service '{name}' publishes {port}, potentially exposing it on every interface.", path,
                    recommendation="Bind to 127.0.0.1 when external access is not required."))
            elif isinstance(port, dict) and port.get("host_ip") in {"0.0.0.0", "::"}:
                findings.append(finding("CMP008", "MEDIUM", "Service bound to all interfaces",
                    f"Service '{name}' publishes port {port.get('published')} on all interfaces.", path,
                    recommendation="Bind to 127.0.0.1 when external access is not required."))
    return findings

def scan_path(target: Path):
    if target.is_file():
        candidates = [target]
    elif target.is_dir():
        candidates = [p for p in target.rglob("*") if p.is_file() and
                      (p.name.lower() in {"dockerfile", "containerfile"} or
                       re.match(r"^(docker-)?compose.*\.ya?ml$", p.name, re.I))]
    else:
        raise FileNotFoundError(f"Path does not exist: {target}")
    findings = []
    for path in sorted(candidates):
        name = path.name.lower()
        if name in {"dockerfile", "containerfile"}:
            findings.extend(analyze_dockerfile(path))
        elif re.match(r"^(docker-)?compose.*\.ya?ml$", name, re.I):
            findings.extend(analyze_compose(path))
    return sorted(findings, key=lambda item: (SEVERITY_ORDER.get(item["severity"], 9), item["file"], item["line"] or 0))

def main(argv=None):
    parser = argparse.ArgumentParser(description="Static security auditor for Dockerfiles and Docker Compose files.")
    parser.add_argument("path", help="Dockerfile, Compose YAML file, or directory to scan")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output", help="Write report to this file instead of stdout")
    args = parser.parse_args(argv)
    try:
        results = scan_path(Path(args.path))
    except (OSError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        rendered = json.dumps({"tool": "ContainerSentry", "findings_count": len(results), "findings": results}, indent=2)
    else:
        rendered = f"ContainerSentry — {len(results)} finding(s)\n" + ("-" * 58) + "\n"
        if not results:
            rendered += "No findings from the enabled static checks.\n"
        for item in results:
            location = f"{item['file']}" + (f":{item['line']}" if item["line"] else "")
            rendered += f"[{item['severity']}] {item['rule_id']} {item['title']}\n  {location}\n  {item['message']}\n  Fix: {item['recommendation']}\n\n"
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 1 if any(x["severity"] in {"CRITICAL", "HIGH"} for x in results) else 0

if __name__ == "__main__":
    raise SystemExit(main())
