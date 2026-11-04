#!/usr/bin/env python3
"""
cloud_manifest_auditor.py — Automated 10%–100% Cloud IAM & Container Manifest Scanner
Part of .agent/skills/cloud-iam-and-container-hardening/
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass
from typing import Dict, List, Pattern, Tuple


class Style:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    MAGENTA = "\033[95m"


def emit_progress(pct: int, label: str, delay: float = 0.04) -> None:
    filled = int(pct // 5)
    bar = "█" * filled + "░" * (20 - filled)
    color = Style.GREEN if pct == 100 else Style.CYAN
    print(f"  {color}{Style.BOLD}[{bar}] {pct:3d}%{Style.RESET}  ▸ {label}", flush=True)
    if delay > 0:
        time.sleep(delay)


@dataclass
class Finding:
    category: str
    severity: str
    file_path: str
    line_number: int
    line_snippet: str
    rationale: str


CHECKS: List[Tuple[str, str, Pattern[str], str]] = [
    (
        "Privileged Container Execution",
        "CRITICAL",
        re.compile(r"privileged\s*:\s*true", re.IGNORECASE),
        "Container runs with full host kernel privileges and capabilities.",
    ),
    (
        "Docker Socket Mount",
        "CRITICAL",
        re.compile(r"(/var/run/docker\.sock|/run/containerd/containerd\.sock)", re.IGNORECASE),
        "Mounting container runtime socket allows trivial container escape to host root.",
    ),
    (
        "Host PID Namespace Sharing",
        "HIGH",
        re.compile(r"hostPID\s*:\s*true", re.IGNORECASE),
        "Shares process namespace with host, exposing host processes and memory.",
    ),
    (
        "Host Network Namespace Sharing",
        "HIGH",
        re.compile(r"hostNetwork\s*:\s*true", re.IGNORECASE),
        "Shares network namespace with host; bypasses localhost-only access controls.",
    ),
    (
        "Wildcard IAM Action",
        "HIGH",
        re.compile(r"[\"']Action[\"']\s*:\s*(\*|\[\s*[\"']\*[\"']\s*\])", re.IGNORECASE),
        "Overly permissive wildcard IAM action assignment.",
    ),
    (
        "Insecure IMDSv1 Default",
        "MEDIUM",
        re.compile(r"http_tokens\s*=\s*[\"']optional[\"']|HttpTokens\s*:\s*optional", re.IGNORECASE),
        "Instance metadata allows unauthenticated IMDSv1 tokenless access.",
    ),
]

SCAN_EXTS = {".yaml", ".yml", ".json", ".tf", ".hcl", "Dockerfile"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Cloud & Container Manifest Security Scanner")
    parser.add_argument("--target", default=".", help="Directory to scan")
    args = parser.parse_args()

    print(f"\n{Style.MAGENTA}{Style.BOLD}⚡ INITIALIZING CLOUD IAM & CONTAINER HARDENING AUDITOR ({args.target}) ⚡{Style.RESET}\n")

    emit_progress(10, "Enumerating manifests (YAML, JSON, Terraform, Dockerfile)...")
    target_files = []
    for root, _, files in os.walk(args.target):
        if any(ignored in root for ignored in [".git", "node_modules", ".agent"]):
            continue
        for f in files:
            if f == "Dockerfile" or any(f.endswith(ext) for ext in SCAN_EXTS):
                target_files.append(os.path.join(root, f))

    emit_progress(20, f"Found {len(target_files)} manifest(s); checking Privileged container configurations...")
    emit_progress(40, "Checking runtime socket volume mounts (docker.sock / containerd.sock)...")
    emit_progress(60, "Scanning for Host Namespace leakage (hostPID / hostNetwork)...")
    emit_progress(80, "Auditing IAM wildcard actions and IMDSv1 configurations...")

    findings: List[Finding] = []
    for fpath in target_files:
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                for idx, line in enumerate(fh, start=1):
                    for cat, sev, regex, rat in CHECKS:
                        if regex.search(line):
                            findings.append(Finding(cat, sev, fpath, idx, line.strip()[:140], rat))
        except Exception:
            pass

    emit_progress(90, "Correlating findings and risk tiers...")
    emit_progress(100, "Audit Complete! Rendering Results...")

    print(f"\n{Style.CYAN}{Style.BOLD}═══ CLOUD & CONTAINER POSTURE FINDINGS ({len(findings)}) ═══{Style.RESET}")
    if not findings:
        print(f"  {Style.GREEN}[OK] No dangerous container escapes or wildcard IAM patterns found.{Style.RESET}")
    for f in findings:
        col = Style.RED if f.severity in ("CRITICAL", "HIGH") else Style.YELLOW
        print(
            f"  {col}[{f.severity}]{Style.RESET} {Style.BOLD}{f.category}{Style.RESET}\n"
            f"    File: {f.file_path}:{f.line_number}\n"
            f"    Line: {f.line_snippet}\n"
            f"    Note: {f.rationale}"
        )
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())

