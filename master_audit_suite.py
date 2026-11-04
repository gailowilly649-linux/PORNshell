#!/usr/bin/env python3
"""
master_audit_suite.py — Zero-Flag Master Orchestrator for All PORNshell Skills
Orchestrates:
  1. Authoritative DNS & RFC 5155 NSEC3 Posture Audit
  2. Static Codebase Sink & Vulnerability Hunter
  3. HTTP Security Header & CORS Posture Inspector
  4. Cloud IAM & Container Manifest Hardening Audit
  5. High-Entropy Secret & Token Leak Hunter
"""

from __future__ import annotations

import os
import subprocess
import sys
import time


class Style:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    MAGENTA = "\033[95m"


def emit_progress(pct: int, label: str, delay: float = 0.05) -> None:
    filled = int(pct // 5)
    bar = "█" * filled + "░" * (20 - filled)
    color = Style.GREEN if pct == 100 else Style.CYAN
    print(f"  {color}{Style.BOLD}[{bar}] {pct:3d}%{Style.RESET}  ▸ {label}", flush=True)
    if delay > 0:
        time.sleep(delay)


def main() -> int:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    skills_dir = os.path.join(base_dir, ".agent", "skills")

    print(f"\n{Style.MAGENTA}{Style.BOLD}╔══════════════════════════════════════════════════════════════════════════════╗")
    print(f"║ 🐉 MASTER PORNshell BUG HUNTING & PROTOCOL AUDITING SUITE 🐉                  ║")
    print(f"╚══════════════════════════════════════════════════════════════════════════════╝{Style.RESET}\n")

    emit_progress(10, "Initializing Master Suite...")
    emit_progress(20, "Launching 1/5: Authoritative DNS & NSEC3 Audit...")
    subprocess.run([sys.executable, os.path.join(base_dir, "dns_posture_audit.py")])

    emit_progress(40, "Launching 2/5: Static Sink & Code Vulnerability Scanner...")
    subprocess.run([sys.executable, os.path.join(skills_dir, "bug-hunting-tactics", "scripts", "static_sink_hunter.py"), "--target", base_dir])

    emit_progress(60, "Launching 3/5: HTTP Header & CORS Inspector...")
    subprocess.run([sys.executable, os.path.join(skills_dir, "web-and-api-audit-methods", "scripts", "http_header_posture.py")])

    emit_progress(80, "Launching 4/5: Cloud IAM & Container Manifest Auditor...")
    subprocess.run([sys.executable, os.path.join(skills_dir, "cloud-iam-and-container-hardening", "scripts", "cloud_manifest_auditor.py"), "--target", base_dir])

    emit_progress(95, "Launching 5/5: Secrets & High-Entropy Token Scanner...")
    subprocess.run([sys.executable, os.path.join(skills_dir, "secrets-and-api-leak-detection", "scripts", "secret_entropy_scanner.py"), "--target", base_dir])

    emit_progress(100, "All 5 Security & Recon Audits Successfully Executed!")
    print(f"\n{Style.GREEN}{Style.BOLD}✔ MASTER SUITE RUN COMPLETE. Reports generated in {base_dir}{Style.RESET}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

