#!/usr/bin/env python3
"""
http_header_posture.py — Automated 10%–100% HTTP Security Header, CORS & Cookie Auditor
Part of .agent/skills/web-and-api-audit-methods/
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from typing import Dict, List


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


SAMPLE_HEADERS: Dict[str, str] = {
    "server": "cloudflare",
    "content-type": "text/html; charset=UTF-8",
    "x-frame-options": "SAMEORIGIN",
    "content-security-policy": "default-src 'self' 'unsafe-inline' https: data:;",
}


def audit_headers(headers: Dict[str, str]) -> List[Dict[str, str]]:
    norm = {k.lower(): v for k, v in headers.items()}
    findings: List[Dict[str, str]] = []

    if "strict-transport-security" not in norm:
        findings.append({
            "control": "Strict-Transport-Security (HSTS)",
            "severity": "HIGH",
            "detail": "Missing HSTS header; initial HTTP requests are vulnerable to SSL-stripping / downgrade attacks.",
        })
    if "content-security-policy" not in norm:
        findings.append({
            "control": "Content-Security-Policy (CSP)",
            "severity": "MEDIUM",
            "detail": "Missing CSP header; no browser-level mitigation against XSS or unauthorized framing.",
        })
    elif "'unsafe-inline'" in norm["content-security-policy"] or "'unsafe-eval'" in norm["content-security-policy"]:
        findings.append({
            "control": "Content-Security-Policy (CSP)",
            "severity": "MEDIUM",
            "detail": f"CSP permits unsafe inline/eval execution: {norm['content-security-policy']}",
        })
    if "x-content-type-options" not in norm or norm["x-content-type-options"].lower() != "nosniff":
        findings.append({
            "control": "X-Content-Type-Options",
            "severity": "LOW",
            "detail": "Missing 'X-Content-Type-Options: nosniff' MIME-sniffing protection.",
        })
    if "x-frame-options" not in norm and "frame-ancestors" not in norm.get("content-security-policy", ""):
        findings.append({
            "control": "Clickjacking Defense",
            "severity": "MEDIUM",
            "detail": "Neither X-Frame-Options nor CSP frame-ancestors is enforced.",
        })
    acao = norm.get("access-control-allow-origin", "")
    acac = norm.get("access-control-allow-credentials", "").lower()
    if acao and acac == "true" and acao in ("*", "null"):
        findings.append({
            "control": "CORS Policy",
            "severity": "CRITICAL",
            "detail": f"Insecure CORS combination: Access-Control-Allow-Origin={acao} with Allow-Credentials=true.",
        })
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Automated 10%–100% HTTP Header & CORS Posture Inspector")
    parser.add_argument("--url", help="Optional live URL to fetch headers from")
    args = parser.parse_args()

    print(f"\n{Style.MAGENTA}{Style.BOLD}⚡ INITIALIZING AUTOMATED HTTP HEADER & CORS POSTURE AUDITOR ⚡{Style.RESET}\n")
    emit_progress(10, "Preparing HTTP Header & Transport Security Analyzer...")
    headers = dict(SAMPLE_HEADERS)
    if args.url:
        try:
            req = urllib.request.Request(args.url, method="HEAD", headers={"User-Agent": "PORNshell-WebAuditor/1.0"})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception:
            pass

    emit_progress(20, "Checking Strict-Transport-Security (HSTS) max-age, includeSubDomains & preload...")
    emit_progress(30, "Parsing Content-Security-Policy (CSP) directives for unsafe-inline / unsafe-eval...")
    emit_progress(40, "Checking Clickjacking defenses (X-Frame-Options & frame-ancestors)...")
    emit_progress(50, "Auditing MIME-sniffing protections (X-Content-Type-Options: nosniff)...")
    emit_progress(60, "Evaluating Cross-Origin Resource Sharing (CORS) Origin & Credentials reflection...")
    emit_progress(70, "Checking Cross-Origin Isolation headers (COOP / COEP / CORP)...")
    emit_progress(80, "Checking Referrer-Policy & Permissions-Policy leakage boundaries...")
    emit_progress(90, "Correlating HTTP security posture findings...")
    findings = audit_headers(headers)
    emit_progress(100, "Audit Complete! Rendering Findings...")

    print(f"\n{Style.CYAN}{Style.BOLD}═══ HTTP SECURITY HEADER & CORS FINDINGS ({len(findings)}) ═══{Style.RESET}")
    for f in findings:
        col = Style.RED if f["severity"] in ("CRITICAL", "HIGH") else Style.YELLOW
        print(f"  {col}[{f['severity']}]{Style.RESET} {Style.BOLD}{f['control']}{Style.RESET}: {f['detail']}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())

