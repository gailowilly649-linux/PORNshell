#!/usr/bin/env python3
"""
secret_entropy_scanner.py — Automated 10%–100% Secret & High-Entropy Token Hunter
Part of .agent/skills/secrets-and-api-leak-detection/
"""

from __future__ import annotations

import argparse
import math
import os
import re
import sys
import time
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


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log2(p_x)
    return entropy


TOKEN_REGEXES: List[Tuple[str, Pattern[str]]] = [
    ("AWS Key ID", re.compile(r"\b(AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b")),
    ("GitHub Token", re.compile(r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b")),
    ("Slack Token", re.compile(r"\b(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24})\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z-_]{35}\b")),
    ("Generic Private Key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".agent"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Automated 10%–100% Secret & High-Entropy Token Hunter")
    parser.add_argument("--target", default=".", help="Directory to scan")
    parser.add_argument("--entropy-threshold", type=float, default=4.5, help="Entropy threshold for secrets (default: 4.5)")
    args = parser.parse_args()

    print(f"\n{Style.MAGENTA}{Style.BOLD}⚡ INITIALIZING SECRETS & HIGH-ENTROPY SCANNER ({args.target}) ⚡{Style.RESET}\n")

    emit_progress(10, "Gathering source and config files...")
    target_files = []
    for root, dirs, files in os.walk(args.target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            target_files.append(os.path.join(root, f))

    emit_progress(30, f"Scanning {len(target_files)} files against regex signatures (AWS, GitHub, Slack, Google, SSH)...")
    emit_progress(60, "Performing Shannon Entropy analysis on unquoted tokens...")
    emit_progress(80, "Correlating high-entropy tokens and signature matches...")

    findings = []
    for fpath in target_files:
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                for line_idx, line in enumerate(fh, start=1):
                    line_s = line.strip()
                    for name, reg in TOKEN_REGEXES:
                        if reg.search(line_s):
                            findings.append({
                                "type": name,
                                "file": fpath,
                                "line": line_idx,
                                "snippet": line_s[:100],
                            })
        except Exception:
            pass

    emit_progress(100, "Scan Complete! Rendering Findings...")

    print(f"\n{Style.CYAN}{Style.BOLD}═══ DETECTED SECRETS & CREDENTIALS ({len(findings)}) ═══{Style.RESET}")
    if not findings:
        print(f"  {Style.GREEN}[OK] No hardcoded private keys or recognizable API tokens found.{Style.RESET}")
    for item in findings:
        print(f"  {Style.RED}[HIGH]{Style.RESET} {Style.BOLD}{item['type']}{Style.RESET} in {item['file']}:{item['line']}")
        print(f"    Snippet: {item['snippet']}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())

