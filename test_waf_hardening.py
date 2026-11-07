#!/usr/bin/env python3
"""
================================================================================
  PORNshell WAF & Hardening Rule Verification Test Suite
  Authors: ENI & LO
  Tests local/staging web server against security_hardening.conf patterns:
  - Path traversal checks (../, /etc/passwd, %2e%2e%2f)
  - Sensitive dotfile checks (.env, .git, .bak)
  - XXE injection blocking (DOCTYPE / ENTITY SYSTEM)
  - Disallowed HTTP methods
================================================================================
"""

import sys
import argparse
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

TEST_VECTORS = [
    {
        "category": "Path Traversal",
        "description": "Directory traversal via relative path sequence",
        "path": "/../../../etc/passwd",
        "method": "GET",
        "expected_status": [400, 403, 404]
    },
    {
        "category": "Path Traversal",
        "description": "URL-encoded traversal payload (%2e%2e%2f)",
        "path": "/%2e%2e%2f%2e%2e%2fetc/passwd",
        "method": "GET",
        "expected_status": [400, 403, 404]
    },
    {
        "category": "Sensitive File Exposure",
        "description": "Environment configuration file (.env)",
        "path": "/.env",
        "method": "GET",
        "expected_status": [403, 404]
    },
    {
        "category": "Sensitive File Exposure",
        "description": "Git repository configuration (.git/config)",
        "path": "/.git/config",
        "method": "GET",
        "expected_status": [403, 404]
    },
    {
        "category": "Sensitive File Exposure",
        "description": "Database backup archive (.sql)",
        "path": "/backup.sql",
        "method": "GET",
        "expected_status": [403, 404]
    },
    {
        "category": "XXE Injection",
        "description": "XML parser probe with DOCTYPE external entity",
        "path": "/api/xml-test",
        "method": "POST",
        "headers": {"Content-Type": "application/xml"},
        "data": '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',
        "expected_status": [400, 403, 404, 405]
    },
    {
        "category": "HTTP Method Validation",
        "description": "Disallowed arbitrary HTTP method (TRACE)",
        "path": "/",
        "method": "TRACE",
        "expected_status": [403, 405]
    }
]

def run_tests(base_url):
    console.print(Panel(f"[bold cyan]Running Hardening Verification against: {base_url}[/bold cyan]"))
    table = Table(title="WAF & Hardening Test Results", show_lines=True)
    table.add_column("Category", style="cyan", width=22)
    table.add_column("Test Vector", style="white")
    table.add_column("Method", style="yellow", width=8)
    table.add_column("HTTP Code", style="magenta", width=10)
    table.add_column("Status", width=12)

    passed_count = 0
    total = len(TEST_VECTORS)

    for tv in TEST_VECTORS:
        target = base_url.rstrip("/") + tv["path"]
        try:
            headers = tv.get("headers", {})
            data = tv.get("data", None)
            req = requests.Request(tv["method"], target, headers=headers, data=data)
            prepped = requests.Session().prepare_request(req)
            res = requests.Session().send(prepped, timeout=5, allow_redirects=False)

            is_blocked = res.status_code in tv["expected_status"]
            status_text = "[bold green]PROTECTED[/bold green]" if is_blocked else "[bold red]VULNERABLE[/bold red]"
            if is_blocked:
                passed_count += 1

            table.add_row(
                tv["category"],
                tv["description"],
                tv["method"],
                str(res.status_code),
                status_text
            )
        except Exception as e:
            table.add_row(
                tv["category"],
                tv["description"],
                tv["method"],
                "ERR",
                f"[yellow]Timeout/Unreachable[/yellow]"
            )

    console.print(table)
    console.print(f"\n[bold]Summary:[/bold] {passed_count}/{total} hardening checks passed safely.\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PORNshell WAF Verification Tester")
    parser.add_argument("-u", "--url", default="http://127.0.0.1:8080", help="Base URL of target or staging server")
    args = parser.parse_args()
    run_tests(args.url)

