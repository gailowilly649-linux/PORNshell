---
name: bug-hunting-tactics
description: >-
  Use this skill when hunting for software bugs, performing source-to-sink taint
  analysis, auditing codebases for memory/logic/injection vulnerabilities,
  performing patch diffing or variant analysis, or running automated static sink
  discovery.
---

# Bug Hunting Methods, Taint Analysis & Variant Discovery

This skill provides structured methodologies and automated tooling for discovering high-impact security flaws, logic bugs, and parser differentials across codebases and binaries.

## Core Bug-Hunting Methodologies

### 1. Source-to-Sink Taint Tracing (Forward & Backward Slicing)
* **Backward Slicing (Sink-First):** Start at high-impact dangerous primitives (command execution, SQL query construction, deserialization, raw memory copy, file path resolution, SSRF HTTP clients) and trace backward through call graphs to verify whether attacker-controlled input reaches the sink without strict canonicalization or type-safe parameterization.
* **Forward Slicing (Source-First):** Enumerate all untrusted entry points (HTTP headers/params/body, WebSocket frames, gRPC protobuf fields, DNS responses, IPC messages, CLI args, environment variables) and trace how trust boundaries validate, transform, or normalize the data.

### 2. Parser Differentials & Canonicalization Mismatches
* **Check-vs-Use Discrepancies:** Hunt for architectures where Layer A (WAF, reverse proxy, validator middleware) parses an input differently from Layer B (backend service, database, OS filesystem):
  * **URL Parser Differentials:** RFC 3986 vs. WHATWG URL parsing (`\`, `@`, `#`, IPv6 zone IDs, octal/hex IPv4 representations) leading to SSRF filter bypasses or open redirects.
  * **Path Traversal & Normalization:** Validating path prefixes before URL-decoding, double-decoding, or symlink resolution (`os.path.realpath` vs string prefix checks).
  * **JSON/XML Duplicate Keys & Unicode Normalization:** First-key-wins vs. last-key-wins across Go `encoding/json`, Python `json`, and C++ parsers; NFKC/NFKD normalization turning benign Unicode characters into syntax metacharacters (`'`, `"`, `<`, `/`, `.`) *after* sanitization.

### 3. State Machine & Race Condition (TOCTOU) Auditing
* **Time-of-Check to Time-of-Use (TOCTOU):** Look for non-atomic check-then-act sequences in database transactions (missing `SELECT ... FOR UPDATE` or serializable isolation) or filesystem operations (checking `os.access()` before `open()`).
* **Multi-Step Workflow Bypass:** Verify whether state transitions (e.g., `initiated -> verified -> completed`) enforce cryptographic or server-side session state at every step rather than trusting client-supplied step parameters.

### 4. N-Day Patch Diffing & Variant Analysis
* When a bug or CVE is fixed in one module:
  1. Extract the exact root-cause pattern (e.g., missing integer overflow check before buffer allocation, or missing tenant ID filter in a query).
  2. Abstract the bug into a structural pattern or regex/AST rule.
  3. Sweep sibling classes, endpoints, and microservices for unpatched variants where the same developer pattern was copy-pasted.

---

## Automated Workflow Steps

1. **Run the Automated 10%–100% Static Sink & Pattern Hunter:**
   Execute [static_sink_hunter.py](./scripts/static_sink_hunter.py) against the target directory or file to automatically scan for high-risk sinks, deserialization primitives, command execution, SQL string formatting, path traversal risks, and cryptographic weaknesses:
   ```bash
   python3 .agent/skills/bug-hunting-tactics/scripts/static_sink_hunter.py --target .
   ```
2. **Consult the Vulnerability Sink & Pattern Reference:**
   Read [vulnerability-classes-and-sinks.md](./references/vulnerability-classes-and-sinks.md) for language-specific sinks (Python, JS/TS, Go, C/C++, PHP, Rust) and exploitation root-cause checklists.
3. **Verify Reachability & Sanitization:**
   For every candidate sink flagged by `static_sink_hunter.py`, trace the variable definitions up the call stack to confirm whether input is constant/trusted or externally reachable.

