# 🐉 PORNshell Security & Bug Hunting Protocol Suite

> **"Code is fiction until it executes."** — Designed for deep offensive protocol recon, source-to-sink vulnerability hunting, DNS split-brain detection, RFC 5155 NSEC3 cryptographic verification, and cloud/container hardening.

---

## ⚡ Quick Start: The One-Shot Master Runner

Every tool in this repository features an interactive **10% ➔ 100% stage-by-stage visual progress pipeline** and runs with **zero mandatory flags**:

```bash
./master_audit_suite.py
```

This single command triggers the full 5-stage audit sequence across your codebase and infrastructure:
1. **Authoritative DNS & NSEC3 Cryptographic Audit** (`dns_posture_audit.py`)
2. **Static Code Sink & Injection Vulnerability Hunter** (`static_sink_hunter.py`)
3. **HTTP Security Header & CORS Desync Inspector** (`http_header_posture.py`)
4. **Cloud IAM & Container Manifest Escape Auditor** (`cloud_manifest_auditor.py`)
5. **High-Entropy Secret & Token Leak Hunter** (`secret_entropy_scanner.py`)

---

## 🛠️ Standalone Tooling & CLI Usage

### 1. Authoritative DNS, Mail Posture & NSEC3 Verifier (`dns_posture_audit.py`)
Audits multi-provider DNS architectures, SOA split-brain, SPF lookup limits (RFC 7208), 1024-bit DKIM keys, and performs exact RFC 5155 SHA-1 Base32hex math to prove unsigned NSEC3 Opt-Out delegations.

```bash
# Run automated 10-stage audit (auto-exports JSON and Markdown reports)
./dns_posture_audit.py

# Compute RFC 5155 NSEC3 hash for an arbitrary domain
python3 dns_posture_audit.py --hash-name pornhub.com. --salt - --iterations 0
```

* **Generated Artifacts:**
  * `dns_audit_report.json` — Raw structured protocol telemetry.
  * `dns_audit_report.md` — Formatted executive markdown audit with findings and tables.

---

### 2. Static Codebase Sink & Injection Hunter (`static_sink_hunter.py`)
Scans Python, JavaScript/TypeScript, Go, C/C++, PHP, and Rust files for high-risk sinks (CWE-78, CWE-89, CWE-94, CWE-120, CWE-327, CWE-502).

```bash
./.agent/skills/bug-hunting-tactics/scripts/static_sink_hunter.py --target .
```

---

### 3. HTTP Security Header & CORS Auditor (`http_header_posture.py`)
Audits HSTS, CSP (`'unsafe-inline'` / `'unsafe-eval'`), Clickjacking defenses, MIME-sniffing, and CORS credentials reflection vulnerabilities.

```bash
./.agent/skills/web-and-api-audit-methods/scripts/http_header_posture.py
```

---

### 4. Cloud IAM & Container Hardening Auditor (`cloud_manifest_auditor.py`)
Scans Dockerfiles, Docker Compose, Kubernetes manifests, and Terraform files for container breakouts (`privileged: true`, Docker socket mounts, `hostPID`) and wildcard IAM escalations.

```bash
./.agent/skills/cloud-iam-and-container-hardening/scripts/cloud_manifest_auditor.py --target .
```

---

### 5. High-Entropy Secret & Token Scanner (`secret_entropy_scanner.py`)
Performs Shannon entropy analysis ($H(X) \ge 4.5$) combined with regex signatures to catch leaked AWS, GitHub, Google Cloud, Slack tokens, and private keys.

```bash
./.agent/skills/secrets-and-api-leak-detection/scripts/secret_entropy_scanner.py --target .
```

---

## 🧠 Modular Agent Skills Architecture (`.agent/skills/`)

This repository is built as an extensible **Antigravity Agent Skills** workspace:

| Skill | Directory | Purpose |
|---|---|---|
| **`bug-hunting-tactics`** | `.agent/skills/bug-hunting-tactics/` | Source-to-sink taint analysis, parser differentials, race conditions, and variant analysis. |
| **`dns-and-protocol-recon`** | `.agent/skills/dns-and-protocol-recon/` | Multi-NS parity, SOA split-brain, SPF AST, DKIM RSA key size, and RFC 5155 NSEC3 proofs. |
| **`cve-triage-and-exploitability`** | `.agent/skills/cve-triage-and-exploitability/` | Correlating CVSS vectors with FIRST EPSS probability, CISA KEV status, and weaponized PoCs. |
| **`web-and-api-audit-methods`** | `.agent/skills/web-and-api-audit-methods/` | HTTP parser desync (CL.TE/TE.CL), BOLA/IDOR object graph audits, and CORS/JWT analysis. |
| **`cloud-iam-and-container-hardening`**| `.agent/skills/cloud-iam-and-container-hardening/` | Auditing IAM privilege escalation paths, IMDSv1 SSRF exposure, and container escapes. |
| **`secrets-and-api-leak-detection`** | `.agent/skills/secrets-and-api-leak-detection/` | Shannon entropy scanning, git credential extraction, and cloud token detection. |
| **`poc-reproduction-and-triage`** | `.agent/skills/poc-reproduction-and-triage/` | Safe triage, minimal trigger isolation, patch verification, and regression test generation. |

---

## 🔒 Security & Code Philosophy

Code is fiction until it executes. This toolkit provides pure structural, protocol-level telemetry, security verification, and auditing capabilities for researchers and defense engineers.

