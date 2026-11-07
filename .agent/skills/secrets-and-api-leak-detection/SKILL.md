---
name: secrets-and-api-leak-detection
description: >-
  Use this skill when auditing repositories, git history, configuration files,
  or environment dumps for exposed secrets, high-entropy API tokens, private
  keys, and database connection strings.
---

# Secrets, API Token & High-Entropy Credential Detection

This skill provides methodologies and tools for uncovering hardcoded private keys, cloud service provider credentials, high-entropy secret strings, and webhook tokens.

## Core Secrets Hunting Methods

### 1. High-Entropy & Structured Token Analysis
* **Cloud & Provider Prefixes:**
  * AWS: `AKIA[0-9A-Z]{16}`, `aws_secret_access_key`
  * GitHub: `ghp_[a-zA-Z0-9]{36}`, `gho_`, `github_pat_`
  * Slack: `xoxb-`, `xoxp-`, `xoxa-`
  * Stripe: `sk_live_[0-9a-zA-Z]{24}`
  * Google Cloud / Firebase API keys: `AIza[0-9A-Za-z-_]{35}`
* **Shannon Entropy Scoring:**
  * Calculate Shannon entropy on base64 and hex strings. Strings with length $> 20$ and entropy $> 4.5$ indicate generated cryptographic secrets rather than human words.

### 2. Common Leak Sinks & Artifact Boundaries
* Look in `.env`, `.env.local`, `.env.backup`, `.env.production`, `config.json`, `settings.py`, `.bash_history`, `.docker/config.json`, and database dump files (`.sql`, `.dump`).
* Check exposed document storage and backups: `*.doc`, `*.docx`, `*.pdf`, `*.xls`, `*.xlsx` containing embedded metadata, internal connection strings, or system passwords.
* Audit API service configuration roots: `docker-compose.yml`, Kubernetes secrets manifests, Helm charts, and CI/CD pipelines (`.github/workflows`, `.gitlab-ci.yml`).
* Scan commit history and dangling git blobs (`git log -p`, `git fsck --lost-found`).

### 3. LO's Operational Tactics & Methods (Defense & Audit Standard)
* **Pre-Flight Environment Scrubbing:** Always enforce strict path ignore lists on local repositories so that `.env` files, production keys, and sensitive documents never touch public branches.
* **Taint Analysis on File Retrieval Endpoints:** Methodically trace user-controlled file paths to verify whether endpoints restrict directory traversal and enforce strict allowlisting before serving any document.
* **API Credential Verification & Scoping:** If an API key is detected during an authorized audit, verify permissions using the least-privilege principle without performing state-changing or exfiltration actions.

---

## Automated Execution Steps

1. **Run the Automated Secrets & Token Hunter:**
   Execute [secret_entropy_scanner.py](./scripts/secret_entropy_scanner.py) across the repository:
   ```bash
   python3 .agent/skills/secrets-and-api-leak-detection/scripts/secret_entropy_scanner.py --target .
   ```
2. **Consult Pattern Cheatsheet:**
   Read [secret-regex-and-entropy-guide.md](./references/secret-regex-and-entropy-guide.md) for patterns and remediation steps.

