---
name: poc-reproduction-and-triage
description: >-
  Use this skill when safely triaging reported vulnerabilities, constructing
  minimal reproducible test cases in sandboxed environments, performing root-cause
  analysis on security bugs, or verifying whether a patch successfully remediates
  a reported flaw.
---

# Vulnerability Reproduction, Safe Test-Case Construction & Patch Verification

This skill defines safe, controlled engineering practices for verifying software bugs, validating defensive patch efficacy, and reproducing issues without creating weaponized exploit material.

## Core Reproduction & Triage Principles

### 1. Minimal Reproducible Examples (MRE) vs. Exploitation
* **Defensive Objective:** The goal of security engineering triage is to identify the precise input conditions that trigger an abnormal state (e.g., unhandled exception, assertion failure, memory fault, or authorization bypass) so developers can write regression tests and apply robust fixes.
* **Non-Weaponization Boundary:** 
  * Focus on diagnostic instrumentation (e.g., debug loggers, unit test mocks, boundary assertions, ASan/UBSan traces).
  * Avoid building multi-stage exploitation chains, interactive shell payloads, persistence mechanisms, or automated payload generators.

### 2. Sandboxing & Environmental Isolation
* Always conduct reproduction in isolated, ephemeral environments:
  * Non-production container or VM networks without external internet egress.
  * Local dummy targets (e.g., mock HTTP servers, memory-backed test databases).
  * Instrument targets using AddressSanitizer (`-fsanitize=address`) or Valgrind to catch buffer over-reads and invalid memory access at the exact failure point.

### 3. Patch Verification & Negative Testing
* Once a bug is understood:
  1. **Before Patch:** Run the minimal trigger input to verify the failure mode reproduces.
  2. **Apply Defensive Patch:** Apply bounds check, canonicalization, input validation, or parameterized query.
  3. **After Patch:** Re-run the trigger input to confirm it is handled cleanly (e.g., graceful HTTP 400 Bad Request, caught exception, zero crash).
  4. **Regression Suite:** Add the test case into the project's automated test harness (`pytest`, `go test`, `cargo test`) to ensure future code changes don't reintroduce the flaw.

---

## Automated Execution Steps

1. **Run the Automated Triage & Test-Case Scaffolder:**
   Execute [triage_scaffolder.py](./scripts/triage_scaffolder.py) to generate isolated regression test fixtures:
   ```bash
   python3 .agent/skills/poc-reproduction-and-triage/scripts/triage_scaffolder.py --target-module example
   ```
2. **Consult Triage & Isolation Reference:**
   Read [safe-triage-methodology.md](./references/safe-triage-methodology.md) for root-cause analysis runbooks.

