# Safe Triage & Vulnerability Analysis Methodology

## 1. The Bug Triage Lifecycle

| Stage | Activity | Key Deliverable |
|---|---|---|
| **1. Report Intake** | Verify prerequisites, affected versions, and configuration flags. | Scope confirmation & reproducibility status. |
| **2. Minimal Trigger Isolation** | Strip extraneous dependencies to find the simplest input that causes the failure. | Minimal test input (JSON, payload string, or unit test). |
| **3. Root-Cause Analysis** | Use debugger/sanitizer to identify the exact line, pointer, or state mismatch. | Source line reference & CWE classification. |
| **4. Patch Evaluation** | Review proposed fix for edge cases, off-by-one errors, or bypass variants. | Patch review comments & regression tests. |

## 2. Sanitizer Instrumentation Guide

For native C/C++ or Rust libraries:
* **AddressSanitizer (ASan):** Compile with `-fsanitize=address -g` to detect buffer overflows, use-after-free, and stack/heap out-of-bounds access.
* **UndefinedBehaviorSanitizer (UBSan):** Compile with `-fsanitize=undefined` to catch integer overflows, null-pointer dereferences, and alignment issues.

