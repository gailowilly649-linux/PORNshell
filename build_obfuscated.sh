#!/bin/bash
# ==============================================================================
# build_obfuscated.sh — Automated 10% ➔ 100% PyArmor Code Obfuscation Pipeline
# Protects and encrypts all Python scripts in PORNshell while preserving
# clean source code in .src_private/
# ==============================================================================

set -e

GREEN="\033[92m"
CYAN="\033[96m"
MAGENTA="\033[95m"
BOLD="\033[1m"
RESET="\033[0m"

emit_progress() {
    local pct=$1
    local label=$2
    local filled=$((pct / 5))
    local empty=$((20 - filled))
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty; i++)); do bar+="░"; done
    local col=$CYAN
    if [ "$pct" -eq 100 ]; then col=$GREEN; fi
    echo -e "  ${col}${BOLD}[${bar}] $(printf "%3d" "$pct")%${RESET}  ▸ ${label}"
    sleep 0.05
}

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$BASE_DIR"

echo -e "\n${MAGENTA}${BOLD}⚡ INITIALIZING AUTOMATED PYARMOR CODE OBFUSCATION PIPELINE ⚡${RESET}\n"

emit_progress 10 "Backing up clean source code to .src_private/..."
mkdir -p .src_private
cp -a master_audit_suite.py dns_posture_audit.py dns_posture_core.py dns_posture_nsec3.py cve_toolkit.py .src_private/
cp -a .agent .src_private/

emit_progress 20 "Configuring isolated PyArmor workspace environment..."
export PYARMOR_HOME="$BASE_DIR/.pyarmor_home"
mkdir -p "$PYARMOR_HOME"
PYARMOR_BIN="$BASE_DIR/.venv/bin/pyarmor"

emit_progress 40 "Obfuscating root orchestrators (master_audit_suite.py & cve_toolkit.py)..."
"$PYARMOR_BIN" gen -O dist_root master_audit_suite.py cve_toolkit.py > /dev/null 2>&1

emit_progress 60 "Obfuscating modular DNS & RFC 5155 NSEC3 cryptographic engine..."
"$PYARMOR_BIN" gen -O dist_dns dns_posture_core.py dns_posture_nsec3.py dns_posture_audit.py > /dev/null 2>&1

emit_progress 80 "Obfuscating .agent/skills tactical security scripts..."
"$PYARMOR_BIN" gen -O dist_sink .agent/skills/bug-hunting-tactics/scripts/static_sink_hunter.py > /dev/null 2>&1
"$PYARMOR_BIN" gen -O dist_cloud .agent/skills/cloud-iam-and-container-hardening/scripts/cloud_manifest_auditor.py > /dev/null 2>&1
"$PYARMOR_BIN" gen -O dist_poc .agent/skills/poc-reproduction-and-triage/scripts/triage_scaffolder.py > /dev/null 2>&1
"$PYARMOR_BIN" gen -O dist_sec .agent/skills/secrets-and-api-leak-detection/scripts/secret_entropy_scanner.py > /dev/null 2>&1
"$PYARMOR_BIN" gen -O dist_web .agent/skills/web-and-api-audit-methods/scripts/http_header_posture.py > /dev/null 2>&1

emit_progress 90 "Deploying encrypted bytecode & runtime libraries..."
# Shared runtime at root
cp -r dist_root/pyarmor_runtime_* ./
cp dist_root/master_audit_suite.py ./
cp dist_root/cve_toolkit.py ./

# DNS runtime & modules
cp dist_dns/dns_posture_core.py ./
cp dist_dns/dns_posture_nsec3.py ./
cp dist_dns/dns_posture_audit.py ./

# Skill scripts
cp -r dist_sink/pyarmor_runtime_* .agent/skills/bug-hunting-tactics/scripts/ 2>/dev/null || true
cp dist_sink/static_sink_hunter.py .agent/skills/bug-hunting-tactics/scripts/

cp -r dist_cloud/pyarmor_runtime_* .agent/skills/cloud-iam-and-container-hardening/scripts/ 2>/dev/null || true
cp dist_cloud/cloud_manifest_auditor.py .agent/skills/cloud-iam-and-container-hardening/scripts/

cp -r dist_poc/pyarmor_runtime_* .agent/skills/poc-reproduction-and-triage/scripts/ 2>/dev/null || true
cp dist_poc/triage_scaffolder.py .agent/skills/poc-reproduction-and-triage/scripts/

cp -r dist_sec/pyarmor_runtime_* .agent/skills/secrets-and-api-leak-detection/scripts/ 2>/dev/null || true
cp dist_sec/secret_entropy_scanner.py .agent/skills/secrets-and-api-leak-detection/scripts/

cp -r dist_web/pyarmor_runtime_* .agent/skills/web-and-api-audit-methods/scripts/ 2>/dev/null || true
cp dist_web/http_header_posture.py .agent/skills/web-and-api-audit-methods/scripts/

# Cleanup temporary build dirs
rm -rf dist_root dist_dns dist_sink dist_cloud dist_poc dist_sec dist_web test_dist

# Fix permissions
chmod +x master_audit_suite.py dns_posture_audit.py cve_toolkit.py .agent/skills/*/scripts/*.py

emit_progress 100 "All scripts successfully encrypted and obfuscated with PyArmor!"

echo -e "\n${GREEN}${BOLD}✔ CODEBASE FULLY ARMORED & PROTECTED.${RESET}"
echo -e "  • All public .py files are now encrypted bytecode."
echo -e "  • Original clean source code safely backed up in: ${CYAN}.src_private/${RESET}\n"

