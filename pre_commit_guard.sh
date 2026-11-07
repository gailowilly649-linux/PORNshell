#!/usr/bin/env bash
# ==============================================================================
# PORNshell Pre-Commit Defense Gate (Secrets, Keys & Env Shield)
# Authors: ENI & LO
# Blocks commits containing sensitive .env files, private keys, or raw tokens
# ==============================================================================

set -e

RED="\033[91m"
GREEN="\033[92m"
YELLOW="\033[93m"
BOLD="\033[1m"
RESET="\033[0m"

echo -e "${YELLOW}${BOLD}🔍 [PORNshell Defense Gate] Scanning staged files for sensitive secrets & environment leaks...${RESET}"

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
    exit 0
fi

LEAK_DETECTED=0

for FILE in $STAGED_FILES; do
    # 1. Block dangerous configuration / environment files
    if [[ "$FILE" =~ \.(env|env\..*|pem|key|pfx|p12|id_rsa|id_ed25519)$ ]]; then
        echo -e "${RED}${BOLD}[!] CRITICAL: Staged file matches blocked credential/environment pattern: ${FILE}${RESET}"
        LEAK_DETECTED=1
    fi

    # 2. Inspect file content for high-entropy tokens and private key banners
    if [ -f "$FILE" ]; then
        if git diff --cached "$FILE" | grep -E -q "BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{36,}|sk-[a-zA-Z0-9]{20,}|xox[baprs]-[0-9a-zA-Z]{10,}"; then
            echo -e "${RED}${BOLD}[!] CRITICAL: High-entropy secret token or private key found in diff: ${FILE}${RESET}"
            LEAK_DETECTED=1
        fi
    fi
done

if [ "$LEAK_DETECTED" -eq 1 ]; then
    echo -e "\n${RED}${BOLD}❌ COMMIT REJECTED: Sensitive credentials or environment files detected!${RESET}"
    echo -e "${YELLOW}Please remove the sensitive tokens or add the file to .gitignore before committing.${RESET}\n"
    exit 1
fi

echo -e "${GREEN}${BOLD}✔ [PORNshell Defense Gate] Clean check: No sensitive secrets or env files found staged.${RESET}"
exit 0

