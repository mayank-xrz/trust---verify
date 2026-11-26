#!/usr/bin/env bash
# ==============================================================================
# P4-16 Pre-Push Security Gate
#
# Enforces:
# 1. No agent/claude prompt files or secrets staged (.env, *.key, *.pem)
# 2. No hard-coded secret patterns in src/
# 3. ZERO AI/ML packages in requirements.txt (torch, scikit-learn, openai, etc.)
# ==============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "======================================================================"
echo "🔒 RUNNING P4-16 PRE-PUSH SECURITY GATE"
echo "======================================================================"

EXIT_CODE=0

# ------------------------------------------------------------------------------
# 1. Check for forbidden staged / tracked files
# ------------------------------------------------------------------------------
echo "▶ 1. Checking for forbidden staged / tracked files..."
# Strictly match agent.md, AGENT.md, claude.md, CLAUDE.md, .cursorrules, .claude, .env (and actual secret envs), *.key, *.pem
FORBIDDEN_FILES_PATTERN='(^|/)(([aA][gG][eE][nN][tT]|[cC][lL][aA][uU][dD][eE])\.[mM][dD]|\.cursorrules|\.claude/|\.env|\.env\.(local|prod|production|dev|development|test|secret|secrets)|.*\.key|.*\.pem)$'

# Check staged files if any
STAGED_FILES=$(git diff --cached --name-only 2>/dev/null || true)
if [ -n "$STAGED_FILES" ]; then
    VIOLATIONS=$(echo "$STAGED_FILES" | grep -E "$FORBIDDEN_FILES_PATTERN" || true)
    if [ -n "$VIOLATIONS" ]; then
        echo "❌ FAILED: The following forbidden files are staged:"
        echo "$VIOLATIONS" | sed 's/^/  - /'
        EXIT_CODE=1
    fi
fi

# Check all tracked files in git
TRACKED_VIOLATIONS=$(git ls-files | grep -E "$FORBIDDEN_FILES_PATTERN" || true)
if [ -n "$TRACKED_VIOLATIONS" ]; then
    echo "❌ FAILED: The following forbidden files are tracked in git:"
    echo "$TRACKED_VIOLATIONS" | sed 's/^/  - /'
    EXIT_CODE=1
fi

if [ $EXIT_CODE -eq 0 ]; then
    echo "  ✅ No forbidden files staged or tracked."
fi

# ------------------------------------------------------------------------------
# 2. Check for hard-coded secret patterns in src/
# ------------------------------------------------------------------------------
echo "▶ 2. Scanning src/ for hard-coded private keys or tokens..."
if [ -d "src" ]; then
    SECRET_MATCHES=$(grep -rnE 'BEGIN (RSA|EC|OPENSSH|DSA|PRIVATE) KEY|PRIVATE KEY-----|BEGIN CERTIFICATE' src/ 2>/dev/null || true)
    if [ -n "$SECRET_MATCHES" ]; then
        echo "❌ FAILED: Found embedded private keys in src/:"
        echo "$SECRET_MATCHES" | head -n 5
        EXIT_CODE=1
    else
        echo "  ✅ Zero hard-coded private keys in src/."
    fi
fi

# ------------------------------------------------------------------------------
# 3. Check for forbidden AI/ML dependencies in requirements.txt
# ------------------------------------------------------------------------------
echo "▶ 3. Verifying ZERO AI/ML packages in requirements.txt..."
FORBIDDEN_AIML_REGEX='(torch|tensorflow|keras|scikit-learn|sklearn|openai|anthropic|transformers|langchain|llama|groq|cohere)'

if [ -f "requirements.txt" ]; then
    AIML_MATCHES=$(grep -iE "$FORBIDDEN_AIML_REGEX" requirements.txt 2>/dev/null || true)
    if [ -n "$AIML_MATCHES" ]; then
        echo "❌ FAILED: Forbidden AI/ML dependencies found in requirements.txt:"
        echo "$AIML_MATCHES" | sed 's/^/  - /'
        EXIT_CODE=1
    else
        echo "  ✅ Zero AI/ML dependencies in requirements.txt."
    fi
fi

echo "======================================================================"
if [ $EXIT_CODE -eq 0 ]; then
    echo "🎉 ALL P4-16 SECURITY CHECKS PASSED!"
    echo "======================================================================"
    exit 0
else
    echo "💥 PRE-PUSH SECURITY CHECKS FAILED! Please fix the errors above."
    echo "======================================================================"
    exit 1
fi
