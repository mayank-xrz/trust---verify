#!/usr/bin/env bash
# ==============================================================================
# P4-16 Pre-Push Security Gate
#
# Enforces:
# a) No forbidden files staged or tracked (agent.md, claude.md case-insensitive,
#    .claude/, .cursorrules, .env, *.key, *.pem, *.p12).
# b) No hard-coded secret patterns (PRIVATE KEY, BEGIN RSA, BEGIN OPENSSH,
#    API_KEY=, SECRET_KEY=) inside src/ or tests/.
# c) ZERO banned AI/ML packages (torch, scikit-learn, sklearn, tensorflow,
#    keras, transformers, openai, anthropic, langchain) in requirements.txt or src/.
# d) Current branch cannot be 'main' (warns and blocks pushing directly to main).
# ==============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "======================================================================"
echo "🔒 RUNNING P4-16 PRE-PUSH SECURITY GATE"
echo "======================================================================"

EXIT_CODE=0

# ------------------------------------------------------------------------------
# d. Check current git branch (block pushing directly to main)
# ------------------------------------------------------------------------------
echo "▶ Checking active git branch..."
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
if [ "$CURRENT_BRANCH" = "main" ]; then
    echo "❌ FAILED: Direct push to 'main' is strictly prohibited!"
    echo "  You must work and push only from your assigned feature/track branch (e.g., krishna)."
    EXIT_CODE=1
else
    echo "  ✅ Active branch is '$CURRENT_BRANCH' (not main)."
fi

# ------------------------------------------------------------------------------
# a. Check for forbidden staged / tracked files
# ------------------------------------------------------------------------------
echo "▶ 1. Checking for forbidden staged / tracked files..."
FORBIDDEN_FILES_PATTERN='(^|/)(([aA][gG][eE][nN][tT]|[cC][lL][aA][uU][dD][eE])\.[mM][dD]|\.cursorrules|\.claude/|\.env|\.env\.(local|prod|production|dev|development|test|secret|secrets)|.*\.key|.*\.pem|.*\.p12)$'

# Check staged files if any
STAGED_FILES=$(git diff --cached --name-only 2>/dev/null || true)
if [ -n "$STAGED_FILES" ]; then
    STAGED_VIOLATIONS=$(echo "$STAGED_FILES" | grep -E "$FORBIDDEN_FILES_PATTERN" || true)
    if [ -n "$STAGED_VIOLATIONS" ]; then
        echo "❌ FAILED: The following forbidden files are staged for commit:"
        echo "$STAGED_VIOLATIONS" | sed 's/^/  - /'
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
# b. Check for hard-coded secret patterns in src/ or tests/
# ------------------------------------------------------------------------------
echo "▶ 2. Scanning src/ and tests/ for hard-coded secret patterns..."
SECRET_PATTERN='PRIVATE KEY|BEGIN RSA|BEGIN OPENSSH|API_KEY=|SECRET_KEY='

for CHECK_DIR in src tests; do
    if [ -d "$CHECK_DIR" ]; then
        SECRET_MATCHES=$(grep -rnE "$SECRET_PATTERN" "$CHECK_DIR" 2>/dev/null | grep -vE 're\.compile|test_security_regression\.py' || true)
        if [ -n "$SECRET_MATCHES" ]; then
            echo "❌ FAILED: Found prohibited secret patterns in $CHECK_DIR/:"
            echo "$SECRET_MATCHES" | head -n 10 | sed 's/^/  - /'
            EXIT_CODE=1
        fi
    fi
done

if [ $EXIT_CODE -eq 0 ]; then
    echo "  ✅ Zero hard-coded secret patterns in src/ and tests/."
fi

# ------------------------------------------------------------------------------
# c. Check for banned AI/ML dependencies in requirements.txt or src/
# ------------------------------------------------------------------------------
echo "▶ 3. Verifying ZERO AI/ML packages in requirements.txt and src/..."
BANNED_AIML_REGEX='(torch|scikit-learn|sklearn|tensorflow|keras|transformers|openai|anthropic|langchain)'

if [ -f "requirements.txt" ]; then
    AIML_REQ_MATCHES=$(grep -iE "$BANNED_AIML_REGEX" requirements.txt 2>/dev/null || true)
    if [ -n "$AIML_REQ_MATCHES" ]; then
        echo "❌ FAILED: Forbidden AI/ML dependencies found in requirements.txt:"
        echo "$AIML_REQ_MATCHES" | sed 's/^/  - /'
        EXIT_CODE=1
    fi
fi

if [ -d "src" ]; then
    AIML_SRC_MATCHES=$(grep -rnE "import (torch|sklearn|scikit_learn|tensorflow|keras|transformers|openai|anthropic|langchain)" src/ 2>/dev/null || true)
    if [ -n "$AIML_SRC_MATCHES" ]; then
        echo "❌ FAILED: Forbidden AI/ML imports found in src/:"
        echo "$AIML_SRC_MATCHES" | sed 's/^/  - /'
        EXIT_CODE=1
    fi
fi

if [ $EXIT_CODE -eq 0 ]; then
    echo "  ✅ Zero AI/ML dependencies in requirements.txt and src/."
fi

echo "======================================================================"
if [ $EXIT_CODE -eq 0 ]; then
    echo "PRE-PUSH CHECK PASSED"
    echo "======================================================================"
    exit 0
else
    echo "💥 PRE-PUSH SECURITY CHECKS FAILED! Please fix the errors above."
    echo "======================================================================"
    exit 1
fi
