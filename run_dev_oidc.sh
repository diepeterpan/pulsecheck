#!/usr/bin/env bash
# ==============================================================================
# PulseCheck - Development OIDC Startup Script
# ==============================================================================
# Sets up OIDC environment variables and starts PulseCheck locally via
# .venv/bin/python3 app.py
# ==============================================================================

set -e

# Resolve script directory (PulseCheck project root)
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

ENV_FILE="$PROJECT_ROOT/.env.oidc"
EXAMPLE_FILE="$PROJECT_ROOT/.env.oidc.example"
VENV_PYTHON="$PROJECT_ROOT/.venv/bin/python3"

# 1. Verify virtual environment exists
if [ ! -x "$VENV_PYTHON" ]; then
    echo "❌ Error: Virtual environment python not found at $VENV_PYTHON" >&2
    echo "   Please create the virtual environment and install dependencies first:" >&2
    echo "   python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
    exit 1
fi

# 2. Check for .env.oidc or create it from .env.oidc.example
if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$EXAMPLE_FILE" ]; then
        echo "ℹ️  No .env.oidc found. Creating .env.oidc from template..."
        cp "$EXAMPLE_FILE" "$ENV_FILE"
        echo "✅ Created $ENV_FILE. Please review/update it with your OIDC credentials."
    else
        echo "⚠️  Warning: Neither .env.oidc nor .env.oidc.example found."
    fi
fi

# 3. Source environment variables from .env.oidc if present
if [ -f "$ENV_FILE" ]; then
    echo "🔧 Loading configuration from $ENV_FILE..."
    # Export all variables defined in .env.oidc
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
fi

# 4. Display startup banner
echo "=============================================================="
echo "🚀 Starting PulseCheck in OIDC Development Mode"
echo "=============================================================="
echo "   OIDC Enabled:    ${PULSECHECK_OIDC_ENABLED:-false}"
echo "   OIDC Issuer:     ${PULSECHECK_OIDC_ISSUER:-'(none)'}"
echo "   Client ID:       ${PULSECHECK_OIDC_CLIENT_ID:-'(none)'}"
echo "   Redirect URI:    ${PULSECHECK_OIDC_REDIRECT_URI:-'(default)'}"
echo "   Match Claim:     ${PULSECHECK_OIDC_MATCH_CLAIM:-'email'}"
echo "   Initial Admin:   ${PULSECHECK_OIDC_INITIAL_ADMIN:-'(none)'}"
echo "   Server URL:      http://${PULSECHECK_HOSTNAME:-127.0.0.1}:${PULSECHECK_PORT:-8182}"
echo "=============================================================="
echo "Press Ctrl+C to stop the server."
echo ""

# 5. Exec into python process, forwarding any extra arguments
exec "$VENV_PYTHON" app.py "$@"
