#!/usr/bin/env bash
# =============================================================================
# BIRDHUNT - "EGG CANDLER" INTERACTIVE AUDIT SHELL WRAPPER
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Activate virtualenv if present
if [ -f "${BASE_DIR}/.venv/bin/activate" ]; then
    # shellcheck disable=SC1091
    source "${BASE_DIR}/.venv/bin/activate"
fi

exec python3 "${SCRIPT_DIR}/candled_egg.py" "$@"
