#!/usr/bin/env bash
# =============================================================================
# BIRDHUNT - "LAY EGG" INVENTORY BUILDER & CONNECTIVITY TESTER WRAPPER
# =============================================================================

set -euo pipefail

# Locate repository root (handles direct execution, symlinks, and working directory)
if [ -f "./nest.yaml" ] || [ -d "./playbooks" ]; then
    BASE_DIR="$(pwd)"
else
    SOURCE="${BASH_SOURCE[0]}"
    while [ -L "$SOURCE" ]; do
        DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
        SOURCE="$(readlink "$SOURCE")"
        [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
    done
    SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
    if [ -f "${SCRIPT_DIR}/nest.yaml" ]; then
        BASE_DIR="${SCRIPT_DIR}"
    else
        BASE_DIR="$(cd -P "${SCRIPT_DIR}/.." && pwd)"
    fi
fi

# Activate virtualenv if present
if [ -f "${BASE_DIR}/.venv/bin/activate" ]; then
    # shellcheck disable=SC1091
    source "${BASE_DIR}/.venv/bin/activate"
fi

# Run lay_egg.py
if [ -f "${BASE_DIR}/SCRIPTS/lay_egg.py" ]; then
    exec python3 "${BASE_DIR}/SCRIPTS/lay_egg.py" "$@"
elif [ -f "${BASE_DIR}/scripts/lay_egg.py" ]; then
    exec python3 "${BASE_DIR}/scripts/lay_egg.py" "$@"
else
    exec python3 "$(dirname "${BASH_SOURCE[0]}")/lay_egg.py" "$@"
fi
