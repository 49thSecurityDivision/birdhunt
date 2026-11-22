#!/usr/bin/env bash
# =============================================================================
# BIRDHUNT - "CRACK EGG" EXECUTION ENVIRONMENT RUNNER
#
# Runs BirdHunt playbooks inside the pre-built, immutable container.
# Uses host networking (--network host) and mounts the current directory into /runner.
# Automatically loads 'birdhunt-ee.tar' if the image is not yet in the local registry.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGE_TAG="birdhunt-ee:latest"
TAR_FILE="${BASE_DIR}/birdhunt-ee.tar"

# 1. Determine container engine
if command -v podman >/dev/null 2>&1; then
    CONTAINER_ENGINE="podman"
elif command -v docker >/dev/null 2>&1; then
    CONTAINER_ENGINE="docker"
else
    echo "[-] Error: Neither podman nor docker found on this machine."
    echo "    To run natively on bare-metal jumpbox without containers, use:"
    echo "    ansible-playbook playbooks/birdshot.yml"
    exit 1
fi

# 2. Check if image exists; if not, load from tar if present
if ! ${CONTAINER_ENGINE} image inspect "${IMAGE_TAG}" >/dev/null 2>&1; then
    if [ -f "${TAR_FILE}" ]; then
        echo "[*] Image '${IMAGE_TAG}' not found locally. Loading from ${TAR_FILE}..."
        ${CONTAINER_ENGINE} load -i "${TAR_FILE}"
        echo "[✓] Loaded successfully."
    else
        echo "[-] Error: Image '${IMAGE_TAG}' not found and ${TAR_FILE} does not exist."
        echo "    Run './scripts/bake_egg.sh' first to build the image."
        exit 1
    fi
fi

# 3. Handle default invocation
if [ "$#" -eq 0 ]; then
    echo "========================================================"
    echo "    BIRDHUNT - CONTAINERIZED EXECUTION ENVIRONMENT      "
    echo "========================================================"
    echo "Usage:"
    echo "    ./scripts/crack_egg.sh playbooks/birdshot.yml -e \"seed_val=YourSeed!\""
    echo "    ./scripts/crack_egg.sh playbooks/snipe.yml"
    echo "    ./scripts/crack_egg.sh playbooks/quail.yml -e \"seed_val=YourSeed!\""
    echo "    ./scripts/crack_egg.sh playbooks/turkey.yml -e \"seed_val=YourSeed!\""
    echo ""
    echo "Or run arbitrary Ansible commands:"
    echo "    ./scripts/crack_egg.sh --version"
    echo "    ./scripts/crack_egg.sh all -m ping"
    exit 0
fi

# 4. Check if first argument is a playbook or an ad-hoc command
FIRST_ARG="$1"
if [[ "${FIRST_ARG}" == *.yml ]] || [[ "${FIRST_ARG}" == *.yaml ]] || [[ "${FIRST_ARG}" == playbooks/* ]]; then
    CMD=("ansible-playbook" "$@")
elif [ "${FIRST_ARG}" = "ping" ] || [ "${FIRST_ARG}" = "all" ]; then
    CMD=("ansible" "$@")
else
    CMD=("$@")
fi

# 5. Execute container with host networking and volume mount
echo "[*] Executing inside BirdHunt Execution Environment (${CONTAINER_ENGINE})..."
${CONTAINER_ENGINE} run --rm -it \
    --network host \
    -v "${BASE_DIR}:/runner:Z" \
    -w /runner \
    "${IMAGE_TAG}" \
    "${CMD[@]}"
