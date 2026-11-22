#!/usr/bin/env bash
# =============================================================================
# BIRDHUNT - "BAKE EGG" ANSIBLE BUILDER PIPELINE
#
# Builds the standalone, immutable BirdHunt Execution Environment (EE) container
# using Ansible Builder. Packages Python dependencies, collections, and binaries.
# Optionally exports the image to 'birdhunt-ee.tar' for air-gapped CCDC transport.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILDER_DIR="${BASE_DIR}/builder"
IMAGE_TAG="birdhunt-ee:latest"
TAR_OUTPUT="${BASE_DIR}/birdhunt-ee.tar"

echo "========================================================"
echo "    BIRDHUNT - BAKING EXECUTION ENVIRONMENT CONTAINER   "
echo "========================================================"

# 1. Determine container engine (podman preferred, docker fallback)
if command -v podman >/dev/null 2>&1; then
    CONTAINER_ENGINE="podman"
elif command -v docker >/dev/null 2>&1; then
    CONTAINER_ENGINE="docker"
else
    echo "[-] Error: Neither podman nor docker found on this machine."
    echo "    Please install podman or docker to build the Execution Environment."
    exit 1
fi
echo "[+] Detected container engine: ${CONTAINER_ENGINE}"

# 2. Check for ansible-builder
if ! command -v ansible-builder >/dev/null 2>&1; then
    echo "[!] ansible-builder not found. Attempting to install via pip3..."
    pip3 install --quiet --upgrade ansible-builder
fi
echo "[+] ansible-builder is ready: $(ansible-builder --version 2>/dev/null || echo 'installed')"

# 3. Build the Execution Environment
echo "[*] Building ${IMAGE_TAG} with Ansible Builder..."
cd "${BUILDER_DIR}"
ansible-builder build \
    --file execution-environment.yml \
    --tag "${IMAGE_TAG}" \
    --container-runtime "${CONTAINER_ENGINE}" \
    --verbosity 2

echo "[✓] Container image built successfully: ${IMAGE_TAG}"

# 4. Export container image to tar archive for air-gapped competition transport
echo "[*] Exporting image to ${TAR_OUTPUT} for air-gapped transport..."
if [ "${CONTAINER_ENGINE}" = "podman" ]; then
    podman save -o "${TAR_OUTPUT}" "${IMAGE_TAG}"
else
    docker save -o "${TAR_OUTPUT}" "${IMAGE_TAG}"
fi

echo "========================================================"
echo "[✓] BAKE COMPLETE!"
echo "    Image:   ${IMAGE_TAG}"
echo "    Archive: ${TAR_OUTPUT} ($(du -h "${TAR_OUTPUT}" | cut -f1))"
echo ""
echo "To run playbooks with this container on any machine:"
echo "    ./scripts/crack_egg.sh playbooks/birdshot.yml -e \"seed_val=YourSeed!\""
echo "========================================================"
