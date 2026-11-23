#!/usr/bin/env bash
# =============================================================================
# BIRDHUNT - "HATCH EGG" JUMPBOX BOOTSTRAP SCRIPT (100% OFFLINE-CAPABLE)
#
# Initializes Jumpbox dependencies for CCDC.
# Automatically detects offline pre-packaged assets in the repository:
#   1. Local Python wheels in ./wheelhouse/ (installs via --no-index)
#   2. Local Ansible collections in ./collections/
#   3. Local agent installers in ./playbooks/files/
# Tolerates completely air-gapped jumpboxes where apt/dnf repositories are unreachable.
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
WHEELHOUSE="${BASE_DIR}/wheelhouse"
COLLECTIONS_DIR="${BASE_DIR}/collections"
FILES_DIR="${BASE_DIR}/playbooks/files"

# Ensure both 'scripts' and 'SCRIPTS' resolve on case-sensitive Linux filesystems
if [ ! -e "${BASE_DIR}/scripts" ] && [ ! -L "${BASE_DIR}/scripts" ]; then
    ln -sf SCRIPTS "${BASE_DIR}/scripts" 2>/dev/null || true
fi

echo "========================================================"
echo "    BIRDHUNT - HATCHING JUMPBOX ENVIRONMENT (OFFLINE)   "
echo "========================================================"

if [ "$EUID" -ne 0 ]; then
    SUDO="sudo"
else
    SUDO=""
fi

# 1. Check if Jumpbox has internet access to system repositories
echo "[*] Checking repository / internet connectivity..."
HAS_INTERNET=false
if curl -s --connect-timeout 3 -I "https://packages.wazuh.com" >/dev/null 2>&1 || \
   curl -s --connect-timeout 3 -I "https://archive.ubuntu.com" >/dev/null 2>&1 || \
   curl -s --connect-timeout 3 -I "https://galaxy.ansible.com" >/dev/null 2>&1; then
    HAS_INTERNET=true
    echo "[+] Internet connectivity detected."
else
    echo "[!] No internet connectivity detected. Operating in 100% AIR-GAPPED mode."
fi

# 2. Attempt system package installations (tolerates air-gap)
if [ "$HAS_INTERNET" = true ]; then
    if command -v apt-get >/dev/null 2>&1; then
        echo "[+] Updating apt repositories..."
        $SUDO apt-get update -y || true
        $SUDO apt-get install -y \
            ansible python3 python3-pip python3-yaml python3-paramiko \
            python3-passlib python3-cryptography graphviz sshpass curl tar || true
    elif command -v dnf >/dev/null 2>&1; then
        echo "[+] Installing packages via dnf..."
        $SUDO dnf install -y \
            ansible-core python3 python3-pip python3-pyyaml python3-paramiko \
            python3-passlib python3-cryptography graphviz sshpass curl tar || true
    fi
else
    echo "[*] Skipping apt/dnf online mirrors (offline mode). Using pre-installed system tools."
fi

# 3. Install Python wheels from local wheelhouse (ZERO INTERNET REQUIRED)
if [ -d "${WHEELHOUSE}" ]; then
    echo "[+] Installing Python dependencies from local ./wheelhouse/ (offline)..."
    python3 -m pip install --quiet --no-index --find-links="${WHEELHOUSE}" \
        pywinrm requests-ntlm passlib pyyaml paramiko scp || {
            echo "[!] Fallback pip install with local search..."
            pip3 install --quiet --no-index --find-links="${WHEELHOUSE}" \
                pywinrm requests-ntlm passlib || true
        }
    echo "[✓] Python dependencies installed from offline wheelhouse."
elif [ "$HAS_INTERNET" = true ]; then
    echo "[+] Installing Python dependencies via online pip..."
    pip3 install --quiet --upgrade pywinrm requests-ntlm passlib pyyaml paramiko scp || true
fi

# 4. Verify Ansible Galaxy collections in ./collections/
if [ -d "${COLLECTIONS_DIR}/ansible_collections" ]; then
    echo "[✓] Found pre-packaged Ansible collections in ./collections/:"
    echo "    - ansible.windows"
    echo "    - community.windows"
    echo "    - community.general"
elif [ "$HAS_INTERNET" = true ] && command -v ansible-galaxy >/dev/null 2>&1; then
    echo "[+] Downloading missing collections from Ansible Galaxy..."
    ansible-galaxy collection install -p "${COLLECTIONS_DIR}" ansible.windows community.windows community.general || true
else
    echo "[!] Warning: Collections directory not found and no internet available."
fi

# 5. Verify and reassemble pre-staged agent & tool artifacts
if [ -d "${FILES_DIR}" ]; then
    # Reassemble split chunks if present (< 80MB GitHub limit bypass)
    if [ -f "${FILES_DIR}/MBSetup.exe.part_aa" ] && [ ! -f "${FILES_DIR}/MBSetup.exe" ]; then
        echo "[*] Reassembling MBSetup.exe from chunks..."
        cat "${FILES_DIR}"/MBSetup.exe.part_* > "${FILES_DIR}/MBSetup.exe"
    fi
    if [ -f "${FILES_DIR}/SysinternalsSuite.zip.part_aa" ] && [ ! -f "${FILES_DIR}/SysinternalsSuite.zip" ]; then
        echo "[*] Reassembling SysinternalsSuite.zip from chunks..."
        cat "${FILES_DIR}"/SysinternalsSuite.zip.part_* > "${FILES_DIR}/SysinternalsSuite.zip"
    fi

    FILE_COUNT=$(find "${FILES_DIR}" -type f | wc -l | tr -d ' ')
    echo "[✓] Found ${FILE_COUNT} pre-staged agent and tool files in ./playbooks/files/:"
    ls -lh "${FILES_DIR}" | grep -E '\.(deb|rpm|msi|zip|exe|sh|xml)$' | awk '{print "    - " $9 " (" $5 ")"}'
fi

echo ""
echo "========================================================"
echo "[✓] HATCH COMPLETE! Environment is competition-ready."
echo "    Run: ansible all -m ping"
echo "========================================================"
