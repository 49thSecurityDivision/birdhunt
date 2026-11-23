#!/usr/bin/env bash
# =============================================================================
# BIRDHUNT - OFFLINE ARTIFACT STAGING SCRIPT
#
# Run this script on the Jumpbox during setup while internet access is available.
# It pre-populates playbooks/files/ so all subsequent deployments operate
# in a 100% offline / air-gapped competition environment.
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

FILES_DIR="${BASE_DIR}/playbooks/files"
WAZUH_AGENT_VER="4.9.0-1"
WAZUH_VER="4.9"

mkdir -p "${FILES_DIR}"
echo "[*] Staging BirdHunt offline artifacts into ${FILES_DIR}..."

download_if_missing() {
    local url="$1"
    local dest="$2"
    if [ -f "${dest}" ]; then
        echo "[+] Exists: $(basename "${dest}")"
    else
        echo "[>] Downloading $(basename "${dest}")..."
        curl -fSL "${url}" -o "${dest}" || {
            echo "[-] Warning: Failed to download ${url}"
            rm -f "${dest}"
        }
    fi
}

# 1. Wazuh Installer (Jumpbox)
download_if_missing \
    "https://packages.wazuh.com/${WAZUH_VER}/wazuh-install.sh" \
    "${FILES_DIR}/wazuh-install.sh"

# 2. Wazuh Agent DEB (Debian/Ubuntu)
download_if_missing \
    "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_${WAZUH_AGENT_VER}_amd64.deb" \
    "${FILES_DIR}/wazuh-agent_${WAZUH_AGENT_VER}_amd64.deb"

# 3. Wazuh Agent RPM (RHEL/CentOS/Rocky)
download_if_missing \
    "https://packages.wazuh.com/4.x/yum/wazuh-agent-${WAZUH_AGENT_VER}.x86_64.rpm" \
    "${FILES_DIR}/wazuh-agent-${WAZUH_AGENT_VER}.x86_64.rpm"

# 4. Wazuh Agent MSI (Windows)
download_if_missing \
    "https://packages.wazuh.com/4.x/windows/wazuh-agent-${WAZUH_AGENT_VER}.msi" \
    "${FILES_DIR}/wazuh-agent-${WAZUH_AGENT_VER}.msi"

# 5. Sysmon64 & Config (Windows)
download_if_missing \
    "https://live.sysinternals.com/Sysmon64.exe" \
    "${FILES_DIR}/Sysmon64.exe"

download_if_missing \
    "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" \
    "${FILES_DIR}/sysmonconfig.xml"

# 6. Windows Tools (Sysinternals Suite & Malwarebytes)
download_if_missing \
    "https://download.sysinternals.com/files/SysinternalsSuite.zip" \
    "${FILES_DIR}/SysinternalsSuite.zip"

download_if_missing \
    "https://downloads.malwarebytes.com/file/mb5_offline" \
    "${FILES_DIR}/MBSetup.exe"

# 7. Linux Offline Staged Tools (LinPEAS / IR scripts)
mkdir -p "${FILES_DIR}/linux_tools"
download_if_missing \
    "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh" \
    "${FILES_DIR}/linux_tools/linpeas.sh"

echo "[✓] Offline staging complete. Current files:"
ls -lh "${FILES_DIR}"
