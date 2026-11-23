# BirdHunt - Collegiate Cyber Defense Competition (CCDC) Operational Guide

> **COMPETITION DIRECTIVE**: You have **NO** access to the competition environment prior to the match. The only asset you bring into the competition is this uploaded repository.
> 
> This guide is an exact, minute-by-minute operational runbook starting at **Minute 0:00** when you first sit at the jumpbox keyboard and clone this repository.

---

## Pre-Competition Checklist (Do This BEFORE Uploading the Repo)

This repository has already been pre-packaged to be **100% self-contained and air-gapped**:
- **Offline Python Wheels**: Pre-downloaded in `./wheelhouse/` (`pywinrm`, `requests-ntlm`, `passlib`, `cryptography`, etc.).
- **Ansible Collections**: Pre-installed in `./collections/` (`ansible.windows`, `community.windows`, `community.general`).
- **Offline Agent & Tool Binaries**: Pre-staged in `./playbooks/files/` (Wazuh installer, Linux `.deb`/`.rpm`, Windows `.msi`, `Sysmon64.exe`, `sysmonconfig.xml`, `SysinternalsSuite`, `MBSetup.exe`, `linpeas.sh`).
- **GitHub File-Size Compliance**: Large binaries (`MBSetup.exe` and `SysinternalsSuite.zip`) are pre-split into `< 80 MB` chunks (`.part_*`) so `git push` will **never** be rejected by GitHub's 100MB file limit. `./hatch_egg.sh` automatically reassembles them upon clone.

**All you need to do before the match is commit and push:**
```bash
cd BirdHunt
git add -A
git commit -m "BirdHunt 100% Self-Contained Offline Competition Repo"
git push origin main
```

---

## Obfuscation & File Taxonomy Reference

All scripts and playbooks use a bird/hunting taxonomy to prevent immediate recognition if exposed:

| Component | Obfuscated File | Operational Purpose |
| :--- | :--- | :--- |
| **Inventory** | **[`nest.yaml`](file:///Users/matt/Desktop/BirdHunt/nest.yaml)** | Master target host & credential inventory ("The Nest") |
| **Master Orchestrator** | **[`playbooks/birdshot.yml`](file:///Users/matt/Desktop/BirdHunt/playbooks/birdshot.yml)** | "Bird Shot" master playbook (executes all phases) |
| **Network Discovery** | **[`playbooks/snipe.yml`](file:///Users/matt/Desktop/BirdHunt/playbooks/snipe.yml)** | [Snipe] Port/listener enumeration & connection graphing |
| **Linux Lockdown** | **[`playbooks/quail.yml`](file:///Users/matt/Desktop/BirdHunt/playbooks/quail.yml)** | [Quail] Unshadow passwords, kill UID 0, rotate credentials |
| **Windows Lockdown** | **[`playbooks/turkey.yml`](file:///Users/matt/Desktop/BirdHunt/playbooks/turkey.yml)** | [Turkey] Deterministic Windows local account rotation (DC-safe) |
| **Windows Tooling** | **[`playbooks/partridge.yml`](file:///Users/matt/Desktop/BirdHunt/playbooks/partridge.yml)** | [Partridge] Deploy Sysinternals Suite & Malwarebytes |
| **Linux Tooling** | **[`playbooks/pheasant.yml`](file:///Users/matt/Desktop/BirdHunt/playbooks/pheasant.yml)** | [Pheasant] Deploy IR tools, `triage.sh`, and `check_integrity.sh` |
| **SIEM & Telemetry** | **[`playbooks/guineafowl.yml`](file:///Users/matt/Desktop/BirdHunt/playbooks/guineafowl.yml)** | [Guineafowl] Air-gapped Wazuh Manager, Agent & Sysmon |
| **Jumpbox Setup** | **[`hatch_egg.sh`](file:///Users/matt/Desktop/BirdHunt/hatch_egg.sh)** | [Hatch Egg] Jumpbox dependency installer |
| **Container Runner** | **[`crack_egg.sh`](file:///Users/matt/Desktop/BirdHunt/crack_egg.sh)** | [Crack Egg] Runs playbooks inside pre-built container |
| **Artifact Stager** | **[`scripts/lay_egg.sh`](file:///Users/matt/Desktop/BirdHunt/scripts/lay_egg.sh)** | [Lay Egg] Downloads all offline installers into `playbooks/files/` |
| **User Audit Tool** | **[`scripts/egg_candler.sh`](file:///Users/matt/Desktop/BirdHunt/scripts/egg_candler.sh)** | [Egg Candler] Fast user audit launcher |
| **Legacy Python Audit** | **[`scripts/candled_egg.py`](file:///Users/matt/Desktop/BirdHunt/scripts/candled_egg.py)** | [Candled Egg] Original Paramiko Python audit script |

---

## Minute-by-Minute Competition Runbook (T-0:00 to T-0:15)

```mermaid
flowchart TD
    M0["T-0:00 - T-0:01<br/>git clone & cd BirdHunt"] --> M1["T-0:01 - T-0:03<br/>Bootstrap Jumpbox (hatch_egg.sh)"]
    M1 --> M3["T-0:03 - T-0:05<br/>Populate nest.yaml (IPs & Passwords)"]
    M3 --> M5["T-0:05 - T-0:06<br/>Verify Reachability (ansible all -m ping)"]
    M5 --> M6["T-0:06 - T-0:08<br/>Phase 1: Network Topology Map (snipe.yml)"]
    M6 --> M8["T-0:08 - T-0:11<br/>Phase 2: Credential Lockdown (quail.yml & turkey.yml)"]
    M8 --> M11["T-0:11 - T-0:13<br/>Phase 3: Defensive Tools (pheasant.yml & partridge.yml)"]
    M11 --> M13["T-0:13 - T-0:15<br/>Phase 4: Wazuh SIEM & Sysmon (guineafowl.yml)"]
```

---

### Minute 0:00 – 0:01 | Drop In & Clone
Sit down at the Jumpbox terminal, open your shell, and pull down your pre-approved repository:
```bash
git clone <YOUR_COMPETITION_REPO_URL> BirdHunt
cd BirdHunt
chmod +x lay_egg.sh hatch_egg.sh bake_egg.sh crack_egg.sh egg_candler.sh SCRIPTS/*.sh SCRIPTS/*.py
```

---

### Minute 0:01 – 0:03 | Bootstrap Jumpbox Dependencies
You are on a fresh Jumpbox VM provided by Black Team. Initialize dependencies immediately:

#### Path A: Standard Bare-Metal Jumpbox
```bash
sudo ./hatch_egg.sh
```
*Installs Ansible, Python 3, PyWinRM, Graphviz, Passlib, and installs the required Windows Galaxy collections.*

#### Path B: Containerized Execution (If Podman/Docker is Available & `birdhunt-ee.tar` was pre-staged)
```bash
# If container runtime is present, you don't even need to run hatch_egg.sh:
./crack_egg.sh all -m ping
```

---

### Minute 0:03 – 0:05 | Populate the "Nest" (`./lay_egg.sh`)
White Team will hand you your team packet containing assigned IP subnets, hostnames, and initial default passwords. The repository ships with an **empty `nest.yaml`** ready to be populated for competition day.

Launch the interactive **Lay Egg** wizard:
```bash
./lay_egg.sh
```
*(Note: If you run `sudo ./hatch_egg.sh`, it will also automatically offer to launch `./lay_egg.sh` at the end if `nest.yaml` is empty!)*

**What the wizard does**:
1. **Global Defaults**: Prompts once for your team's default Linux password, Windows password, and rotation seed.
2. **Target Hosts**:
   - **Interactive Mode**: Prompts for each host's name, IP, OS (Linux/Windows), port, and whitelisted scored accounts (e.g. `serveradmin`).
   - **Batch Paste Mode**: Allows pasting multiple lines directly from your inject packet spreadsheet!
3. **Auto-Generates `nest.yaml`**: Writes the clean, valid Ansible inventory. (A pre-populated example is preserved in `nest.example.yaml`).
4. **Automated Ping Test**: Immediately prompts and runs `ansible all -m ping` to verify SSH and WinRM reachability across all entered hosts in real-time.

---

### Minute 0:05 – 0:06 | The "Ping Gate" (Connection Verification)
If you need to re-verify network and credential access to every box at any time:
```bash
ansible all -m ping
```

- **Green (`SUCCESS`)**: Machine is connected and credentials are verified.
- **Red (`UNREACHABLE / AUTH FAILED`)**:
  - Linux: Check SSH port, firewall, and verify password.
  - Windows: Check WinRM port 5985 is open.
  - Re-run `./lay_egg.sh` or edit `nest.yaml` to adjust IPs/credentials.
  - **COMPETITION RULE**: Do not let 1 failing host stall you. Use `--limit` to exclude stubborn hosts and keep moving forward with the rest of the fleet!

---

### Minute 0:06 – 0:08 | Phase 1: Network Topology & Listener Discovery (`snipe.yml`)
Before changing configurations, capture the initial state of the network:
```bash
ansible-playbook playbooks/snipe.yml
```
*(Container: `./crack_egg.sh playbooks/snipe.yml`)*

**What this does**:
- Linux nodes dump `ss -tulnp` (listeners) and `ss -tn state established` (active connections).
- Windows nodes dump `Get-NetTCPConnection` and `Get-NetUDPEndpoint`.
- Jumpbox compiles and renders `network-maps/network-<timestamp>.png` and `.json`.

**Immediate Operator Action**:
Open the generated image:
```bash
xdg-open network-maps/network-*.png 2>/dev/null || open network-maps/network-*.png
```
- **Inspect listeners**: Spot non-standard ports (e.g. 4444, 1337, 8888, 31337) indicating pre-installed backdoors or extra web shells.
- **Inspect established connections**: Look for active outbound sessions to unknown foreign IPs (Red Team C2 beacons!).

---

### Minute 0:08 – 0:11 | Phase 2: Credential Lockdown & Backdoor Eradication
Red Team will attempt to log in using default credentials and pre-planted backdoors within minutes. Shut the door immediately.

Choose a secret team password seed for this match:
```bash
SEED="CCDC2026_TeamSuperSecret!"
```

#### Step 2A: Linux Lockdown ([`quail.yml`](file:///Users/matt/Desktop/CCDC2027/birdhunt/playbooks/quail.yml))
```bash
# Default interactive execution (Method 2 - Egg Candler):
ansible-playbook playbooks/quail.yml

# Or standalone interactive execution:
./egg_candler.sh

# Or automated non-interactive batch execution:
ansible-playbook playbooks/quail.yml -e "seed_val=${SEED} interactive=false"
```
- **Interactive Egg Candler (Method 2 - Enabled by Default)**:
  - Connects to each Linux node over SSH and audits `/etc/passwd` & `/etc/shadow`.
  - Fixes unshadowed accounts automatically.
  - Prompts operator for rogue UID 0 / GID 0 accounts (`r=reassign UID, d=delete, i=ignore`).
  - Prompts operator for each active user account:
    `[r=rotate, A=always rotate, h=always for host, i=ignore, N=never rotate (blacklist), X=never rotate for host, d=delete]`
  - Generates deterministic password if Enter is pressed, or accepts custom password.
  - Safely writes updated `/etc/passwd` and `/etc/shadow` via base64 pipeline and deletes flagged users.
  - Automatically updates `nest.yaml` with rotated passwords, blacklist, and whitelist.
- **Verification & Safety Backups**: Creates safety backups in `/root/birdhunt_backups/`, neutralizes any remaining rogue UID 0 backdoors, and synchronizes `ansible_password` in memory.

#### Step 2B: Windows Lockdown ([`turkey.yml`](file:///Users/matt/Desktop/BirdHunt/playbooks/turkey.yml))
```bash
ansible-playbook playbooks/turkey.yml -e "seed_val=${SEED}"
```
- **Domain Controller Safeguard**: Automatically queries `Win32_ComputerSystem.DomainRole`. If the host is a Domain Controller (Role 4 or 5), it **aborts execution on that host** to prevent breaking Active Directory replication or domain-wide lockouts.
- **Disables Built-in Guest**: Shuts down the default `Guest` account.
- **Rotates Discovered Local Users**: Enumerates enabled non-system accounts and updates passwords using deterministic SHA-256 + complexity suffix (`B@LL5`).
- **Rotates Local Administrator**: Sets the new Administrator password and updates `ansible_password` in memory.

---

### Minute 0:11 – 0:13 | Phase 3: Defensive Tooling Deployment

#### Step 3A: Linux Defensive Tools ([`pheasant.yml`](file:///Users/matt/Desktop/BirdHunt/playbooks/pheasant.yml))
```bash
ansible-playbook playbooks/pheasant.yml
```
- Installs `lsof`, `tcpdump`, `htop`, `psmisc`, `strace`, `auditd`, `debsums`, `tmux`, and `net-tools`.
- Starts and enables the `auditd` system audit daemon.
- Deploys **`/opt/birdhunt/tools/triage.sh`**: Instantly dumps listening sockets, active connections, deleted running binaries (`/proc/*/exe -> (deleted)`), SUID binaries, cron jobs, and SSH authorized keys.
- Deploys **`/opt/birdhunt/tools/check_integrity.sh`**: Runs `debsums -c` or `rpm -Va` to alert if Red Team replaced system binaries (`ls`, `ps`, `sshd`, `netstat`).
- Adds `/opt/birdhunt/tools` to global `$PATH`.

#### Step 3B: Windows Defensive Tools ([`partridge.yml`](file:///Users/matt/Desktop/BirdHunt/playbooks/partridge.yml))
```bash
ansible-playbook playbooks/partridge.yml
```
- Extracts Sysinternals Suite to `C:\Tools\Sysinternals` and adds it to the machine system `PATH`.
- Copies the Malwarebytes offline installer to `C:\Temp\Installers\MBSetup.exe`.

---

### Minute 0:13 – 0:15 | Phase 4: Wazuh SIEM & Sysmon Deployment ([`guineafowl.yml`](file:///Users/matt/Desktop/BirdHunt/playbooks/guineafowl.yml))
Gain immediate real-time detection and file integrity monitoring (FIM) across all hosts:
```bash
ansible-playbook playbooks/guineafowl.yml
```
- **Play 1**: Deploys Wazuh Manager, Indexer, and Dashboard locally on the Jumpbox.
- **Play 2**: Verifies offline agent artifacts in `playbooks/files/`.
- **Play 3 (Linux)**: Copies `.deb`/`.rpm` agent, installs locally without internet, points agent to Jumpbox IP, and configures real-time FIM for `/etc`, `/usr/bin`, `/root`, and `/var/www`.
- **Play 4 (Windows)**: Installs Sysmon64 with modular configuration (1 GB event log buffer), installs Wazuh MSI agent silently, and enables log ingestion for Sysmon and Windows Security event channels.
- **Credentials**: Wazuh Dashboard username (`admin`) and generated password are saved to `wazuh_credentials.txt` in the BirdHunt root directory.

---

## The All-in-One Fast-Track Alternative: "Bird Shot"

If you want to execute all 4 phases in a single pipeline:

```bash
ansible-playbook playbooks/birdshot.yml -e "seed_val=CCDC2026MasterSeed!"
```
*(Or via container: `./crack_egg.sh playbooks/birdshot.yml -e "seed_val=CCDC2026MasterSeed!"`)*

You can also target specific phases using tags:
```bash
ansible-playbook playbooks/birdshot.yml --tags map
ansible-playbook playbooks/birdshot.yml --tags passwords -e "seed_val=CCDC2026MasterSeed!"
ansible-playbook playbooks/birdshot.yml --tags tools
ansible-playbook playbooks/birdshot.yml --tags wazuh
```

---

## Competition Troubleshooting & Contingencies

### 1. How to Recalculate a User's Password Manually
If you need to log into a host via console (vSphere/Proxmox) after running password rotation:
- **Windows**:
  Run in bash/python:
  ```bash
  python3 -c "import hashlib; print(hashlib.sha256(('administrator' + 'viking' + 'YOUR_SEED').encode()).hexdigest() + 'B@LL5')"
  ```
- **Linux**:
  Run in bash/python:
  ```bash
  python3 -c "import hashlib; print(hashlib.sha256(('root' + 'brassknuckels' + 'YOUR_SEED').encode()).hexdigest())"
  ```

### 2. Emergency Linux Rollback
If a credential rotation locks out a scored service or breaks an SSH inject:
```bash
sudo cp /root/birdhunt_backups/passwd.*.bak /etc/passwd
sudo cp /root/birdhunt_backups/shadow.*.bak /etc/shadow
```

### 3. WinRM Connection Refused on Windows
If Windows fails on ping or playbook execution:
- Run locally on the Windows target VM console in PowerShell (as Administrator):
  ```powershell
  winrm quickconfig -q
  Set-Item -Path WSMan:\localhost\Service\Auth\Negotiate -Value $true
  Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true
  Restart-Service WinRM
  ```

### 4. Jumpbox Host Key Verification Hangs
If SSH prompts for confirmation (`The authenticity of host... can't be established`):
- `ansible.cfg` has `host_key_checking = False` pre-configured. If running ad-hoc `ssh`, use:
  ```bash
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null user@host
  ```
