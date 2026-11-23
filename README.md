# **49th Security Division - CCDC 2026**

## Team Roster

| Name                     | Role          | Primary Box   |
| ------------------------ |:-------------:|:-------------:|
| Matthew De La Rosa       | Linux         | balrog        |
| Lansina Diakite          | Router        | O             |
| Tyler Eisenbraun         | Linux         | O             |
| Matthew Hampton          | Windows       | cthulu        |
| Hunter Korff (Team Lead) | Windows       | Viking        |
| Henry Shearer            | Windows       | kerberos      |
| Cameron Taylor           | Linux         | O             |

---

# BirdHunt - CCDC Automation & Defensive Suite

BirdHunt is an Ansible-based defensive automation suite developed for the Collegiate Cyber Defense Competition (CCDC). To maintain operational security when repositories or scripts become publicly visible, all files and operations are obfuscated using a bird and game fowl hunting taxonomy:
- **Inventory**: `nest.yaml`
- **Execution Engine**: `birdshot.yml`
- **Playbooks**: Named after specific game fowl and wild birds (`snipe`, `quail`, `turkey`, `partridge`, `pheasant`, `guineafowl`)
- **Scripts**: Named as variations of `egg` (`hatch_egg`, `lay_egg`, `egg_candler`, `candled_egg`, `bake_egg`, `crack_egg`)
- **Ansible Builder**: `builder/` directory with `execution-environment.yml` for immutable containerized runs.

---

## Quick Reference Cheat Sheet

### Option A: Containerized Execution (Ansible Builder / Recommended)
Pre-build and air-gap the immutable container so you have **zero** dependency issues in competition:
```bash
# 1. Before competition: build and export container image
./bake_egg.sh

# 2. At competition: run playbooks inside the pre-built container
./crack_egg.sh playbooks/birdshot.yml -e "seed_val=CCDC2026SecureSeed!"
./crack_egg.sh playbooks/snipe.yml
```

### Option B: Bare-Metal Jumpbox Execution (100% Offline Pre-Packaged)
Everything is pre-packaged in the repo (`wheelhouse/`, `collections/`, `playbooks/files/`). No internet needed:
```bash
chmod +x hatch_egg.sh bake_egg.sh crack_egg.sh egg_candler.sh SCRIPTS/*.sh SCRIPTS/*.py
sudo ./hatch_egg.sh

# Verify connectivity & run:
ansible all -m ping
ansible-playbook playbooks/birdshot.yml -e "seed_val=CCDC2026SecureSeed!"
```

### Execution Commands (Bare-Metal or via `./crack_egg.sh`)
| Phase / Objective | Obfuscated Playbook | Bare-Metal Command | Containerized Command |
| :--- | :--- | :--- | :--- |
| **All-in-One Execution** | `birdshot.yml` | `ansible-playbook playbooks/birdshot.yml -e "seed_val=..."` | `./crack_egg.sh playbooks/birdshot.yml -e "seed_val=..."` |
| **Phase 1: Network Map** | `snipe.yml` | `ansible-playbook playbooks/snipe.yml` | `./crack_egg.sh playbooks/snipe.yml` |
| **Phase 2A: Linux Audit & Passwords** | `quail.yml` | `ansible-playbook playbooks/quail.yml` *(interactive)* | `./crack_egg.sh playbooks/quail.yml` |
| **Interactive Linux Auditor** | `candled_egg.py` | `./egg_candler.sh` | `./crack_egg.sh ./egg_candler.sh` |
| **Phase 2B: Windows Passwords** | `turkey.yml` | `ansible-playbook playbooks/turkey.yml -e "seed_val=..."` | `./crack_egg.sh playbooks/turkey.yml -e "seed_val=..."` |
| **Phase 3A: Windows Tools** | `partridge.yml` | `ansible-playbook playbooks/partridge.yml` | `./crack_egg.sh playbooks/partridge.yml` |
| **Phase 3B: Linux Tools** | `pheasant.yml` | `ansible-playbook playbooks/pheasant.yml` | `./crack_egg.sh playbooks/pheasant.yml` |
| **Phase 4: Wazuh SIEM & Sysmon** | `guineafowl.yml` | `ansible-playbook playbooks/guineafowl.yml` | `./crack_egg.sh playbooks/guineafowl.yml` |

---

## Repository Structure & Taxonomy

```
BirdHunt/
├── ansible.cfg                    # Hardened Ansible defaults (inventory = nest.yaml, forks = 20)
├── nest.yaml                      # Active inventory ("Nest") with windows, linux & jumpbox
├── hatch_egg.sh                   # Jumpbox bare-metal bootstrap script (symlink -> scripts/hatch_egg.sh)
├── bake_egg.sh                    # Symlink -> scripts/bake_egg.sh (Builds & exports EE container)
├── crack_egg.sh                   # Symlink -> scripts/crack_egg.sh (Runs playbooks inside EE container)
├── egg_candler.sh                 # Symlink -> scripts/egg_candler.sh (Interactive user auditor - Method 2)
├── USER_GUIDE.md                  # Comprehensive CCDC User Guide
├── README.md                      # This file
│
├── builder/                       # Ansible Builder execution environment files
│   ├── execution-environment.yml  # EE definition (base image, dependencies, system packages)
│   ├── requirements.yml           # Galaxy collections (ansible.windows, community.windows, etc.)
│   ├── requirements.txt           # Python packages (pywinrm, passlib, cryptography, etc.)
│   └── bindep.txt                 # System packages (graphviz, gcc, krb5-devel)
│
├── playbooks/
│   ├── birdshot.yml               # "Bird Shot" master orchestration playbook (runs all phases)
│   ├── bird_shot.yml              # Symlink alias to birdshot.yml
│   ├── snipe.yml                  # [Snipe] Network mapping & connection topology
│   ├── quail.yml                  # [Quail] Linux account audit, unshadow, UID 0 kill, rotation
│   ├── turkey.yml                 # [Turkey] Deterministic Windows local account rotation
│   ├── partridge.yml              # [Partridge] Windows defensive tooling (Sysinternals, Malwarebytes)
│   ├── pheasant.yml               # [Pheasant] Linux incident response tooling, triage & integrity
│   ├── guineafowl.yml             # [Guineafowl] Air-gapped Wazuh Manager, Agent & Sysmon
│   └── files/                     # Staged offline installers (.deb, .rpm, .msi, Sysmon, etc.)
│
├── network-maps/                  # Rendered network maps (.png, .svg, .dot, .json)
└── scripts/
    ├── bake_egg.sh                # [Bake Egg] Ansible Builder pipeline & tar exporter
    ├── crack_egg.sh               # [Crack Egg] Containerized execution runner
    ├── hatch_egg.sh               # [Hatch Egg] Jumpbox dependency installer
    ├── lay_egg.sh                 # [Lay Egg] Pre-downloads all offline artifacts & tools
    ├── egg_candler.sh             # [Egg Candler] Helper launcher for user account auditing
    └── candled_egg.py             # [Candled Egg] Original Paramiko Python audit script
```

For complete details on scoring preservation, domain controller safeguards, backdoor detection logic, and troubleshooting, refer to [USER_GUIDE.md](file:///Users/matt/Desktop/BirdHunt/USER_GUIDE.md).
