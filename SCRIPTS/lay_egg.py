#!/usr/bin/env python3
"""
=============================================================================
BIRDHUNT - "LAY EGG" INTERACTIVE INVENTORY BUILDER & CONNECTIVITY TESTER
=============================================================================
Guides the operator through creating or updating 'nest.yaml' during CCDC:
  1. Sets global defaults (Linux/Windows usernames, passwords, default ports).
  2. Interactively prompts for hostnames, IPs, operating systems, and credentials.
  3. Supports quick batch paste for rapid Minute-0 ingestion of competition topologies.
  4. Generates a fully formatted, hardened Ansible inventory ('nest.yaml').
  5. Automatically executes 'ansible all -m ping' to verify connectivity in real-time.
"""

import sys
import os
import shutil
import subprocess
import yaml
from pathlib import Path


# =============================================================================
# TERMINAL I/O HELPERS
# =============================================================================
def get_tty_handles():
    if os.path.exists("/dev/tty"):
        try:
            fin = open("/dev/tty", "r")
            fout = open("/dev/tty", "w")
            return fin, fout
        except Exception:
            pass
    return sys.stdin, sys.stdout


def prompt(text, default=""):
    fin, fout = get_tty_handles()
    prompt_str = f"{text} [{default}]: " if default else f"{text}: "
    fout.write(prompt_str)
    fout.flush()
    try:
        line = fin.readline()
        if not line:
            return default
        val = line.strip()
        return val if val else default
    except Exception:
        return default


def prompt_secret(text, default=""):
    """Prompt for password; masks or takes default."""
    import getpass
    fin, fout = get_tty_handles()
    prompt_str = f"{text} [{default}]: " if default else f"{text}: "
    try:
        val = getpass.getpass(prompt_str, stream=fout)
        return val.strip() if val.strip() else default
    except Exception:
        return prompt(text, default)


def print_ui(*args, **kwargs):
    _, fout = get_tty_handles()
    end = kwargs.get("end", "\n")
    sep = kwargs.get("sep", " ")
    fout.write(sep.join(str(a) for a in args) + end)
    fout.flush()


# =============================================================================
# INVENTORY RESOLUTION
# =============================================================================
def find_repo_root():
    script_dir = Path(__file__).resolve().parent
    if (script_dir / "nest.yaml").exists() or (script_dir / "playbooks").exists():
        return script_dir
    parent = script_dir.parent
    if (parent / "nest.yaml").exists() or (parent / "playbooks").exists():
        return parent
    cwd = Path.cwd()
    if (cwd / "nest.yaml").exists() or (cwd / "playbooks").exists():
        return cwd
    return parent


# =============================================================================
# MAIN INVENTORY WIZARD
# =============================================================================
def main():
    repo_root = find_repo_root()
    nest_path = repo_root / "nest.yaml"

    print_ui("")
    print_ui("=======================================================================")
    print_ui("       BIRDHUNT - 'LAY EGG' INVENTORY WIZARD (NEST.YAML BUILDER)       ")
    print_ui("=======================================================================")
    print_ui(f"[*] Target Inventory: {nest_path}")
    print_ui("[*] Quickly build your CCDC target list and verify connectivity.")
    print_ui("")

    # --- STEP 1: GLOBAL DEFAULTS ---
    print_ui("--- STEP 1: GLOBAL / TEAM CREDENTIAL DEFAULTS ---")
    print_ui("These will apply to any host unless you specify a custom override.")
    print_ui("")

    linux_user = prompt("Default Linux username", default="root")
    linux_pass = prompt_secret("Default Linux password", default="")
    linux_port = int(prompt("Default Linux SSH port", default="22"))

    print_ui("")
    win_user = prompt("Default Windows username", default="administrator")
    win_pass = prompt_secret("Default Windows password", default="")
    win_port = int(prompt("Default Windows WinRM port", default="5985"))

    print_ui("")
    seed_val = prompt("Competition Password Rotation Seed", default="CCDC2026SecureSeed!")

    # --- STEP 2: HOST ENTRY MODE ---
    print_ui("")
    print_ui("--- STEP 2: ADD TARGET HOSTS ---")
    print_ui("Choose entry method:")
    print_ui("  1) Interactive step-by-step (recommended)")
    print_ui("  2) Batch paste (paste lines from inject sheet: hostname, ip, [os], [password])")
    mode_choice = prompt("Select mode [1/2]", default="1")

    linux_hosts = {}
    windows_hosts = {}

    if mode_choice == "2":
        print_ui("")
        print_ui("Paste your hosts below. Supported formats per line:")
        print_ui("  hostname, ip, os (e.g. 'web01, 192.168.1.10, linux')")
        print_ui("  hostname, ip, os, password (e.g. 'dc01, 192.168.1.20, windows, Secret123')")
        print_ui("  hostname, ip, os, password, whitelist_accounts (e.g. 'db01, 192.168.1.11, linux, pass, serveradmin:scoreuser')")
        print_ui("Enter an empty line when finished pasting:")
        print_ui("-----------------------------------------------------------------------")

        fin, _ = get_tty_handles()
        while True:
            line = fin.readline()
            if not line or not line.strip():
                break
            line = line.strip()
            parts = [p.strip() for p in line.split(",") if p.strip()]
            if len(parts) < 2:
                continue
            hname = parts[0]
            ip = parts[1]
            os_type = parts[2].lower() if len(parts) > 2 else "linux"
            custom_pwd = parts[3] if len(parts) > 3 and parts[3] else None
            wl_str = parts[4] if len(parts) > 4 and parts[4] else ""
            whitelist = [u.strip() for u in wl_str.replace(":", ",").split(",") if u.strip()]

            if "win" in os_type:
                h_user = win_user
                h_pwd = custom_pwd if custom_pwd else win_pass
                h_port = win_port
                windows_hosts[hname] = {
                    "ansible_host": ip,
                    "ansible_port": h_port,
                    "ansible_password": h_pwd,
                    "blacklist": [],
                    "whitelist": whitelist,
                    "user_passwords": {h_user: h_pwd} if h_pwd else {},
                }
                print_ui(f"  [+] Added Windows host: {hname} ({ip}:{h_port})")
            else:
                h_user = linux_user
                h_pwd = custom_pwd if custom_pwd else linux_pass
                h_port = linux_port
                linux_hosts[hname] = {
                    "ansible_host": ip,
                    "ansible_port": h_port,
                    "ansible_password": h_pwd,
                    "blacklist": [],
                    "whitelist": whitelist,
                    "user_passwords": {h_user: h_pwd} if h_pwd else {},
                }
                print_ui(f"  [+] Added Linux host: {hname} ({ip}:{h_port})")

    # Step-by-step interactive entry
    if not linux_hosts and not windows_hosts or mode_choice != "2":
        print_ui("")
        print_ui("Adding hosts interactively. Press Enter with an empty hostname when done.")
        while True:
            print_ui("-----------------------------------------------------------------------")
            hname = prompt("Hostname (e.g. web01, db01, dc01 - or empty to finish)")
            if not hname:
                if linux_hosts or windows_hosts:
                    break
                confirm_exit = prompt("No hosts added yet. Stop adding hosts? [y/N]", default="n")
                if confirm_exit.lower() in ("y", "yes"):
                    break
                continue

            ip = prompt(f"IP address for {hname}")
            if not ip:
                print_ui("[-] Error: IP address cannot be empty.")
                continue

            # Detect default OS based on name convention or prompt
            default_os = "windows" if any(w in hname.lower() for w in ["win", "dc", "ad", "exchange", "sql"]) else "linux"
            os_type = prompt(f"Operating System for {hname} (l=Linux, w=Windows)", default=default_os[0])
            is_win = os_type.lower().startswith("w")

            if is_win:
                h_port = int(prompt(f"WinRM port for {hname}", default=str(win_port)))
                h_user = prompt(f"Username for {hname}", default=win_user)
                h_pwd = prompt_secret(f"Password for {hname}", default=win_pass)
                wl_input = prompt(f"Whitelisted / scored accounts for {hname} (comma-separated)", default=h_user)
                whitelist = [u.strip() for u in wl_input.split(",") if u.strip()]

                windows_hosts[hname] = {
                    "ansible_host": ip,
                    "ansible_port": h_port,
                    "ansible_password": h_pwd,
                    "blacklist": [],
                    "whitelist": whitelist,
                    "user_passwords": {h_user: h_pwd} if h_pwd else {},
                }
                print_ui(f"[✓] Added Windows host '{hname}' ({ip}:{h_port})")
            else:
                h_port = int(prompt(f"SSH port for {hname}", default=str(linux_port)))
                h_user = prompt(f"Username for {hname}", default=linux_user)
                h_pwd = prompt_secret(f"Password for {hname}", default=linux_pass)
                wl_input = prompt(f"Whitelisted / scored accounts for {hname} (comma-separated)", default=f"{h_user}, serveradmin")
                whitelist = [u.strip() for u in wl_input.split(",") if u.strip()]

                linux_hosts[hname] = {
                    "ansible_host": ip,
                    "ansible_port": h_port,
                    "ansible_password": h_pwd,
                    "blacklist": [],
                    "whitelist": whitelist,
                    "user_passwords": {h_user: h_pwd} if h_pwd else {},
                }
                print_ui(f"[✓] Added Linux host '{hname}' ({ip}:{h_port})")

            add_more = prompt("Add another host? [Y/n]", default="y")
            if add_more.lower() in ("n", "no"):
                break

    # --- STEP 3: REVIEW & WRITE INVENTORY ---
    print_ui("")
    print_ui("=======================================================================")
    print_ui("                      INVENTORY CONFIGURATION REVIEW                   ")
    print_ui("=======================================================================")
    print_ui(f"Linux Hosts ({len(linux_hosts)}):")
    for hn, info in linux_hosts.items():
        print_ui(f"  • {hn:16} | IP: {info['ansible_host']}:{info['ansible_port']:<5} | Whitelist: {info['whitelist']}")
    print_ui(f"Windows Hosts ({len(windows_hosts)}):")
    for hn, info in windows_hosts.items():
        print_ui(f"  • {hn:16} | IP: {info['ansible_host']}:{info['ansible_port']:<5} | Whitelist: {info['whitelist']}")
    print_ui(f"Seed: {seed_val}")
    print_ui("=======================================================================")

    save_confirm = prompt("Write this configuration to nest.yaml? [Y/n]", default="y")
    if save_confirm.lower() not in ("y", "yes", ""):
        print_ui("[-] Aborted. nest.yaml was not modified.")
        sys.exit(0)

    # Build final nest.yaml dictionary
    nest_data = {
        "all": {
            "children": {
                "windows": {
                    "hosts": windows_hosts,
                    "vars": {
                        "ansible_user": win_user,
                        "ansible_password": win_pass,
                        "ansible_connection": "winrm",
                        "ansible_winrm_server_cert_validation": "ignore",
                        "ansible_winrm_transport": "ntlm",
                        "seed_val": seed_val,
                    },
                },
                "linux": {
                    "hosts": linux_hosts,
                    "vars": {
                        "ansible_user": linux_user,
                        "ansible_password": linux_pass,
                        "ansible_connection": "ssh",
                        "ansible_become": True,
                        "ansible_become_method": "sudo",
                        "ansible_become_password": "{{ ansible_password }}",
                        "seed_val": seed_val,
                    },
                },
                "jumpbox": {
                    "hosts": {
                        "localhost": {
                            "ansible_connection": "local",
                            "ansible_python_interpreter": "{{ ansible_playbook_python }}",
                        }
                    }
                },
            }
        }
    }

    # Backup old nest.yaml if it exists and has content
    if nest_path.exists() and nest_path.stat().st_size > 50:
        backup_path = nest_path.with_suffix(".yaml.bak")
        shutil.copyfile(nest_path, backup_path)
        print_ui(f"[+] Saved previous inventory backup to {backup_path}")

    with open(nest_path, "w") as f:
        yaml.dump(nest_data, f, sort_keys=False, default_flow_style=False)

    print_ui(f"[✓] Successfully generated and saved {nest_path}!")

    # --- STEP 4: VERIFY CONNECTIVITY (ACTUAL PING) ---
    print_ui("")
    total_hosts = len(linux_hosts) + len(windows_hosts)
    if total_hosts == 0:
        print_ui("[!] No remote hosts configured. Skipping connectivity ping.")
        return

    run_ping = prompt(f"Execute 'ansible all -m ping' now to test connectivity across {total_hosts} hosts? [Y/n]", default="y")
    if run_ping.lower() in ("y", "yes", ""):
        print_ui("")
        print_ui("=======================================================================")
        print_ui("              EXECUTING ANSIBLE CONNECTIVITY PING                      ")
        print_ui("=======================================================================")
        try:
            # Change directory to repo root so ansible.cfg is respected
            cmd = ["ansible", "all", "-m", "ping"]
            subprocess.run(cmd, cwd=str(repo_root))
        except Exception as e:
            print_ui(f"[-] Error running ansible ping: {e}")

        print_ui("")
        print_ui("=======================================================================")
        print_ui("                       CONNECTIVITY SUMMARY                            ")
        print_ui("=======================================================================")
        print_ui("[✓] Green (SUCCESS): Host is reachable and credentials are valid.")
        print_ui("[!] Red (UNREACHABLE / AUTH FAILED):")
        print_ui("    • Linux: Verify SSH port, firewall, and root/sudo password.")
        print_ui("    • Windows: Verify WinRM port 5985 is open and Administrator password.")
        print_ui("    • Re-run './lay_egg.sh' anytime to adjust hosts, or edit 'nest.yaml'.")
        print_ui("=======================================================================")


if __name__ == "__main__":
    main()
