#!/usr/bin/env python3
"""
=============================================================================
BIRDHUNT - "EGG CANDLER" INTERACTIVE LINUX AUDITOR & CREDENTIAL MANAGER
=============================================================================
Performs deep live security auditing of /etc/passwd and /etc/shadow over SSH:
  1. Detects and relocates unshadowed passwords from /etc/passwd to /etc/shadow.
  2. Detects rogue root UID 0 accounts (backdoors) and root GID 0 members.
  3. Detects duplicate UIDs and accounts with active passwords but invalid shells.
  4. Interactively prompts the operator (Method 2) for each account:
       r: Rotate password (prompts for new password or auto-generates on Enter)
       A: Always rotate (globally across all hosts)
       h: Always rotate (for this host)
       i: Ignore / leave untouched
       N: Never rotate (blacklist from rotation globally)
       X: Never rotate (blacklist from rotation for this host)
       d: Delete / purge user from system
  5. Updates target /etc/passwd and /etc/shadow safely and atomically.
  6. Updates nest.yaml (and inventory.yaml) with user_passwords, blacklist,
     whitelist, and updated ansible_password.
"""

import sys
import os
import time
import base64
import yaml
import hashlib
import secrets
import string
from pathlib import Path
from datetime import datetime, timezone
from paramiko import SSHClient, AutoAddPolicy

days_since_epoch = (datetime.now(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)).days
SUDO_PASSWORD_PROMPT = b"SUDO_PASSWORD_PROMPT:"


# =============================================================================
# TERMINAL I/O HELPERS (Compatible with direct CLI and Ansible execution)
# =============================================================================
def get_tty_handles():
    """Retrieve terminal handles, allowing interactive prompts even inside Ansible."""
    if os.path.exists("/dev/tty"):
        try:
            fin = open("/dev/tty", "r")
            fout = open("/dev/tty", "w")
            return fin, fout
        except Exception:
            pass
    return sys.stdin, sys.stdout


def tty_prompt(prompt_text, default=""):
    """Prompt the operator on their active terminal."""
    fin, fout = get_tty_handles()
    fout.write(prompt_text)
    fout.flush()
    try:
        line = fin.readline()
        if not line:
            return default
        return line.strip()
    except Exception:
        return default


def tty_print(*args, **kwargs):
    """Print directly to the operator's active terminal."""
    _, fout = get_tty_handles()
    end = kwargs.get("end", "\n")
    sep = kwargs.get("sep", " ")
    text = sep.join(str(a) for a in args) + end
    fout.write(text)
    fout.flush()


# =============================================================================
# PASSWORD GENERATION & HASHING
# =============================================================================
def hash_shadow_password(password):
    """Generate SHA-512 crypt hash for /etc/shadow ($6$...)."""
    try:
        from passlib.hash import sha512_crypt
        return sha512_crypt.using(rounds=5000).hash(password)
    except ImportError:
        pass

    try:
        salt = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
        import subprocess
        res = subprocess.run(["openssl", "passwd", "-6", "-salt", salt, password], capture_output=True, text=True)
        if res.returncode == 0 and res.stdout.strip().startswith("$6$"):
            return res.stdout.strip()
    except Exception:
        pass

    try:
        import crypt
        res = crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))
        if res.startswith("$6$"):
            return res
    except Exception:
        pass

    raise RuntimeError("Unable to generate SHA-512 crypt hash: passlib, openssl, and crypt were unavailable.")


def gen_password(username, host):
    """Prompt operator for new password or generate a deterministic high-entropy one."""
    pw = tty_prompt(f"Enter password for {username} on {host} [Press Enter to auto-generate]: ")
    if not pw:
        seed = os.environ.get("seed_val", os.environ.get("SEED_VAL", "CCDC2026SecureSeed!"))
        derived = hashlib.sha256(f"{username}{host}{seed}".encode()).hexdigest()[:20]
        pw = f"{derived}B@LL5"
        tty_print(f"  -> Generated deterministic password: {pw}")
    return pw


# =============================================================================
# INVENTORY DISCOVERY & MANAGEMENT
# =============================================================================
def find_inventory_file():
    """Locate nest.yaml or fallback to inventory.yaml."""
    for i, arg in enumerate(sys.argv):
        if arg in ("-i", "--inventory") and i + 1 < len(sys.argv):
            return Path(sys.argv[i + 1])

    script_dir = Path(__file__).resolve().parent
    base_dir = script_dir.parent
    candidates = [
        Path("nest.yaml"),
        Path("nest.yml"),
        base_dir / "nest.yaml",
        Path("inventory.yaml"),
        Path("inventory.yml"),
        base_dir / "inventory.yaml",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def load_inventory():
    """Load target configuration from nest.yaml or prompt interactively to initialize."""
    inv_path = find_inventory_file()

    if inv_path is None or not inv_path.exists():
        tty_print("===================================================================")
        tty_print("       BIRDHUNT - EGG CANDLER INITIAL SETUP                        ")
        tty_print("===================================================================")
        login_username = tty_prompt("Enter username used for login [root]: ") or "root"
        login_password = tty_prompt(f"Enter password for user '{login_username}': ")
        targets_list = tty_prompt("Enter targets as ip:port separated by commas (e.g. 192.168.1.10:22,192.168.1.11:22): ")
        targets = []
        for t in targets_list.split(","):
            t = t.strip()
            if not t:
                continue
            parts = t.split(":")
            ip = parts[0].strip()
            port = int(parts[1].strip()) if len(parts) > 1 else 22
            targets.append({"ip": ip, "port": port})

        nest_data = {
            "all": {
                "children": {
                    "linux": {
                        "hosts": {},
                        "vars": {
                            "ansible_user": login_username,
                            "ansible_password": login_password,
                            "ansible_connection": "ssh",
                            "ansible_become": True,
                            "ansible_become_method": "sudo",
                        },
                    }
                }
            }
        }
        for t in targets:
            hname = t["ip"].replace(".", "_")
            nest_data["all"]["children"]["linux"]["hosts"][hname] = {
                "ansible_host": t["ip"],
                "ansible_port": t["port"],
                "ansible_password": login_password,
                "blacklist": [],
                "whitelist": [],
                "user_passwords": {login_username: login_password},
            }
        inv_path = Path("nest.yaml")
        with open(inv_path, "w") as f:
            yaml.dump(nest_data, f, sort_keys=False, default_flow_style=False)
        tty_print(f"[+] Initialized new inventory at {inv_path}")

    with open(inv_path, "r") as f:
        raw_data = yaml.safe_load(f) or {}

    # Check if standard Ansible nest.yaml format
    if "all" in raw_data or "linux" in raw_data:
        linux_group = raw_data.get("all", {}).get("children", {}).get("linux", {})
        if not linux_group:
            linux_group = raw_data.get("linux", {})
        group_vars = linux_group.get("vars", {})
        hosts_dict = linux_group.get("hosts", {})

        targets = []
        for hname, hinfo in hosts_dict.items():
            if hinfo is None:
                hinfo = {}
            ip = hinfo.get("ansible_host", hname)
            port = int(hinfo.get("ansible_port", 22))
            login_user = hinfo.get("ansible_user", group_vars.get("ansible_user", "root"))
            login_pwd = hinfo.get("ansible_password", group_vars.get("ansible_password", ""))
            targets.append({
                "hostname": hname,
                "ip": ip,
                "port": port,
                "login_user": login_user,
                "login_password": login_pwd,
                "host_ref": hinfo,
            })
        return inv_path, raw_data, targets, "nest"

    # Legacy inventory.yaml format fallback
    targets = []
    login_user = raw_data.get("login", "root")
    for t in raw_data.get("targets", []):
        ip = t["ip"]
        port = int(t.get("port", 22))
        login_pwd = raw_data.get("inventory", {}).get(ip, {}).get(login_user, {}).get("password", "")
        targets.append({
            "hostname": ip,
            "ip": ip,
            "port": port,
            "login_user": login_user,
            "login_password": login_pwd,
            "host_ref": raw_data.get("inventory", {}).get(ip, {}),
        })
    return inv_path, raw_data, targets, "legacy"


# =============================================================================
# SSH EXECUTION HELPERS
# =============================================================================
def run_ssh_command(client, command, handle_buffer=None):
    stdin, stdout, stderr = client.exec_command(command, get_pty=True)
    buffer = b""
    channel = stdout.channel
    while not channel.exit_status_ready():
        if channel.recv_ready():
            buffer += channel.recv(1024)
            if handle_buffer is not None:
                buffer = handle_buffer(buffer, stdin, stdout, stderr, client)
    while channel.recv_ready():
        buffer += channel.recv(1024)
    return buffer


def gen_place_sudo_password(password):
    def place_sudo_password(buffer, stdin, stdout, stderr, client):
        if SUDO_PASSWORD_PROMPT in buffer:
            stdin.write(password.encode() if isinstance(password, str) else password)
            stdin.write(b"\n")
            stdin.flush()
            buffer = buffer.replace(SUDO_PASSWORD_PROMPT, b"<Password Prompt>")
        return buffer
    return place_sudo_password


def run_ssh_sudo_command(client, command, password):
    buf = run_ssh_command(client, f"\\sudo -S -p '{SUDO_PASSWORD_PROMPT.decode()}' {command}", gen_place_sudo_password(password))
    lines = buf.split(b"\r\n")
    new_lines = list(filter(lambda a: SUDO_PASSWORD_PROMPT not in a and b"<Password Prompt>" not in a, lines))
    return b"\r\n".join(new_lines)


# =============================================================================
# MAIN INTERACTIVE AUDIT WORKFLOW (METHOD 2)
# =============================================================================
def main():
    inv_path, raw_config, targets, inv_type = load_inventory()
    global_policy = raw_config.get("global_policy", {})

    tty_print("")
    tty_print("=======================================================================")
    tty_print("    BIRDHUNT - EGG CANDLER INTERACTIVE LINUX AUDITOR (METHOD 2)       ")
    tty_print("=======================================================================")
    tty_print(f"[*] Loaded inventory: {inv_path} ({len(targets)} Linux target hosts)")
    tty_print("")

    for target in targets:
        hname = target["hostname"]
        ip = target["ip"]
        port = target["port"]
        login_user = target["login_user"]
        login_pwd = target["login_password"]

        tty_print("-----------------------------------------------------------------------")
        tty_print(f"[*] Auditing Target: {hname} ({ip}:{port}) as '{login_user}'")
        tty_print("-----------------------------------------------------------------------")

        ssh = SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(AutoAddPolicy())

        try:
            ssh.connect(hostname=ip, port=port, username=login_user, password=login_pwd, timeout=10)
        except Exception as e:
            tty_print(f"[-] ERROR: Failed to connect to {hname} ({ip}:{port}): {e}")
            tty_print("    Skipping host and continuing...")
            continue

        try:
            raw_shells = run_ssh_command(ssh, "\\cat /etc/shells | \\grep -v '#'").decode(errors="ignore").split("\n")
            shells = list(map(lambda a: a.strip(), filter(lambda a: len(a) > 0, raw_shells)))

            passwd_raw = base64.b64decode(run_ssh_command(ssh, "\\cat /etc/passwd | \\base64"))
            shadow_raw = base64.b64decode(run_ssh_sudo_command(ssh, "\\cat /etc/shadow | \\base64", login_pwd))
        except Exception as e:
            tty_print(f"[-] ERROR reading /etc/passwd or /etc/shadow on {hname}: {e}")
            ssh.close()
            continue

        user_entries = []
        for line in passwd_raw.decode(errors="ignore").split("\n"):
            line = line.strip()
            if not line:
                continue
            parts = line.split(":")
            if len(parts) < 7:
                continue
            username = parts[0]
            password = parts[1]
            uid = int(parts[2])
            gid = int(parts[3])
            comment = parts[4]
            home_dir = parts[5]
            login_shell = parts[6]
            user_entries.append([username, password, uid, gid, comment, home_dir, login_shell])

        shadow_entries = []
        for line in shadow_raw.decode(errors="ignore").split("\n"):
            line = line.strip()
            if not line:
                continue
            parts = line.split(":")
            if len(parts) < 9:
                parts += [""] * (9 - len(parts))
            shadow_entries.append(parts[:9])

        # Step 1: Detect and relocate unshadowed passwords
        passwd_password_users = []
        unshadowed_entries = []
        for username, password, uid, gid, comment, home_dir, login_shell in user_entries:
            correct_password = password
            if password == "x":
                for sp in shadow_entries:
                    if sp[0] == username:
                        correct_password = sp[1]
                        break
            else:
                passwd_password_users.append((username, password))
            unshadowed_entries.append([username, correct_password, uid, gid, comment, home_dir, login_shell])

        for username, password in passwd_password_users:
            tty_print(f"[!] User '{username}' has password stored directly in /etc/passwd; relocating to /etc/shadow")
            found = False
            for i in range(len(shadow_entries)):
                if shadow_entries[i][0] == username:
                    shadow_entries[i] = [username, password, str(days_since_epoch), shadow_entries[i][3], shadow_entries[i][4], shadow_entries[i][5], shadow_entries[i][6], shadow_entries[i][7], shadow_entries[i][8]]
                    found = True
                    break
            if not found:
                shadow_entries.append([username, password, str(days_since_epoch), "0", "99999", "7", "", "", ""])

            for i in range(len(user_entries)):
                if user_entries[i][0] == username:
                    user_entries[i][1] = "x"

        # Step 2: Audit UID 0 backdoors, root GIDs, duplicate UIDs
        duplicate_uid_users = []
        root_gid_users = []
        root_uid_users = []
        unique_uids = list({item[2] for item in user_entries})
        unique_gids = list({item[3] for item in user_entries})
        next_uid = max(max(unique_uids) + 1, 1000)
        next_gid = max(max(unique_gids) + 1, 1000)

        for i in range(len(user_entries)):
            username, _, uid, gid, _, _, _ = user_entries[i]
            for j in range(len(user_entries)):
                if j >= i:
                    break
                if user_entries[j][2] == uid and username not in duplicate_uid_users:
                    if uid == 0 and username != "root" and username not in root_uid_users:
                        root_uid_users.append(username)
                    else:
                        duplicate_uid_users.append((username, uid))
                if user_entries[j][3] == gid and gid == 0 and username != "root" and username not in root_gid_users:
                    root_gid_users.append(username)

        users_to_delete = []
        blacklist_never_rotate = []
        whitelist_keep = []

        # Interactive handling for rogue UID 0 accounts
        for username in root_uid_users:
            tty_print(f"[CRITICAL ALERT] User '{username}' has UID 0 (Acting as root backdoor!)")
            user_input = "0"
            while user_input not in "rdi":
                user_input = tty_prompt(f"Select action for UID 0 backdoor '{username}': [r=reassign UID, d=delete user, i=ignore]: ")
            if user_input == "r":
                for i in range(len(user_entries)):
                    if user_entries[i][0] == username:
                        user_entries[i][2] = next_uid
                        tty_print(f"[+] Reassigned UID for '{username}' to {next_uid}")
                        next_uid += 1
            elif user_input == "d":
                users_to_delete.append(username)
                tty_print(f"[+] Flagged backdoor '{username}' for deletion")

        # Interactive handling for root GID 0 accounts
        for username in root_gid_users:
            tty_print(f"[WARNING] User '{username}' has primary GID 0 (In root group!)")
            user_input = "0"
            while user_input not in "rdi":
                user_input = tty_prompt(f"Select action for root GID user '{username}': [r=reassign GID, d=delete user, i=ignore]: ")
            if user_input == "r":
                for i in range(len(user_entries)):
                    if user_entries[i][0] == username:
                        user_entries[i][3] = next_gid
                        tty_print(f"[+] Reassigned GID for '{username}' to {next_gid}")
                        next_gid += 1
            elif user_input == "d":
                users_to_delete.append(username)
                tty_print(f"[+] Flagged '{username}' for deletion")

        for username, uid in duplicate_uid_users:
            tty_print(f"[!] Warning: User '{username}' has duplicate UID {uid}.")

        # Step 3: Interactive User Password Auditing & Rotation Prompting (Method 2)
        password_rotations = {}
        for username, password, uid, gid, comment, home_dir, login_shell in unshadowed_entries:
            # Skip accounts that are already locked, disabled, or marked for deletion
            if password.startswith("!") or password.startswith("*") or len(password) == 0:
                continue
            if username in users_to_delete:
                continue

            has_shell = login_shell in shells
            shell_note = "Valid shell" if has_shell else f"NO SHELL ({login_shell})"
            tty_print(f"[?] User: '{username}' (UID: {uid}, Shell: {shell_note})")

            # Check existing policy
            policy = global_policy.get(username, "ask")
            if policy == "ask":
                user_input = "0"
                while user_input not in "rAhiNXd":
                    user_input = tty_prompt(
                        f"    Action for '{username}'? [r=rotate, A=always rotate, h=always for host, i=ignore, N=never rotate (blacklist), X=never rotate for host, d=delete]: "
                    )
                if user_input == "r":
                    policy = "rotate"
                elif user_input == "A":
                    policy = "always"
                    global_policy[username] = "always"
                elif user_input == "h":
                    policy = "always"
                elif user_input == "i":
                    policy = "ignore"
                elif user_input == "N":
                    policy = "never"
                    global_policy[username] = "never"
                elif user_input == "X":
                    policy = "never"
                elif user_input == "d":
                    policy = "delete"

            if policy in ("rotate", "always"):
                new_pw = gen_password(username, hname)
                password_rotations[username] = new_pw
                # Update shadow entry hash
                new_hash = hash_shadow_password(new_pw)
                found = False
                for i in range(len(shadow_entries)):
                    if shadow_entries[i][0] == username:
                        shadow_entries[i][1] = new_hash
                        shadow_entries[i][2] = str(days_since_epoch)
                        found = True
                        break
                if not found:
                    shadow_entries.append([username, new_hash, str(days_since_epoch), "0", "99999", "7", "", "", ""])

            elif policy == "never":
                blacklist_never_rotate.append(username)
                whitelist_keep.append(username)
                tty_print(f"    -> Added '{username}' to never-rotate blacklist / whitelist.")

            elif policy == "delete":
                users_to_delete.append(username)
                tty_print(f"    -> Added '{username}' to deletion blacklist.")

        # Filter out deleted users from passwd and shadow
        if users_to_delete:
            user_entries = [u for u in user_entries if u[0] not in users_to_delete]
            shadow_entries = [s for s in shadow_entries if s[0] not in users_to_delete]

        updated_passwd = "\n".join(":".join(map(str, a)) for a in user_entries) + "\n"
        updated_shadow = "\n".join(":".join(map(str, a)) for a in shadow_entries) + "\n"

        tty_print("")
        tty_print(f"[*] Summary for {hname}: {len(password_rotations)} passwords to rotate, {len(users_to_delete)} users to delete, {len(blacklist_never_rotate)} blacklisted from rotation.")
        confirm = tty_prompt(f"Ready to apply changes to {hname}? [y/n, default: y]: ", default="y")
        if confirm.lower() in ("y", "yes", ""):
            new_passwd_b64 = base64.b64encode(updated_passwd.encode()).decode()
            new_shadow_b64 = base64.b64encode(updated_shadow.encode()).decode()

            run_ssh_sudo_command(ssh, f"sh -c '\\echo \"{new_passwd_b64}\" | \\base64 -d > /etc/passwd.tmp'", login_pwd)
            run_ssh_sudo_command(ssh, f"sh -c '\\echo \"{new_shadow_b64}\" | \\base64 -d > /etc/shadow.tmp'", login_pwd)
            run_ssh_sudo_command(ssh, "\\chmod 644 /etc/passwd.tmp", login_pwd)
            run_ssh_sudo_command(ssh, "\\chmod 640 /etc/shadow.tmp", login_pwd)
            run_ssh_sudo_command(ssh, "\\mv /etc/shadow.tmp /etc/shadow", login_pwd)
            run_ssh_sudo_command(ssh, "\\mv /etc/passwd.tmp /etc/passwd", login_pwd)

            # Delete users via userdel if requested
            for u in users_to_delete:
                run_ssh_sudo_command(ssh, f"\\userdel -r {u}", login_pwd)
                tty_print(f"[✓] Deleted user '{u}' on {hname}")

            tty_print(f"[✓] Successfully updated /etc/passwd and /etc/shadow on {hname}.")

            # Step 4: Synchronize choices to inventory in-memory reference
            if inv_type == "nest":
                href = target["host_ref"]
                href.setdefault("user_passwords", {})
                for u, p in password_rotations.items():
                    href["user_passwords"][u] = p
                    if u == login_user:
                        href["ansible_password"] = p
                        login_pwd = p

                # Update blacklist (deleted rogue accounts)
                cur_bl = set(href.get("blacklist", []))
                for u in users_to_delete:
                    cur_bl.add(u)
                href["blacklist"] = sorted(list(cur_bl))

                # Update whitelist / do_not_rotate
                cur_wl = set(href.get("whitelist", []))
                for u in whitelist_keep:
                    cur_wl.add(u)
                    if u in href["user_passwords"]:
                        del href["user_passwords"][u]
                href["whitelist"] = sorted(list(cur_wl))

        ssh.close()

    # Step 5: Save updated choices back to nest.yaml
    tty_print("")
    tty_print(f"[*] Writing updated audit policies and rotated credentials to {inv_path}...")
    raw_config["global_policy"] = global_policy
    with open(inv_path, "w") as f:
        yaml.dump(raw_config, f, sort_keys=False, default_flow_style=False)
    tty_print(f"[✓] Inventory {inv_path} successfully saved.")
    tty_print("=======================================================================")
    tty_print("    EGG CANDLER AUDIT COMPLETE - READY FOR ANSIBLE PLAYBOOK STAGES    ")
    tty_print("=======================================================================")


if __name__ == "__main__":
    main()
