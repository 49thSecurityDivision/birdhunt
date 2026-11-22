#!/usr/bin/env python3
"""
Legacy BirdHunt User Auditing & Password Rotation Script
Original Paramiko-based implementation.
"""

from paramiko import SSHClient, AutoAddPolicy
from scp import SCPClient
import time
import base64
import yaml
from pathlib import Path
import sys
from datetime import datetime, timezone
from passlib.hash import sha512_crypt

days_since_epoch = (datetime.now(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)).days

def gen_password(username, host):
	return input(f"Enter password for {username} on {host}:")

if not Path("inventory.yaml").exists():
	login_username = input("Enter username used for login:")
	login_password = input(f"Enter password for user {login_username}:")
	targets_list = input("Enter targets as ip:port separated by commas:")
	targets = list(map(lambda a: {"ip":a.split(':')[0].strip(), "port":int(a.split(":")[1].strip())}, targets_list.split(",")))
	data = {"targets": targets, "login": login_username, "inventory": {}, "global_policy": {}}
	for target in targets:
		ip = target["ip"]
		data["inventory"][ip] = {}
		data["inventory"][ip][login_username] = {"password": login_password, "policy": "ask", "has_shell": True}
	with open("inventory.yaml", "wt+") as file:
		yaml.dump(data, file, sort_keys=False, default_flow_style=False)

with open("inventory.yaml", "rt") as file:
	config = yaml.safe_load(file)

#for ip, port in config["targets"]
#ssh = SSHClient()
#ssh.load_system_host_keys()
#ssh.set_missing_host_key_policy(AutoAddPolicy())

#ssh.connect(hostname="127.0.0.1", port=22, username="kali", password="kali")

SUDO_PASSWORD_PROMPT = b"SUDO_PASSWORD_PROMPT:"

def run_ssh_command(client, command, handle_buffer = None):
	stdin, stdout, stderr = client.exec_command(command, get_pty=True)
	buffer = b""
	channel = stdout.channel
	while not channel.exit_status_ready():
		if channel.recv_ready():
			buffer += channel.recv(1024)
			#print("[ ] Buffer contents", buffer)
			if handle_buffer is not None:
				buffer = handle_buffer(buffer, stdin, stdout, stderr, client)
	while channel.recv_ready():
		buffer += channel.recv(1024)
	return buffer

def gen_place_sudo_password(password):
	def place_sudo_password(buffer, stdin, stdout, stderr, client):
		if SUDO_PASSWORD_PROMPT in buffer:
			print("[+] Sudo password prompt received; responding now", buffer)
			stdin.write(password)
			stdin.write("\n")
			stdin.flush()
			buffer = buffer.replace(SUDO_PASSWORD_PROMPT, b"<Password Prompt>")
		return buffer
	return place_sudo_password

def run_ssh_sudo_command(client, command, password):
	buf = run_ssh_command(client, f"\\sudo -S -p '{SUDO_PASSWORD_PROMPT}' {command}", gen_place_sudo_password(password))
	lines = buf.split(b"\r\n")
	new_lines = list(filter(lambda a: SUDO_PASSWORD_PROMPT not in a and b"<Password Prompt>" not in a, lines))
	return b"\r\n".join(new_lines)


for target in config["targets"]:
	ip = target["ip"]
	port = target["port"]
	ssh = SSHClient()
	ssh.load_system_host_keys()
	ssh.set_missing_host_key_policy(AutoAddPolicy())

	ssh.connect(hostname=ip, port=port, username=config["login"], password=config["inventory"][ip][config["login"]]["password"])

	shells = run_ssh_command(ssh, "\\cat /etc/shells | \\grep -v '#'").decode().split("\n")
	shells = list(map(lambda a: a.strip(), filter(lambda a: len(a) > 0, shells)))
	passwd_file = base64.b64decode(run_ssh_command(ssh, "\\cat /etc/passwd | \\base64"))
	shadow_file = base64.b64decode(run_ssh_sudo_command(ssh, "\\cat /etc/shadow | \\base64", config["inventory"][ip][config["login"]]["password"]))

	user_entries = []
	for line in passwd_file.decode().split("\n"):
		if len(line.strip()) == 0:
			continue
		splitted = line.strip().split(":")
		username = splitted[0]
		password = splitted[1]
		uid = int(splitted[2])
		gid = int(splitted[3])
		comment = splitted[4]
		home_dir = splitted[5]
		login_shell = splitted[6]
		user_entries.append([username, password, uid, gid, comment, home_dir, login_shell])

	shadow_entries = []
	for line in shadow_file.decode().split("\n"):
		if len(line.strip()) == 0:
			continue
		splitted = line.strip().split(":")
		username = splitted[0]
		password = splitted[1]
		lastchg = splitted[2]
		min_age = splitted[3]
		max_age = splitted[4]
		warn_period = splitted[5]
		inactivity_period = splitted[6]
		expire_date = splitted[7]
		reserved = splitted[8]
		shadow_entries.append([username, password, lastchg, min_age, max_age, warn_period, inactivity_period, expire_date, reserved])

	unshadowed_entries = []
	passwd_password_users = []
	for username, password, uid, gid, comment, home_dir, login_shell in user_entries:
		correct_password = password
		if password == "x":
			for uname, passwd, _, _, _, _, _, _, _ in shadow_entries:
				if uname == username:
					correct_password = passwd
					break
		else:
			passwd_password_users.append((username, password))
		unshadowed_entries.append([username, correct_password, uid, gid, comment, home_dir, login_shell])

	for username, password in passwd_password_users:
		print(f"User {username} has password in /etc/passwd; relocating to /etc/shadow")
		found = False
		for i in range(len(shadow_entries)):
			uname, passwd, lastchg, min_age, max_age, warn_period, inactivity_period, expire_date, reserved = shadow_entries[i]
			if uname == username:
				if password != passwd:
					print(f"Warning: Updating shadow file password {passwd} to active password {password}")
				shadow_entries[i] = [username, password, days_since_epoch, min_age, max_age, warn_period, inactivity_period, expire_date, reserved]
				found = True
				break
		if not found:
			print(f"Info: Entry for {username} does not exist in shadow file; creating new entry")
			shadow_entries.append([username, password, days_since_epoch, 0, 99999, "", "", "", ""])

		for i in range(len(user_entries)):
			uname, passwd, uid, gid, comment, home_dir, login_shell = user_entries[i]
			if uname == username:
				user_entries[i] = [username, "x", uid, gid, comment, home_dir, login_shell]


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
				if uid == 0 and username not in root_uid_users:
					root_uid_users.append(username)
				else:
					duplicate_uid_users.append((username, uid))
			if user_entries[j][3] == gid and gid == 0 and username not in root_gid_users:
				root_gid_users.append(username)

	users_to_delete = []

	for username in root_uid_users:
		print(f"User {username} has UID 0, acting as root")
		user_input = "0"
		while user_input not in "rdi":
			user_input = input("Enter action: r = reassign UID, d = delete user, i = ignore")
		if user_input == "r":
			for i in range(len(user_entries)):
				uname, password, uid, gid, comment, home_dir, login_shell = user_entries[i]
				user_entries[i] = [username, password, next_uid, gid, comment, home_dir, login_shell]
				for j in range(len(unshadowed_entries)):
					uname, password, uid, gid, comment, home_dir, login_shell = unshadowed_entries[j]
					unshadowed_entries[j] = [username, password, next_uid, gid, comment, home_dir, login_shell]
				print(f"Updated UID for user {username}")
				next_uid += 1
		if user_input == "d":
			users_to_delete.append(username)
			print(f"Set user {username} to be deleted")

	for username in root_gid_users:
		print(f"User {username} has GID 0, in root group")
		user_input = "0"
		while user_input not in "rdi":
			user_input = input("Enter action: r = reassign UID, d = delete user, i = ignore")
		if user_input == "r":
			for i in range(len(user_entries)):
				uname, password, uid, gid, comment, home_dir, login_shell = user_entries[i]
				user_entries[i] = [username, password, uid, next_gid, comment, home_dir, login_shell]
				next_gid += 1
				print(f"Updated GID for user {username}")
		if user_input == "d":
			users_to_delete.append(username)
			print(f"Set user {username} to be deleted")


	for username, uid in duplicate_uid_users:
		print(f"Warning: User {username} has duplicate UID {uid}. Please audit this later to ensure appropriate access controls.")

	password_rotations = []
	renames = []
	for username, password, uid, gid, comment, home_dir, login_shell in unshadowed_entries:
		if password[0] == "!" or password[0] == "*":
			continue
		print("Auditing user", username)
		if username in config["inventory"][ip]:
			if "uid" not in config["inventory"][ip][username] or uid != config["inventory"][ip][username]["uid"]:
				print(f"Updating inventory UID of {username} to {uid}")
				config["inventory"][ip][username]["uid"] = uid
		else:
			found = False
			for uname, user_data in enumerate(config["inventory"][ip].values()):
				if "uid" in user_data and user_data["uid"] == uid:
					print(f"Found matching UID {uid} in inventoried user {uname} for user {username}")
					user_input = "0"
					while user_input not in "yn":
						user_input = input("Select action: u = update user, r = rename entry to inventoried username, n = new entry")
					if user_input == "u":
						config["inventory"][ip][username] = dict(config["inventory"][ip][uname])
						del config["inventory"][ip][uname]
						found = True
						break
					if user_input == "r":
						username = uname
						renames.append((username, uname))
						found = True
						break
			if not found:
				config["inventory"][ip][username] = {"uid": uid, "policy": "ask"}
		has_shell = login_shell in shells
		if "has_shell" not in config["inventory"][ip][username] or has_shell != config["inventory"][ip][username]["has_shell"]:
			print(f"Updating {username} has shell to {has_shell}")
			config["inventory"][ip][username]["has_shell"] = has_shell
		if not has_shell:
			print(f"Warning: User {username} has a password but not a shell")

		policy = config["global_policy"][username] if username in config["global_policy"] else config["inventory"][ip][username]["policy"]
		if policy == "ask":
			print(f"What do you want to do for user {username}?")
			user_input = "0"
			while user_input not in "rAhiNXd":
				user_input = input("r = rotate, A = always rotate, h = rotate always for this host, i = ignore, N = never rotate, X = never rotate for this host, d = delete user")
			if user_input == "r":
				policy = "rotate"
			if user_input == "A":
				policy = "always"
				config["global_policy"][username] = "always"
			if user_input == "h":
				policy = "always"
				config["inventory"][ip][username]["policy"] = "always"
			if user_input == "i":
				policy = "ignore"
			if user_input == "N":
				policy = "never"
				config["global_policy"][username] = "never"
			if user_input == "X":
				policy = "never"
				config["inventory"][ip][username]["policy"] = "never"
			if user_input == "d":
				policy = "delete"

		if policy == "rotate" or policy == "always":
			password_rotations.append(username)
			print(f"Pending rotation for user {username}")

		if policy == "delete":
			users_to_delete.append(username)
			print(f"Pending delete for user {username}")

	for old, new in renames:
		for i in range(len(user_entries)):
			if user_entries[i][0] == old:
				user_entries[i][0] = new
				print(f"Renamed {old} to {new} in passwd")
		for i in range(len(shadow_entries)):
			if shadow_entries[i][0] == old:
				shadow_entries[i][0] = new
				print(f"Renamed {old} to {new} in shadow")
		config["inventory"][ip][new] = config["inventory"][ip][old]
		del config["inventory"][ip][old]

	for username in users_to_delete:
		user_entries = list(filter(lambda a: a[0] != username, user_entries))
		shadow_entries = list(filter(lambda a: a[0] != username, shadow_entries))
		print(f"Deleted {username} from /etc/passwd and /etc/shadow")
		del config["inventory"][ip][username]

	for user in password_rotations:
		for i in range(len(shadow_entries)):
			if shadow_entries[i][0] == user:
				new_password = gen_password(user, ip)
				shadow_entries[i][1] = sha512_crypt.using(rounds=5000).hash(new_password)
				config["inventory"][ip][user]["password"] = new_password
				print(f"Updated password for {user}")

	updated_passwd = "\n".join(list(map(lambda a: ":".join(list(map(str, a))), user_entries))) + "\n"
	updated_shadow = "\n".join(list(map(lambda a: ":".join(a), shadow_entries))) + "\n"

	print("New /etc/passwd\n", updated_passwd)
	print("New /etc/shadow\n", updated_shadow)

	user_input = "0"
	while user_input not in "yn":
		user_input = input("Ready to update? ")
	if user_input == "y":
		new_passwd = base64.b64encode(updated_passwd.encode()).decode()
		new_shadow = base64.b64encode(updated_shadow.encode()).decode()
		run_ssh_sudo_command(ssh, f"sh -c '\\echo \"{new_passwd}\" | \\base64 -d > /etc/passwd.tmp'", config["inventory"][ip][config["login"]]["password"])
		run_ssh_sudo_command(ssh, f"sh -c '\\echo \"{new_shadow}\" | \\base64 -d > /etc/shadow.tmp'", config["inventory"][ip][config["login"]]["password"])
		run_ssh_sudo_command(ssh, f"\\chmod 644 /etc/passwd.tmp", config["inventory"][ip][config["login"]]["password"])
		run_ssh_sudo_command(ssh, f"\\chmod 640 /etc/shadow.tmp", config["inventory"][ip][config["login"]]["password"])
		run_ssh_sudo_command(ssh, f"\\mv /etc/shadow.tmp /etc/shadow", config["inventory"][ip][config["login"]]["password"])
		run_ssh_sudo_command(ssh, f"\\mv /etc/passwd.tmp /etc/passwd", config["inventory"][ip][config["login"]]["password"])
	ssh.close()

print("Updating inventory file:")
with open("inventory.yaml", "wt+") as file:
	yaml.dump(config, file, sort_keys=False, default_flow_style=False)
