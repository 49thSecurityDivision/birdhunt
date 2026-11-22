#!/usr/bin/env bash
# Wrapper to run the python-based user audit using standard Python or Ansible
exec python3 -c "
import sys, os

print('[*] BirdHunt Egg Candler (User Audit Companion)')
print('[*] Note: For native, multi-threaded CCDC operations, prefer running:')
print('    ansible-playbook playbooks/quail.yml')
print('    ansible-playbook playbooks/quail.yml -e \"seed_val=YourSeed!\"')
print('')
"
