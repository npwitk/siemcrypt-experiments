#!/usr/bin/env bash
# Install a Wazuh 4.8 manager (no indexer, no dashboard) with libfaketime on Ubuntu 24.04,
# for tools/wazuh_replay.py. Run once with sudo on the evaluation VM.
set -euo pipefail
VERSION=4.8.2-1

apt-get update -q
apt-get install -y -q curl gnupg apt-transport-https faketime gcc
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list
apt-get update -q
apt-get install -y -q "wazuh-manager=$VERSION"
apt-mark hold wazuh-manager

# The replay clock: only wazuh-analysisd (which serves the logtest socket) runs under
# libfaketime, started by tools/wazuh_faketime_start.sh after the manager is up.
gcc -shared -fPIC -O2 -o /var/ossec/lib/wazuh_fastsleep.so "$(dirname "$0")/wazuh_fastsleep.c"
# longer logtest sessions (the replay keeps one session per scenario)
sed -i 's|<session_timeout>.*</session_timeout>|<session_timeout>86400</session_timeout>|' /var/ossec/etc/ossec.conf || true
# the vulnerability detector is not used and its feed updater fills ~35 GB of disk
sed -i '/<vulnerability-detection>/,/<\/vulnerability-detection>/s|<enabled>yes</enabled>|<enabled>no</enabled>|' \
  /var/ossec/etc/ossec.conf
systemctl daemon-reload
systemctl enable --now wazuh-manager
sleep 10
bash "$(dirname "$0")/wazuh_faketime_start.sh"
