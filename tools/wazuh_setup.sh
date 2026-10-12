#!/usr/bin/env bash
# Install a Wazuh 4.8 manager (no indexer, no dashboard) with libfaketime on Ubuntu 24.04,
# for tools/wazuh_replay.py. Run once with sudo on the evaluation VM.
set -euo pipefail
VERSION=4.8.2-1

apt-get update -q
apt-get install -y -q curl gnupg apt-transport-https faketime
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list
apt-get update -q
apt-get install -y -q "wazuh-manager=$VERSION"
apt-mark hold wazuh-manager

# wazuh-analysisd (which serves the logtest socket) runs under libfaketime; the replay
# script writes the clock offset to /var/ossec/tmp/faketime before every event.
LIB=$(dpkg -L libfaketime | grep 'faketime/libfaketime.so.1$' | head -1)
echo "+0" > /var/ossec/tmp/faketime
chown root:wazuh /var/ossec/tmp/faketime && chmod 664 /var/ossec/tmp/faketime
mkdir -p /etc/systemd/system/wazuh-manager.service.d
cat > /etc/systemd/system/wazuh-manager.service.d/faketime.conf <<EOF
[Service]
Environment=LD_PRELOAD=$LIB
Environment=FAKETIME_TIMESTAMP_FILE=/var/ossec/tmp/faketime
Environment=FAKETIME_NO_CACHE=1
Environment=DONT_FAKE_MONOTONIC=1
EOF
# longer logtest sessions (the replay keeps one session per scenario)
sed -i 's|<session_timeout>.*</session_timeout>|<session_timeout>86400</session_timeout>|' /var/ossec/etc/ossec.conf || true
systemctl daemon-reload
systemctl enable --now wazuh-manager
sleep 10
/var/ossec/bin/wazuh-control status
echo "logtest socket: $(ls -l /var/ossec/queue/sockets/logtest)"
