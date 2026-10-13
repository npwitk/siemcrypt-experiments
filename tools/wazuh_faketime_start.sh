#!/usr/bin/env bash
# (Re)start wazuh-analysisd alone under libfaketime + the fast-sleep shim, for
# tools/wazuh_replay.py. The other Wazuh daemons keep the real clock (wazuh-modulesd
# fails under libfaketime). Run with sudo after every boot or `systemctl restart wazuh-manager`.
#
# analysisd chroots into /var/ossec, so libfaketime reads the clock offset from
# /tmp/faketime inside the chroot, i.e. /var/ossec/tmp/faketime on the host
# (the replay writes that file); /tmp/faketime on the host is read only before the chroot.
set -euo pipefail
FT=$(dpkg -L libfaketime | grep 'faketime/libfaketime.so.1$' | head -1)
SHIM=/var/ossec/lib/wazuh_fastsleep.so

pkill -x wazuh-analysisd || true
sleep 3
for f in /var/ossec/tmp/faketime /tmp/faketime; do echo "+0" > "$f"; done
chown root:wazuh /var/ossec/tmp/faketime && chmod 664 /var/ossec/tmp/faketime
env LD_PRELOAD="$SHIM:$FT" FAKETIME_TIMESTAMP_FILE=/tmp/faketime FAKETIME_NO_CACHE=1 \
  /var/ossec/bin/wazuh-analysisd
sleep 8
pgrep -a wazuh-analysisd
ls -l /var/ossec/queue/sockets/logtest
