#!/bin/bash
# run as root
#

umask 022
mkdir -p /dev/shm/iptables-stats 2>/dev/null
rm -f /dev/shm/iptables-stats/iptables.rules
touch /dev/shm/iptables-stats/iptables.rules
chown -R root:nogroup /dev/shm/iptables-stats/


while true ; do
  /usr/sbin/iptables-save -c > /dev/shm/iptables-stats/iptables.rules.tmp && mv /dev/shm/iptables-stats/iptables.rules.tmp /dev/shm/iptables-stats/iptables.rules
  sleep 1
done
