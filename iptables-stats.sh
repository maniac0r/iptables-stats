#!/bin/bash
# Run this as root
#

WRITE_FOLDER="/dev/shm/iptables-stats"

# Setup folder and files in /dev/shm
umask 022
mkdir -p ${WRITE_FOLDER} 2>/dev/null
rm -f ${WRITE_FOLDER}/{ip,nf}tables.rules
chown -R root:nogroup ${WRITE_FOLDER}/
chmod 750 ${WRITE_FOLDER}

# Decide which fw tool to use
if [ -x /usr/sbin/iptables-save ] ; then
  CMD="/usr/sbin/iptables-save -c"
  OUTFILE="iptables.rules"
elif [ -x /usr/sbin/nft ] ; then
  CMD="/usr/sbin/nft list ruleset"
  OUTFILE="nftables.rules"
else
  echo "No fw detected: /usr/sbin/iptables-save nor /usr/sbin/nft" >&2
  exit 1
fi

# Main loop
while true ; do
  $CMD > ${WRITE_FOLDER}/${OUTFILE}.tmp && mv ${WRITE_FOLDER}/${OUTFILE}.tmp ${WRITE_FOLDER}/${OUTFILE}
  sleep 1
done
