#!/bin/bash
# Root-only coordinated removal from daemon memory, saved state and nft sets.
set -euo pipefail
[[ $EUID == 0 && $# == 1 ]]
exec 9>/run/lock/vpnshop-probe-blackhole-unban.lock
flock -x 9
systemctl stop vpnshop-probe-blackhole.service
trap 'systemctl start vpnshop-probe-blackhole.service' EXIT
/usr/local/libexec/vpnshop-probe-blackhole -config /etc/vpnshop-security/probe-blackhole/config.json -unban "$1"
