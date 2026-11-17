#!/usr/bin/env bash
# Build a fresh installation tree without activating services or touching nft.
set -euo pipefail
[[ $# == 1 && -n "$1" ]] || { echo 'usage: stage.sh EMPTY_DESTDIR' >&2; exit 2; }
root=$(cd "$(dirname "$0")/.." && pwd)
bin_dir=${QNTW_STAGE_BIN_DIR:-"$root/bin"}
[[ "$bin_dir" == /* ]] || bin_dir="$root/$bin_dir"
dest=$(python3 - "$1" <<'PY'
import pathlib,sys
print(pathlib.Path(sys.argv[1]).resolve())
PY
)
case "$dest" in
 /|/etc|/usr|/var|/run|/opt|/bin|/sbin|/lib|/lib64) echo 'refusing system directory' >&2; exit 2 ;;
esac
if [[ -e "$dest" ]]; then
 [[ -d "$dest" && -z $(find "$dest" -mindepth 1 -maxdepth 1 -print -quit) ]] || { echo 'DESTDIR must be absent or empty' >&2; exit 2; }
fi
for binary in vpnshop-probe-blackhole vpnshop-tls-alert-gate vpnshop-udp-observer; do
 [[ -f "$bin_dir/$binary" ]] || { echo "missing $bin_dir/$binary; run make build" >&2; exit 2; }
done
install -d -m 0755 "$dest/usr/local/libexec" "$dest/usr/local/sbin" "$dest/etc/systemd/system" \
 "$dest/var/lib/node_exporter/textfile" "$dest/usr/share/doc/qntw-blackhole" \
 "$dest/etc/nginx/snippets" "$dest/etc/systemd/system/nftables.service.d"
install -d -m 0700 "$dest/etc/vpnshop-security/probe-blackhole" "$dest/etc/vpnshop-security/tls-alert-gate" \
 "$dest/var/lib/vpnshop-probe-blackhole" "$dest/var/lib/vpnshop-tls-alert" \
 "$dest/var/lib/vpnshop-udp-observer" "$dest/var/lib/vpnshop-probe-analysis" \
 "$dest/var/log/vpnshop-probes" "$dest/var/log/vpnshop-udp"
for binary in vpnshop-probe-blackhole vpnshop-tls-alert-gate vpnshop-udp-observer; do
 install -m 0755 "$bin_dir/$binary" "$dest/usr/local/libexec/$binary"
done
install -m 0755 "$root/probe-blackhole/filter.sh" "$dest/usr/local/libexec/vpnshop-probe-blackhole-filter"
install -m 0755 "$root/probe-blackhole/unban.sh" "$dest/usr/local/sbin/vpnshop-blackhole-unban"
install -m 0755 "$root/tls-alert-gate/routing.sh" "$dest/usr/local/libexec/vpnshop-tls-alert-routing"
install -m 0755 "$root/tls-alert-gate/control.sh" "$dest/usr/local/libexec/vpnshop-tls-alert-control"
install -m 0755 "$root/observability/probe-logging.py" "$dest/usr/local/libexec/vpnshop-probe-logging"
install -m 0755 "$root/observability/probe-analysis.py" "$dest/usr/local/libexec/vpnshop-probe-analysis"
for row in 'probe-blackhole/daemon.service:vpnshop-probe-blackhole.service' \
 'probe-blackhole/filter.service:vpnshop-probe-blackhole-filter.service' \
 'tls-alert-gate/gate.service:vpnshop-tls-alert-gate.service' \
 'observability/probe-logging.service:vpnshop-probe-logging.service' \
 'observability/probe-analysis.service:vpnshop-probe-analysis.service' \
 'observability/udp-observer/observer.service:vpnshop-udp-observer.service'; do
 install -m 0644 "$root/${row%%:*}" "$dest/etc/systemd/system/${row#*:}"
done
for file in profiles.nft counters.nft; do
 install -m 0644 "$root/probe-blackhole/$file" "$dest/etc/vpnshop-security/probe-blackhole/$file"
done
install -m 0644 "$root/probe-blackhole/profiles.json" "$dest/etc/vpnshop-security/tls-alert-gate/profiles.json"
for file in "$root/examples/probe-blackhole/"*; do
 install -m 0600 "$file" "$dest/etc/vpnshop-security/probe-blackhole/$(basename "$file")"
done
for file in "$root/examples/tls-alert-gate/"*; do
 install -m 0600 "$file" "$dest/etc/vpnshop-security/tls-alert-gate/$(basename "$file")"
done
shopt -s nullglob
for file in "$root/observability/"*.example.json; do
 install -m 0600 "$file" "$dest/etc/$(basename "$file")"
done
install -m 0644 "$root/observability/probe-logging-nginx.conf" "$dest/etc/nginx/snippets/qntw-probes.conf.example"
install -m 0644 "$root/probe-blackhole/nftables.conf" "$dest/etc/systemd/system/nftables.service.d/qntw-blackhole.conf.example"
install -m 0644 "$root/README.md" "$root/SECURITY.md" "$dest/usr/share/doc/qntw-blackhole/"
printf 'Staged all components at %s; no services activated.\n' "$dest"
