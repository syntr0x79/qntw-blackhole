#!/bin/bash
# Inspect a fresh installation tree without installing or starting anything.
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
stage=$work/rootfs
make -C "$repo" stage DESTDIR="$stage"
python3 - "$stage" <<'PY'
from pathlib import Path
import json
import stat
import sys

root = Path(sys.argv[1])
units = sorted((root / 'etc/systemd/system').glob('*.service'))
assert len(units) == 6, [p.name for p in units]
for name in ('vpnshop-probe-blackhole', 'vpnshop-tls-alert-gate', 'vpnshop-udp-observer'):
    path = root / 'usr/local/libexec' / name
    assert path.is_file() and path.stat().st_mode & stat.S_IXUSR, path
for directory in ('etc/vpnshop-security/probe-blackhole', 'etc/vpnshop-security/tls-alert-gate'):
    path = root / directory
    assert stat.S_IMODE(path.stat().st_mode) == 0o700, path
    assert list(path.glob('*.example*')), f'no configuration examples in {path}'
    assert not (path / 'config.json').exists(), path
    assert not (path / 'gate.json').exists(), path
examples = sorted((root / 'etc').rglob('*.example.json')) + sorted((root / 'etc').rglob('*.json.example'))
assert len(examples) >= 7, [str(p) for p in examples]
for path in examples:
    json.loads(path.read_text())
    assert stat.S_IMODE(path.stat().st_mode) == 0o600, path
assert not (root / 'etc/vpnshop-probe-logging.json').exists()
assert not (root / 'etc/vpnshop-probe-analysis.json').exists()
for directory in ('var/lib/vpnshop-probe-blackhole', 'var/lib/vpnshop-tls-alert', 'var/log/vpnshop-probes'):
    assert not any((root / directory).iterdir()), directory
assert not list(root.rglob('*.key'))
print(f'Stage verification passed: {len(units)} units, 3 binaries, {len(examples)} JSON examples; no active configuration or runtime state')
PY
# Refusal to merge into a populated tree protects a previously reviewed stage.
if bash "$repo/tools/stage.sh" "$stage" >/dev/null 2>&1; then
  echo 'stage unexpectedly accepted a populated destination' >&2
  exit 1
fi
