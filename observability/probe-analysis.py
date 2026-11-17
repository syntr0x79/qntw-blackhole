#!/usr/bin/python3
"""Passive triage of existing sanitized ingress journals; no network actions."""
import argparse
import collections
import datetime as dt
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import time

UTC = dt.timezone.utc
BKK = dt.timezone(dt.timedelta(hours=7))
VERSION = 4
BAD_PATH = re.compile(r'(?i)(/\.env(?:[/.]|$)|/\.git(?:/|$)|/wp-(?:admin|login)|/owa/|/cgi-bin/|/actuator(?:/|$)|/phpmyadmin|/vendor/phpunit|/HNAP1|/boaform|/manager/html|/server-status|/(?:dns-query|resolve|doh)(?:/|$))')
FAILURE = re.compile(r'(?i)(failed password|invalid user|authentication failure|unable to negotiate|bad protocol|SSL_do_handshake\(\) failed|client sent invalid)')


def stamp(t):
    return dt.datetime.fromtimestamp(t, UTC).isoformat(timespec='milliseconds')


def localstamp(t):
    return dt.datetime.fromtimestamp(t, BKK).isoformat(timespec='milliseconds')


def atomic(path, data):
    tmp = path.with_suffix(path.suffix + '.tmp')
    with open(tmp, 'w') as f:
        os.chmod(tmp, 0o600)
        json.dump(data, f, ensure_ascii=False, separators=(',', ':'))
    os.replace(tmp, path)


class JournalReader:
    """Recover unread tails from gzip archives when the collector truncates in-place."""
    def __init__(self, directory, state, cutoff):
        self.directory = Path(directory)
        self.state = state
        self.cutoff = cutoff
        self.seen = set(state.get('archives', []))
        self.positions = state.get('positions', {})
        self.errors = collections.Counter()

    def consume(self, f, callback):
        first = f.readline()
        if not first:
            return
        marker = hashlib.sha256(first).hexdigest()
        offset = self.positions.get(marker, 0)
        f.seek(offset)
        while True:
            before = f.tell()
            line = f.readline()
            if not line or not line.endswith(b'\n'):
                f.seek(before)
                break
            try:
                event = json.loads(line)
                observed = dt.datetime.fromisoformat(event['observed_utc']).timestamp()
                if observed >= self.cutoff:
                    callback(event)
            except (ValueError, KeyError, TypeError):
                self.errors['invalid_json_or_time'] += 1
        self.positions[marker] = f.tell()

    def poll(self, callback):
        archives = sorted(self.directory.glob('events-*.jsonl.gz'))
        existing = {p.name for p in archives}
        for path in archives:
            if path.name in self.seen:
                continue
            if path.stat().st_mtime < self.cutoff:
                self.seen.add(path.name)
                continue
            with gzip.open(path, 'rb') as f:
                self.consume(f, callback)
            self.seen.add(path.name)
        with open(self.directory / 'events.jsonl', 'rb') as f:
            self.consume(f, callback)
        self.seen.intersection_update(existing)
        # At most one current file and a small number of rotations per tick.
        self.positions = dict(list(self.positions.items())[-128:])
        self.state.update(archives=sorted(self.seen), positions=self.positions)


def normalize(d, known, local_ips):
    event, node = d.get('event'), d.get('node', '')
    src = d.get('src') or d.get('client')
    message = d.get('message', '')
    if event in ('service', 'nginx_error'):
        match = re.search(r'(?:client: |\bfrom |\brhost=)([0-9a-fA-F:.]+)', message)
        src = match[1].rstrip(':') if match else None
    try:
        addr = ipaddress.ip_address(src)
    except (ValueError, TypeError):
        return None, 'no_external_source'
    if str(addr) in known or not addr.is_global:
        return None, 'known_monitor_or_private'
    if event in ('tcp', 'tls_hello', 'flow', 'icmp') and d.get('dst') not in local_ips:
        return None, 'outbound'
    if event == 'flow':
        # TCP SYN is counted from packet observations only, not again as conntrack.
        if d.get('protocol') != 'udp' or d.get('change') != 'NEW':
            return None, 'flow_state_update'
        kind = 'udp_new'
    elif event == 'tcp':
        flags = int(d.get('flags') or '0', 0)
        kind = 'syn' if flags & 2 and not flags & 16 else 'close' if flags & 5 else None
        if not kind:
            return None, 'other_tcp'
    elif event in ('tls_hello', 'http'):
        kind = event
    elif event in ('service', 'nginx_error') and FAILURE.search(message):
        kind = 'failure'
    else:
        return None, 'other'
    observed = dt.datetime.fromisoformat(d['observed_utc']).timestamp()
    try:
        t = float(d.get('epoch') or observed)
        # Reject implausible packet clocks rather than polluting the window.
        if abs(t - observed) > 300:
            t = observed
    except (ValueError, TypeError):
        t = observed
    result = {'t': t, 'node': node, 'kind': kind, 'src': str(addr),
              'sport': str(d.get('sport') or d.get('client_port') or ''),
              'dport': str(d.get('dport') or d.get('port') or ''),
              'dst': str(d.get('dst') or d.get('server') or ''),
              'flags': str(d.get('flags') or ''),
              'sni': str(d.get('sni') or '')[:255], 'ja3': str(d.get('ja3') or '')[:100],
              'path': str(d.get('request_line') or d.get('uri') or '')[:512],
              'status': str(d.get('status') or ''),
              'ua': re.sub(r'\?[^\s"<>]*', '?[redacted]', str(d.get('user_agent') or ''))[:240]}
    if kind == 'failure':
        # Store only classification, no usernames or arbitrary service messages.
        result['failure'] = FAILURE.search(message)[0].lower()
    if kind == 'tls_hello':
        for key in ('client_hello', 'client_hello_ref'):
            if isinstance(d.get(key), dict):
                result[key] = d[key]
    return result, 'external'


def flowkey(e):
    return e['node'], e['src'], e['sport'], e['dport']


def detect(events, now):
    """Heuristics identify candidates, never an operator or a blocking cause."""
    groups = collections.defaultdict(list)
    prefixes = collections.defaultdict(list)
    for e in events:
        if now - 900 <= e['t'] <= now + 5:
            groups[e['src']].append(e)
            if e['kind'] == 'syn' and e['t'] >= now - 300:
                a = ipaddress.ip_address(e['src'])
                prefixes[str(ipaddress.ip_network(str(a) + ('/24' if a.version == 4 else '/48'), strict=False))].append(e)
    findings = []

    def add(rule, key, evidence, reason, confidence='candidate'):
        evidence = sorted(evidence, key=lambda e: e['t'])
        if not evidence:
            return
        findings.append({'rule': rule, 'key': key, 'assessment': confidence,
            'reason': reason, 'first_utc': stamp(evidence[0]['t']),
            'last_utc': stamp(evidence[-1]['t']),
            'first_bangkok': localstamp(evidence[0]['t']),
            'last_bangkok': localstamp(evidence[-1]['t']),
            'event_count': len(evidence),
            'source_count': len({e['src'] for e in evidence}),
            'nodes': sorted({e['node'] for e in evidence}),
            'ports': sorted({e['dport'] for e in evidence if e['dport']})[:128],
            'distinct_ports': len({e['dport'] for e in evidence if e['dport']}),
            'distinct_connections': len({flowkey(e) for e in evidence if e['sport']}),
            'paths': sorted({e['path'] for e in evidence if e['path']})[:32],
            'sni': sorted({e['sni'] for e in evidence if e['sni']})[:24],
            'ja3': sorted({e['ja3'] for e in evidence if e['ja3']})[:24],
            'samples': (evidence[:4] + evidence[-4:]) if len(evidence) > 8 else evidence})

    for src, rows in groups.items():
        recent = [e for e in rows if e['t'] >= now - 300]
        syn = {flowkey(e): e for e in recent if e['kind'] == 'syn'}
        if len({e['dport'] for e in syn.values()}) >= 8:
            add('port_sweep', src, list(syn.values()), '>=8 destination ports in 5 minutes; SYN retransmissions deduplicated', 'scan_pattern')
        activity = [e for e in recent if e['kind'] in ('syn', 'tls_hello', 'http', 'udp_new')]
        if len({e['node'] for e in activity}) >= 3 and len({flowkey(e) for e in activity}) >= 6:
            add('multi_node_contact', src, activity, '>=3 nodes and >=6 connections in 5 minutes; shared NAT or legitimate clients remain possible')
        bad = [e for e in recent if e['kind'] == 'http' and BAD_PATH.search(e['path'])]
        if bad:
            add('application_probe', src, bad, 'Known discovery/exploit-check/DoH endpoint requested; intent and operator unverified')
        mismatch = [e for e in recent if e['kind'] == 'http' and e['path'].startswith('SSH-')]
        if mismatch:
            add('ssh_in_http', src, mismatch, 'SSH identification sent to HTTP listener', 'scan_pattern')
        failures = [e for e in recent if e['kind'] == 'failure']
        if len(failures) >= 6:
            add('repeated_auth_or_tls_failure', src, failures, '>=6 SSH/authentication/TLS/protocol failures in 5 minutes; configuration errors remain possible')
        # Frontend :443 can terminate on an nginx backend :8443 via PROXY.
        # The client address/port survive while the local destination port changes.
        # Conservatively accept HTTP on either local port as a counterpart.
        http = {(e['node'], e['src'], e['sport']) for e in rows if e['kind'] == 'http'}
        closed = {flowkey(e): e for e in rows if e['kind'] == 'close'}
        hello = {flowkey(e): e for e in recent if e['kind'] == 'tls_hello'}
        incomplete = [e for k, e in hello.items() if k[:3] not in http and k in closed and closed[k]['t'] >= e['t'] and e['t'] < now - 30]
        if len(incomplete) >= 5:
            add('tls_closed_without_visible_http', src, incomplete, '>=5 TLS ClientHello connections closed with no matching visible HTTP after >=30s; access_log off/non-HTTP transports may explain this')
    for prefix, rows in prefixes.items():
        if len({e['src'] for e in rows}) >= 8 and len({e['dport'] for e in rows}) >= 20 and len({e['node'] for e in rows}) >= 2:
            unique = {flowkey(e): e for e in rows}
            add('prefix_scan_pattern', prefix, list(unique.values()), '>=8 source IPs in one prefix, >=20 destination ports and >=2 nodes in 5 minutes; grouping does not establish common ownership', 'scan_pattern')
    return findings


def select_evidence(events, findings, now):
    """Preserve full matching compact events, not only the eight report examples."""
    by_source = collections.defaultdict(list)
    by_prefix = {}
    for f in findings:
        if f['rule'] == 'prefix_scan_pattern':
            by_prefix[f['key']] = f['rule']
        elif f['rule'] != 'multi_node_contact':
            by_source[f['key']].append(f['rule'])
    for e in events:
        if e['t'] < now - 300:
            continue
        rules = list(by_source.get(e['src'], []))
        if e['kind'] == 'tls_hello' and ('client_hello' in e or 'client_hello_ref' in e):
            # Retain the structure before a short TLS series reaches any
            # heuristic threshold; this is evidence retention, not an alert.
            rules.append('client_hello_structure')
        if e['kind'] == 'syn':
            if ':' in e['src']:
                prefix = str(ipaddress.ip_network(e['src'] + '/48', strict=False))
            else:
                prefix = e['src'].rsplit('.', 1)[0] + '.0/24'
            if prefix in by_prefix:
                rules.append(by_prefix[prefix])
        if rules:
            yield e, sorted(rules)


class Output:
    def __init__(self, directory, budget=256 * 1024 * 1024):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        self.budget = budget

    def append(self, kind, data):
        suffix = dt.datetime.now(UTC).strftime('%Y%m%dT%H')
        p = self.directory / (kind + '-' + suffix + '.jsonl')
        with open(p, 'a') as f:
            os.chmod(p, 0o600)
            f.write(json.dumps(data, ensure_ascii=False, separators=(',', ':')) + '\n')

    def trim(self):
        files = sorted(self.directory.glob('*.jsonl'), key=lambda p: p.stat().st_mtime)
        size = sum(p.stat().st_size for p in files)
        for p in files:
            if size <= self.budget and time.time() - p.stat().st_mtime < 14 * 86400:
                break
            size -= p.stat().st_size
            p.unlink()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--config', required=True)
    args = ap.parse_args()
    cfg = json.load(open(args.config))
    output = Output(cfg['output_dir'])
    state_path = output.directory / 'cursor.json'
    state = json.load(open(state_path)) if state_path.exists() else {}
    # On restart only unread log bytes are replayed; the previous analysis window
    # is restored so TLS/HTTP and multi-node correlation survive process restarts.
    state_events = output.directory / 'window.json'
    events = collections.deque(json.load(open(state_events)) if state_events.exists() else [], maxlen=80000)
    reader = JournalReader(cfg['log_dir'], state, time.time() - 900)
    known = set(cfg['known_sources'])
    local_ips = set(cfg['local_ips'])
    counters = collections.Counter(state.get('counters', {}))
    heartbeats = state.get('heartbeats', {})
    emitted = state.get('emitted', {})
    evidence_saved = state.get('evidence_saved', {})
    cycles = state.get('cycles', 0)
    stop = False

    def stopping(*_):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGTERM, stopping)
    signal.signal(signal.SIGINT, stopping)

    def consume(d):
        counters['records_read'] += 1
        if d.get('event') == 'heartbeat':
            heartbeats[d['node']] = {'at': d['observed_utc'], 'sensors': d.get('sensors', {}), 'counters': d.get('counters', {})}
            return
        event, category = normalize(d, known, local_ips)
        counters[category] += 1
        if event:
            if len(events) == events.maxlen:
                counters['window_capacity_evicted'] += 1
            events.append(event)

    while not stop:
        started = time.monotonic()
        started_at = time.time()
        previous = counters.copy()
        try:
            reader.poll(consume)
            now = time.time()
            # Arrival order can differ from packet timestamp order.
            events = collections.deque((e for e in events if e['t'] >= now - 900), maxlen=80000)
            findings = detect(events, now)
            new_evidence = 0
            for event, rules in select_evidence(events, findings, now):
                evidence_id = hashlib.sha256(json.dumps(event, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
                if evidence_id not in evidence_saved:
                    output.append('evidence', {'analysis_version': VERSION, 'evidence_id': evidence_id,
                        'saved_utc': stamp(now), 'event_utc': stamp(event['t']),
                        'event_bangkok': localstamp(event['t']), 'detection_rules': rules, **event})
                    evidence_saved[evidence_id] = event['t']
                    new_evidence += 1
            evidence_saved = {k: v for k, v in evidence_saved.items() if v >= now - 900}
            counters['evidence_records_written'] += new_evidence
            for finding in findings:
                key = finding['rule'] + ':' + finding['key']
                old = emitted.get(key, {})
                signature = hashlib.sha256(json.dumps({k: finding[k] for k in ('event_count', 'nodes', 'ports', 'paths', 'sni', 'ja3')}, sort_keys=True).encode()).hexdigest()
                if now - old.get('at', 0) >= 60 and signature != old.get('signature'):
                    output.append('findings', {'analysis_version': VERSION, 'analyzed_utc': stamp(now), **finding})
                    emitted[key] = {'at': now, 'signature': signature}
            emitted = {k: v for k, v in emitted.items() if now - v['at'] < 86400}
            per_node = collections.defaultdict(collections.Counter)
            for e in events:
                if e['t'] >= now - 15:
                    per_node[e['node']][e['kind']] += 1
            stale = sorted(n for n in cfg['expected_nodes'] if n not in heartbeats or now - dt.datetime.fromisoformat(heartbeats[n]['at']).timestamp() > 90)
            bad_sensors = {n: [k for k, v in h['sensors'].items() if not v] for n, h in heartbeats.items() if any(not v for v in h['sensors'].values())}
            cycles += 1
            summary = {'at_utc': stamp(now), 'at_bangkok': localstamp(now), 'interval_seconds': 15,
                'cycle_started_utc': stamp(started_at), 'analysis_version': VERSION,
                'cycles': cycles, 'cycle_processing_seconds': round(time.monotonic() - started, 3),
                'records_read': counters['records_read'], 'external_window_records': len(events),
                'new_records': counters['records_read'] - previous['records_read'],
                'new_external': counters['external'] - previous['external'],
                'new_evidence_records': new_evidence,
                'evidence_records_written': counters['evidence_records_written'],
                'known_monitor_records_excluded': counters['known_monitor_or_private'],
                'reader_errors': dict(reader.errors), 'window_capacity_evicted': counters['window_capacity_evicted'],
                'stale_collectors': stale, 'bad_sensors': bad_sensors,
                'collector_loss_counters': {n: {k: v for k, v in h['counters'].items() if v and re.search(r'dropped|overruns|errors', k)} for n, h in heartbeats.items() if any(v and re.search(r'dropped|overruns|errors', k) for k, v in h['counters'].items())},
                'per_node_last_15s': dict(per_node), 'active_candidates': len(findings),
                'rules': dict(collections.Counter(f['rule'] for f in findings)),
                'recent_candidates': sorted(findings, key=lambda f: (f['assessment'] == 'scan_pattern', f['event_count']), reverse=True)[:50],
                'limitations': ['Candidates are not proof of identity or causation', f"{len(cfg['expected_nodes'])} collectors; retired nodes excluded by expected inventory", 'Central UDP delivery is best effort; oversized ClientHello details referenced to local journals', 'ClientHello structure has explicit completeness flags; fragmented first segments are not full handshakes', 'Missing HTTP can reflect disabled access logging or non-HTTP VPN protocols']}
            output.append('windows', {k: v for k, v in summary.items() if k != 'recent_candidates'})
            atomic(output.directory / 'summary.json', summary)
            atomic(state_events, list(events))
            state.update(counters=dict(counters), heartbeats=heartbeats, emitted=emitted, evidence_saved=evidence_saved, cycles=cycles)
            atomic(state_path, state)
            output.trim()
        except Exception as exc:
            output.append('errors', {'at_utc': stamp(time.time()), 'error_type': type(exc).__name__, 'message': str(exc)[:300]})
            raise
        remaining = 15 - (time.monotonic() - started)
        # Sleep in small steps to honor a stop without a 15-second delay.
        deadline = time.monotonic() + max(0.1, remaining)
        while not stop and time.monotonic() < deadline:
            time.sleep(min(0.5, max(0, deadline - time.monotonic())))


if __name__ == '__main__':
    os.umask(0o077)
    main()
