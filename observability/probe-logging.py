#!/usr/bin/python3
"""Bounded, metadata-only edge evidence. Never writes packets or VPN payloads."""
import collections
import csv
import ctypes as C
import ctypes.util
import datetime as dt
import gzip
import grp
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import queue
import re
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='milliseconds')


def capture_drops(line):
    match = re.search(r'(\d+) packets dropped by kernel', line)
    return int(match[1]) if match else 0


def clean_path(value):
    value = str(value).split('?', 1)[0].split('#', 1)[0]
    value = re.sub(r'(?i)(https?://)[^/@\s]+@', r'\1[redacted]@', value)
    value = re.sub(r'(?i)(/(?:sub|subscription|webhook|token|invite|reset|connect|addlink)/)[^ /"<>]+', r'\1[redacted]', value)
    value = re.sub(r'[a-fA-F0-9]{8}-[a-fA-F0-9-]{27,}', '[uuid]', value)
    value = re.sub(r'(?<=/)[A-Za-z0-9_+%=.-]{24,}', '[id]', value)
    return value[:512]


def clean_message(value):
    # Strip URL queries and credential-bearing paths before any persistence.
    value = re.sub(r'\?[^\s"<>]*', '?[redacted]', str(value))
    value = re.sub(r'(?i)(https?://)[^/@\s]+@', r'\1[redacted]@', value)
    value = re.sub(r'(?i)(/(?:sub|subscription|webhook|token|invite|reset|connect|addlink)/)[^ /"<>]+', r'\1[redacted]', value)
    value = re.sub(r'[a-fA-F0-9]{8}-[a-fA-F0-9-]{27,}', '[uuid]', value)
    value = re.sub(r'(?i)((?:token|password|authorization|secret)[=: ]+)[^ ,;"<>]+', r'\1[redacted]', value)
    return value[:1600]


HTTP_FIELDS = {'event', 'epoch', 'client', 'peer', 'client_port', 'server', 'port',
               'connection', 'connection_requests', 'host', 'sni', 'tls', 'cipher',
               'uri', 'status', 'request_bytes', 'response_bytes', 'seconds', 'user_agent'}


def nginx_event(line):
    # Match the first actual syslog tag, before examining request-controlled text.
    tag = re.search(r'(?:^| )qntw_(http|error): ?', line)
    if not tag:
        return None
    payload = line[tag.end():]
    if tag[1] == 'error':
        return {'event': 'nginx_error', 'message': clean_message(payload)}
    d = json.loads(payload)
    if not isinstance(d, dict) or d.get('event') != 'http':
        raise ValueError('invalid HTTP log object')
    if any(not isinstance(value, str) for value in d.values()):
        raise ValueError('HTTP fields must be strings')
    for key in ('client', 'peer', 'server'):
        if d.get(key):
            ipaddress.ip_address(d[key])
    request = d.get('request', '')
    pieces = request.split(' ')
    result = {k: str(v)[:512] for k, v in d.items() if k in HTTP_FIELDS}
    if len(pieces) >= 2:
        result['request_line'] = pieces[0][:40] + ' ' + clean_path(pieces[1])
    else:
        result['request_line'] = clean_message(request)[:120]
    result['uri'] = clean_path(d.get('uri', ''))
    return result


def nginx_sender_allowed(credentials, executable):
    """Authenticate the kernel supplied sender, including shared web UIDs."""
    pid, uid, _ = credentials
    if uid == 0:
        return True
    try:
        expected = os.stat(executable)
        with open('/proc/%d/status' % pid) as source:
            status = dict(line.rstrip().split(':', 1) for line in source if ':' in line)
        if int(status['Uid'].split()[1]) != uid:
            return False
        parent = int(status['PPid'].strip())
        master = os.stat('/proc/%d/exe' % parent)
        with open('/proc/%d/status' % parent) as source:
            parent_status = dict(line.rstrip().split(':', 1) for line in source if ':' in line)
        identity = (expected.st_dev, expected.st_ino)
        # An arbitrary user can run the nginx binary with their own config.
        # Only workers of a root-owned nginx master supply enforcement input.
        return (stat.S_ISREG(expected.st_mode) and expected.st_uid == 0
                and not expected.st_mode & 0o022
                and identity == (master.st_dev, master.st_ino)
                and int(parent_status['Uid'].split()[1]) == 0)
    except (OSError, ValueError, KeyError, IndexError):
        return False


def nginx_socket_group(cfg):
    if 'nginx_socket_gid' in cfg:
        gid = cfg['nginx_socket_gid']
        if isinstance(gid, bool) or not isinstance(gid, int) or not 0 <= gid <= 0xffffffff:
            raise ValueError('invalid nginx_socket_gid')
        return gid
    for name in ('www-data', 'nginx'):
        try:
            return grp.getgrnam(name).gr_gid
        except KeyError:
            pass
    return 0


HUB_REPLAY_CAPACITY = 32768


def hub_event(raw, address, peers):
    """Reject untrusted shapes before indexing or authenticating their contents."""
    if len(raw) > 16000:
        raise ValueError('oversized hub record')
    d = json.loads(raw)
    if not isinstance(d, dict) or not isinstance(d.get('node'), str):
        raise ValueError('invalid hub object')
    peer = peers.get(d['node'])
    if not peer or address != peer['mesh_ip']:
        return None
    signature = d.pop('signature', None)
    if not isinstance(signature, str) or not re.fullmatch(r'[0-9a-f]{64}', signature):
        return None
    check = hmac.new(peer['key'].encode(), json.dumps(d, sort_keys=True, separators=(',', ':')).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, check):
        return None
    event, observed = d.get('event'), d.get('observed_utc')
    if not isinstance(event, str) or not re.fullmatch(r'[a-z_]{1,64}', event):
        raise ValueError('invalid hub event')
    if not isinstance(observed, str) or len(observed) > 64:
        raise ValueError('invalid hub timestamp')
    at = dt.datetime.fromisoformat(observed)
    if at.tzinfo is None or not time.time() - 90 <= at.timestamp() <= time.time() + 5:
        raise ValueError('hub timestamp is stale or invalid')
    # Fields consumed by the analyzer are typed before crossing its trust boundary.
    for key in ('src', 'client', 'dst', 'message', 'flags'):
        if key in d and not isinstance(d[key], str):
            raise ValueError('invalid hub field')
    for key in ('sensors', 'counters'):
        if key in d and (not isinstance(d[key], dict) or any(
                not isinstance(k, str) or not isinstance(v, (int, float))
                for k, v in d[key].items())):
            raise ValueError('invalid hub health')
    return d


def conntrack_event(line, local):
    event = re.search(r'\[(NEW|UPDATE|DESTROY)\]', line)
    proto = re.search(r'\b(tcp|udp|icmp|icmpv6)\b', line)
    if not event or not proto:
        return None
    original = {}
    for key, value in re.findall(r'\b(src|dst|sport|dport)=([^\s]+)', line):
        original.setdefault(key, value)
    if original.get('dst') not in local:
        return None  # Do not record the destinations of customers' egress.
    state = re.search(r'\b(SYN_SENT|SYN_RECV|ESTABLISHED|FIN_WAIT|CLOSE_WAIT|LAST_ACK|TIME_WAIT|CLOSE)\b', line)
    return {'event': 'flow', 'change': event[1], 'protocol': proto[1],
            **original, 'state': state[1] if state else '',
            'source_time': line.partition(']')[0].lstrip('[')[:60],
            'assured': '[ASSURED]' in line, 'unreplied': '[UNREPLIED]' in line}


class Ring:
    """Compressed UTC files, bounded both by age and bytes, private to root."""
    def __init__(self, directory, budget):
        self.directory, self.budget = directory, budget
        os.makedirs(directory, mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)
        self.path = directory + '/events.jsonl'
        self.file = open(self.path, 'ab', buffering=0)
        os.chmod(self.path, 0o600)
        self.size = os.path.getsize(self.path)
        self.rotated = time.time()
        self.trim()

    def trim(self):
        files = sorted((e for e in os.scandir(self.directory)
                        if e.name.startswith('events-') and e.name.endswith('.jsonl.gz')),
                       key=lambda e: e.name)
        size = sum(e.stat().st_size for e in files) + self.size
        for e in files:
            if size <= self.budget and time.time() - e.stat().st_mtime < 7 * 86400:
                break
            size -= e.stat().st_size
            os.unlink(e.path)

    def write(self, event):
        data = (json.dumps(event, ensure_ascii=True, separators=(',', ':')) + '\n').encode()
        if self.size + len(data) > 16 * 1024 * 1024 or (self.size and time.time() - self.rotated > 3600):
            self.file.close()
            name = self.directory + '/events-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + str(time.time_ns()) + '.jsonl.gz'
            with open(self.path, 'rb') as source, gzip.open(name + '.tmp', 'wb', compresslevel=1) as target:
                shutil.copyfileobj(source, target)
            os.chmod(name + '.tmp', 0o600)
            os.replace(name + '.tmp', name)
            self.file = open(self.path, 'wb', buffering=0)
            os.chmod(self.path, 0o600)
            self.size = 0
            self.rotated = time.time()
            self.trim()
        self.file.write(data)
        self.size += len(data)


FIELDS = ['frame.time_epoch', 'ip.src', 'ipv6.src', 'ip.dst', 'ipv6.dst',
          'tcp.srcport', 'tcp.dstport', 'tcp.flags', 'tcp.len',
          'tls.handshake.type', 'tls.handshake.extensions_server_name',
          'tls.handshake.ja3', 'tls.handshake.extensions_alpn_str',
          'tls.handshake.version', 'icmp.type', 'icmp.code', 'icmpv6.type', 'icmpv6.code']

# Ordered, non-secret ClientHello parameters only. Never request randoms,
# session IDs/tickets, PSK identities/binders, key bytes or the ECH payload.
HELLO_LIST_FIELDS = {
    'record_versions': 'tls.record.version',
    'record_lengths': 'tls.record.length',
    'handshake_lengths': 'tls.handshake.length',
    'cipher_suites': 'tls.handshake.ciphersuite',
    'extension_types': 'tls.handshake.extension.type',
    'extension_lengths': 'tls.handshake.extension.len',
    'supported_groups': 'tls.handshake.extensions_supported_group',
    'ec_point_formats': 'tls.handshake.extensions_ec_point_format',
    'signature_algorithms': 'tls.handshake.sig_hash_alg',
    'supported_versions': 'tls.handshake.extensions.supported_version',
    'key_share_groups': 'tls.handshake.extensions_key_share_group',
    'compression_methods': 'tls.handshake.comp_method',
    'psk_key_exchange_modes': 'tls.extension.psk_ke_mode',
    'certificate_compression_algorithms': 'tls.compress_certificate.algorithm',
}
HELLO_SCALAR_FIELDS = {
    'cipher_suites_length': 'tls.handshake.cipher_suites_length',
    'compression_methods_length': 'tls.handshake.comp_methods_length',
    'extensions_length': 'tls.handshake.extensions_length',
    'session_id_length': 'tls.handshake.session_id_length',
    'frame_captured_length': 'frame.cap_len',
    'frame_wire_length': 'frame.len',
}
FIELDS += list(HELLO_LIST_FIELDS.values()) + list(HELLO_SCALAR_FIELDS.values()) + ['tls.handshake.ja3_full']
FIELDS += ['tls.record.content_type', 'tls.alert_message.level', 'tls.alert_message.desc']


def hello_structure(row):
    """Keep on-wire order and GREASE; JA3's canonical string excludes GREASE."""
    result = {'schema': 1}
    reasons = []
    for key, field in HELLO_LIST_FIELDS.items():
        values = [v for v in row.get(field, '').split(',') if v]
        if len(values) > 8192:
            reasons.append('field_limit:' + key)
        try:
            result[key] = [int(v, 16 if v.lower().startswith('0x') else 10) for v in values[:8192]]
        except ValueError:
            result[key] = []
            reasons.append('invalid_field:' + key)
    for key, field in HELLO_SCALAR_FIELDS.items():
        try:
            result[key] = int(row.get(field, '').split(',')[0])
        except ValueError:
            result[key] = None
    full = row.get('tls.handshake.ja3_full', '')
    result['ja3_full'] = full[:65536]
    if len(full) > 65536:
        reasons.append('field_limit:ja3_full')
    result['legacy_version'] = row.get('tls.handshake.version', '').split(',')[0]
    result['alpn_protocols'] = row.get('tls.handshake.extensions_alpn_str', '').split(',') if row.get('tls.handshake.extensions_alpn_str') else []
    # Reassembly stays disabled: explicitly label a first segment/record that
    # doesn't contain the entire hello, rather than invent missing parameters.
    try:
        tcp_bytes = int(row.get('tcp.len') or 0)
    except ValueError:
        tcp_bytes = 0
    if result['frame_captured_length'] is None or result['frame_captured_length'] != result['frame_wire_length']:
        reasons.append('capture_truncated')
    if len(result['handshake_lengths']) != 1 or not result['record_lengths']:
        reasons.append('multiple_or_missing_records')
    elif (result['record_lengths'][0] + 5 > tcp_bytes or
          result['handshake_lengths'][0] + 4 > result['record_lengths'][0]):
        reasons.append('fragmented_or_incomplete')
    if result['cipher_suites_length'] != 2 * len(result['cipher_suites']):
        reasons.append('incomplete_cipher_suites')
    if result['compression_methods_length'] != len(result['compression_methods']):
        reasons.append('incomplete_compression_methods')
    if len(result['extension_types']) != len(result['extension_lengths']):
        reasons.append('incomplete_extensions')
    if result['extension_types'] and result['extensions_length'] != sum(result['extension_lengths']) + 4 * len(result['extension_types']):
        reasons.append('incomplete_extensions_length')
    digest = hashlib.md5(full.encode()).hexdigest() if full else None
    result['ja3_matches'] = digest == row.get('tls.handshake.ja3') if digest else None
    if result['ja3_matches'] is not True:
        reasons.append('missing_or_mismatching_ja3')
    result['complete'] = not reasons
    result['incomplete_reasons'] = sorted(set(reasons))
    return result


def tls_response_structure(row):
    """Public plaintext TLS parameters only; no keys, certificates or payloads.

    In TLS 1.3, ServerHello is plaintext but the subsequent handshake/alerts
    are encrypted. A ServerHello (including HelloRetryRequest) is not proof
    that the handshake completed, nor that the remote peer received it.
    """
    fields = {
        'record_types': 'tls.record.content_type',
        'record_versions': 'tls.record.version',
        'record_lengths': 'tls.record.length',
        'handshake_types': 'tls.handshake.type',
        'handshake_lengths': 'tls.handshake.length',
        'cipher_suites': 'tls.handshake.ciphersuite',
        'extension_types': 'tls.handshake.extension.type',
        'extension_lengths': 'tls.handshake.extension.len',
        'key_share_groups': 'tls.handshake.extensions_key_share_group',
        'alert_levels': 'tls.alert_message.level',
        'alert_descriptions': 'tls.alert_message.desc',
    }
    result = {'schema': 1, 'visibility': 'plaintext_tls_only'}
    for key, field in fields.items():
        values = row.get(field, '').split(',')
        try:
            result[key] = [int(v, 16 if v.lower().startswith('0x') else 10)
                           for v in values[:256] if v]
        except ValueError:
            result[key] = []
    result['legacy_version'] = row.get('tls.handshake.version', '').split(',')[0]
    result['selected_version'] = ''
    result['alpn_protocols'] = row.get('tls.handshake.extensions_alpn_str', '')[:512].split(',') if row.get('tls.handshake.extensions_alpn_str') else []
    for key, field in [('frame_captured_length', 'frame.cap_len'), ('frame_wire_length', 'frame.len')]:
        try:
            result[key] = int(row.get(field, '').split(',')[0])
        except ValueError:
            result[key] = None
    result['capture_truncated'] = (result['frame_captured_length'] is None or
                                    result['frame_captured_length'] != result['frame_wire_length'])
    try:
        tcp_length = int(row.get('tcp.len') or 0)
    except ValueError:
        tcp_length = 0
    complete = (not result['capture_truncated'] and bool(result['record_lengths']) and
                bool(result['handshake_lengths']) and
                result['record_lengths'][0] + 5 <= tcp_length and
                result['handshake_lengths'][0] + 4 <= result['record_lengths'][0])
    result['server_hello_message_complete'] = bool(2 in result['handshake_types'] and complete)
    if 2 in result['handshake_types']:
        # TLS 1.3 keeps legacy_version=0303. Missing supported_versions in a
        # partial message is NOT evidence that the server selected TLS 1.2.
        selected = row.get('tls.handshake.extensions.supported_version', '').split(',')[0]
        result['selected_version'] = selected or (result['legacy_version'] if complete else '')
    result['scope'] = 'first_record_per_segment_no_tcp_reassembly'
    return result


def packet_filter(local):
    hosts = ' or '.join('host ' + str(ipaddress.ip_address(x)) for x in local)
    incoming = '(' + ' or '.join('dst host ' + str(ipaddress.ip_address(x)) for x in local) + ')'
    outgoing = '(' + ' or '.join('src host ' + str(ipaddress.ip_address(x)) for x in local) + ')'
    # Incoming ClientHello remains visible before ingress DROP. Outgoing
    # plaintext handshake/alert is observed at the public interface after
    # postrouting DROP. Never select standalone application records (type 23)
    # or outgoing ClientHello; coalesced encrypted records may share a packet.
    v4 = 'tcp[((tcp[12]&240)>>2)]'
    v4_type = 'tcp[((tcp[12]&240)>>2)+5]'
    v6 = 'ip6[40+((ip6[52]&240)>>2)]'
    v6_type = 'ip6[45+((ip6[52]&240)>>2)]'
    ipv4 = '(ip and tcp and ((tcp[13] & 7 != 0) or (' + incoming + ' and ' + v4 + ' = 22 and ' + v4_type + ' = 1) or (' + outgoing + ' and (' + v4 + ' = 21 or (' + v4 + ' = 22 and ' + v4_type + ' != 1)))))'
    ipv6 = '(ip6 and ip6[6] = 6 and ((ip6[53] & 7 != 0) or (' + incoming + ' and ' + v6 + ' = 22 and ' + v6_type + ' = 1) or (' + outgoing + ' and (' + v6 + ' = 21 or (' + v6 + ' = 22 and ' + v6_type + ' != 1)))))'
    return '(' + hosts + ') and (' + ipv4 + ' or ' + ipv6 + ' or icmp or icmp6)'


class Collector:
    def __init__(self, cfg):
        self.cfg = cfg
        self.local = set(cfg['local_ips'])
        self.events = queue.Queue(8192)
        self.stop = threading.Event()
        self.counts = collections.Counter()
        self.health = {}
        self.children = []
        self.ring = Ring(cfg['log_dir'], cfg.get('budget_bytes', 512 * 1024 * 1024))
        self.sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.last_remote = {}

    def emit(self, d):
        if not d:
            return
        d = {**d, 'observed_utc': utc(), 'node': self.cfg['node']}
        try:
            self.events.put_nowait(d)
        except queue.Full:
            self.counts['queue_dropped'] += 1

    def process(self, name, args, decode, capture_args=None):
        while not self.stop.is_set():
            children = []
            try:
                def errors(child, label):
                    dropped_before = 0
                    for line in child.stderr:
                        if isinstance(line, bytes):
                            line = line.decode(errors='replace')
                        if 'ENOBUFS' in line:
                            self.counts[label + '_kernel_overruns'] += 1
                        dropped_now = capture_drops(line)
                        if dropped_now > dropped_before:
                            self.counts[label + '_kernel_dropped_packets'] += dropped_now - dropped_before
                            dropped_before = dropped_now
                        self.emit({'event': 'sensor_notice', 'sensor': label, 'message': clean_message(line)})
                capture = None
                if capture_args:
                    capture = subprocess.Popen(capture_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    children.append(capture)
                    self.children.append(capture)
                    threading.Thread(target=errors, args=(capture, 'capture'), daemon=True).start()
                    def statistics(child):
                        while not self.stop.wait(15) and child.poll() is None:
                            try:
                                child.send_signal(signal.SIGUSR1)
                            except ProcessLookupError:
                                return
                    threading.Thread(target=statistics, args=(capture,), daemon=True).start()
                p = subprocess.Popen(args, stdin=capture.stdout if capture else None,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
                if capture:
                    capture.stdout.close()
                children.append(p)
                self.children.append(p)
                self.health[name] = 1
                threading.Thread(target=errors, args=(p, name), daemon=True).start()
                for line in p.stdout:
                    try:
                        self.emit(decode(line))
                    except (ValueError, KeyError, IndexError, TypeError):
                        self.counts[name + '_parse_dropped'] += 1
                    if self.stop.is_set():
                        break
                p.wait()
                self.emit({'event': 'sensor_exit', 'sensor': name, 'code': p.returncode})
            except OSError as e:
                self.emit({'event': 'sensor_error', 'sensor': name, 'message': str(e)[:300]})
            finally:
                for child in children:
                    if child.poll() is None:
                        child.terminate()
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        child.kill()
                    if child in self.children:
                        self.children.remove(child)
            self.health[name] = 0
            self.stop.wait(5)

    def packet(self, line):
        values = next(csv.reader([line.rstrip('\n')], delimiter='\t', quotechar='"'))
        row = dict(zip(FIELDS, values))
        src, dst = row.get('ip.src') or row.get('ipv6.src'), row.get('ip.dst') or row.get('ipv6.dst')
        if not src or not dst:
            return None
        flags = int(row.get('tcp.flags') or '0', 16)
        hello = '1' in row.get('tls.handshake.type', '').split(',')
        if row.get('tcp.srcport'):
            inbound = dst in self.local
            ports = set(self.cfg.get('listen_ports', []))
            if not inbound and not (src in self.local and int(row['tcp.srcport']) in ports):
                return None
            # Ignore inbound replies to unrelated outgoing customer connections.
            if inbound and not (flags & 2 and not flags & 16) and int(row.get('tcp.dstport') or 0) not in ports:
                return None
            d = {'event': 'tls_hello' if hello else 'tcp', 'epoch': row.get('frame.time_epoch'),
                 'src': src, 'dst': dst, 'sport': row['tcp.srcport'], 'dport': row['tcp.dstport'],
                 'flags': row.get('tcp.flags'), 'length': row.get('tcp.len')}
            d['direction'] = 'ingress' if inbound else 'egress'
            d['capture_point'] = ('public_interface_ingress_before_netfilter' if inbound
                                  else 'public_interface_egress_after_netfilter')
            d['connection'] = {'client_ip': src if inbound else dst,
                               'client_port': row['tcp.srcport'] if inbound else row['tcp.dstport'],
                               'server_ip': dst if inbound else src,
                               'server_port': row['tcp.dstport'] if inbound else row['tcp.srcport']}
            if not inbound and (row.get('tls.record.content_type') or row.get('tls.handshake.type')
                                or row.get('tls.alert_message.desc')):
                d['event'] = 'tls_response'
                d['response'] = tls_response_structure(row)
                d['remote_receipt_confirmed'] = False
                return d
            if hello:
                d.update(sni=row.get('tls.handshake.extensions_server_name', '')[:255],
                         ja3=row.get('tls.handshake.ja3', ''), alpn=row.get('tls.handshake.extensions_alpn_str', '')[:100],
                         tls_version=row.get('tls.handshake.version', ''))
                if src not in set(self.cfg.get('hello_detail_exclude_sources', [])):
                    d['client_hello'] = hello_structure(row)
                else:
                    d['client_hello_details_omitted'] = 'known_monitor'
            return d
        if row.get('icmp.type') or row.get('icmpv6.type'):
            return {'event': 'icmp', 'epoch': row.get('frame.time_epoch'), 'src': src, 'dst': dst,
                    'type': row.get('icmp.type') or row.get('icmpv6.type'),
                    'code': row.get('icmp.code') or row.get('icmpv6.code')}
        return None

    def nginx(self, path='/run/vpnshop-probes/nginx.sock'):
        executable = self.cfg.get('nginx_executable', '/usr/sbin/nginx')
        while not self.stop.is_set():
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            try:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                sock.bind(path)
                os.chown(path, 0, nginx_socket_group(self.cfg))
                os.chmod(path, 0o660)
                sock.settimeout(1)
                self.health['nginx_receiver'] = 1
                while not self.stop.is_set():
                    try:
                        data, ancillary, flags, _ = sock.recvmsg(65535, socket.CMSG_SPACE(12))
                        credentials = [struct.unpack('3i', value[:12]) for level, kind, value in ancillary
                                       if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS
                                       and len(value) >= 12]
                        if (flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(credentials) != 1
                                or not nginx_sender_allowed(credentials[0], executable)):
                            self.counts['nginx_rejected'] += 1
                            continue
                        self.emit(nginx_event(data.decode(errors='replace')))
                    except socket.timeout:
                        pass
                    except (ValueError, TypeError, RecursionError):
                        self.counts['nginx_parse_dropped'] += 1
            except OSError as exc:
                self.counts['nginx_receiver_errors'] += 1
                self.emit({'event': 'sensor_error', 'sensor': 'nginx_receiver', 'message': str(exc)[:300]})
            finally:
                self.health['nginx_receiver'] = 0
                sock.close()
            self.stop.wait(2)

    def journal(self, line):
        d = json.loads(line)
        return {'event': 'service', 'unit': d.get('_SYSTEMD_UNIT', ''),
                'journal_us': d.get('__REALTIME_TIMESTAMP', ''),
                'message': clean_message(d.get('MESSAGE', ''))}

    def kernel_flows(self):
        # libnetfilter_conntrack compiles a socket BPF filter. Unlike CLI -d,
        # irrelevant events are discarded BEFORE the netlink receive buffer.
        # This changes only our observer socket, never firewall/conntrack state.
        class IPv4(C.Structure):
            _fields_ = [('addr', C.c_uint32), ('mask', C.c_uint32)]
        class IPv6(C.Structure):
            _fields_ = [('addr', C.c_uint32 * 4), ('mask', C.c_uint32 * 4)]
        callback_type = C.CFUNCTYPE(C.c_int, C.c_uint, C.c_void_p, C.c_void_p)
        lib = C.CDLL(ctypes.util.find_library('netfilter_conntrack') or 'libnetfilter_conntrack.so.3', use_errno=True)
        declarations = {
            'nfct_open': ([C.c_uint8, C.c_uint], C.c_void_p),
            'nfct_close': ([C.c_void_p], C.c_int),
            'nfct_fd': ([C.c_void_p], C.c_int),
            'nfct_filter_create': ([], C.c_void_p),
            'nfct_filter_destroy': ([C.c_void_p], None),
            'nfct_filter_add_attr': ([C.c_void_p, C.c_int, C.c_void_p], None),
            'nfct_filter_set_logic': ([C.c_void_p, C.c_int, C.c_int], C.c_int),
            'nfct_filter_attach': ([C.c_int, C.c_void_p], C.c_int),
            'nfct_callback_register': ([C.c_void_p, C.c_int, callback_type, C.c_void_p], C.c_int),
            'nfct_catch': ([C.c_void_p], C.c_int),
            'nfct_snprintf': ([C.c_void_p, C.c_uint, C.c_void_p, C.c_uint, C.c_uint, C.c_uint], C.c_int),
        }
        for name, (args, result) in declarations.items():
            getattr(lib, name).argtypes, getattr(lib, name).restype = args, result
        while not self.stop.is_set():
            handle = None
            try:
                handle = lib.nfct_open(1, 7)  # CONNTRACK; NEW | UPDATE | DESTROY
                if not handle:
                    raise OSError(C.get_errno(), 'nfct_open')
                fd = lib.nfct_fd(handle)
                duplicate = socket.socket(fileno=os.dup(fd))
                duplicate.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
                duplicate.close()
                filt = lib.nfct_filter_create()
                if not filt:
                    raise MemoryError('nfct_filter_create')
                try:
                    for version, attr, structure in [(4, 3, IPv4), (6, 5, IPv6)]:
                        addresses = [ipaddress.ip_address(x) for x in self.local if ipaddress.ip_address(x).version == version]
                        if not addresses:
                            value = structure()  # prefix /0, negative => exclude family
                            lib.nfct_filter_set_logic(filt, attr, 1)
                            lib.nfct_filter_add_attr(filt, attr, C.byref(value))
                        for address in addresses:
                            if version == 4:
                                value = IPv4(int(address), 0xffffffff)
                            else:
                                words = [(int(address) >> n) & 0xffffffff for n in (96, 64, 32, 0)]
                                value = IPv6((C.c_uint32 * 4)(*words), (C.c_uint32 * 4)(*[0xffffffff] * 4))
                            lib.nfct_filter_add_attr(filt, attr, C.byref(value))
                    if lib.nfct_filter_attach(fd, filt) != 0:
                        raise OSError(C.get_errno(), 'nfct_filter_attach')
                finally:
                    lib.nfct_filter_destroy(filt)
                buffer = C.create_string_buffer(4096)
                @callback_type
                def callback(kind, entry, unused):
                    try:
                        lib.nfct_snprintf(buffer, len(buffer), entry, kind, 0, 1)
                        label = {1: 'NEW', 2: 'UPDATE', 4: 'DESTROY'}.get(kind, 'UNKNOWN')
                        self.emit(conntrack_event('[' + utc() + '] [' + label + '] ' + buffer.value.decode(errors='replace'), self.local))
                    except Exception:
                        self.counts['flows_parse_dropped'] += 1
                    return 0 if self.stop.is_set() else 1
                if lib.nfct_callback_register(handle, 7, callback, None) != 0:
                    raise OSError(C.get_errno(), 'nfct_callback_register')
                self.health['flows'] = 1
                self.emit({'event': 'sensor_ready', 'sensor': 'flows', 'kernel_filter': 'original_destination'})
                if lib.nfct_catch(handle) < 0:
                    raise OSError(C.get_errno(), 'nfct_catch')
            except Exception as e:
                self.counts['flows_errors'] += 1
                if isinstance(e, OSError) and e.errno == 105:
                    self.counts['flows_kernel_overruns'] += 1
                self.emit({'event': 'sensor_error', 'sensor': 'flows', 'message': str(e)[:300]})
            finally:
                self.health['flows'] = 0
                if handle:
                    lib.nfct_close(handle)
            self.stop.wait(2)

    def hub(self):
        while not self.stop.is_set():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
                sock.bind((self.cfg['hub_bind'], 19014))
                sock.settimeout(1)
                self.health['hub'] = 1
                seen = collections.OrderedDict()
                while not self.stop.is_set():
                    try:
                        raw, addr = sock.recvfrom(16384)
                        digest = hashlib.sha256(raw).digest()
                        now = time.monotonic()
                        if digest in seen and now - seen[digest] <= 95:
                            self.counts['hub_replay_dropped'] += 1
                            continue
                        d = hub_event(raw, addr[0], self.cfg['peers'])
                        if d is None:
                            self.counts['hub_rejected'] += 1
                            continue
                        while seen and now - next(iter(seen.values())) > 95:
                            seen.popitem(last=False)
                        if len(seen) >= HUB_REPLAY_CAPACITY:
                            seen.popitem(last=False)
                            self.counts['hub_replay_cache_evicted'] += 1
                        seen[digest] = now
                        self.last_remote[d['node']] = time.time()
                        self.events.put_nowait({**d, 'received_utc': utc()})
                    except socket.timeout:
                        pass
                    except (ValueError, KeyError, TypeError, RecursionError, queue.Full):
                        self.counts['hub_parse_dropped'] += 1
            except OSError as exc:
                self.counts['hub_errors'] += 1
                self.emit({'event': 'sensor_error', 'sensor': 'hub', 'message': str(exc)[:300]})
            finally:
                self.health['hub'] = 0
                sock.close()
            self.stop.wait(2)

    def forward(self, d):
        if not self.cfg.get('hub_address'):
            return
        payload = dict(d)
        # Very large, unusual hellos stay complete in the local private ring;
        # forward a verifiable reference instead of silently losing the event.
        if 'client_hello' in payload and len(json.dumps(payload, separators=(',', ':')).encode()) > 15000:
            detail = payload.pop('client_hello')
            raw_detail = json.dumps(detail, sort_keys=True, separators=(',', ':')).encode()
            payload['client_hello_ref'] = {'sha256': hashlib.sha256(raw_detail).hexdigest(),
                                           'bytes': len(raw_detail), 'local_only': True}
            self.counts['hello_detail_local_only'] += 1
        payload['signature'] = hmac.new(self.cfg['key'].encode(), json.dumps(payload, sort_keys=True, separators=(',', ':')).encode(), hashlib.sha256).hexdigest()
        raw = json.dumps(payload, separators=(',', ':')).encode()
        if len(raw) > 16000:
            self.counts['forward_oversize'] += 1
            return
        try:
            self.sender.sendto(raw, (self.cfg['hub_address'], 19014))
        except OSError:
            self.counts['forward_errors'] += 1

    def metrics(self):
        lines = ['# HELP qntw_probe_logging_heartbeat_seconds Last collector heartbeat.',
                 '# TYPE qntw_probe_logging_heartbeat_seconds gauge',
                 'qntw_probe_logging_heartbeat_seconds ' + str(time.time())]
        for k, v in self.health.copy().items():
            lines.append('qntw_probe_logging_sensor_up{sensor="' + k + '"} ' + str(v))
        for k, v in self.counts.copy().items():
            lines.append('qntw_probe_logging_events_total{kind="' + k + '"} ' + str(v))
        for name in self.cfg.get('peers', {}):
            lines.append('qntw_probe_logging_last_remote_seconds{node="' + name + '"} ' + str(self.last_remote.get(name, 0)))
        path = '/var/lib/node_exporter/textfile/probe_logging.prom'
        if os.path.isdir(os.path.dirname(path)):
            with open(path + '.tmp', 'w') as f:
                f.write('\n'.join(lines) + '\n')
            os.chmod(path + '.tmp', 0o644)
            os.replace(path + '.tmp', path)

    def run(self):
        def start(fn, *args):
            threading.Thread(target=fn, args=args, daemon=True).start()
        start(self.nginx)
        if self.cfg.get('hub_bind'):
            start(self.hub)
        fields = sum((['-e', f] for f in FIELDS), [])
        # The dissector consumes an anonymous pipe as uid/gid 65534, with no
        # root privileges or access to root-only evidence / HMAC credentials.
        start(self.process, 'packets', ['setpriv', '--reuid=65534', '--regid=65534', '--clear-groups',
              'tshark', '-n', '-l', '-r', '-', '-M', '20000',
              '-o', 'tcp.desegment_tcp_streams:FALSE', '-o', 'tls.desegment_ssl_records:FALSE',
              '-T', 'fields', '-E', 'quote=d', '-E', 'occurrence=a', '-E', 'aggregator=,', *fields], self.packet,
              ['tcpdump', '-n', '-p', '-U', '-i', self.cfg['interface'], '-s', '16384', '-w', '-', packet_filter(self.local)])
        # Kernel events are filtered before persistence; only ORIGINAL ingress.
        start(self.kernel_flows)
        start(self.process, 'journal', ['journalctl', '-f', '-n', '0', '-q', '-o', 'json',
              '-u', 'ssh', '-u', 'sshd', '-u', 'xray', '-u', 'vpnshop-tinc', '-u', 'vpnshop-nodeagent'], self.journal)
        self.emit({'event': 'collector_start', 'version': 3, 'client_hello_schema': 1,
                   'tls_response_schema': 1, 'tls_response_visibility': 'plaintext_tls_only'})
        last = 0
        disk_ok = True
        while not self.stop.is_set():
            if time.monotonic() - last > 15:
                self.emit({'event': 'heartbeat', 'sensors': self.health.copy(), 'counters': self.counts.copy()})
                self.metrics()
                self.ring.trim()
                disk_ok = shutil.disk_usage(self.cfg['log_dir']).free > 1024 * 1024 * 1024
                self.health['disk'] = int(disk_ok)
                last = time.monotonic()
            try:
                d = self.events.get(timeout=1)
            except queue.Empty:
                continue
            if disk_ok:
                self.ring.write(d)
                self.counts[d.get('event', 'unknown')] += 1
            else:
                self.counts['disk_dropped'] += 1
            # Hub does not re-forward received records. Local copy is durable;
            # central UDP is best effort and does not block the traffic services.
            if 'received_utc' not in d:
                self.forward(d)
        for p in list(self.children):
            p.terminate()
        self.ring.file.close()


if __name__ == '__main__':
    os.umask(0o077)
    with open(sys.argv[1]) as source:
        cfg = json.load(source)
    collector = Collector(cfg)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: collector.stop.set())
    collector.run()
