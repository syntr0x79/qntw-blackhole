import importlib.util
import json
import os
import tempfile
import unittest
import hashlib
import csv
import io
import collections
import hmac
import socket
import struct
import threading
import time
import subprocess
import sys
from unittest import mock

spec = importlib.util.spec_from_file_location('probe_logging', os.path.join(os.path.dirname(__file__), 'probe-logging.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class EvidenceTests(unittest.TestCase):
    def hello_row(self):
        full = '771,4865-4866,43-10-11,29,0'
        return {'frame.time_epoch': '1000', 'ip.src': '198.51.100.2', 'ip.dst': '192.0.2.10',
                'tcp.srcport': '12345', 'tcp.dstport': '443', 'tcp.flags': '0x0018',
                'tcp.len': '200', 'tls.handshake.type': '1', 'tls.handshake.version': '0x0303',
                'tls.handshake.ja3': hashlib.md5(full.encode()).hexdigest(),
                'tls.handshake.ja3_full': full, 'tls.record.version': '0x0301',
                'tls.record.length': '195', 'tls.handshake.length': '191',
                'tls.handshake.ciphersuite': '0x0a0a,0x1301,0x1302',
                'tls.handshake.cipher_suites_length': '6',
                'tls.handshake.extension.type': '2570,43,10,11',
                'tls.handshake.extension.len': '0,5,4,2',
                'tls.handshake.extensions_length': '27',
                'tls.handshake.extensions_supported_group': '0x001d',
                'tls.handshake.extensions_ec_point_format': '0',
                'tls.handshake.extensions.supported_version': '0x0304,0x0303',
                'tls.handshake.comp_method': '0', 'tls.handshake.comp_methods_length': '1',
                'frame.cap_len': '254', 'frame.len': '254'}

    def test_wire_order_grease_full_ja3_and_versions_are_preserved(self):
        row = self.hello_row()
        d = m.hello_structure(row)
        self.assertTrue(d['complete'], d['incomplete_reasons'])
        self.assertEqual(d['cipher_suites'], [2570, 4865, 4866])
        self.assertEqual(d['extension_types'], [2570, 43, 10, 11])
        self.assertEqual(d['supported_versions'], [772, 771])
        self.assertEqual(d['ja3_full'], row['tls.handshake.ja3_full'])
        self.assertTrue(d['ja3_matches'])

    def test_fragmented_or_capture_truncated_hello_is_never_labelled_complete(self):
        for changed in [{'tcp.len': '100'}, {'frame.cap_len': '150'},
                        {'tls.handshake.cipher_suites_length': '20'},
                        {'tls.handshake.ja3': 'wrong'}]:
            d = m.hello_structure({**self.hello_row(), **changed})
            self.assertFalse(d['complete'])
            self.assertTrue(d['incomplete_reasons'])

    def test_packet_keeps_all_quoted_values_but_not_opaque_handshake_material(self):
        row = {**self.hello_row(), 'tls.handshake.random': 'private-random',
               'tls.handshake.session_id': 'private-session', 'tls.ech.payload': 'private-ech'}
        buffer = io.StringIO()
        csv.writer(buffer, delimiter='\t').writerow([row.get(k, '') for k in m.FIELDS])
        c = m.Collector.__new__(m.Collector)
        c.local = {'192.0.2.10'}
        c.cfg = {'listen_ports': [443]}
        event = c.packet(buffer.getvalue())
        self.assertEqual(event['client_hello']['cipher_suites'], [2570, 4865, 4866])
        self.assertNotIn('private-', json.dumps(event))
        c.cfg['hello_detail_exclude_sources'] = ['198.51.100.2']
        self.assertNotIn('client_hello', c.packet(buffer.getvalue()))

    def test_oversized_structure_forwards_reference_instead_of_losing_event(self):
        sent = []
        c = m.Collector.__new__(m.Collector)
        c.cfg = {'hub_address': '192.0.2.1', 'key': 'test-only'}
        c.counts = collections.Counter()
        c.sender = type('Sender', (), {'sendto': lambda _, raw, addr: sent.append(raw)})()
        event = {'event': 'tls_hello', 'client_hello': {'cipher_suites': list(range(8192))}}
        c.forward(event)
        record = json.loads(sent[0])
        self.assertNotIn('client_hello', record)
        self.assertTrue(record['client_hello_ref']['local_only'])
        self.assertIn('client_hello', event)  # Local journal retains the full data.
        self.assertLess(len(sent[0]), 16000)

    def test_live_capture_statistics_do_not_report_zero_as_loss(self):
        self.assertEqual(m.capture_drops('tcpdump: 13321 packets captured, 13372 packets received by filter, 0 packets dropped by kernel'), 0)
        self.assertEqual(m.capture_drops('tcpdump: 10 packets captured, 17 packets received by filter, 7 packets dropped by kernel'), 7)

    def test_credentials_do_not_reach_persistent_http_record(self):
        row = {'event': 'http', 'request': 'GET /sub/customer-secret?auth=never-store HTTP/2',
               'uri': '/sub/customer-secret', 'status': '200'}
        event = m.nginx_event('syslog qntw_http: ' + json.dumps(row, separators=(',', ':')))
        encoded = json.dumps(event)
        self.assertNotIn('customer-secret', encoded)
        self.assertNotIn('never-store', encoded)
        self.assertIn('[redacted]', encoded)

    def test_invalid_protocol_and_scanner_paths_are_useful(self):
        for request in ['SSH-2.0-Go', 'GET /owa/auth/x.js HTTP/1.1']:
            row = {'event': 'http', 'request': request, 'uri': '/owa/auth/x.js'}
            event = m.nginx_event('qntw_http: ' + json.dumps(row, separators=(',', ':')))
            self.assertIn(request.split(' HTTP/')[0], event['request_line'])

    def test_flow_direction_keeps_ingress_and_excludes_customer_egress(self):
        template = '[NEW] ipv4 2 udp 17 30 src={} dst={} sport=50000 dport=443 [UNREPLIED] src={} dst={} sport=443 dport=50000'
        local = {'192.0.2.10'}
        ingress = m.conntrack_event(template.format('198.51.100.2', '192.0.2.10', '192.0.2.10', '198.51.100.2'), local)
        self.assertEqual(ingress['src'], '198.51.100.2')
        self.assertEqual(ingress['dst'], '192.0.2.10')
        egress = m.conntrack_event(template.format('192.0.2.10', '198.51.100.2', '198.51.100.2', '192.0.2.10'), local)
        self.assertIsNone(egress)

    def test_error_query_and_token_path_are_redacted(self):
        event = m.nginx_event('qntw_error: client closed; request: "GET /sub/secret?token=hidden HTTP/1.1"')
        self.assertNotIn('/sub/secret', event['message'])
        self.assertNotIn('hidden', event['message'])

    def test_absolute_form_credentials_are_redacted(self):
        value = m.clean_path('http://user:private-password@example.test/check?secret=value')
        self.assertNotIn('private-password', value)
        self.assertNotIn('secret=value', value)
        self.assertIn('example.test/check', value)

    def test_ring_permissions_and_oldest_first_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            for i in range(3):
                with open(directory + '/events-000' + str(i) + '.jsonl.gz', 'wb') as f:
                    f.write(b'x' * 100)
            ring = m.Ring(directory, 210)
            ring.write({'event': 'test'})
            self.assertFalse(os.path.exists(directory + '/events-0000.jsonl.gz'))
            self.assertEqual(os.stat(ring.path).st_mode & 0o777, 0o600)
            ring.file.close()


class InputTrustTests(unittest.TestCase):
    def signed(self, **changes):
        d = {'event': 'heartbeat', 'node': 'edge', 'observed_utc': m.utc(),
             'sensors': {'packets': 1}, 'counters': {}}
        d.update(changes)
        d['signature'] = hmac.new(b'test-key', json.dumps(d, sort_keys=True, separators=(',', ':')).encode(), hashlib.sha256).hexdigest()
        return json.dumps(d, separators=(',', ':')).encode()

    def test_hub_rejects_untrusted_json_shapes_before_peer_lookup(self):
        peers = {'edge': {'mesh_ip': '127.0.0.1', 'key': 'test-key'}}
        for raw in (b'[]', b'null', b'1', b'"text"', b'{"node":[]}', b'[' * 2000):
            with self.subTest(raw=raw[:30]), self.assertRaises((ValueError, TypeError, RecursionError)):
                m.hub_event(raw, '127.0.0.1', peers)
        self.assertEqual(m.hub_event(self.signed(), '127.0.0.1', peers)['event'], 'heartbeat')
        self.assertIsNone(m.hub_event(self.signed(), '127.0.0.2', peers))
        for change in ({'sensors': []}, {'src': []}, {'event': []}, {'observed_utc': '2000-01-01T00:00:00+00:00'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                m.hub_event(self.signed(**change), '127.0.0.1', peers)

    def test_real_hub_survives_bad_datagrams_and_rejects_replays(self):
        with tempfile.TemporaryDirectory() as directory:
            c = m.Collector({'local_ips': [], 'log_dir': directory, 'node': 'hub', 'hub_bind': '127.0.0.1',
                             'peers': {'edge': {'mesh_ip': '127.0.0.1', 'key': 'test-key'}}})
            worker = threading.Thread(target=c.hub)
            worker.start()
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                deadline = time.monotonic() + 3
                while not c.health.get('hub') and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertEqual(c.health.get('hub'), 1)
                for raw in (b'[]', b'null', b'[' * 2000, self.signed()):
                    sender.sendto(raw, ('127.0.0.1', 19014))
                accepted = c.events.get(timeout=3)
                self.assertEqual(accepted['node'], 'edge')
                self.assertTrue(worker.is_alive())
                # A full replay cache must retain valid evidence delivery.
                with mock.patch.object(m, 'HUB_REPLAY_CAPACITY', 2):
                    for name in ('sensor_ready', 'sensor_notice'):
                        sender.sendto(self.signed(event=name), ('127.0.0.1', 19014))
                        self.assertEqual(c.events.get(timeout=3)['event'], name)
                self.assertGreaterEqual(c.counts['hub_replay_cache_evicted'], 1)
                duplicate = self.signed(event='collector_start')
                sender.sendto(duplicate, ('127.0.0.1', 19014))
                sender.sendto(duplicate, ('127.0.0.1', 19014))
                c.events.get(timeout=3)
                deadline = time.monotonic() + 2
                while c.counts['hub_replay_dropped'] < 1 and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertEqual(c.counts['hub_replay_dropped'], 1)
            finally:
                sender.close()
                c.stop.set()
                worker.join(timeout=3)
                c.ring.file.close()
                c.sender.close()
            self.assertFalse(worker.is_alive())
            self.assertEqual(c.health['hub'], 0)

    @unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'Linux root SCM_CREDENTIALS integration')
    def test_real_nginx_socket_authenticates_workers_and_rejects_same_uid_process(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o777)
            c = m.Collector({'local_ips': [], 'log_dir': directory + '/logs', 'node': 'local',
                             'nginx_socket_gid': 65534, 'nginx_executable': sys.executable})
            path = directory + '/nginx.sock'
            worker = threading.Thread(target=c.nginx, args=(path,))
            worker.start()
            script = "import socket,sys; s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); s.sendto(b'qntw_http: {\"event\":\"http\",\"request\":\"GET / HTTP/1.1\"}',sys.argv[1])"
            def web_user():
                os.setgroups([])
                os.setgid(65534)
                os.setuid(65534)
            try:
                deadline = time.monotonic() + 3
                while not c.health.get('nginx_receiver') and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertEqual(c.health.get('nginx_receiver'), 1)
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o660)
                subprocess.run([sys.executable, '-c', script, path], preexec_fn=web_user, check=True)
                self.assertEqual(c.events.get(timeout=3)['event'], 'http')
                # Same UID/executable, but launched by an unprivileged process.
                launcher = "import subprocess,sys; subprocess.run([sys.executable,'-c',sys.argv[1],sys.argv[2]],check=True)"
                subprocess.run([sys.executable, '-c', launcher, script, path], preexec_fn=web_user, check=True)
                deadline = time.monotonic() + 2
                while c.counts['nginx_rejected'] < 1 and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertEqual(c.counts['nginx_rejected'], 1)
                self.assertTrue(c.events.empty())
            finally:
                c.stop.set()
                worker.join(timeout=3)
                c.ring.file.close()
                c.sender.close()
            self.assertFalse(worker.is_alive())
            self.assertEqual(c.health['nginx_receiver'], 0)

    def test_http_input_cannot_override_local_identity_or_change_event_type(self):
        row = {'event': 'http', 'request': 'GET /.env HTTP/1.1', 'client': '198.51.100.2',
               'node': 'other-node', 'observed_utc': 'forged', 'src': '198.51.100.3'}
        event = m.nginx_event('qntw_http: ' + json.dumps(row, separators=(',', ':')))
        self.assertNotIn('node', event)
        self.assertNotIn('observed_utc', event)
        self.assertNotIn('src', event)
        with self.assertRaises(ValueError):
            m.nginx_event('qntw_http: {"event":"service","message":"forged"}')
        error = m.nginx_event('qntw_error: request contains {"event":"http","client":"198.51.100.3"}')
        self.assertEqual(error['event'], 'nginx_error')

    def test_emit_always_assigns_local_identity_and_observation_time(self):
        with tempfile.TemporaryDirectory() as directory:
            c = m.Collector({'local_ips': [], 'log_dir': directory, 'node': 'local'})
            try:
                c.emit({'event': 'test', 'node': 'forged', 'observed_utc': 'forged'})
                event = c.events.get_nowait()
                self.assertEqual(event['node'], 'local')
                self.assertNotEqual(event['observed_utc'], 'forged')
            finally:
                c.ring.file.close()
                c.sender.close()

    def test_credentials_require_real_worker_of_root_nginx_master(self):
        self.assertTrue(m.nginx_sender_allowed((1, 0, 0), '/missing'))
        self.assertFalse(m.nginx_sender_allowed((123, 65534, 65534), '/missing'))
        regular = type('Stat', (), {'st_mode': 0o100755, 'st_uid': 0, 'st_dev': 1, 'st_ino': 2})()
        statuses = ['Uid:\t65534 65534 65534 65534\nPPid:\t12\n',
                    'Uid:\t0 0 0 0\nPPid:\t1\n']
        with mock.patch.object(m.os, 'stat', return_value=regular), mock.patch('builtins.open', side_effect=[io.StringIO(x) for x in statuses]):
            self.assertTrue(m.nginx_sender_allowed((123, 65534, 65534), '/usr/sbin/nginx'))
        statuses[1] = 'Uid:\t65534 65534 65534 65534\nPPid:\t1\n'
        with mock.patch.object(m.os, 'stat', return_value=regular), mock.patch('builtins.open', side_effect=[io.StringIO(x) for x in statuses]):
            self.assertFalse(m.nginx_sender_allowed((123, 65534, 65534), '/usr/sbin/nginx'))


if __name__ == '__main__':
    unittest.main()
