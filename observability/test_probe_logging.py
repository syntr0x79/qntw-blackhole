import importlib.util
import json
import os
import tempfile
import unittest
import hashlib
import csv
import io
import collections

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


if __name__ == '__main__':
    unittest.main()
