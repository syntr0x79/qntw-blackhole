"""Server TLS evidence must describe visible responses without storing secrets."""
import csv
import importlib.util
import io
import json
import os
import unittest


spec = importlib.util.spec_from_file_location(
    'probe_logging_tls_responses',
    os.path.join(os.path.dirname(__file__), 'probe-logging.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class TLSResponseTests(unittest.TestCase):
    def server_row(self):
        return {
            'frame.time_epoch': '1794757533.7',
            'ip.src': '192.0.2.10', 'ip.dst': '198.51.100.2',
            'tcp.srcport': '443', 'tcp.dstport': '50000',
            'tcp.flags': '0x0018', 'tcp.len': '95',
            'tls.record.content_type': '22',
            'tls.record.version': '0x0303', 'tls.record.length': '90',
            'tls.handshake.type': '2', 'tls.handshake.length': '86',
            'tls.handshake.version': '0x0303',
            'tls.handshake.extensions.supported_version': '0x0304',
            'tls.handshake.ciphersuite': '0x1301',
            'tls.handshake.extension.type': '43,51',
            'tls.handshake.extension.len': '2,36',
            'tls.handshake.extensions_key_share_group': '0x001d',
            'frame.cap_len': '149', 'frame.len': '149',
        }

    def alert_row(self):
        return {
            'frame.time_epoch': '1794757533.8',
            'ip.src': '192.0.2.10', 'ip.dst': '198.51.100.2',
            'tcp.srcport': '7444', 'tcp.dstport': '50001',
            'tcp.flags': '0x0018', 'tcp.len': '7',
            'tls.record.content_type': '21',
            'tls.record.version': '0x0303', 'tls.record.length': '2',
            'tls.alert_message.level': '2',
            'tls.alert_message.desc': '70',
            'frame.cap_len': '61', 'frame.len': '61',
        }

    def collector(self):
        c = m.Collector.__new__(m.Collector)
        c.local = {'192.0.2.10', '2001:db8::10'}
        c.cfg = {'listen_ports': [443, 7444]}
        return c

    def packet(self, row, collector=None):
        data = io.StringIO()
        csv.writer(data, delimiter='\t').writerow(
            [row.get(name, '') for name in m.FIELDS])
        return (collector or self.collector()).packet(data.getvalue())

    def test_tls13_selected_version_is_not_legacy_version(self):
        d = m.tls_response_structure(self.server_row())
        self.assertEqual(d['legacy_version'], '0x0303')
        self.assertEqual(d['selected_version'], '0x0304')
        self.assertEqual(d['record_types'], [22])
        self.assertEqual(d['record_versions'], [771])
        self.assertEqual(d['record_lengths'], [90])
        self.assertEqual(d['handshake_types'], [2])
        self.assertEqual(d['handshake_lengths'], [86])
        self.assertEqual(d['cipher_suites'], [4865])
        self.assertEqual(d['extension_types'], [43, 51])
        self.assertEqual(d['extension_lengths'], [2, 36])
        self.assertEqual(d['key_share_groups'], [29])
        self.assertEqual(d['alpn_protocols'], [])
        self.assertEqual(d['alert_levels'], [])
        self.assertEqual(d['alert_descriptions'], [])
        self.assertFalse(d['capture_truncated'])

    def test_tls12_serverhello_uses_legacy_version_without_supported_versions(self):
        row = self.server_row()
        row.pop('tls.handshake.extensions.supported_version')
        row['tls.handshake.ciphersuite'] = '0xc02f'
        row['tls.handshake.extensions_alpn_str'] = 'h2'
        d = m.tls_response_structure(row)
        self.assertEqual(d['selected_version'], '0x0303')
        self.assertEqual(d['cipher_suites'], [49199])
        self.assertEqual(d['alpn_protocols'], ['h2'])

    def test_plaintext_alert_does_not_invent_negotiated_tls_version(self):
        d = m.tls_response_structure(self.alert_row())
        self.assertEqual(d['record_types'], [21])
        self.assertEqual(d['alert_levels'], [2])
        self.assertEqual(d['alert_descriptions'], [70])
        self.assertEqual(d['handshake_types'], [])
        self.assertEqual(d['selected_version'], '')

    def test_encrypted_tls12_alert_keeps_type_without_inventing_description(self):
        row = self.alert_row()
        row.pop('tls.alert_message.level')
        row.pop('tls.alert_message.desc')
        row['tls.record.length'] = '26'
        d = m.tls_response_structure(row)
        self.assertEqual(d['record_types'], [21])
        self.assertEqual(d['alert_levels'], [])
        self.assertEqual(d['alert_descriptions'], [])
        self.assertEqual(d['selected_version'], '')

    def test_truncated_capture_is_explicit(self):
        row = self.server_row()
        row['frame.cap_len'] = '100'
        row['frame.len'] = '149'
        d = m.tls_response_structure(row)
        self.assertTrue(d['capture_truncated'])
        self.assertEqual(d['frame_captured_length'], 100)
        self.assertEqual(d['frame_wire_length'], 149)

    def test_partial_tls13_serverhello_does_not_fall_back_to_tls12(self):
        row = self.server_row()
        row.pop('tls.handshake.extensions.supported_version')
        row['tcp.len'] = '60'  # Declared 90-byte record is not fully present.
        row['frame.cap_len'] = '114'
        row['frame.len'] = '114'  # Full capture of one incomplete TCP segment.
        d = m.tls_response_structure(row)
        self.assertFalse(d['capture_truncated'])
        self.assertFalse(d['server_hello_message_complete'])
        self.assertEqual(d['legacy_version'], '0x0303')
        self.assertEqual(d['selected_version'], '')

    def test_missing_selected_version_in_snaplen_truncation_is_unknown(self):
        row = self.server_row()
        row.pop('tls.handshake.extensions.supported_version')
        row['frame.cap_len'] = '100'
        d = m.tls_response_structure(row)
        self.assertTrue(d['capture_truncated'])
        self.assertFalse(d['server_hello_message_complete'])
        self.assertEqual(d['selected_version'], '')

    def test_coalesced_handshakes_preserve_order_without_certificate_bytes(self):
        row = self.server_row()
        row.update({'tls.record.content_type': '22,22',
                    'tls.record.version': '0x0303,0x0303',
                    'tls.record.length': '90,800',
                    'tls.handshake.type': '2,11',
                    'tls.handshake.length': '86,796',
                    'tls.handshake.certificate': 'PRIVATE-TEST-CERTIFICATE'})
        d = m.tls_response_structure(row)
        self.assertEqual(d['handshake_types'], [2, 11])
        self.assertEqual(d['handshake_lengths'], [86, 796])
        self.assertEqual(d['record_lengths'], [90, 800])
        self.assertNotIn('PRIVATE-TEST', json.dumps(d))

    def test_structure_allowlist_does_not_store_randoms_session_or_key_material(self):
        row = self.server_row()
        for key in ['tls.handshake.random', 'tls.handshake.session_id',
                    'tls.handshake.extensions_key_share_key_exchange',
                    'tls.handshake.session_ticket', 'tls.ech.payload',
                    'tls.handshake.certificate']:
            row[key] = 'NEVER-PERSIST-THIS-VALUE'
        d = m.tls_response_structure(row)
        self.assertNotIn('NEVER-PERSIST', json.dumps(d))
        self.assertNotIn('tls.handshake.random', m.FIELDS)
        self.assertNotIn('tls.handshake.session_id', m.FIELDS)
        self.assertNotIn('tls.handshake.certificate', m.FIELDS)

    def test_server_response_is_egress_after_firewall_not_proof_of_receipt(self):
        d = self.packet(self.server_row())
        self.assertEqual(d['event'], 'tls_response')
        self.assertEqual(d['direction'], 'egress')
        self.assertEqual(d['capture_point'], 'public_interface_egress_after_netfilter')
        self.assertIs(d['remote_receipt_confirmed'], False)
        self.assertEqual(d['connection'], {
            'client_ip': '198.51.100.2', 'client_port': '50000',
            'server_ip': '192.0.2.10', 'server_port': '443'})
        self.assertEqual(d['response']['selected_version'], '0x0304')
        self.assertNotIn('client_hello', d)

    def test_plaintext_alert_is_a_server_response(self):
        d = self.packet(self.alert_row())
        self.assertEqual(d['event'], 'tls_response')
        self.assertEqual(d['connection']['server_port'], '7444')
        self.assertEqual(d['response']['alert_descriptions'], [70])

    def test_outgoing_customer_connection_is_not_a_server_response(self):
        row = self.server_row()
        row['tcp.srcport'] = '54000'
        row['tcp.dstport'] = '443'
        self.assertIsNone(self.packet(row))
        row['tls.handshake.type'] = '1'
        self.assertIsNone(self.packet(row))

    def test_ipv6_server_response_has_the_same_connection_orientation(self):
        row = self.server_row()
        row.pop('ip.src')
        row.pop('ip.dst')
        row['ipv6.src'] = '2001:db8::10'
        row['ipv6.dst'] = '2001:db8:1::2'
        d = self.packet(row)
        self.assertEqual(d['event'], 'tls_response')
        self.assertEqual(d['connection']['server_ip'], '2001:db8::10')
        self.assertEqual(d['connection']['client_ip'], '2001:db8:1::2')

    def test_clienthello_keeps_the_existing_client_evidence_schema(self):
        row = self.server_row()
        row.update({'ip.src': '198.51.100.2', 'ip.dst': '192.0.2.10',
                    'tcp.srcport': '50000', 'tcp.dstport': '443',
                    'tls.handshake.type': '1',
                    'tls.handshake.extensions_server_name': 'vpn.example.test',
                    'tls.handshake.extensions_alpn_str': 'h2'})
        d = self.packet(row)
        self.assertEqual(d['event'], 'tls_hello')
        self.assertEqual(d['sni'], 'vpn.example.test')
        self.assertEqual(d['alpn'], 'h2')
        self.assertIn('client_hello', d)
        self.assertNotIn('response', d)

    def test_fin_and_reset_remain_tcp_events_with_correct_flow_orientation(self):
        for flags in ['0x0011', '0x0014']:
            row = self.server_row()
            for key in list(row):
                if key.startswith('tls.'):
                    row.pop(key)
            row.update({'tcp.flags': flags, 'tcp.len': '0'})
            d = self.packet(row)
            self.assertEqual(d['event'], 'tcp')
            self.assertEqual(d['direction'], 'egress')
            self.assertEqual(d['connection']['client_port'], '50000')
            self.assertNotIn('response', d)


if __name__ == '__main__':
    unittest.main()
