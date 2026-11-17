import gzip
import importlib.util
import ipaddress
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('analysis', Path(__file__).with_name('probe-analysis.py'))
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


real_ip_address = ipaddress.ip_address


class SimulatedPublicIPv4(ipaddress.IPv4Address):
    """Documentation-only fixtures represent public sources in these tests."""
    @property
    def is_global(self):
        return True


def fixture_ip_address(value):
    address = real_ip_address(value)
    if str(address) in {'192.0.2.10', '198.51.100.2'}:
        return SimulatedPublicIPv4(address)
    return address


class AnalysisTest(unittest.TestCase):
    def setUp(self):
        # RFC 5737 addresses are intentionally non-global in ipaddress. Model
        # public sources only inside this fixture; runtime filtering is unchanged.
        patcher = mock.patch.object(a.ipaddress, 'ip_address', fixture_ip_address)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_hello_structure_survives_normalization_and_is_retained_without_alert(self):
        detail = {'schema': 1, 'cipher_suites': [2570, 4865], 'extension_types': [43, 10],
                  'ja3_full': '771,4865,43-10,29,0', 'complete': True}
        e, _ = a.normalize({'observed_utc': a.stamp(1000), 'event': 'tls_hello',
                            'node': 'one', 'src': '198.51.100.2', 'dst': '192.0.2.10',
                            'sport': '1234', 'dport': '443', 'client_hello': detail}, set(), {'192.0.2.10'})
        self.assertEqual(e['client_hello'], detail)
        self.assertEqual(a.detect([e], 1001), [])
        selected = list(a.select_evidence([e], [], 1001))
        self.assertEqual(selected, [(e, ['client_hello_structure'])])

    def event(self, **kwargs):
        return {'t': 1000, 'node': 'one', 'kind': 'syn', 'src': '198.51.100.2',
                'dst': '192.0.2.10', 'sport': '1234', 'dport': '443',
                'flags': '0x0002', 'sni': '', 'ja3': '', 'path': '',
                'status': '', 'ua': '', **kwargs}

    def test_retransmissions_are_not_port_sweep(self):
        self.assertEqual(a.detect([self.event()] * 20, 1001), [])
        events = [self.event(dport=str(p)) for p in range(8)]
        self.assertEqual(a.detect(events, 1001)[0]['rule'], 'port_sweep')

    def test_own_monitors_and_outgoing_are_excluded(self):
        event = {'observed_utc': a.stamp(1000), 'event': 'tcp', 'src': '198.51.100.2',
                 'dst': '192.0.2.10', 'flags': '0x0002'}
        self.assertIsNone(a.normalize(event, {'198.51.100.2'}, {'192.0.2.10'})[0])
        self.assertIsNone(a.normalize({**event, 'src': '192.0.2.10', 'dst': '198.51.100.2'}, set(), {'192.0.2.10'})[0])

    def test_private_sources_are_excluded(self):
        event = {'observed_utc': a.stamp(1000), 'event': 'tcp',
                 'src': '127.0.0.1', 'dst': '192.0.2.10', 'flags': '0x0002'}
        self.assertEqual(a.normalize(event, set(), {'192.0.2.10'}),
                         (None, 'known_monitor_or_private'))

    def test_tls_with_http_is_not_incomplete(self):
        events = []
        for p in range(5):
            for kind in ('tls_hello', 'http', 'close'):
                events.append(self.event(kind=kind, sport=str(p), t=1000 if kind == 'tls_hello' else 1001))
        self.assertEqual(a.detect(events, 1100), [])
        without_http = [e for e in events if e['kind'] != 'http']
        self.assertEqual(a.detect(without_http, 1100)[0]['rule'], 'tls_closed_without_visible_http')

    def test_ja3_or_many_connections_alone_are_not_a_probe(self):
        events = [self.event(kind='tls_hello', sport=str(p), ja3='common-browser') for p in range(50)]
        self.assertEqual(a.detect(events, 1001), [])

    def test_http_on_proxy_backend_port_matches_public_tls(self):
        events = []
        for p in range(5):
            events.extend([self.event(kind='tls_hello', sport=str(p)),
                           self.event(kind='close', sport=str(p), t=1001),
                           self.event(kind='http', sport=str(p), dport='8443', t=1001)])
        self.assertEqual(a.detect(events, 1100), [])

    def test_user_agent_url_query_is_not_copied_to_evidence(self):
        e, _ = a.normalize({'observed_utc': a.stamp(1000), 'event': 'http',
                            'client': '198.51.100.2', 'user_agent': 'https://example.test/?token=private'}, set(), set())
        self.assertNotIn('private', json.dumps(e))

    def test_complete_scan_evidence_is_selected_but_weak_contact_is_not(self):
        events = [self.event(dport=str(p)) for p in range(12)]
        findings = a.detect(events, 1001)
        selected = list(a.select_evidence(events, findings, 1001))
        self.assertEqual(len(selected), 12)
        self.assertEqual(selected[0][1], ['port_sweep'])
        weak = [{'rule': 'multi_node_contact', 'key': '198.51.100.2'}]
        self.assertEqual(list(a.select_evidence(events, weak, 1001)), [])

    def test_source_time_and_service_identity_sanitized(self):
        d = {'observed_utc': a.stamp(1000), 'event': 'service', 'node': 'one',
             'message': 'Failed password for invalid user secret-name from 198.51.100.2 port 20'}
        e, _ = a.normalize(d, set(), {'192.0.2.10'})
        self.assertEqual(e['src'], '198.51.100.2')
        self.assertNotIn('secret-name', json.dumps(e))

    def test_rotated_unread_tail_is_recovered_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'events.jsonl'
            row = lambda n: (json.dumps({'observed_utc': a.stamp(1000 + n), 'n': n}) + '\n').encode()
            p.write_bytes(row(1))
            state, seen = {}, []
            reader = a.JournalReader(tmp, state, 0)
            callback = lambda d: seen.append(d['n'])
            reader.poll(callback)
            # Collector appends unseen bytes, compresses, then truncates in place.
            with open(p, 'ab') as f:
                f.write(row(2))
            with gzip.open(Path(tmp) / 'events-001.jsonl.gz', 'wb') as f:
                f.write(p.read_bytes())
            p.write_bytes(row(3))
            reader.poll(callback)
            reader.poll(callback)
            self.assertEqual(seen, [1, 2, 3])
            restarted = a.JournalReader(tmp, state, 0)
            restarted.poll(callback)
            self.assertEqual(seen, [1, 2, 3])

    def test_partial_line_is_not_lost(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'events.jsonl'
            data = json.dumps({'observed_utc': a.stamp(1000), 'n': 1}).encode()
            p.write_bytes(data[:12])
            reader, seen = a.JournalReader(tmp, {}, 0), []
            reader.poll(seen.append)
            with open(p, 'ab') as f:
                f.write(data[12:] + b'\n')
            reader.poll(seen.append)
            self.assertEqual(len(seen), 1)


if __name__ == '__main__':
    unittest.main()
