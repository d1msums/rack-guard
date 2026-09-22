"""Isolated regression suite: no real keys, hardware, or deployment state used."""
import concurrent.futures
import datetime
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import uuid
from contextlib import closing

import requests
from counter import get_next_sequence, reconcile_counter
from export_events import export_events
from receiver import create_app
from security import generate_signature, verify_signature
from verify_database import verify_database
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent
KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex('ab' * 32))
PEER = 'a' * 64


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = {'log_dir': self.temp.name, 'enrolled_devices': ['test-pi'],
                       'authorized_cards': {'token-good': True},
                       'rate_limit': {'requests_per_minute': 10000, 'burst': 1000},
                       'devices': {'test-pi': {'tls_fingerprint_sha256': PEER}}}
        self.app = create_app(self.config, {'test-pi': KEY.public_key()})
        self.db = self.app.config['DB_FILE']

    def event(self, seq=1):
        return {'device_id': 'test-pi', 'event_id': str(uuid.uuid4()), 'sequence': seq,
                'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'simulated': True, 'event_type': 'temperature', 'data': {'temperature_c': 5.0}}

    def send(self, event, tamper=False):
        payload = json.dumps(event).encode()
        signature = generate_signature(KEY, payload)
        if tamper:
            payload += b' '
        with self.app.test_client() as client:
            return client.post('/events', data=payload,
                headers={'X-Signature': signature, 'X-Device-ID': 'test-pi'},
                environ_overrides={'rackguard.peer_sha256': PEER})

    def state(self):
        with closing(sqlite3.connect(self.db)) as conn:
            return (conn.execute('SELECT device_id, last_sequence FROM device_state ORDER BY device_id').fetchall(),
                    conn.execute('SELECT COUNT(*) FROM accepted_events').fetchone()[0])

    def assert_rejected(self, response, status, reason):
        self.assertEqual(response.status_code, status, response.get_data(as_text=True))
        self.assertEqual(response.json['reason'], reason)

    def test_validation_does_not_change_state(self):
        variants = [None, [], True, 'text', 12]
        for field, values in {
            'sequence': [True, False, 0, -1, 2**63, '1', 1.5],
            'device_id': ['', ' ', [], None], 'event_id': ['', ' ', None, 1],
            'simulated': [1, 'true', None], 'event_type': ['unknown', [], {}],
            'timestamp': [None, '', '2026-01-01T00:00:00', 'invalid'],
            'data': [None, [], 'text'],
        }.items():
            for value in values:
                event = self.event(); event[field] = value; variants.append(event)
        for value in [None, '5', True, float('nan'), float('inf'), -float('inf'), 10**400]:
            event = self.event(); event['data']['temperature_c'] = value; variants.append(event)
        for value in [[], {}, None, '', ' ', 12]:
            event = self.event(); event.update(event_type='rfid_scan', data={'card_alias': value})
            variants.append(event)
        for field in self.event():
            event = self.event(); del event[field]; variants.append(event)
        for event in variants:
            with self.subTest(event=event):
                self.assert_rejected(self.send(event), 400, 'INVALID_INPUT')
                self.assertEqual(self.state(), ([], 0))
        self.assertEqual(self.send(self.event()).status_code, 201)

    def test_authentication_and_timestamp_reasons(self):
        self.assert_rejected(self.send(self.event(), tamper=True), 403, 'BAD_AUTHENTICATION')
        for seconds in [-300, 300]:
            event = self.event()
            event['timestamp'] = (datetime.datetime.now(datetime.timezone.utc) +
                                  datetime.timedelta(seconds=seconds)).isoformat()
            self.assert_rejected(self.send(event), 403, 'STALE_OR_FUTURE_TIMESTAMP')
        event = self.event(); event['device_id'] = 'unknown'
        self.assert_rejected(self.send(event), 403, 'UNKNOWN_DEVICE')
        self.assertEqual(self.state(), ([], 0))
        self.assertFalse(verify_signature(KEY.public_key(), b'payload', '\u00e9' * 64))

    def test_malformed_json(self):
        for payload in [b'{', b'\xff']:
            with self.app.test_client() as client:
                response = client.post('/events', data=payload,
                    headers={'X-Signature': generate_signature(KEY, payload), 'X-Device-ID': 'test-pi'},
                    environ_overrides={'rackguard.peer_sha256': PEER})
            self.assert_rejected(response, 400, 'INVALID_INPUT')
        self.assertEqual(self.state(), ([], 0))

    def test_sensor_capability_payload_and_rate_limits(self):
        config = dict(self.config)
        config['log_dir'] = str(Path(self.temp.name) / 'limited')
        config['max_payload_bytes'] = 512
        config['rate_limit'] = {'requests_per_minute': 1, 'burst': 2}
        app = create_app(config, {'test-pi': KEY.public_key()})
        with app.test_client() as client:
            response = client.get('/events', environ_overrides={'rackguard.peer_sha256': PEER})
            self.assert_rejected(response, 405, 'METHOD_NOT_ALLOWED')
            oversized = b'x' * 513
            response = client.post('/events', data=oversized,
                headers={'X-Signature': generate_signature(KEY, oversized), 'X-Device-ID': 'test-pi'},
                environ_overrides={'rackguard.peer_sha256': PEER})
            self.assert_rejected(response, 413, 'PAYLOAD_TOO_LARGE')
            for sequence in (1, 2):
                payload = json.dumps(self.event(sequence)).encode()
                response = client.post('/events', data=payload,
                    headers={'X-Signature': generate_signature(KEY, payload), 'X-Device-ID': 'test-pi'},
                    environ_overrides={'rackguard.peer_sha256': PEER})
                self.assertEqual(response.status_code, 201)
            payload = json.dumps(self.event(3)).encode()
            response = client.post('/events', data=payload,
                headers={'X-Signature': generate_signature(KEY, payload), 'X-Device-ID': 'test-pi'},
                environ_overrides={'rackguard.peer_sha256': PEER})
            self.assert_rejected(response, 429, 'RATE_LIMITED')
            self.assertIn('Retry-After', response.headers)

    def test_concurrent_duplicate_and_replay(self):
        event = self.event()
        import threading
        barrier = threading.Barrier(2)
        def send_duplicate(_):
            barrier.wait(timeout=5)
            return self.send(event)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(send_duplicate, range(2)))
        self.assertEqual(sorted(r.status_code for r in results), [201, 403])
        self.assert_rejected(next(r for r in results if r.status_code == 403), 403, 'REPLAY')
        self.assert_rejected(self.send(event), 403, 'REPLAY')
        self.assertEqual(self.state(), ([('test-pi', 1)], 1))

    def test_rfid_permissions_and_export(self):
        for seq, token in enumerate(['token-good', 'token-denied'], 1):
            event = self.event(seq)
            event.update(event_type='rfid_scan', data={'card_alias': token}, access_granted=True)
            self.assertEqual(self.send(event).status_code, 201)
        output = Path(self.temp.name) / 'events.jsonl'
        export_events(self.db, output)
        events = [json.loads(line) for line in output.read_text().splitlines()]
        self.assertEqual([e['access_granted'] for e in events], [True, False])
        export_events(self.db, output)
        self.assertEqual(len(output.read_text().splitlines()), 2)
        self.assertEqual(self.state(), ([('test-pi', 2)], 2))

    def test_database_provenance_detects_injection_and_modification(self):
        self.assertEqual(self.send(self.event()).status_code, 201)
        public_path = Path(self.temp.name) / 'signing.pub'
        public_path.write_bytes(KEY.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        config_path = Path(self.temp.name) / 'verify-config.json'
        config_path.write_text(json.dumps({'devices': {
            'test-pi': {'signing_public_key': str(public_path)}}}))
        result = verify_database(self.db, config_path)
        self.assertEqual((result['valid'], result['invalid']), (1, 0))
        with closing(sqlite3.connect(self.db)) as conn:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute('INSERT INTO accepted_events '
                             '(device_id, sequence, event_id, received_at, event_json) '
                             "VALUES ('test-pi', 99, 'fake', 'now', '{}')")
            conn.execute("UPDATE accepted_events SET event_json = '{}' WHERE id = 1")
            conn.commit()
        result = verify_database(self.db, config_path)
        self.assertEqual((result['valid'], result['invalid']), (0, 1))
        self.assertIn('stored event differs from signed message', result['problems'][0])

    def test_event_write_failure_rolls_back_replay_state(self):
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute("CREATE TRIGGER fail_event BEFORE INSERT ON accepted_events "
                         "BEGIN SELECT RAISE(ABORT, 'injected failure'); END")
        event = self.event()
        self.assert_rejected(self.send(event), 500, 'STATE_ERROR')
        self.assertEqual(self.state(), ([], 0))
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute('DROP TRIGGER fail_event')
        self.assertEqual(self.send(event).status_code, 201)
        self.assertEqual(self.state(), ([('test-pi', 1)], 1))

    def test_commit_failure_rolls_back_both_tables(self):
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute('CREATE TABLE commit_parent (id INTEGER PRIMARY KEY)')
            conn.execute('CREATE TABLE commit_child (id INTEGER REFERENCES commit_parent(id) '
                         'DEFERRABLE INITIALLY DEFERRED)')
            conn.execute('CREATE TRIGGER fail_commit AFTER INSERT ON accepted_events '
                         'BEGIN INSERT INTO commit_child VALUES (999); END')
        from unittest.mock import patch
        connect = sqlite3.connect
        def constrained_connect(*args, **kwargs):
            conn = connect(*args, **kwargs)
            conn.execute('PRAGMA foreign_keys = ON')
            return conn
        with patch('receiver.sqlite3.connect', constrained_connect):
            self.assert_rejected(self.send(self.event()), 500, 'STATE_ERROR')
        self.assertEqual(self.state(), ([], 0))

    def test_counter_process_restart_and_migration(self):
        db = str(Path(self.temp.name) / 'pi_state.db')
        with self.assertRaises(RuntimeError):
            get_next_sequence(db)
        self.assertEqual(reconcile_counter(db, 50, 100), 100)
        command = [sys.executable, str(ROOT / 'counter.py'), 'next', '--db', db]
        first = int(subprocess.check_output(command, timeout=10, text=True))
        second = int(subprocess.check_output(command, timeout=10, text=True))
        self.assertEqual((first, second), (101, 102))
        self.assertEqual(reconcile_counter(db, 0, 1), 102)
        self.assertEqual(reconcile_counter(db, 200, 100), 200)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            values = list(pool.map(lambda _: get_next_sequence(db), range(8)))
        self.assertEqual(sorted(values), list(range(201, 209)))

    def test_sequence_upper_boundary(self):
        self.assertEqual(self.send(self.event(2**63 - 1)).status_code, 201)
        self.assert_rejected(self.send(self.event(2**63)), 400, 'INVALID_INPUT')
        self.assertEqual(self.state(), ([('test-pi', 2**63 - 1)], 1))

    def start_receiver(self):
        config_path = Path(self.temp.name) / 'test-config.json'
        config_path.write_text(json.dumps(self.config))
        # Binding port zero lets the OS select a free port without a reservation race.
        code = ("import json,sys; from receiver import create_app; from werkzeug.serving import make_server; "
                "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; "
                "app=create_app(json.load(open(sys.argv[1])), {'test-pi':Ed25519PrivateKey.from_private_bytes(bytes.fromhex('ab'*32)).public_key()}); "
                "wrapped=lambda env,start: app(dict(env, **{'rackguard.peer_sha256':'a'*64}),start); "
                "server=make_server('127.0.0.1',0,wrapped); "
                "print(server.server_port,flush=True); server.serve_forever()")
        process = subprocess.Popen([sys.executable, '-u', '-c', code, str(config_path)],
                                   cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        self.addCleanup(self.stop_receiver, process)
        # Bound readiness wait, including failures before the port is printed.
        import queue
        import threading
        ready = queue.Queue()
        threading.Thread(target=lambda: ready.put(process.stdout.readline()), daemon=True).start()
        try:
            port = int(ready.get(timeout=10).strip())
        except Exception:
            self.stop_receiver(process)
            raise
        return process, f'http://127.0.0.1:{port}/events'

    @staticmethod
    def stop_receiver(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=5)
        if process.stdout:
            process.stdout.close()

    def test_receiver_process_restart_rejects_replay(self):
        event = self.event()
        payload = json.dumps(event).encode()
        headers = {'X-Signature': generate_signature(KEY, payload), 'X-Device-ID': 'test-pi'}
        process, url = self.start_receiver()
        self.assertEqual(requests.post(url, data=payload, headers=headers, timeout=5).status_code, 201)
        self.stop_receiver(process)
        process, url = self.start_receiver()
        response = requests.post(url, data=payload, headers=headers, timeout=5)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()['reason'], 'REPLAY')
        self.assertEqual(self.state(), ([('test-pi', 1)], 1))
        self.stop_receiver(process)


class ClearResult(unittest.TextTestResult):
    def addSuccess(self, test):
        super().addSuccess(test)
        self.stream.writeln(f'PASS: {test.id()}')

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.stream.writeln(f'FAIL: {test.id()}')

    def addError(self, test, err):
        super().addError(test, err)
        self.stream.writeln(f'FAIL (error): {test.id()}')


if __name__ == '__main__':
    unittest.main(testRunner=unittest.TextTestRunner(verbosity=0, resultclass=ClearResult))
