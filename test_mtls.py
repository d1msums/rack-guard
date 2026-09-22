"""Real loopback TLS sockets and disposable certificates; no production keys."""
import datetime
import json
import tempfile
import threading
import unittest
from pathlib import Path
from contextlib import closing
import sqlite3

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from provision import ca_init, make_request, issue, fingerprint
from security import generate_signature, load_private, load_public
from receiver import create_app
from transport import build_server, client_session

class MutualTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.ca = cls.root / 'ca'; cls.vm = cls.root / 'vm'; cls.pi = cls.root / 'pi'
        ca_init(cls.ca); make_request(cls.vm, 'vm'); make_request(cls.pi, 'pi')
        issue(cls.ca, cls.vm / 'request.csr', cls.vm / 'server.crt', 'vm', '127.0.0.1')
        issue(cls.ca, cls.pi / 'request.csr', cls.pi / 'client.crt', 'pi')
        cls.key = load_private(cls.pi / 'signing.key')
        cls.config = {
            'log_dir': str(cls.root / 'state'),
            'devices': {'test-pi': {'signing_public_key': str(cls.pi / 'signing.pub'),
                                  'tls_fingerprint_sha256': fingerprint(cls.pi / 'client.crt')}},
            'tls': {'ca': str(cls.ca / 'ca.crt'), 'cert': str(cls.vm / 'server.crt'), 'key': str(cls.vm / 'tls.key')}
        }
        cls.app = create_app(cls.config)
        cls.dispatched_requests = 0
        def observed_app(environ, start_response):
            cls.dispatched_requests += 1
            return cls.app(environ, start_response)
        cls.server = build_server(cls.config, observed_app, '127.0.0.1', 0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f'https://127.0.0.1:{cls.server.server_port}/events'
        cls.client_config = {'server_url': cls.url, 'tls': {
            'ca': str(cls.ca / 'ca.crt'), 'cert': str(cls.pi / 'client.crt'), 'key': str(cls.pi / 'tls.key')}}

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.thread.join(timeout=5); cls.server.server_close()
        cls.tmp.cleanup()

    def payload(self, sequence=1, device='test-pi'):
        return json.dumps({'device_id': device, 'event_id': f'tls-{sequence}',
            'sequence': sequence, 'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'event_type': 'temperature', 'simulated': True, 'data': {'temperature_c': 24.0}}).encode()

    def headers(self, payload, key=None):
        return {'X-Device-ID': 'test-pi', 'X-Signature': generate_signature(key or self.key, payload),
                'Content-Type': 'application/json'}

    def test_valid_mtls_ed25519_and_replay(self):
        payload = self.payload()
        with client_session(self.client_config) as session:
            response = session.post(self.url, data=payload, headers=self.headers(payload), timeout=5)
            self.assertEqual(response.status_code, 201, response.text)
            response = session.post(self.url, data=payload, headers=self.headers(payload), timeout=5)
            self.assertEqual(response.json()['reason'], 'REPLAY')
        with closing(sqlite3.connect(self.app.config['DB_FILE'])) as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM accepted_events').fetchone()[0], 1)

    def test_missing_client_certificate(self):
        before = self.dispatched_requests
        with requests.Session() as session:
            session.trust_env = False
            # Windows may surface a peer-rejected TLS handshake as a reset
            # rather than SSLError. Both are ConnectionError subclasses.
            with self.assertRaises(requests.exceptions.ConnectionError) as raised:
                session.post(self.url, data=b'{}', verify=str(self.ca / 'ca.crt'), timeout=5)
        self.assertNotIsInstance(raised.exception, requests.exceptions.Timeout)
        self.assertEqual(self.dispatched_requests, before)

    def test_untrusted_client_certificate(self):
        ca = self.root / 'rogue-ca'; client = self.root / 'rogue-client'
        ca_init(ca); make_request(client, 'pi'); issue(ca, client/'request.csr', client/'client.crt', 'pi')
        config = {'server_url': self.url, 'tls': dict(self.client_config['tls'],
                  cert=str(client/'client.crt'), key=str(client/'tls.key'))}
        before = self.dispatched_requests
        with client_session(config) as session:
            with self.assertRaises(requests.exceptions.ConnectionError) as raised:
                session.post(self.url, data=b'{}', timeout=5)
        self.assertNotIsInstance(raised.exception, requests.exceptions.Timeout)
        self.assertEqual(self.dispatched_requests, before)

    def test_other_ca_valid_client_cannot_claim_pi_identity(self):
        client = self.root / 'other-client'; make_request(client, 'pi')
        issue(self.ca, client/'request.csr', client/'client.crt', 'pi')
        config = {'server_url': self.url, 'tls': dict(self.client_config['tls'],
                  cert=str(client/'client.crt'), key=str(client/'tls.key'))}
        payload = self.payload(2)
        with client_session(config) as session:
            response = session.post(self.url, data=payload, headers=self.headers(payload), timeout=5)
            self.assertEqual(response.json()['reason'], 'TLS_IDENTITY_MISMATCH')

    def test_wrong_signing_key_and_modified_bytes(self):
        payload = self.payload(3)
        with client_session(self.client_config) as session:
            for body, headers in [(payload, self.headers(payload, Ed25519PrivateKey.generate())),
                                  (payload + b' ', self.headers(payload))]:
                response = session.post(self.url, data=body, headers=headers, timeout=5)
                self.assertEqual(response.json()['reason'], 'BAD_AUTHENTICATION')

    def test_server_identity_verification(self):
        ca = self.root / 'wrong-trust'; ca_init(ca)
        config = {'server_url': self.url, 'tls': dict(self.client_config['tls'], ca=str(ca/'ca.crt'))}
        with client_session(config) as session:
            with self.assertRaises(requests.exceptions.SSLError):
                session.post(self.url, data=b'{}', timeout=5)
        with client_session(self.client_config) as session:
            with self.assertRaises(requests.exceptions.SSLError):
                session.post(self.url.replace('127.0.0.1', 'localhost'), data=b'{}', timeout=5)

    def test_no_http_fallback(self):
        with self.assertRaises(ValueError):
            client_session(dict(self.client_config, server_url=self.url.replace('https:', 'http:')))

if __name__ == '__main__': unittest.main(verbosity=2)
