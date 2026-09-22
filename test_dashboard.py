import base64
import datetime as dt
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from contextlib import closing
from werkzeug.security import generate_password_hash
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from dashboard import create_dashboard, read_snapshot
from receiver import create_app
from security import generate_signature


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.key = Ed25519PrivateKey.generate()
        self.config = {'log_dir': self.tmp.name, 'devices': {'pi': {'tls_fingerprint_sha256': 'a' * 64}}}
        self.keys = {'pi': self.key.public_key()}
        self.ingest = create_app(self.config, self.keys)
        self.options = {'username': 'operator', 'password_hash': generate_password_hash('test-password-long'),
                        'analysis_file': str(Path(self.tmp.name) / 'analysis.json')}
        self.app = create_dashboard(self.options, self.config, self.keys)
        self.client = self.app.test_client()
        self.headers = {'Authorization': 'Basic ' + base64.b64encode(b'operator:test-password-long').decode()}

    def get(self, path):
        return self.client.get(path, headers=self.headers)

    def add(self):
        event = {'device_id': 'pi', 'event_id': 'event-1', 'sequence': 1,
                 'timestamp': dt.datetime.now(dt.timezone.utc).isoformat(), 'event_type': 'temperature',
                 'simulated': True, 'data': {'temperature_c': 23.1}}
        raw = json.dumps(event).encode()
        response = self.ingest.test_client().post('/events', data=raw,
            headers={'X-Device-ID': 'pi', 'X-Signature': generate_signature(self.key, raw)},
            environ_overrides={'rackguard.peer_sha256': 'a' * 64})
        self.assertEqual(response.status_code, 201)

    def test_all_data_and_assets_require_login(self):
        for route in ('/', '/api/events', '/api/analysis', '/api/alerts', '/static/rackguard-background.png'):
            with self.subTest(route=route):
                self.assertEqual(self.client.get(route).status_code, 401)
        self.assertEqual(self.client.get('/', headers={'Authorization': 'Basic eDp5'}).status_code, 401)

    def test_page_image_and_security_headers(self):
        page = self.get('/')
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'/static/dashboard.js', page.data)
        self.assertNotIn(b'https://cdn', page.data)
        self.assertEqual(page.headers['Cache-Control'], 'no-store')
        self.assertIn("script-src 'self'", page.headers['Content-Security-Policy'])
        image = self.get('/static/rackguard-background.png')
        self.assertEqual(image.status_code, 200)
        self.assertEqual(image.mimetype, 'image/png')
        image.close()

    def test_live_updates_and_no_signature_or_secret_export(self):
        self.assertEqual(self.get('/api/events').json['events'], [])
        self.add()
        result = self.get('/api/events').json
        self.assertEqual(result['events'][0]['data']['temperature_c'], 23.1)
        self.assertEqual(result['events'][0]['provenance'], 'signature_verified')
        for field in ('signature', 'raw_event', 'signing_private_key'):
            self.assertNotIn(field, result['events'][0])

    def test_tampered_rows_withheld(self):
        self.add()
        with closing(sqlite3.connect(self.ingest.config['DB_FILE'])) as conn, conn:
            conn.execute("UPDATE accepted_events SET event_json='{}'")
        result = self.get('/api/events').json
        self.assertEqual(result['events'], [])
        self.assertEqual(result['invalid_rows'], 1)

    def test_bounded_readonly_routes_and_no_cors(self):
        for limit in ('0', '201', '1 OR 1=1'):
            self.assertEqual(self.get('/api/events?limit=' + limit).status_code, 400)
        self.assertEqual(self.client.post('/events', headers=self.headers).status_code, 405)
        self.assertEqual(self.get('/events.jsonl').status_code, 404)
        self.assertEqual(self.get('/static/../config.json').status_code, 404)
        self.assertNotIn('Access-Control-Allow-Origin', self.get('/api/events').headers)
        self.assertEqual(self.client.get('/', headers=self.headers, base_url='http://evil.test').status_code, 400)

    def test_missing_database_returns_503_without_creating_it(self):
        config = dict(self.config, log_dir=str(Path(self.tmp.name) / 'missing'))
        client = create_dashboard(self.options, config, self.keys).test_client()
        self.assertEqual(client.get('/api/events', headers=self.headers).status_code, 503)
        self.assertFalse((Path(config['log_dir']) / 'state.db').exists())

    def test_no_default_password_and_login_limit(self):
        with self.assertRaises(ValueError):
            create_dashboard(dict(self.options, password_hash=''), self.config, self.keys)
        for _ in range(10):
            self.assertEqual(self.client.get('/').status_code, 401)
        self.assertEqual(self.client.get('/').status_code, 429)

    def test_analysis_unavailable_available_and_stale(self):
        self.assertEqual(self.get('/api/analysis').json['status'], 'unavailable')
        report = {'summary': '<script>alert(1)</script>', 'model': 'local-test', 'events_analyzed': 1,
                  'generated_at': (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=10)).isoformat()}
        Path(self.options['analysis_file']).write_text(json.dumps(report))
        result = self.get('/api/analysis').json
        self.assertEqual(result['status'], 'available')
        self.assertTrue(result['stale'])
        self.assertTrue(result['advisory_only'])
        self.assertEqual(result['summary'], report['summary'])

    def test_ingestion_still_has_no_browser_api(self):
        for route in ('/', '/api/events', '/api/analysis', '/api/alerts'):
            self.assertEqual(self.ingest.test_client().get(route).status_code, 404)
        self.assertEqual(self.ingest.test_client().get('/events').status_code, 405)

    def test_real_replay_rejection_appears_in_alert_api(self):
        self.add()
        event = {'device_id': 'pi', 'event_id': 'replay-test', 'sequence': 1,
                 'timestamp': dt.datetime.now(dt.timezone.utc).isoformat(), 'event_type': 'temperature',
                 'simulated': True, 'data': {'temperature_c': 23.1}}
        raw = json.dumps(event).encode()
        response = self.ingest.test_client().post('/events', data=raw,
            headers={'X-Device-ID':'pi', 'X-Signature':generate_signature(self.key,raw)},
            environ_overrides={'rackguard.peer_sha256':'a'*64})
        self.assertEqual(response.status_code,403)
        alert = self.get('/api/alerts').json['alerts'][0]
        self.assertEqual(alert['reason'],'REPLAY')
        self.assertEqual(alert['severity'],'high')
        self.assertNotIn('raw_event',alert)
        self.assertEqual(self.get('/api/alerts?limit=101').status_code,400)
        self.assertEqual(self.client.post('/api/alerts',headers=self.headers).status_code,405)

    def test_local_analysis_worker_publishes_real_response_shape(self):
        import analysis_worker
        self.add()
        config_file = Path(self.tmp.name) / 'worker-config.json'
        config_file.write_text(json.dumps(self.config))
        options = dict(self.options, config=str(config_file))
        response = MagicMock()
        response.__enter__.return_value = response
        response.iter_content.return_value = [json.dumps({'response':'Test model advisory output'}).encode()]
        session = MagicMock()
        session.__enter__.return_value = session
        session.post.return_value = response
        with patch.object(analysis_worker, 'settings', return_value=options), \
             patch.object(analysis_worker, 'load_public', return_value=self.key.public_key()), \
             patch.object(analysis_worker.requests, 'Session', return_value=session), \
             patch.dict('os.environ', {'OLLAMA_MODEL':'test-local-model'}):
            # The worker only needs a public-key path for loading; mocked here.
            config_file.write_text(json.dumps({'log_dir':self.tmp.name,
                'devices':{'pi':{'signing_public_key':'test-public-key'}}}))
            analysis_worker.main()
        report = self.get('/api/analysis').json
        self.assertEqual(report['summary'], 'Test model advisory output')
        self.assertEqual(report['events_analyzed'], 1)
        self.assertEqual(session.post.call_args.args[0], 'http://127.0.0.1:11434/api/generate')
        self.assertFalse(session.post.call_args.kwargs['allow_redirects'])
        self.assertFalse(session.trust_env)


if __name__ == '__main__':
    unittest.main(verbosity=2)
