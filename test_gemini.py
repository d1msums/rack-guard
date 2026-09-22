import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from gemini_worker import observations, generate, save_report
from dashboard import read_analysis


class GeminiTests(unittest.TestCase):
    def test_filtered_data(self):
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        snapshot = {'events': [{'event_type': 'rfid_scan', 'timestamp': now,
            'simulated': True, 'device_id': 'PRIVATE-DEVICE', 'event_id': 'PRIVATE-ID',
            'data': {'card_alias': 'PRIVATE-CARD'}, 'access_granted': False}],
            'invalid_rows': 2, 'unverifiable_rows': 1}
        alerts = {'status': 'ok', 'tail_limited': False, 'alerts': [
            {'reason': 'REPLAY', 'received_at': now, 'error': 'PRIVATE-ERROR'},
            {'reason': 'REPLAY', 'received_at': '2020-01-01T00:00:00+00:00'}]}
        data = observations(snapshot, alerts)
        self.assertNotIn('PRIVATE', json.dumps(data))
        self.assertEqual(data['rejection_counts'], {'REPLAY': 1})
        self.assertTrue(data['samples'][0]['simulated'])

    def response(self, status=200, payload=None):
        session = MagicMock()
        response = session.__enter__.return_value.post.return_value.__enter__.return_value
        response.status_code = status
        response.iter_content.return_value = [json.dumps(payload or {}).encode()]
        return session

    def test_success_and_transport(self):
        session = self.response(payload={'candidates': [{'finishReason': 'STOP',
            'content': {'parts': [{'text': 'Advice only.'}]}}]})
        with patch('gemini_worker.requests.Session', return_value=session):
            self.assertEqual(generate('secret', 'gemini-flash-latest', {}), 'Advice only.')
        args, kwargs = session.__enter__.return_value.post.call_args
        self.assertTrue(args[0].startswith('https://generativelanguage.googleapis.com/'))
        self.assertNotIn('secret', args[0])
        self.assertFalse(kwargs['allow_redirects'])
        self.assertEqual(kwargs['headers']['x-goog-api-key'], 'secret')

    def test_quota_error_sanitized(self):
        with patch('gemini_worker.requests.Session', return_value=self.response(429)):
            with self.assertRaisesRegex(ValueError, 'Gemini HTTP 429'):
                generate('secret', 'gemini-flash-latest', {})

    def test_incomplete_rejected(self):
        with patch('gemini_worker.requests.Session', return_value=self.response(payload={
                'candidates': [{'finishReason': 'MAX_TOKENS'}]})):
            with self.assertRaises(ValueError):
                generate('secret', 'gemini-flash-latest', {})

    def test_model_cannot_change_endpoint(self):
        with self.assertRaises(ValueError):
            generate('secret', '../evil?key=', {})

    def test_report_dashboard_compatible(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'analysis.json'
            save_report(target, {'summary': 'Example test report', 'model': 'Gemini / test',
                'events_analyzed': 4, 'generated_at': dt.datetime.now(dt.timezone.utc).isoformat()})
            report = read_analysis(target)
            self.assertEqual(report['status'], 'available')
            self.assertFalse(report['stale'])
            self.assertTrue(report['advisory_only'])

if __name__ == '__main__':
    unittest.main()
