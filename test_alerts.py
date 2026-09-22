import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from alerts import read_alerts, MAX_TAIL_BYTES


class AlertLogTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'security_alerts.jsonl'

    def record(self, reason='REPLAY'):
        return json.dumps({'reason':reason,'error':'<script>secret</script>',
                          'received_at':dt.datetime.now(dt.timezone.utc).isoformat()})+'\n'

    def test_missing_and_unreadable_are_distinct(self):
        self.assertEqual(read_alerts(self.tmp.name)['status'],'no_log_yet')
        with patch.object(Path,'open',side_effect=PermissionError()):
            self.assertEqual(read_alerts(self.tmp.name)['status'],'unavailable')

    def test_static_descriptions_and_stable_ids(self):
        self.path.write_text(self.record('BAD_AUTHENTICATION'))
        first=read_alerts(self.tmp.name)['alerts'][0]
        self.assertEqual(first['severity'],'high')
        self.assertNotIn('secret',json.dumps(first))
        self.assertEqual(first['id'],read_alerts(self.tmp.name)['alerts'][0]['id'])

    def test_malformed_unknown_and_partial_lines(self):
        self.path.write_text('broken\n'+self.record('UNSUPPORTED')+self.record()+self.record().rstrip('\n'))
        result=read_alerts(self.tmp.name)
        self.assertEqual(len(result['alerts']),1)
        self.assertEqual(result['skipped_lines'],2)

    def test_tail_bound_limit_and_rotation(self):
        self.path.write_text('x'*(MAX_TAIL_BYTES+100)+'\n'+self.record('REPLAY')+self.record('RATE_LIMITED'))
        result=read_alerts(self.tmp.name,1)
        self.assertTrue(result['tail_limited'])
        self.assertEqual(result['alerts'][0]['reason'],'RATE_LIMITED')
        self.path.write_text(self.record('INVALID_INPUT'))
        self.assertEqual(read_alerts(self.tmp.name)['alerts'][0]['reason'],'INVALID_INPUT')

    def test_naive_timestamp_rejected_and_severity_not_from_log(self):
        self.path.write_text(json.dumps({'reason':'REPLAY','received_at':'2026-09-20T10:00:00'})+'\n'+
                             json.dumps({'reason':'METHOD_NOT_ALLOWED','severity':'critical',
                             'received_at':dt.datetime.now(dt.timezone.utc).isoformat()})+'\n')
        result=read_alerts(self.tmp.name)
        self.assertEqual(result['skipped_lines'],1)
        self.assertEqual(result['alerts'][0]['severity'],'info')


if __name__=='__main__': unittest.main(verbosity=2)
