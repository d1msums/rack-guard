import unittest
from unittest.mock import patch
import test_security
import hardware

class AccessTests(unittest.TestCase):
    def test_server_allowlist_controls_reply(self):
        fixture = test_security.SecurityTests()
        fixture.setUp()
        try:
            for seq, token, allowed in [(1, 'token-good', True), (2, 'not-enrolled', False)]:
                event = fixture.event(seq)
                event.update(event_type='rfid_scan', data={'card_alias': token})
                reply = fixture.send(event)
                self.assertEqual(reply.status_code, 201)
                self.assertEqual(reply.json['event_id'], event['event_id'])
                self.assertIs(reply.json['access_granted'], allowed)
        finally:
            fixture.doCleanups()

    def test_display_distinguishes_unknown_from_denial(self):
        with patch.object(hardware, '_set_leds') as leds, patch.object(hardware, 'lcd_show') as lcd:
            for decision, text in [(True, 'ACCESS GRANTED'), (False, 'ACCESS DENIED'), (None, 'NO DECISION')]:
                hardware.show_access_result(decision)
                self.assertEqual(lcd.call_args.args, ('RackGuard', text))
                self.assertIs(leds.call_args.args[0], decision)

    def test_expiry_clears_green(self):
        with patch.object(hardware, '_set_leds') as leds, patch.object(hardware, 'lcd_show'), patch.object(hardware.time, 'monotonic', return_value=100):
            hardware.show_access_result(True)
        with patch.object(hardware, '_set_leds') as leds, patch.object(hardware, 'lcd_show'), patch.object(hardware.time, 'monotonic', return_value=105):
            hardware.refresh_display()
            leds.assert_called_once_with(None)

if __name__ == '__main__':
    unittest.main()
