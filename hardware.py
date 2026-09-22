"""ColdGuard Raspberry Pi hardware adapter.

Provides the two functions required by sender.py:
  - read_temperature() -> Celsius float or None
  - read_rfid() -> uppercase UID string once per presentation, or None

This module never generates simulated readings. Hardware failures are reported
and returned as None so they cannot be mistaken for real telemetry.
"""

from __future__ import annotations

import glob
import os
import time
import atexit

# Confirmed team wiring: BCM numbers, not physical header positions.
GREEN_LED_BCM = 22  # physical pin 15
RED_LED_BCM = 23    # physical pin 16
LED_ACTIVE_HIGH = True  # resistor + LED to GND; verified by separate LED test
LCD_ADDRESS = 0x27
os.environ.setdefault('GPIOZERO_PIN_FACTORY', 'lgpio')


_pn532 = None
_nfc_init_attempted = False
_active_uid = None
_last_error = {}
_lcd = None
_lcd_retry_at = 0.0
_lcd_lines = None
_temperature_text = "Temp: waiting"
_rfid_text = "Tap to access"
_result_until = 0.0
_result_text = None
_leds = None
_leds_attempted = False


def _cleanup_leds():
    if _leds:
        for led in _leds:
            try:
                led.off()
                led.close()
            except Exception:
                pass


atexit.register(_cleanup_leds)


def _set_leds(granted=None):
    """Use the team's confirmed active-high LED wiring directly."""
    global _leds, _leds_attempted
    try:
        if not _leds_attempted:
            _leds_attempted = True
            red, green = RED_LED_BCM, GREEN_LED_BCM
            if red == green or red not in range(2, 28) or green not in range(2, 28) or {red, green} & {2, 3}:
                raise ValueError('Invalid/conflicting BCM pins; GPIO2/3 are reserved for I2C')
            from gpiozero import LED
            active_high = LED_ACTIVE_HIGH
            r = LED(red, active_high=active_high, initial_value=False)
            try:
                g = LED(green, active_high=active_high, initial_value=False)
            except Exception:
                r.close()
                raise
            _leds = (r, g)
            print('[LED] Ready: green GPIO22, red GPIO23 (active-high).', flush=True)
        if _leds:
            r, g = _leds
            r.off()
            g.off()
            if granted is True:
                g.on()
            elif granted is False:
                r.on()
    except Exception as error:
        _report_once('led', f'[LED ERROR] {error}')


def show_access_result(granted):
    """Display only the server decision; None means no verified decision."""
    global _result_until, _result_text, _rfid_text
    _result_text = ('ACCESS GRANTED' if granted is True else
                    'ACCESS DENIED' if granted is False else 'NO DECISION')
    _result_until = time.monotonic() + 4
    _rfid_text = 'Remove card' if _active_uid is not None else 'Tap to access'
    _set_leds(granted)
    lcd_show('RackGuard', _result_text)


def refresh_display():
    global _result_text
    if _result_text is not None:
        if time.monotonic() < _result_until:
            lcd_show('RackGuard', _result_text)
            return
        _result_text = None
        _set_leds(None)
    lcd_show(_temperature_text, _rfid_text)


def lcd_show(line1: str, line2: str) -> bool:
    """Optional 1602 PCF8574 LCD. Failure never substitutes sensor data."""
    global _lcd, _lcd_retry_at, _lcd_lines
    if os.environ.get("LCD_ENABLED", "1") == "0":
        return False
    if _lcd is None and time.monotonic() < _lcd_retry_at:
        return False
    try:
        if _lcd is None:
            # Imports stay optional: missing LCD dependencies must not break sender import.
            from RPLCD.i2c import CharLCD
            address_text = os.environ.get("LCD_I2C_ADDRESS", hex(LCD_ADDRESS)).strip()
            if not address_text:
                raise ValueError("Set LCD_I2C_ADDRESS to the confirmed LCD address, e.g. 0x27")
            address = int(address_text, 0)
            if address not in range(0x20, 0x28) and address not in range(0x38, 0x40):
                raise ValueError("Address outside PCF8574 ranges; confirm the LCD backpack type")
            _lcd = CharLCD(i2c_expander="PCF8574", address=address,
                           port=int(os.environ.get("LCD_I2C_BUS", "1")),
                           cols=16, rows=2, auto_linebreaks=False, backlight_enabled=True)
            _lcd_lines = None
            print(f"[LCD] 16x2 display initialized at {address:#04x}", flush=True)
        lines = tuple(str(s).encode("ascii", "replace").decode()[:16].ljust(16)
                      for s in (line1, line2))
        if lines != _lcd_lines:
            for row, line in enumerate(lines):
                _lcd.cursor_pos = (row, 0)
                _lcd.write_string(line)
            _lcd_lines = lines
        return True
    except Exception as error:
        if _lcd is not None:
            try:
                _lcd.close(clear=False)
            except Exception:
                pass
        _lcd = None
        _lcd_lines = None
        _lcd_retry_at = time.monotonic() + 30
        _report_once("lcd", f"[LCD ERROR] {error}; sensor processing continues.")
        return False


def _display_status():
    refresh_display()


def _report_once(key: str, message: str, interval: float = 30.0) -> None:
    now = time.monotonic()
    if key not in _last_error or now - _last_error[key] >= interval:
        print(message, flush=True)
        _last_error[key] = now


def _find_dht_iio() -> str | None:
    for path in glob.glob("/sys/bus/iio/devices/iio:device*"):
        if (
            os.path.exists(os.path.join(path, "in_temp_input"))
            and os.path.exists(os.path.join(path, "in_humidityrelative_input"))
        ):
            return path
    return None


def read_temperature() -> float | None:
    """Read DHT22 temperature through the configured kernel IIO driver."""
    global _temperature_text
    base = _find_dht_iio()
    if base is None:
        _temperature_text = "Temp: no sensor"
        _display_status()
        _report_once(
            "dht_missing",
            "[HARDWARE ERROR] DHT22 IIO device not found; no temperature event sent.",
        )
        return None

    try:
        with open(os.path.join(base, "in_temp_input"), encoding="utf-8") as handle:
            value = int(handle.read().strip()) / 1000.0
        _temperature_text = f"Temp: {value:.1f} C"
        _display_status()
        return value
    except (OSError, ValueError) as error:
        _temperature_text = "Temp: read error"
        _display_status()
        _report_once(
            "dht_read",
            f"[HARDWARE ERROR] DHT22 read failed: {error}; no temperature event sent.",
        )
        return None


def _get_pn532():
    global _pn532, _nfc_init_attempted
    if _pn532 is not None:
        return _pn532
    if _nfc_init_attempted:
        return None

    _nfc_init_attempted = True
    try:
        import board
        import busio
        from adafruit_pn532.i2c import PN532_I2C

        i2c = busio.I2C(board.SCL, board.SDA)
        device = PN532_I2C(i2c, debug=False)
        _, version, revision, _ = device.firmware_version
        device.SAM_configuration()
        _pn532 = device
        print(f"[RFID] PN532 ready, firmware v{version}.{revision}.", flush=True)
    except Exception as error:
        _report_once("pn532_init", f"[HARDWARE ERROR] PN532 unavailable: {error}")
    return _pn532


def read_rfid() -> str | None:
    """Return one UID per presentation and suppress reads while it remains held."""
    global _active_uid, _rfid_text
    device = _get_pn532()
    if device is None:
        _rfid_text = "RFID: offline"
        _display_status()
        return None

    try:
        uid = device.read_passive_target(timeout=0.5)
    except Exception as error:
        _rfid_text = "RFID: read error"
        _display_status()
        _report_once("pn532_read", f"[HARDWARE ERROR] PN532 read failed: {error}")
        return None

    if uid is None:
        # A no-card observation rearms the same card for its next presentation.
        _active_uid = None
        _rfid_text = "Tap to access"
        _display_status()
        return None

    uid_hex = bytes(uid).hex().upper()
    if uid_hex == _active_uid:
        return None

    _active_uid = uid_hex
    # A scan is not an authorization result: never show ACCESS GRANTED here.
    _rfid_text = "Checking card..."
    _set_leds(None)
    _display_status()
    print("[RFID] New card presentation detected.", flush=True)
    return uid_hex


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--lcd-test", action="store_true")
    args = parser.parse_args()
    if args.lcd_test:
        if not lcd_show("RackGuard", "LCD test OK"):
            raise SystemExit(1)
        print("Check the physical screen: RackGuard / LCD test OK. I2C success alone does not prove visible text.")
    else:
        parser.print_help()
