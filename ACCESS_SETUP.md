# RFID access display update

This update needs three files: receiver.py on the VM, sender.py and hardware.py on the Pi. It is based on the supplied v7 code. Preserve any newer teammate changes before replacing files. Do not deploy while SSH is corrupting connections; use a recovered connection first.

The LCD shows Tap to access, Checking card, then ACCESS GRANTED or ACCESS DENIED according to the server's card allowlist. Network failure, a rejected request or an old server without an explicit decision shows NO DECISION. HTTP 201 alone is never permission. This controls indicator LEDs only, not a door lock.

## 1. Stage files from Windows PowerShell

```powershell
scp "C:\Users\sofea\Documents\Codex\2026-09-19\righ\outputs\RackGuard-Access-Update\receiver.py" delta@172.16.40.10:~/RackGuard-Stage2-Ed25519-mTLS/receiver_access.py
scp "C:\Users\sofea\Documents\Codex\2026-09-19\righ\outputs\RackGuard-Access-Update\sender.py" techtarik@10.40.40.20:~/RackGuard-Stage2-Ed25519-mTLS/sender_access.py
scp "C:\Users\sofea\Documents\Codex\2026-09-19\righ\outputs\RackGuard-Access-Update\hardware.py" techtarik@10.40.40.20:~/RackGuard-Stage2-Ed25519-mTLS/hardware_access.py
```

## 2. VM: stop only receiver, back up and replace

Press Ctrl+C in the receiver terminal, then:

```bash
cd ~/RackGuard-Stage2-Ed25519-mTLS
cp receiver.py "receiver.py.backup-$(date +%Y%m%d-%H%M%S)"
cp receiver_access.py receiver.py
source .venv/bin/activate
python -u receiver.py
```

Existing certificate binding, message verification, replay protection and database transactions remain. The only receiver change adds event_id and the server's RFID boolean decision to the successful response, after the transaction completes. The TLS connection authenticates that response; no standalone Ed25519 response signature is added.

## 3. Pi: stop sender, back up and replace

```bash
cd ~/RackGuard-Stage2-Ed25519-mTLS
cp sender.py "sender.py.backup-$(date +%Y%m%d-%H%M%S)"
cp hardware.py "hardware.py.backup-$(date +%Y%m%d-%H%M%S)"
cp sender_access.py sender.py
cp hardware_access.py hardware.py
source .venv/bin/activate
python -m pip install RPLCD smbus2 gpiozero lgpio
export GPIOZERO_PIN_FACTORY=lgpio
export LCD_I2C_ADDRESS=0x27
```

Your confirmed assignments are green BCM GPIO22 and red BCM GPIO23. Set them before starting the sender:

```bash
export GREEN_LED_BCM=22
export RED_LED_BCM=23
export LED_ACTIVE_HIGH=1
``` They must be BCM GPIO numbers, not physical header positions. GPIO2 and GPIO3 are reserved for the existing I2C devices. Do not reuse sensor pins. Use properly fitted current-limiting resistors. Red/green power indicators built into modules are not necessarily software controllable.

After wiring is confirmed, set RED_LED_BCM and GREEN_LED_BCM to the actual BCM numbers. LED_ACTIVE_HIGH=1 is for LEDs driven high to light; LED_ACTIVE_HIGH=0 is for confirmed active-low wiring. Do not guess these values.

You can test the LCD now without LED assignments:

```bash
python -u sender.py
```

Hold a card at the reader until detected, then remove it. The existing sampling cadence remains approximately five seconds plus network time; fast taps may be missed. Results display for about four seconds, then LEDs turn off and the screen asks for card removal or another presentation. LEDs require a sender restart after setting their environment variables.

## 4. Card enrollment

The VM config's authorized_cards mapping must contain the exact token produced by the Pi, with JSON boolean true, for a card to be granted. An empty mapping denies all cards. Only enroll a card the team has explicitly chosen to authorize; do not automatically authorize all scanned cards.

For one approved token, stop the receiver and run this on the VM from its active application folder (uses the standard config.json):

```bash
python - <<'PY'
import json, shutil, datetime
from pathlib import Path
p = Path('config.json')
data = json.loads(p.read_text())
print('Paste the approved card token shown by the Pi: ', end='', flush=True)
with open('/dev/tty') as terminal:
    token = terminal.readline().strip()
if not token.startswith('token-') or not token[6:] or any(c not in '0123456789abcdef' for c in token[6:]):
    raise SystemExit('Unexpected token format; unchanged')
shutil.copy2(p, 'config.json.backup-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S'))
data.setdefault('authorized_cards', {})[token] = True
p.write_text(json.dumps(data, indent=2) + '\n')
print('Approved card enrolled. Restart receiver.')
PY
```

## 5. Evidence and limitations

Test one approved card, one unenrolled card, and a server-unavailable scan. Expected results: GRANTED/green, DENIED/red, NO DECISION/neither. Do not claim authorization merely from a green board power light. Capture LCD and server evidence without secrets.

The existing 35-test suite passed against the changed receiver/sender package, plus three new tests for server decisions and display state. Hardware LED behavior has not been tested on the physical Pi. Pins must still be confirmed. Indicator expiration depends on the running process; this is not a safety-rated physical lock controller.
