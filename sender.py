import requests
import time
import uuid
import json
import os
import datetime
from counter import get_next_sequence as allocate_sequence
from security import load_private, load_rfid_secret, rfid_token, generate_signature
from transport import client_session

SIMULATION_MODE = False
try:
    import hardware
except ImportError:
    class hardware:
        @staticmethod
        def read_temperature(): return 6.2
        @staticmethod
        def read_rfid(): return "RAW-UID-A1B2C3D4" # Simulated raw read
    SIMULATION_MODE = True

try:
    with open(os.environ.get('COLDGUARD_CONFIG', 'config.json'), 'r') as f:
        config = json.load(f)
except FileNotFoundError:
    print("CRITICAL: config.json not found! Copy config.example.json to config.json.")
    exit(1)

SERVER_URL = config.get('server_url')
DEVICE_ID = config.get('device_id')
LOG_DIR = os.path.expanduser(config.get('log_dir', '~/.local/state/coldguard'))
SENSOR_INTERVAL = float(config.get('sensor_interval_seconds', 5))
REQUEST_TIMEOUT = float(config.get('request_timeout_seconds', 5))
FAILURE_BACKOFF = float(config.get('failure_backoff_seconds', 10))
if min(SENSOR_INTERVAL, REQUEST_TIMEOUT, FAILURE_BACKOFF) <= 0:
    raise ValueError('Sender timing values must be positive')

SIGNING_KEY = load_private(config['signing_private_key'])
RFID_KEY = load_rfid_secret(config.get('rfid_key_path', '~/.config/coldguard/rfid.key'))
SESSION = client_session(config)

DB_FILE = os.path.join(LOG_DIR, "pi_state.db")
os.makedirs(LOG_DIR, exist_ok=True)

def get_next_sequence():
    return allocate_sequence(DB_FILE)

def tokenize_rfid(raw_uid):
    token = rfid_token(RFID_KEY, raw_uid)
    print(f"[RFID] Scanned raw UID. Generated token: {token}")
    return token

def send_event(event_type, payload):
    event = {
        "device_id": DEVICE_ID,
        "event_id": str(uuid.uuid4()),
        "sequence": get_next_sequence(),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z'),
        "event_type": event_type,
        "simulated": SIMULATION_MODE,
        "data": payload
    }
    
    payload_str = json.dumps(event, separators=(',', ':'), sort_keys=True, allow_nan=False)
    signature = generate_signature(SIGNING_KEY, payload_str.encode('utf-8'))
    headers = {'Content-Type': 'application/json', 'X-Signature': signature, 'X-Device-ID': DEVICE_ID}
    
    try:
        response = SESSION.post(SERVER_URL, data=payload_str.encode('utf-8'), headers=headers,
                                timeout=REQUEST_TIMEOUT, allow_redirects=False)
        print(f"SENT | Seq: {event['sequence']} | ID: {event['event_id']} | Status: {response.status_code}")
        if event_type == 'rfid_scan' and hasattr(hardware, 'show_access_result'):
            decision = None
            try:
                reply = response.json()
                if (response.status_code == 201 and isinstance(reply, dict)
                        and reply.get('event_id') == event['event_id']
                        and type(reply.get('access_granted')) is bool):
                    decision = reply['access_granted']
            except ValueError:
                pass
            hardware.show_access_result(decision)
        if response.status_code != 201:
            print('REJECTED:', response.text)
        if response.status_code == 429:
            try:
                return min(300.0, max(1.0, float(response.headers.get('Retry-After', FAILURE_BACKOFF))))
            except ValueError:
                return FAILURE_BACKOFF
        return 0.0
    except requests.exceptions.RequestException as e:
        if event_type == 'rfid_scan' and hasattr(hardware, 'show_access_result'):
            hardware.show_access_result(None)
        print(f"FAILED to send Seq {event['sequence']} - Error: {e}")
        return FAILURE_BACKOFF

if __name__ == '__main__':
    print(f"Starting Secure ColdGuard Sender to {SERVER_URL}...")
    if SIMULATION_MODE:
        print("WARNING: hardware.py not found. Running in FULL SIMULATION MODE.")
        
    while True:
        requested_delay = 0.0
        temp = hardware.read_temperature()
        if temp is not None:
            requested_delay = max(requested_delay,
                                  send_event("temperature", {"temperature_c": temp}))
        
        raw_card = hardware.read_rfid()
        if raw_card is not None:
            tokenized_card = tokenize_rfid(raw_card)
            requested_delay = max(requested_delay,
                                  send_event("rfid_scan", {"card_alias": tokenized_card}))
            
        until = time.monotonic() + max(SENSOR_INTERVAL, requested_delay)
        while time.monotonic() < until:
            if hasattr(hardware, 'refresh_display'):
                hardware.refresh_display()
            time.sleep(min(0.1, max(0, until - time.monotonic())))
