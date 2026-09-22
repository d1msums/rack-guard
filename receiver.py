"""Authenticated event receiver. SQLite is the authoritative event journal."""
import datetime
import json
import math
import os
import sqlite3
from contextlib import closing

from flask import Flask, jsonify, request
from security import load_public, verify_signature

MAX_SEQUENCE = 2**63 - 1
DEFAULT_RATE_PER_MINUTE = 36
DEFAULT_BURST = 8


def validate_event(data):
    if not isinstance(data, dict):
        return "Body must be an object"
    required = ('device_id', 'event_id', 'sequence', 'timestamp',
                'event_type', 'simulated', 'data')
    if not all(field in data for field in required):
        return "Missing required fields"
    for field in ('device_id', 'event_id'):
        if not isinstance(data[field], str) or not data[field].strip():
            return f"{field} must be a nonempty string"
    if type(data['sequence']) is not int or not 1 <= data['sequence'] <= MAX_SEQUENCE:
        return "Sequence must be a positive signed 64-bit integer"
    if type(data['simulated']) is not bool:
        return "simulated must be boolean"
    if data['event_type'] not in ('temperature', 'rfid_scan'):
        return "Unsupported event type"
    if not isinstance(data['data'], dict):
        return "data must be an object"
    if data['event_type'] == 'rfid_scan':
        token = data['data'].get('card_alias')
        if not isinstance(token, str) or not token.strip():
            return "card_alias must be a nonempty string"
    else:
        temperature = data['data'].get('temperature_c')
        if type(temperature) not in (int, float):
            return "temperature_c must be a finite number"
        try:
            if not math.isfinite(temperature):
                return "temperature_c must be a finite number"
        except OverflowError:
            return "temperature_c must be a finite number"
    try:
        timestamp = data['timestamp']
        if not isinstance(timestamp, str):
            raise ValueError()
        event_time = datetime.datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        if event_time.utcoffset() is None:
            raise ValueError()
    except (ValueError, OverflowError):
        return "Invalid timezone-aware timestamp"
    return None


def create_app(config=None, public_keys=None):
    if config is None:
        with open(os.environ.get('COLDGUARD_CONFIG', 'config.json'), encoding='utf-8') as handle:
            config = json.load(handle)
    devices = config['devices']
    if public_keys is None:
        public_keys = {device: load_public(entry['signing_public_key'])
                       for device, entry in devices.items()}
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = int(config.get('max_payload_bytes', 8192))
    rate_config = config.get('rate_limit', {})
    rate_per_minute = int(rate_config.get('requests_per_minute', DEFAULT_RATE_PER_MINUTE))
    rate_burst = int(rate_config.get('burst', DEFAULT_BURST))
    if rate_per_minute < 1 or rate_burst < 1:
        raise ValueError('Rate-limit values must be positive integers')
    log_dir = os.path.expanduser(config.get('log_dir', '~/.local/state/coldguard'))
    os.makedirs(log_dir, exist_ok=True)
    db_file = os.path.join(log_dir, 'state.db')
    app.config['DB_FILE'] = db_file
    with closing(sqlite3.connect(db_file)) as conn, conn:
        conn.execute('CREATE TABLE IF NOT EXISTS device_state '
                     '(device_id TEXT PRIMARY KEY, last_sequence INTEGER)')
        conn.execute('CREATE TABLE IF NOT EXISTS accepted_events ('
                     'id INTEGER PRIMARY KEY, device_id TEXT NOT NULL, '
                     'sequence INTEGER NOT NULL, event_id TEXT NOT NULL, '
                     'received_at TEXT NOT NULL, event_json TEXT NOT NULL, '
                     'raw_event BLOB, signature TEXT, '
                     'UNIQUE(device_id, sequence))')
        columns = {row[1] for row in conn.execute('PRAGMA table_info(accepted_events)')}
        if 'raw_event' not in columns:
            conn.execute('ALTER TABLE accepted_events ADD COLUMN raw_event BLOB')
        if 'signature' not in columns:
            conn.execute('ALTER TABLE accepted_events ADD COLUMN signature TEXT')
        conn.execute('CREATE TABLE IF NOT EXISTS security_metadata '
                     '(key TEXT PRIMARY KEY, value TEXT NOT NULL)')
        proof_start = conn.execute("SELECT value FROM security_metadata WHERE key = 'proof_start_id'").fetchone()
        if proof_start is None:
            first_protected_id = conn.execute('SELECT COALESCE(MAX(id), 0) + 1 FROM accepted_events').fetchone()[0]
            conn.execute("INSERT INTO security_metadata VALUES ('proof_start_id', ?)",
                         (str(first_protected_id),))
        conn.execute('CREATE TRIGGER IF NOT EXISTS require_event_proof '
                     'BEFORE INSERT ON accepted_events '
                     'WHEN NEW.raw_event IS NULL OR NEW.signature IS NULL '
                     "BEGIN SELECT RAISE(ABORT, 'cryptographic proof required'); END")
        conn.execute('CREATE TABLE IF NOT EXISTS request_limits ('
                     'device_id TEXT PRIMARY KEY, tokens REAL NOT NULL, '
                     'updated_at REAL NOT NULL)')

    def reject(reason, message, status):
        # Rejection audit is best-effort; accepted events never depend on a text file.
        try:
            with open(os.path.join(log_dir, 'security_alerts.jsonl'), 'a', encoding='utf-8') as handle:
                handle.write(json.dumps({'reason': reason, 'error': message,
                    'received_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}) + '\n')
        except OSError:
            app.logger.exception('Could not write rejection audit')
        return jsonify(error=message, reason=reason), status

    def consume_request_token(device_id, now_seconds):
        """Durable per-device token bucket, updated atomically in SQLite."""
        refill_per_second = rate_per_minute / 60.0
        with closing(sqlite3.connect(db_file, timeout=10)) as conn, conn:
            conn.execute('BEGIN IMMEDIATE')
            row = conn.execute('SELECT tokens, updated_at FROM request_limits '
                               'WHERE device_id = ?', (device_id,)).fetchone()
            if row is None:
                tokens = float(rate_burst)
            else:
                elapsed = max(0.0, now_seconds - row[1])
                tokens = min(float(rate_burst), row[0] + elapsed * refill_per_second)
            allowed = tokens >= 1.0
            if allowed:
                tokens -= 1.0
            conn.execute('INSERT INTO request_limits VALUES (?, ?, ?) '
                         'ON CONFLICT(device_id) DO UPDATE SET '
                         'tokens = excluded.tokens, updated_at = excluded.updated_at',
                         (device_id, tokens, now_seconds))
        return allowed

    @app.errorhandler(405)
    def method_not_allowed(_error):
        return reject('METHOD_NOT_ALLOWED', 'Sensor identity may only POST to /events', 405)

    @app.errorhandler(413)
    def payload_too_large(_error):
        return reject('PAYLOAD_TOO_LARGE', 'Event exceeds the configured size limit', 413)

    @app.post('/events')
    def receive_event():
        raw = request.get_data()
        key_id = request.headers.get('X-Device-ID', '')
        signature = request.headers.get('X-Signature')
        if key_id not in devices or key_id not in public_keys:
            return reject('UNKNOWN_DEVICE', 'Device not enrolled', 403)
        if request.environ.get('rackguard.peer_sha256') != devices[key_id]['tls_fingerprint_sha256']:
            return reject('TLS_IDENTITY_MISMATCH', 'Client certificate does not match device', 403)
        try:
            if not consume_request_token(key_id, datetime.datetime.now(datetime.timezone.utc).timestamp()):
                response, status = reject('RATE_LIMITED', 'Device request budget exhausted', 429)
                response.headers['Retry-After'] = str(max(1, round(60 / rate_per_minute)))
                return response, status
        except sqlite3.Error:
            app.logger.exception('Rate-limit state failed')
            return reject('STATE_ERROR', 'Internal state error', 500)
        if not verify_signature(public_keys[key_id], raw, signature):
            return reject('BAD_AUTHENTICATION', 'Forbidden', 403)
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            return reject('INVALID_INPUT', 'Malformed JSON', 400)
        error = validate_event(data)
        if error:
            return reject('INVALID_INPUT', error, 400)
        if data['device_id'] != key_id:
            return reject('UNKNOWN_DEVICE', 'Device not enrolled', 403)
        event_time = datetime.datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
        now = datetime.datetime.now(datetime.timezone.utc)
        if abs((now - event_time).total_seconds()) > 60:
            return reject('STALE_OR_FUTURE_TIMESTAMP', 'Stale or future timestamp', 403)
        data.pop('access_granted', None)
        if data['event_type'] == 'rfid_scan':
            data['access_granted'] = config.get('authorized_cards', {}).get(data['data']['card_alias']) is True
        data['received_at'] = now.isoformat().replace('+00:00', 'Z')
        try:
            with closing(sqlite3.connect(db_file, timeout=10)) as conn, conn:
                conn.execute('BEGIN IMMEDIATE')
                row = conn.execute('SELECT last_sequence FROM device_state WHERE device_id = ?',
                                   (data['device_id'],)).fetchone()
                if row and data['sequence'] <= row[0]:
                    return reject('REPLAY', 'Replay detected', 403)
                conn.execute('INSERT INTO device_state VALUES (?, ?) ON CONFLICT(device_id) '
                             'DO UPDATE SET last_sequence = excluded.last_sequence',
                             (data['device_id'], data['sequence']))
                conn.execute('INSERT INTO accepted_events '
                             '(device_id, sequence, event_id, received_at, event_json, raw_event, signature) '
                             'VALUES (?, ?, ?, ?, ?, ?, ?)',
                             (data['device_id'], data['sequence'], data['event_id'], data['received_at'],
                              json.dumps(data, allow_nan=False), raw, signature))
        except (sqlite3.Error, ValueError):
            app.logger.exception('Event transaction failed')
            return reject('STATE_ERROR', 'Internal state error', 500)
        reply = {'status': 'acknowledged', 'event_id': data['event_id']}
        if data['event_type'] == 'rfid_scan':
            reply['access_granted'] = data['access_granted']
        return jsonify(reply), 201

    return app


if __name__ == '__main__':
    from transport import build_server
    with open(os.environ.get('COLDGUARD_CONFIG', 'config.json')) as handle:
        configuration = json.load(handle)
    server = build_server(configuration, create_app(configuration))
    print('RackGuard listening on HTTPS port 18443; client certificates REQUIRED', flush=True)
    server.serve_forever()
