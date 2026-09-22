"""Operator-only read dashboard. Ingestion remains in receiver.py on mTLS 18443.

This listener deliberately binds only to loopback; use an authenticated SSH tunnel.
"""
import datetime as dt
import hmac
import json
import math
import os
from pathlib import Path
import sqlite3
import threading
import time
from contextlib import closing

from flask import Flask, jsonify, request, render_template
from werkzeug.security import check_password_hash
from receiver import validate_event
from security import load_public, verify_signature
from alerts import read_alerts

ROOT = Path(__file__).resolve().parent
FIELDS = ('device_id', 'event_id', 'sequence', 'timestamp', 'event_type', 'simulated', 'data')


def load_environment():
    """Read simple KEY=value settings without executing shell code."""
    path = ROOT / '.env'
    if path.exists():
        for line in path.read_text(encoding='utf-8-sig').splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            name, separator, value = line.partition('=')
            if not separator or not name.replace('_', '').isalnum():
                raise ValueError('Invalid .env line')
            os.environ.setdefault(name, value.strip().strip('\"\''))


def settings():
    load_environment()
    return {
        'config': os.environ.get('COLDGUARD_CONFIG', str(ROOT / 'config.json')),
        'username': os.environ.get('DASHBOARD_USERNAME', 'operator'),
        'password_hash': os.environ.get('DASHBOARD_PASSWORD_HASH', ''),
        'analysis_file': os.environ.get('RACKGUARD_ANALYSIS_FILE', '~/.local/state/coldguard/analysis.json'),
    }


def read_snapshot(config, keys, limit=200):
    database = Path(config.get('log_dir', '~/.local/state/coldguard')).expanduser() / 'state.db'
    uri = database.resolve().as_uri() + '?mode=ro'
    with closing(sqlite3.connect(uri, uri=True, timeout=2)) as conn:
        conn.execute('PRAGMA query_only=ON')
        rows = conn.execute('SELECT id, device_id, sequence, event_id, received_at, event_json, '
                            'raw_event, signature FROM accepted_events ORDER BY id DESC LIMIT ?',
                            (limit,)).fetchall()
    events, invalid, legacy = [], 0, 0
    for row_id, device, sequence, event_id, received, stored_json, raw, signature in reversed(rows):
        if raw is None or signature is None:
            legacy += 1
            continue
        try:
            if not isinstance(raw, bytes) or len(raw) > 8192 or device not in keys:
                raise ValueError()
            if not verify_signature(keys[device], raw, signature):
                raise ValueError()
            signed, stored = json.loads(raw), json.loads(stored_json)
            if validate_event(signed) or not isinstance(stored, dict):
                raise ValueError()
            if (device, sequence, event_id) != (signed['device_id'], signed['sequence'], signed['event_id']):
                raise ValueError()
            if any(stored.get(field) != signed[field] for field in FIELDS):
                raise ValueError()
            event = {field: signed[field] for field in FIELDS}
            # Only explicitly supported fields reach the browser or model.
            event['data'] = ({'temperature_c': signed['data']['temperature_c']}
                             if signed['event_type'] == 'temperature' else
                             {'card_alias': signed['data']['card_alias']})
            event.update(row_id=row_id, received_at=received, provenance='signature_verified')
            if signed['event_type'] == 'rfid_scan':
                decision = stored.get('access_granted')
                event['access_granted'] = decision if type(decision) is bool else None
            events.append(event)
        except (ValueError, TypeError, KeyError, OverflowError):
            invalid += 1
    return {'events': events, 'invalid_rows': invalid, 'unverifiable_rows': legacy,
            'window_size': len(rows), 'limit': limit,
            'server_time': dt.datetime.now(dt.timezone.utc).isoformat()}


def read_analysis(path):
    try:
        with Path(path).expanduser().open('rb') as handle:
            raw = handle.read(65537)
        if len(raw) > 65536:
            raise ValueError()
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError()
        for field in ('summary', 'model', 'generated_at'):
            if not isinstance(value.get(field), str):
                raise ValueError()
        created = dt.datetime.fromisoformat(value['generated_at'].replace('Z', '+00:00'))
        if created.utcoffset() is None:
            raise ValueError()
        age = (dt.datetime.now(dt.timezone.utc) - created).total_seconds()
        count = value.get('events_analyzed')
        if type(count) is not int or count < 0:
            raise ValueError()
        return {'status': 'available', 'summary': value['summary'][:16000],
                'model': value['model'][:120], 'generated_at': value['generated_at'],
                'events_analyzed': count, 'stale': age > 300 or age < -60,
                'advisory_only': True}
    except FileNotFoundError:
        return {'status': 'unavailable', 'summary': 'No LLM report yet. Run the optional analysis worker.'}
    except (OSError, ValueError, TypeError, OverflowError):
        return {'status': 'unavailable', 'summary': 'The analysis report could not be validated.'}


def create_dashboard(options=None, config=None, public_keys=None):
    options = options or settings()
    password_hash = options.get('password_hash', '')
    if not password_hash.startswith(('scrypt:', 'pbkdf2:')):
        raise ValueError('Set a dashboard password with python setup_dashboard.py first')
    if config is None:
        config = json.loads(Path(options['config']).expanduser().read_text())
    keys = public_keys if public_keys is not None else {
        device: load_public(entry['signing_public_key']) for device, entry in config['devices'].items()}
    app = Flask(__name__, template_folder=str(ROOT / 'templates'), static_folder=str(ROOT / 'static'))
    app.config['MAX_CONTENT_LENGTH'] = 1024
    attempts, lock = [], threading.Lock()

    @app.before_request
    def authorize():
        # Reject non-loopback Host values (including DNS-rebinding requests).
        if request.host.split(':')[0] not in ('127.0.0.1', 'localhost'):
            return jsonify(error='Invalid host'), 400
        now = time.monotonic()
        with lock:
            attempts[:] = [stamp for stamp in attempts if now - stamp < 60]
            if len(attempts) >= 10:
                return jsonify(error='Login attempts limited; wait one minute'), 429
        auth = request.authorization
        valid = (auth is not None and auth.type == 'basic' and
                 hmac.compare_digest((auth.username or '').encode(), options['username'].encode()) and
                 len(auth.password or '') <= 1024 and check_password_hash(password_hash, auth.password or ''))
        if not valid:
            with lock:
                attempts.append(now)
            return jsonify(error='Operator login required'), 401, {'WWW-Authenticate': 'Basic realm="RackGuard operator"'}
        if request.method not in ('GET', 'HEAD'):
            return jsonify(error='Read-only dashboard'), 405

    @app.after_request
    def headers(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        return response

    @app.get('/')
    def index():
        return render_template('dashboard.html')

    @app.get('/api/events')
    def events():
        try:
            limit = int(request.args.get('limit', '200'))
            if not 1 <= limit <= 200:
                raise ValueError()
        except ValueError:
            return jsonify(error='limit must be between 1 and 200'), 400
        try:
            return jsonify(read_snapshot(config, keys, limit))
        except (sqlite3.Error, OSError):
            return jsonify(error='Event database unavailable; start the receiver first'), 503

    @app.get('/api/analysis')
    def analysis():
        return jsonify(read_analysis(options['analysis_file']))

    @app.get('/api/alerts')
    def alerts():
        try:
            limit = int(request.args.get('limit', '100'))
            if not 1 <= limit <= 100:
                raise ValueError()
        except ValueError:
            return jsonify(error='limit must be between 1 and 100'), 400
        result = read_alerts(config.get('log_dir', '~/.local/state/coldguard'), limit)
        return jsonify(result), 503 if result['status'] == 'unavailable' else 200

    return app


if __name__ == '__main__':
    # Never bind this HTTP listener to a LAN interface. SSH supplies encrypted transport.
    create_dashboard().run(host='127.0.0.1', port=18080, debug=False, threaded=True)
