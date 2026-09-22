"""Verify cryptographic provenance of accepted RackGuard database rows."""
import argparse
import json
import sqlite3
from contextlib import closing
from pathlib import Path

from security import load_public, verify_signature


SIGNED_FIELDS = ('device_id', 'event_id', 'sequence', 'timestamp',
                 'event_type', 'simulated', 'data')


def verify_database(db_path, config_path):
    config = json.loads(Path(config_path).expanduser().read_text(encoding='utf-8'))
    keys = {device_id: load_public(device['signing_public_key'])
            for device_id, device in config['devices'].items()}
    valid = invalid = legacy = 0
    problems = []
    with closing(sqlite3.connect(Path(db_path).expanduser())) as conn:
        columns = {row[1] for row in conn.execute('PRAGMA table_info(accepted_events)')}
        if not {'raw_event', 'signature'}.issubset(columns):
            count = conn.execute('SELECT COUNT(*) FROM accepted_events').fetchone()[0]
            return {'valid': 0, 'invalid': 0, 'legacy': count,
                    'problems': ['Database predates cryptographic proof columns']}
        metadata = conn.execute("SELECT value FROM security_metadata WHERE key = 'proof_start_id'").fetchone()
        proof_start = int(metadata[0]) if metadata else 1
        rows = conn.execute('SELECT id, device_id, sequence, event_id, event_json, '
                            'raw_event, signature FROM accepted_events ORDER BY id').fetchall()
        seen_sequences = set()
        for row_id, device_id, sequence, event_id, event_json, raw_event, signature in rows:
            if row_id < proof_start and (raw_event is None or signature is None):
                legacy += 1
                continue
            reason = None
            if raw_event is None or signature is None:
                reason = 'missing cryptographic proof'
            elif device_id not in keys:
                reason = 'unknown device identity'
            elif not verify_signature(keys[device_id], bytes(raw_event), signature):
                reason = 'invalid Ed25519 signature'
            else:
                try:
                    signed = json.loads(bytes(raw_event))
                    stored = json.loads(event_json)
                except (ValueError, TypeError, UnicodeDecodeError):
                    reason = 'malformed stored JSON'
                else:
                    if (signed.get('device_id'), signed.get('sequence'), signed.get('event_id')) != \
                            (device_id, sequence, event_id):
                        reason = 'database columns do not match signed message'
                    elif any(stored.get(field) != signed.get(field) for field in SIGNED_FIELDS):
                        reason = 'stored event differs from signed message'
            identity = (device_id, sequence)
            if reason is None and identity in seen_sequences:
                reason = 'duplicate device sequence'
            seen_sequences.add(identity)
            if reason:
                invalid += 1
                problems.append(f'row {row_id}: {reason}')
            else:
                valid += 1
    return {'valid': valid, 'invalid': invalid, 'legacy': legacy, 'problems': problems}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', default='~/.local/state/coldguard/state.db')
    parser.add_argument('--config', default='config.json')
    args = parser.parse_args()
    result = verify_database(args.db, args.config)
    print(f"VERIFIED={result['valid']} INVALID={result['invalid']} LEGACY={result['legacy']}")
    for problem in result['problems']:
        print('ALERT:', problem)
    raise SystemExit(1 if result['invalid'] else 0)


if __name__ == '__main__':
    main()
