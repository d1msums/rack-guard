"""Bounded, read-only receiver rejection-log adapter. No attacker text is rendered."""
import datetime as dt
import hashlib
import json
from pathlib import Path

MAX_TAIL_BYTES = 256 * 1024
REASONS = {
    'BAD_AUTHENTICATION': ('high', 'Invalid message signature', 'The message signature failed verification. Possible tampering or an incorrect signing key.'),
    'REPLAY': ('high', 'Reused sequence rejected', 'The receiver rejected a previously used or lower sequence. Possible replay or a sender counter problem.'),
    'TLS_IDENTITY_MISMATCH': ('high', 'Device identity mismatch', 'The client certificate did not match the claimed device.'),
    'UNKNOWN_DEVICE': ('warning', 'Unknown device rejected', 'The claimed device was not enrolled or did not match the signed identity.'),
    'RATE_LIMITED': ('warning', 'Request allowance exceeded', 'The device exceeded its request budget. Possible excessive traffic or a sender fault.'),
    'STALE_OR_FUTURE_TIMESTAMP': ('warning', 'Timestamp rejected', 'The event was too old or ahead of server time. Check clocks and connectivity.'),
    'PAYLOAD_TOO_LARGE': ('warning', 'Oversized message rejected', 'The request exceeded the payload limit.'),
    'INVALID_INPUT': ('warning', 'Invalid event rejected', 'The event failed format or field validation.'),
    'METHOD_NOT_ALLOWED': ('info', 'Unsupported method rejected', 'The endpoint received an unsupported HTTP method, such as GET /events.'),
    'STATE_ERROR': ('high', 'Receiver storage failure', 'The receiver could not commit or check state. Investigate storage availability; this is not evidence of an attack.'),
}


def read_alerts(log_dir, limit=100):
    path = Path(log_dir).expanduser() / 'security_alerts.jsonl'
    result = {'alerts': [], 'status': 'ok', 'skipped_lines': 0, 'tail_limited': False,
              'server_time': dt.datetime.now(dt.timezone.utc).isoformat(),
              'scope': 'Receiver application rejections only; TLS handshake failures are not included.'}
    try:
        with path.open('rb') as handle:
            handle.seek(0, 2)
            length = handle.tell()
            start = max(0, length - MAX_TAIL_BYTES)
            result['tail_limited'] = start > 0
            if start:
                handle.seek(start - 1)
                boundary = handle.read(1) == b'\n'
            else:
                boundary = True
            handle.seek(start)
            content = handle.read(MAX_TAIL_BYTES)
    except FileNotFoundError:
        result['status'] = 'no_log_yet'
        return result
    except OSError:
        result['status'] = 'unavailable'
        return result
    if not boundary:
        content = content.partition(b'\n')[2]
    # Ignore a partially written final record; next poll will read it when complete.
    lines = content.split(b'\n')[:-1]
    for line in reversed(lines):
        if not line.strip():
            continue
        try:
            if len(line) > 16384:
                raise ValueError()
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError()
            reason, stamp = record.get('reason'), record.get('received_at')
            if not isinstance(reason, str) or reason not in REASONS or not isinstance(stamp, str):
                raise ValueError()
            parsed = dt.datetime.fromisoformat(stamp.replace('Z', '+00:00'))
            if parsed.utcoffset() is None:
                raise ValueError()
            severity, title, description = REASONS[reason]
            result['alerts'].append({'id': hashlib.sha256(line).hexdigest(), 'reason': reason,
                'received_at': parsed.isoformat(), 'severity': severity, 'title': title,
                'description': description, 'source': 'receiver'})
            if len(result['alerts']) == limit:
                break
        except (ValueError, TypeError, OverflowError):
            result['skipped_lines'] += 1
    return result
