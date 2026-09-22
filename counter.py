"""Shared persistent counter and explicit upgrade reconciliation."""
import argparse
import sqlite3
from contextlib import closing
from pathlib import Path

MAX_SEQUENCE = 2**63 - 1


def _initialize(conn):
    conn.execute('CREATE TABLE IF NOT EXISTS sequence_allocator '
                 '(id INTEGER PRIMARY KEY CHECK (id = 1), seq INTEGER)')
    conn.execute('INSERT OR IGNORE INTO sequence_allocator VALUES (1, 0)')


def reconcile_counter(db_file, legacy_sequence, receiver_sequence):
    for value in (legacy_sequence, receiver_sequence):
        if type(value) is not int or not 0 <= value < MAX_SEQUENCE:
            raise ValueError('Counter floor must be an integer from 0 to 2**63 - 2')
    Path(db_file).expanduser().parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(str(Path(db_file).expanduser()), timeout=10)) as conn, conn:
        conn.execute('BEGIN IMMEDIATE')
        _initialize(conn)
        existing = conn.execute('SELECT seq FROM sequence_allocator WHERE id = 1').fetchone()[0]
        floor = max(existing, legacy_sequence, receiver_sequence)
        if floor >= MAX_SEQUENCE:
            raise OverflowError('Sequence space exhausted')
        conn.execute('UPDATE sequence_allocator SET seq = ? WHERE id = 1', (floor,))
    return floor


def get_next_sequence(db_file):
    # Never silently initialize a missing DB: upgrades must reconcile with the VM first.
    if not Path(db_file).expanduser().is_file():
        raise RuntimeError('Counter missing: run counter.py init after checking the VM replay state')
    with closing(sqlite3.connect(str(Path(db_file).expanduser()), timeout=10)) as conn, conn:
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute('SELECT seq FROM sequence_allocator WHERE id = 1').fetchone()
        if row is None or type(row[0]) is not int or row[0] < 0:
            raise RuntimeError('Invalid counter state')
        if row[0] >= MAX_SEQUENCE:
            raise OverflowError('Sequence space exhausted')
        value = row[0] + 1
        conn.execute('UPDATE sequence_allocator SET seq = ? WHERE id = 1', (value,))
    return value


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    init = sub.add_parser('init', help='Initialize or raise a counter without lowering it')
    init.add_argument('--db', required=True)
    init.add_argument('--legacy-last-sequence', type=int, required=True)
    init.add_argument('--receiver-last-sequence', type=int, required=True)
    peek = sub.add_parser('receiver-state', help='Read VM replay state without modifying it')
    peek.add_argument('--db', required=True)
    peek.add_argument('--device-id', required=True)
    nxt = sub.add_parser('next', help='Allocate one sequence (also used by restart tests)')
    nxt.add_argument('--db', required=True)
    args = parser.parse_args()
    if args.action == 'init':
        floor = reconcile_counter(args.db, args.legacy_last_sequence, args.receiver_last_sequence)
        print(f'Counter floor: {floor}; next sequence: {floor + 1}')
    elif args.action == 'next':
        print(get_next_sequence(args.db))
    else:
        uri = Path(args.db).expanduser().resolve().as_uri() + '?mode=ro'
        with closing(sqlite3.connect(uri, uri=True)) as conn:
            row = conn.execute('SELECT last_sequence FROM device_state WHERE device_id = ?',
                               (args.device_id,)).fetchone()
        print(row[0] if row else 0)
