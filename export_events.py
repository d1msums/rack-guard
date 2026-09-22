"""Export a snapshot of committed events; JSONL is never the source of truth."""
import argparse
import os
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path


def export_events(db_file, output_file):
    source = Path(db_file).expanduser().resolve()
    target = Path(output_file).expanduser().resolve()
    if target == source or target.suffix.lower() != '.jsonl':
        raise ValueError('Output must be a separate .jsonl file')
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True)) as conn:
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=target.parent,
                                             delete=False) as handle:
                temporary = handle.name
                for (event,) in conn.execute('SELECT event_json FROM accepted_events ORDER BY id'):
                    handle.write(event + '\n')
        os.replace(temporary, target)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    export_events(args.db, args.output)
