"""SQLite persistence; all externally derived values are bound parameters."""
from contextlib import contextmanager
from dataclasses import asdict
import sqlite3
from .events import Event
from .rules import analyze

@contextmanager
def connect(path):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    try:
        with db:
            yield db
    finally:
        db.close()


def initialize(path):
    with connect(path) as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL,
            kind TEXT NOT NULL, account TEXT NOT NULL, source TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
        ''')


def ingest(path, events):
    with connect(path) as db:
        before = db.total_changes
        db.executemany('''INSERT INTO events(event_id,timestamp,kind,account,source)
            VALUES(:event_id,:timestamp,:kind,:account,:source)
            ON CONFLICT(event_id) DO NOTHING''', [asdict(e) for e in events])
        return db.total_changes - before


def snapshot(path, kind='', search=''):
    with connect(path) as db:
        rows = db.execute('SELECT * FROM events ORDER BY timestamp DESC, event_id').fetchall()
    events = [Event(**dict(row)) for row in rows]
    alerts = analyze(events)
    q = search.casefold()
    selected = [e for e in events if (not kind or e.kind == kind) and
                (not q or q in e.account.casefold() or q in e.source.casefold() or q in e.event_id.casefold())]
    return {'total':len(events), 'failures':sum(e.kind=='login_failure' for e in events),
            'accounts':len({e.account for e in events}), 'alerts':[asdict(a) for a in alerts],
            'events':[asdict(e) for e in selected[:200]], 'matched':len(selected)}
