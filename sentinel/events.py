"""Validate structured, synthetic security events before storing them."""
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address
import json
import re

KINDS = frozenset({'login_success', 'login_failure', 'access_denied', 'account_locked', 'policy_change'})
TOKEN = re.compile(r'[A-Za-z0-9_.@-]{1,64}\Z')

@dataclass(frozen=True)
class Event:
    event_id: str
    timestamp: str
    kind: str
    account: str
    source: str

    @classmethod
    def parse(cls, raw):
        if not isinstance(raw, dict):
            raise ValueError('Expected an event object')
        for key in ('event_id', 'account'):
            if not isinstance(raw.get(key), str) or not TOKEN.fullmatch(raw[key]):
                raise ValueError(f'Invalid {key}')
        if not isinstance(raw.get('kind'), str) or raw['kind'] not in KINDS:
            raise ValueError('Unknown event kind')
        try:
            ts = datetime.fromisoformat(raw['timestamp'].replace('Z', '+00:00'))
            if ts.tzinfo is None:
                raise ValueError('Time zone required')
            timestamp = ts.astimezone(timezone.utc).isoformat(timespec='seconds')
            if not isinstance(raw['source'], str) or '%' in raw['source']:
                raise ValueError('Invalid source')
            source = str(ip_address(raw['source']))
        except (KeyError, TypeError, ValueError, AttributeError, OverflowError) as exc:
            raise ValueError('Invalid timestamp or source address') from exc
        return cls(raw['event_id'], timestamp, raw['kind'], raw['account'], source)


def read_jsonl(path):
    """Return validated events; reject the entire batch on malformed input."""
    events = []
    with open(path, encoding='utf-8') as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            if len(line) > 4096 or len(events) >= 10000:
                raise ValueError(f'Input limit exceeded at line {number}')
            try:
                events.append(Event.parse(json.loads(line)))
            except ValueError as exc:
                raise ValueError(f'Line {number}: {exc}') from exc
    return events
