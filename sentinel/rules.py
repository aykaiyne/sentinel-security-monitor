"""Explainable rules for reviewing synthetic event records."""
from collections import Counter
from dataclasses import dataclass

@dataclass(frozen=True)
class Alert:
    rule: str
    severity: str
    subject: str
    evidence: str
    count: int


def analyze(events):
    """Aggregate a batch by account; alerts are triage signals, not verdicts."""
    counts = Counter((e.kind, e.account) for e in events)
    alerts = []
    for (kind, account), count in sorted(counts.items()):
        if kind == 'login_failure':
            alerts.append(Alert('Authentication review', 'medium', account,
                                'Failed authentication records in dataset', count))
        elif kind == 'access_denied':
            alerts.append(Alert('Access review', 'medium', account,
                                'Access-control denial recorded', count))
        elif kind == 'account_locked':
            alerts.append(Alert('Account lockout', 'high', account,
                                'Account lockout recorded by source', count))
        elif kind == 'policy_change':
            alerts.append(Alert('Policy audit', 'low', account,
                                'Security policy change recorded', count))
    return sorted(alerts, key=lambda a: ({'high':0,'medium':1,'low':2}[a.severity], a.rule, a.subject))
