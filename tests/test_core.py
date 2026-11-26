import json
import pytest
from sentinel.events import Event, read_jsonl
from sentinel.rules import analyze
from sentinel.storage import initialize, ingest, snapshot


def raw(**changes):
    return dict(event_id='e1', timestamp='2026-01-15T10:00:00-05:00', kind='login_failure',
                account='demo', source='192.0.2.1') | changes


def test_normalization():
    assert Event.parse(raw()).timestamp == '2026-01-15T15:00:00+00:00'

@pytest.mark.parametrize('changes',[{'timestamp':'2026-01-01'}, {'source':'invalid'}, {'kind':'other'}, {'kind':[]}, {'account':'<script>'}, {'event_id':''}])
def test_invalid_event(changes):
    with pytest.raises(ValueError):
        Event.parse(raw(**changes))


def test_aggregation():
    alerts = analyze([Event.parse(raw()),Event.parse(raw(event_id='e2')), Event.parse(raw(event_id='e3',kind='account_locked'))])
    assert alerts[0].severity == 'high'
    assert alerts[1].count == 2


def test_success_no_alert():
    assert analyze([Event.parse(raw(kind='login_success'))]) == []


def test_storage_and_filters(tmp_path):
    db=tmp_path/'test.db'; initialize(db)
    events=[Event.parse(raw()),Event.parse(raw(event_id='e2',account='other',kind='login_success'))]
    assert ingest(db,events)==2
    assert ingest(db,events)==0
    result=snapshot(db,search='DEMO')
    assert result['total']==2 and result['matched']==1 and result['failures']==1
    assert snapshot(db,kind='login_success')['matched']==1
    assert snapshot(db,search="' OR 1=1 --")['matched']==0


def test_malformed_file(tmp_path):
    path=tmp_path/'events.jsonl'; path.write_text(json.dumps(raw())+'\nnot json\n')
    with pytest.raises(ValueError,match='Line 2'):
        read_jsonl(path)


def test_bundled_demo():
    from pathlib import Path
    events=read_jsonl(Path(__file__).resolve().parents[1]/'data'/'demo.jsonl')
    assert len(events)==48
