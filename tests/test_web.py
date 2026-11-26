import pytest
pytest.importorskip('flask')
from sentinel.web import create_app
from sentinel.events import Event
from sentinel.storage import ingest


def test_dashboard_api_report(tmp_path):
    db=tmp_path/'web.db'; app=create_app(db)
    ingest(db,[Event.parse(dict(event_id='one',timestamp='2026-01-15T10:00:00Z',kind='login_failure',account='@demo',source='192.0.2.1'))])
    client=app.test_client()
    page=client.get('/')
    assert page.status_code==200 and b'Sentinel' in page.data
    assert 'Content-Security-Policy' in page.headers
    assert client.get('/api/summary').json['total']==1
    assert client.get('/api/summary?q=absent').json['matched']==0
    report=client.get('/reports/alerts.csv')
    assert report.status_code==200 and b"'@demo" in report.data
