"""Read-only local dashboard. Import is deliberately separate from analysis."""
from flask import Flask, jsonify, render_template, request, Response
from pathlib import Path
import csv
import io
from .events import KINDS
from .storage import initialize, snapshot


def create_app(database=None):
    app = Flask(__name__)
    db = Path(database or 'instance/sentinel.db').resolve()
    db.parent.mkdir(parents=True, exist_ok=True)
    initialize(db)

    def filtered():
        kind = request.args.get('kind', '')
        return snapshot(db, kind if kind in KINDS else '', request.args.get('q', '')[:100])

    @app.after_request
    def headers(response):
        response.headers['Content-Security-Policy'] = "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.get('/')
    def dashboard():
        return render_template('dashboard.html', data=filtered(), kinds=sorted(KINDS),
                               kind=request.args.get('kind',''), q=request.args.get('q','')[:100])

    @app.get('/api/summary')
    def summary():
        return jsonify(filtered())

    @app.get('/reports/alerts.csv')
    def report():
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['rule','severity','subject','evidence','count'])
        for a in snapshot(db)['alerts']:
            # Prevent spreadsheet formula interpretation of user-derived values.
            subject = a['subject']
            if subject.startswith(('=', '+', '-', '@', '\t', '\r')):
                subject = "'" + subject
            writer.writerow([a['rule'],a['severity'],subject,a['evidence'],a['count']])
        return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition':'attachment; filename=sentinel-alerts.csv'})
    return app
