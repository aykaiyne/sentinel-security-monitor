"""Command-line entry point."""
import argparse
from pathlib import Path
from .events import read_jsonl
from .storage import initialize, ingest, snapshot
import json


def main():
    parser = argparse.ArgumentParser(description='Sentinel security event review')
    parser.add_argument('--database', default='instance/sentinel.db')
    commands = parser.add_subparsers(dest='command', required=True)
    load = commands.add_parser('import', help='Import authorized JSONL data')
    load.add_argument('file')
    commands.add_parser('demo', help='Import bundled synthetic events')
    commands.add_parser('summary', help='Print a JSON summary')
    serve = commands.add_parser('serve', help='Start local dashboard')
    serve.add_argument('--port', type=int, default=5000)
    args = parser.parse_args()
    db = Path(args.database)
    db.parent.mkdir(parents=True, exist_ok=True)
    initialize(db)
    if args.command in ('import','demo'):
        file = args.file if args.command == 'import' else Path(__file__).resolve().parents[1] / 'data' / 'demo.jsonl'
        try:
            events = read_jsonl(file)
            print(f'Imported {ingest(db, events)} new events from {len(events)} records.')
        except (ValueError, OSError) as exc:
            parser.exit(1, f'Import failed: {exc}\n')
    elif args.command == 'summary':
        print(json.dumps(snapshot(db), indent=2))
    elif args.command == 'serve':
        from .web import create_app
        create_app(db).run(host='127.0.0.1', port=args.port, debug=False)

if __name__ == '__main__':
    main()
