#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


PORT = int(os.environ.get('WEBHOOK_SINK_PORT', '8787'))
EVENTS_PATH = Path(os.environ.get('WEBHOOK_SINK_FILE', '.data/webhook-events.jsonl')).resolve()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z')


def read_payload(raw: bytes) -> Any:
    if not raw:
        return {}
    try:
        return json.loads(raw.decode('utf-8'))
    except Exception:
        return {'raw': raw.decode('utf-8', errors='replace')}


class WebhookSinkHandler(BaseHTTPRequestHandler):
    server_version = 'SuiGuardianWebhookSink/1.0'

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header('access-control-allow-origin', '*')
        self.send_header('access-control-allow-methods', 'GET,POST,OPTIONS')
        self.send_header('access-control-allow-headers', 'content-type,x-sui-guardian-idempotency-key')
        self.end_headers()

    def do_GET(self) -> None:
        self.respond_json({
            'ok': True,
            'eventsFile': str(EVENTS_PATH),
            'postTo': f'http://127.0.0.1:{PORT}/webhook',
        })

    def do_POST(self) -> None:
        length = int(self.headers.get('content-length', '0') or '0')
        payload = read_payload(self.rfile.read(length))
        received_at = utc_now()
        record = {
            'receivedAt': received_at,
            'path': self.path,
            'idempotencyKey': self.headers.get('x-sui-guardian-idempotency-key'),
            'payload': payload,
        }

        EVENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with EVENTS_PATH.open('a', encoding='utf-8') as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + '\n')

        summary = payload.get('text') if isinstance(payload, dict) else None
        if not summary and isinstance(payload, dict) and isinstance(payload.get('alert'), dict):
            alert = payload['alert']
            summary = f"{alert.get('severity', 'unknown')} {alert.get('ruleName', alert.get('ruleId', 'alert'))}"
        print(f"[webhook] {received_at} {summary or 'received alert'}", flush=True)
        self.respond_json({'ok': True})

    def respond_json(self, payload: object) -> None:
        body = json.dumps(payload).encode('utf-8')
        self.send_response(200)
        self.send_header('content-type', 'application/json')
        self.send_header('access-control-allow-origin', '*')
        self.send_header('content-length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    server = ThreadingHTTPServer(('127.0.0.1', PORT), WebhookSinkHandler)
    print(f"Webhook sink listening on http://127.0.0.1:{PORT}/webhook", flush=True)
    print(f"Writing received events to {EVENTS_PATH}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
