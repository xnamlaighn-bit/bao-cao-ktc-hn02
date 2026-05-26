#!/usr/bin/env python3
"""
Dashboard Proxy Server — KTC HN02
  • Serves static files from this directory (port 8888)
  • Proxies /mb-proxy/* → https://data-bi.ghn.vn  (no CORS restriction)
"""
import os, json, ssl
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.request import urlopen, Request
from urllib.error import HTTPError

METABASE = 'https://data-bi.ghn.vn'
PROXY    = '/mb-proxy'
GS_PROXY = '/gs-proxy'
PORT     = 8888

class Handler(SimpleHTTPRequestHandler):

    # ── CORS preflight ──────────────────────────────────────
    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    # ── GET ───────────────────────────────────────────────
    def do_GET(self):
        if self.path.startswith(PROXY):
            self._relay('GET', None)
        elif self.path.startswith(GS_PROXY):
            self._relay_gs()
        else:
            super().do_GET()

    # ── POST ────────────────────────────────────────────────
    def do_POST(self):
        if self.path.startswith(PROXY):
            length = int(self.headers.get('Content-Length', 0))
            body   = self.rfile.read(length) if length else None
            self._relay('POST', body)
        else:
            super().do_POST()

    # ── Relay to Metabase ───────────────────────────────────
    def _relay(self, method, body):
        mb_path    = self.path[len(PROXY):]
        target_url = f'{METABASE}{mb_path}'

        fwd_headers = {}
        for h in ['Content-Type', 'X-Metabase-Session']:
            v = self.headers.get(h)
            if v: fwd_headers[h] = v

        print(f'  → PROXY {method} {target_url}')

        try:
            # Disable cert verification — internal GHN servers may use self-signed certs
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            req = Request(target_url, data=body, headers=fwd_headers, method=method)
            with urlopen(req, context=ctx, timeout=20) as r:
                data = r.read()
                print(f'  ← {r.status} OK ({len(data)} bytes)')
                self.send_response(r.status)
                self._cors()
                self.send_header('Content-Type',
                                 r.headers.get('Content-Type', 'application/json'))
                self.send_header('Content-Length', len(data))
                self.end_headers()
                self.wfile.write(data)

        except HTTPError as e:
            data = e.read()
            print(f'  ← HTTP {e.code} from Metabase: {data[:200]}')
            self.send_response(e.code)
            self._cors()
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(data)

        except Exception as e:
            msg = str(e)
            print(f'  ← ERROR: {msg}')
            self.send_response(502)
            self._cors()
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': msg, 'url': target_url}).encode())

    # ── Relay Google Sheets CSV ──────────────────────────
    def _relay_gs(self):
        from urllib.parse import urlparse, parse_qs, unquote
        qs = self.path.split('?', 1)
        params = parse_qs(qs[1]) if len(qs) > 1 else {}
        target_url = unquote(params.get('url', [''])[0])

        if not target_url.startswith('https://docs.google.com/'):
            self.send_response(400)
            self._cors()
            self.end_headers()
            self.wfile.write(b'Only Google Sheets URLs allowed')
            return

        print(f'  → GS-PROXY GET {target_url[:80]}')
        try:
            req = Request(target_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urlopen(req, timeout=20) as r:
                data = r.read()
                ctype = r.headers.get('Content-Type', 'text/csv')
                print(f'  ← GS {r.status} OK ({len(data)} bytes)')
                self.send_response(200)
                self._cors()
                self.send_header('Content-Type', ctype)
                self.send_header('Content-Length', len(data))
                self.end_headers()
                self.wfile.write(data)
        except Exception as e:
            print(f'  ← GS ERROR: {e}')
            self.send_response(502)
            self._cors()
            self.end_headers()
            self.wfile.write(str(e).encode())

    def _cors(self):
        self.send_header('Access-Control-Allow-Origin',  '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers',
                         'Content-Type, X-Metabase-Session')

    def log_message(self, fmt, *args):
        if not self.path.startswith(PROXY):
            super().log_message(fmt, *args)


if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    server = HTTPServer(('', PORT), Handler)
    print(f'\n✅ Dashboard server:  http://localhost:{PORT}/bao-cao-nhan-su-san-luong.html')
    print(f'   Metabase proxy:   http://localhost:{PORT}/mb-proxy/api/session')
    print(f'   Serving files from: {os.getcwd()}\n')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nServer stopped.')
