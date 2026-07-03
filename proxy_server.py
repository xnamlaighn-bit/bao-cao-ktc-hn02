#!/usr/bin/env python3
"""
Dashboard Proxy Server — KTC HN02
  • Serves static files from this directory (port 8888)
  • Proxies /mb-proxy/* → https://data-bi.ghn.vn
  • Credentials loaded from environment variables — NEVER hardcoded

Setup:
  export MB_USER='your_email@ghn.vn'
  export MB_PASS='your_password'
  python3 proxy_server.py
"""
import os, json, ssl, time, collections
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.request import urlopen, Request
from urllib.error import HTTPError

METABASE = 'https://data-bi.ghn.vn'
PROXY    = '/mb-proxy'
GS_PROXY = '/gs-proxy'
PORT     = int(os.environ.get('PORT', 8888))

# ── SECURITY CONFIG ─────────────────────────────
# Credentials MUST be set via environment variables — never hardcode
MB_USER = os.environ.get('MB_USER', '')
MB_PASS = os.environ.get('MB_PASS', '')

# CORS: restrict to allowed frontend origins only (no wildcard in production)
_CORS_ALLOWED = [
    'https://xnamlaighn-bit.github.io',  # GitHub Pages production
    'http://localhost:8888',              # local dev
    'http://127.0.0.1:8888',
]

# Rate limiting: max 60 requests per minute per IP
_rate_counter = collections.defaultdict(list)
MAX_REQUESTS_PER_MIN = 60

# Max request body size: 64 KB
MAX_BODY_SIZE = 64 * 1024

class Handler(SimpleHTTPRequestHandler):

    # ── CORS preflight ──────────────────────────────────────
    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    # ── Rate limit check ────────────────────────────────────
    def _check_rate_limit(self):
        ip = self.client_address[0]
        now = time.time()
        window = _rate_counter[ip]
        # Remove entries older than 60 seconds
        _rate_counter[ip] = [t for t in window if now - t < 60]
        if len(_rate_counter[ip]) >= MAX_REQUESTS_PER_MIN:
            self.send_response(429)
            self._cors()
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'Rate limit exceeded'}).encode())
            print(f'  ⚠️ [RATE LIMIT] IP {ip} blocked ({len(_rate_counter[ip])} req/min)')
            return False
        _rate_counter[ip].append(now)
        return True

    # ── GET ───────────────────────────────────────────────
    def do_GET(self):
        if self.path.startswith(PROXY):
            if not self._check_rate_limit(): return
            self._relay('GET', None)
        elif self.path.startswith(GS_PROXY):
            if not self._check_rate_limit(): return
            self._relay_gs()
        else:
            super().do_GET()

    # ── POST ────────────────────────────────────────────────
    def do_POST(self):
        if self.path.startswith(PROXY):
            if not self._check_rate_limit(): return
            length = int(self.headers.get('Content-Length', 0))
            # Request size limit
            if length > MAX_BODY_SIZE:
                self.send_response(413)
                self._cors()
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'Request body too large'}).encode())
                return
            body = self.rfile.read(length) if length else None
            self._relay('POST', body)
        else:
            super().do_POST()

    # ── Relay to Metabase ───────────────────────────────────
    def _relay(self, method, body):
        mb_path    = self.path[len(PROXY):]
        target_url = f'{METABASE}{mb_path}'

        # ── AUTO-LOGIN (dùng env vars, KHÔNG hardcode) ──
        # Credentials phải được set qua environment variables:
        #   export MB_USER='email@ghn.vn'
        #   export MB_PASS='your_password'
        global_vars = globals()
        cached_token = global_vars.get('_mb_cached_token')

        fwd_headers = {}
        for h in ['Content-Type', 'X-Metabase-Session']:
            v = self.headers.get(h)
            if v: fwd_headers[h] = v

        # Nếu browser không gửi Session, dùng token đã cache hoặc auto-login
        if not fwd_headers.get('X-Metabase-Session'):
            if cached_token:
                fwd_headers['X-Metabase-Session'] = cached_token
            elif MB_USER and MB_PASS:
                # Auto-login using env var credentials
                print("  🔑 [AUTO-LOGIN] Tiến hành login tự động (via env vars)...")
                try:
                    ctx_login = ssl.create_default_context()
                    ctx_login.check_hostname = False
                    ctx_login.verify_mode = ssl.CERT_NONE

                    login_req = Request(
                        f'{METABASE}/api/session',
                        data=json.dumps({'username': MB_USER, 'password': MB_PASS}).encode('utf-8'),
                        headers={'Content-Type': 'application/json'},
                        method='POST'
                    )
                    with urlopen(login_req, context=ctx_login, timeout=10) as r_login:
                        res_login = json.loads(r_login.read().decode('utf-8'))
                        new_token = res_login.get('id')
                        if new_token:
                            print("  🔑 [AUTO-LOGIN] Login thành công!")
                            global_vars['_mb_cached_token'] = new_token
                            fwd_headers['X-Metabase-Session'] = new_token
                except Exception as e_login:
                    print("  ❌ [AUTO-LOGIN] Lỗi login:", e_login)
            else:
                print("  ⚠️ [AUTO-LOGIN] MB_USER/MB_PASS chưa được set trong environment variables.")
                print("     Chạy: export MB_USER='email@ghn.vn' && export MB_PASS='password'")

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
            # Nếu token đã cache bị hết hạn (HTTP 401), xóa cache để lần sau login lại
            if e.code in [401, 403]:
                print("  🔑 [AUTO-LOGIN] Token hết hạn (401/403). Xóa cache để login lại.")
                global_vars['_mb_cached_token'] = None
                
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
        # Restrict CORS to specific allowed origins — no wildcard for token-handling endpoints
        origin = self.headers.get('Origin', '')
        if origin in _CORS_ALLOWED:
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Vary', 'Origin')
        else:
            # Fallback for local dev without Origin header (e.g. curl, direct browser)
            if not origin:  # direct access, no cross-origin
                self.send_header('Access-Control-Allow-Origin', 'null')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers',
                         'Content-Type, X-Metabase-Session, ngrok-skip-browser-warning')

    def log_message(self, fmt, *args):
        if not self.path.startswith(PROXY):
            super().log_message(fmt, *args)


if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    # Startup security checks
    if not MB_USER or not MB_PASS:
        print('⚠️  CẢNH BÁO: MB_USER hoặc MB_PASS chưa được set!')
        print('   Auto-login sẽ không hoạt động.')
        print('   Chạy: export MB_USER="email@ghn.vn" && export MB_PASS="your_password"')
    else:
        print(f'🔑 Auto-login được cấu hình cho: {MB_USER}')

    server = HTTPServer(('', PORT), Handler)
    print(f'\n✅ Dashboard server:  http://localhost:{PORT}/index.html')
    print(f'   Metabase proxy:   http://localhost:{PORT}/mb-proxy/api/session')
    print(f'   CORS allowed:     {_CORS_ALLOWED}')
    print(f'   Serving files from: {os.getcwd()}\n')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nServer stopped.')
