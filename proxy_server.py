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

# Rate limiting — per IP, per minute
_rate_counter = collections.defaultdict(list)
MAX_REQUESTS_PER_MIN     = 60   # general endpoints
MAX_AUTH_REQUESTS_PER_MIN = 5   # auth endpoint (/mb-proxy/api/session) — stricter
RATE_LIMIT_WINDOW = 60          # seconds

# Max request body size: 64 KB
MAX_BODY_SIZE = 64 * 1024

# D4 — SSRF: allowlist specific Google Sheet IDs
# Only these exact Sheet IDs can be fetched via /gs-proxy
ALLOWED_SHEET_IDS = {
    '1BKqLa9uB8JJ3em0bY6R1QqkZDPYdHYWfnT5crXVLbRc',  # Sheet NV (SHEET1)
    '1jfvNucUpdvqJHZqW1Jl9t53DEDzvPiTtQBRAoJpRMhY',  # Sheet FL (SHEET2 + SHEET3)
}

class Handler(SimpleHTTPRequestHandler):

    # ── CORS preflight ──────────────────────────────────────
    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    # ── Rate limit check ────────────────────────────────────
    # R2: auth endpoint uses stricter limit; R3: include Retry-After header
    def _check_rate_limit(self, is_auth_endpoint=False):
        ip = self.client_address[0]
        # Use separate key for auth endpoint to apply stricter limit independently
        key = f'{ip}:auth' if is_auth_endpoint else ip
        now = time.time()
        _rate_counter[key] = [t for t in _rate_counter[key] if now - t < RATE_LIMIT_WINDOW]
        limit = MAX_AUTH_REQUESTS_PER_MIN if is_auth_endpoint else MAX_REQUESTS_PER_MIN
        if len(_rate_counter[key]) >= limit:
            self.send_response(429)
            self._cors()
            self.send_header('Content-Type', 'application/json')
            self.send_header('Retry-After', str(RATE_LIMIT_WINDOW))  # R3
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'Too many requests. Please wait and try again.'}).encode())
            print(f'  ⚠️ [RATE LIMIT] IP {ip} blocked ({len(_rate_counter[key])}/{limit} req/min, auth={is_auth_endpoint})')
            return False
        _rate_counter[key].append(now)
        return True

    # ── GET ───────────────────────────────────────────────
    def do_GET(self):
        if self.path.startswith(PROXY):
            # R2: apply stricter rate limit for the auth/session endpoint
            is_auth = '/api/session' in self.path
            if not self._check_rate_limit(is_auth_endpoint=is_auth): return
            self._relay('GET', None)
        elif self.path.startswith(GS_PROXY):
            if not self._check_rate_limit(): return
            self._relay_gs()
        else:
            super().do_GET()

    # ── POST ────────────────────────────────────────────────
    def do_POST(self):
        if self.path.startswith(PROXY):
            # R2: apply stricter rate limit for the auth/session endpoint
            is_auth = '/api/session' in self.path
            if not self._check_rate_limit(is_auth_endpoint=is_auth): return
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
                print(f'  🔑 [AUTO-LOGIN] Token hết hạn ({e.code}). Xóa cache để login lại.')
                global_vars['_mb_cached_token'] = None
            # S3: DO NOT log response body — may contain token/credential fragments
            e.read()  # consume body to free connection, but do not log or forward
            print(f'  <- HTTP {e.code} from Metabase')
            # D2: return generic error — do not expose Metabase status codes to client
            self.send_response(502)
            self._cors()
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'Upstream error. Please check your token and try again.'}).encode())

        except Exception as e:
            # D2: log internally but never expose exception details or internal URLs to client
            print(f'  <- PROXY ERROR: {type(e).__name__}')
            self.send_response(502)
            self._cors()
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'Proxy error. Please try again.'}).encode())

    # ── Relay Google Sheets CSV ──────────────────────────
    def _relay_gs(self):
        from urllib.parse import parse_qs, unquote, urlparse
        qs = self.path.split('?', 1)
        params = parse_qs(qs[1]) if len(qs) > 1 else {}
        target_url = unquote(params.get('url', [''])[0])

        # D4 — SSRF prevention: allowlist domain
        if not target_url.startswith('https://docs.google.com/'):
            self.send_response(400)
            self._cors()
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'Only Google Sheets URLs are allowed'}).encode())
            return

        # D4 — SSRF prevention: allowlist specific Sheet IDs
        # Extract the spreadsheet ID from the URL path
        try:
            path_parts = urlparse(target_url).path.split('/')
            # URL format: /spreadsheets/d/{SHEET_ID}/export
            d_idx = path_parts.index('d')
            sheet_id = path_parts[d_idx + 1]
        except (ValueError, IndexError):
            sheet_id = ''

        if sheet_id not in ALLOWED_SHEET_IDS:
            print(f'  ⚠️ [GS-PROXY] Blocked non-allowlisted sheet ID: {sheet_id[:16]}...')
            self.send_response(403)
            self._cors()
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'Sheet ID not in allowlist'}).encode())
            return

        print(f'  → GS-PROXY GET sheet={sheet_id[:8]}...')
        try:
            req = Request(target_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urlopen(req, timeout=20) as r:
                data = r.read()
                ctype = r.headers.get('Content-Type', 'text/csv')
                print(f'  <- GS {r.status} OK ({len(data)} bytes)')
                self.send_response(200)
                self._cors()
                self.send_header('Content-Type', ctype)
                self.send_header('Content-Length', len(data))
                self.end_headers()
                self.wfile.write(data)
        except Exception as e:
            # D2: do not expose exception details to client
            print(f'  <- GS ERROR: {type(e).__name__}')
            self.send_response(502)
            self._cors()
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'Failed to fetch sheet data'}).encode())

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
