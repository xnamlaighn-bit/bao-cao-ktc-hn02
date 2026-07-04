/**
 * Cloudflare Worker — KTC HN02 Security Proxy
 *
 * Endpoints:
 *   POST /verify-token   — Verify Google id_token server-side via JWKS (fixes C1)
 *   GET  /gs-proxy       — Proxy Google Sheets CSV with session auth (fixes C2)
 *   GET  /health         — Health check
 *
 * Required env variable (set in Cloudflare Dashboard → Worker → Settings → Variables):
 *   SESSION_SECRET  — Random 32+ char string to sign session tokens (HMAC-SHA256)
 *
 * Deploy: Cloudflare Dashboard → Workers → Create Worker → paste code này → Save & Deploy
 *
 * C1 Fix: JWT Google SSO verified server-side (RSA-SHA256 via Google JWKS public keys)
 * C2 Fix: Sheet IDs hidden in Worker; frontend only uses aliases, must present valid session
 */

// ─── CONFIG ──────────────────────────────────────────────────────────────────

const GOOGLE_CLIENT_ID = '875628384453-m9e0pn20peoqp3g5occ4kkcm2eoengir.apps.googleusercontent.com';
const ALLOWED_DOMAIN   = 'ghn.vn';
const GOOGLE_JWKS_URL  = 'https://www.googleapis.com/oauth2/v3/certs';
// Session duration: 8 hours (seconds)
const SESSION_TTL_SEC  = 8 * 60 * 60;

// ─── C2 FIX: Sheet IDs kept ONLY in Worker, never sent to browser ─────────────
// key = alias used by frontend, value = real Google Spreadsheet ID
const SHEET_ALIASES = {
  'nv':  '1BKqLa9uB8JJ3em0bY6R1QqkZDPYdHYWfnT5crXVLbRc',  // Nhân viên
  'fl':  '1jfvNucUpdvqJHZqW1Jl9t53DEDzvPiTtQBRAoJpRMhY',  // Freelancer
};

// ─── CORS: only allow from this project's GitHub Pages ───────────────────────
const ALLOWED_ORIGINS = new Set([
  'https://xnamlaighn-bit.github.io',
  'http://localhost',
  'http://127.0.0.1',
  'http://localhost:3000',
]);

// ─── JWKS CACHE (in-memory, per Worker instance) ─────────────────────────────
let jwksCache = null;
let jwksCacheTime = 0;
const JWKS_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

// ═════════════════════════════════════════════════════════════════════════════
// MAIN FETCH HANDLER
// ═════════════════════════════════════════════════════════════════════════════
export default {
  async fetch(request, env, ctx) {
    const url    = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const isAllowedOrigin = [...ALLOWED_ORIGINS].some(o => origin.startsWith(o));

    // ── CORS preflight ────────────────────────────────────────────────────────
    if (request.method === 'OPTIONS') {
      return corsResponse('', 204, origin, isAllowedOrigin, 'text/plain');
    }

    // ── Route ─────────────────────────────────────────────────────────────────
    try {
      if (url.pathname === '/verify-token' && request.method === 'POST') {
        return await handleVerifyToken(request, env, origin, isAllowedOrigin);
      }

      if (url.pathname === '/gs-proxy' && request.method === 'GET') {
        return await handleGsProxy(request, env, url, origin, isAllowedOrigin);
      }

      if (url.pathname === '/health' && request.method === 'GET') {
        return corsResponse(JSON.stringify({ ok: true, ts: Date.now() }), 200, origin, isAllowedOrigin);
      }

      return corsResponse(JSON.stringify({ error: 'Not Found' }), 404, origin, isAllowedOrigin);
    } catch (err) {
      console.error('[Worker] Unhandled error:', err);
      return corsResponse(JSON.stringify({ error: 'Internal Server Error' }), 500, origin, isAllowedOrigin);
    }
  },
};

// ═════════════════════════════════════════════════════════════════════════════
// POST /verify-token  — C1 FIX: Real server-side JWT verification
// ═════════════════════════════════════════════════════════════════════════════
async function handleVerifyToken(request, env, origin, isAllowedOrigin) {
  let body;
  try {
    body = await request.json();
  } catch {
    return corsResponse(JSON.stringify({ error: 'Invalid JSON body' }), 400, origin, isAllowedOrigin);
  }

  const { id_token } = body || {};
  if (!id_token || typeof id_token !== 'string') {
    return corsResponse(JSON.stringify({ error: 'Missing id_token' }), 400, origin, isAllowedOrigin);
  }

  // ── 1. Parse JWT (header + payload + signature) ───────────────────────────
  const parts = id_token.split('.');
  if (parts.length !== 3) {
    return corsResponse(JSON.stringify({ error: 'Malformed JWT' }), 401, origin, isAllowedOrigin);
  }

  let header, payload;
  try {
    header  = JSON.parse(base64urlDecode(parts[0]));
    payload = JSON.parse(base64urlDecode(parts[1]));
  } catch {
    return corsResponse(JSON.stringify({ error: 'JWT parse error' }), 401, origin, isAllowedOrigin);
  }

  // ── 2. Validate payload claims BEFORE signature (fast-fail) ───────────────

  // 2a. Expiry
  const nowSec = Math.floor(Date.now() / 1000);
  if (!payload.exp || payload.exp <= nowSec) {
    return corsResponse(JSON.stringify({ error: 'Token expired' }), 401, origin, isAllowedOrigin);
  }

  // 2b. Audience — must match our Client ID
  const audOk = Array.isArray(payload.aud)
    ? payload.aud.includes(GOOGLE_CLIENT_ID)
    : payload.aud === GOOGLE_CLIENT_ID;
  if (!audOk) {
    console.warn('[C1] JWT aud mismatch:', payload.aud);
    return corsResponse(JSON.stringify({ error: 'Invalid audience' }), 401, origin, isAllowedOrigin);
  }

  // 2c. Issuer — must be Google
  const validIssuers = ['https://accounts.google.com', 'accounts.google.com'];
  if (!validIssuers.includes(payload.iss)) {
    console.warn('[C1] JWT iss mismatch:', payload.iss);
    return corsResponse(JSON.stringify({ error: 'Invalid issuer' }), 401, origin, isAllowedOrigin);
  }

  // 2d. Hosted domain — must be @ghn.vn
  const email = (payload.email || '').toLowerCase();
  if (!email.endsWith('@' + ALLOWED_DOMAIN)) {
    return corsResponse(JSON.stringify({ error: `Only @${ALLOWED_DOMAIN} accounts allowed` }), 403, origin, isAllowedOrigin);
  }

  // ── 3. Verify RSA-SHA256 SIGNATURE via Google JWKS ────────────────────────
  // This is the true C1 fix — client-side code CANNOT forge this check
  const kid = header.kid;
  if (!kid) {
    return corsResponse(JSON.stringify({ error: 'JWT missing kid' }), 401, origin, isAllowedOrigin);
  }

  let jwk;
  try {
    jwk = await getJwkByKid(kid);
  } catch (err) {
    console.error('[C1] Failed to fetch JWKS:', err);
    return corsResponse(JSON.stringify({ error: 'JWKS fetch failed' }), 502, origin, isAllowedOrigin);
  }

  if (!jwk) {
    console.warn('[C1] No JWK found for kid:', kid);
    return corsResponse(JSON.stringify({ error: 'Unknown signing key' }), 401, origin, isAllowedOrigin);
  }

  const sigInput   = new TextEncoder().encode(parts[0] + '.' + parts[1]);
  const sigBytes   = base64urlToBytes(parts[2]);

  let sigValid = false;
  try {
    const cryptoKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    );
    sigValid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey, sigBytes, sigInput);
  } catch (err) {
    console.error('[C1] Signature verify error:', err);
    return corsResponse(JSON.stringify({ error: 'Signature verification failed' }), 401, origin, isAllowedOrigin);
  }

  if (!sigValid) {
    console.warn('[C1] Invalid JWT signature — possible forgery attempt!');
    return corsResponse(JSON.stringify({ error: 'Invalid JWT signature' }), 401, origin, isAllowedOrigin);
  }

  // ── 4. All checks passed — issue a server-signed session token ───────────
  const sessionPayload = {
    email,
    name:    payload.name    || '',
    picture: payload.picture || '',
    iss:     'ktc-hn02-worker',
    iat:     nowSec,
    exp:     nowSec + SESSION_TTL_SEC,
  };

  const sessionToken = await signSessionToken(sessionPayload, env.SESSION_SECRET);

  return corsResponse(
    JSON.stringify({
      ok:      true,
      email,
      name:    sessionPayload.name,
      picture: sessionPayload.picture,
      exp:     sessionPayload.exp,
      session: sessionToken,
    }),
    200,
    origin,
    isAllowedOrigin
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// GET /gs-proxy?sheet=<alias>&gid=<gid>  — C2 FIX: Sheet proxy with auth
// ═════════════════════════════════════════════════════════════════════════════
async function handleGsProxy(request, env, url, origin, isAllowedOrigin) {
  // ── 1. Require valid session token ────────────────────────────────────────
  const authHeader = request.headers.get('Authorization') || '';
  const sessionToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';

  if (!sessionToken) {
    return corsResponse(JSON.stringify({ error: 'Unauthorized — missing session' }), 401, origin, isAllowedOrigin);
  }

  const sessionPayload = await verifySessionToken(sessionToken, env.SESSION_SECRET);
  if (!sessionPayload) {
    return corsResponse(JSON.stringify({ error: 'Unauthorized — invalid or expired session' }), 401, origin, isAllowedOrigin);
  }

  // ── 2. Resolve sheet alias → real Sheet ID ────────────────────────────────
  const alias   = url.searchParams.get('sheet') || '';
  const gid     = url.searchParams.get('gid')   || '';
  const sheetId = SHEET_ALIASES[alias];

  if (!sheetId) {
    return corsResponse(JSON.stringify({ error: 'Unknown sheet alias' }), 400, origin, isAllowedOrigin);
  }

  // gid must be numeric only (prevent injection)
  if (gid && !/^\d+$/.test(gid)) {
    return corsResponse(JSON.stringify({ error: 'Invalid gid' }), 400, origin, isAllowedOrigin);
  }

  // ── 3. Build Google Sheets export URL (Sheet ID never leaves Worker) ──────
  const sheetUrl = `https://docs.google.com/spreadsheets/d/${sheetId}/export?format=csv${gid ? '&gid=' + gid : ''}`;

  // ── 4. Fetch CSV ─────────────────────────────────────────────────────────
  try {
    const resp = await fetch(sheetUrl, {
      headers: { 'User-Agent': 'Cloudflare-Worker/KTC-HN02-Proxy' },
      redirect: 'follow',
      cf: { cacheTtl: 60, cacheEverything: false },
    });

    if (!resp.ok) {
      return corsResponse(
        JSON.stringify({ error: 'Upstream error', status: resp.status }),
        502, origin, isAllowedOrigin
      );
    }

    const csv = await resp.text();
    return corsResponse(csv, 200, origin, isAllowedOrigin, 'text/csv; charset=utf-8');
  } catch (e) {
    console.error('[GS-PROXY] Fetch error:', e);
    return corsResponse(JSON.stringify({ error: 'Proxy error' }), 502, origin, isAllowedOrigin);
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// SESSION TOKEN — HMAC-SHA256 signed, base64url encoded
// Format: base64url(payload_json).base64url(hmac_sig)
// ═════════════════════════════════════════════════════════════════════════════
async function signSessionToken(payload, secret) {
  if (!secret) throw new Error('SESSION_SECRET not configured');
  const data    = bytesToBase64url(new TextEncoder().encode(JSON.stringify(payload)));
  const key     = await importHmacKey(secret);
  const sigBuf  = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const sig     = bytesToBase64url(new Uint8Array(sigBuf));
  return data + '.' + sig;
}

async function verifySessionToken(token, secret) {
  if (!secret || !token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [data, sig] = parts;
  try {
    const key    = await importHmacKey(secret);
    const sigBuf = base64urlToBytes(sig);
    const valid  = await crypto.subtle.verify('HMAC', key, sigBuf, new TextEncoder().encode(data));
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(base64urlToBytes(data)));
    const nowSec  = Math.floor(Date.now() / 1000);
    if (!payload.exp || payload.exp <= nowSec) return null;
    return payload;
  } catch {
    return null;
  }
}

async function importHmacKey(secret) {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// GOOGLE JWKS HELPERS
// ═════════════════════════════════════════════════════════════════════════════
async function getJwkByKid(kid) {
  const now = Date.now();
  if (!jwksCache || (now - jwksCacheTime) > JWKS_CACHE_TTL_MS) {
    const resp = await fetch(GOOGLE_JWKS_URL, { cf: { cacheTtl: 3600 } });
    if (!resp.ok) throw new Error('JWKS fetch HTTP ' + resp.status);
    const data = await resp.json();
    jwksCache    = data.keys || [];
    jwksCacheTime = now;
  }
  return jwksCache.find(k => k.kid === kid) || null;
}

// ═════════════════════════════════════════════════════════════════════════════
// BASE64URL UTILITIES
// ═════════════════════════════════════════════════════════════════════════════
function base64urlDecode(str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad  = (4 - b64.length % 4) % 4;
  return atob(b64 + '='.repeat(pad));
}

function base64urlToBytes(str) {
  const b64  = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad  = (4 - b64.length % 4) % 4;
  const bin  = atob(b64 + '='.repeat(pad));
  const buf  = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf;
}

function bytesToBase64url(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ─── Helper: build CORS Response ─────────────────────────────────────────────
function corsResponse(body, status, origin, isAllowedOrigin, contentType = 'application/json') {
  const headers = {
    'Content-Type': contentType,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  };

  if (isAllowedOrigin && origin) {
    headers['Access-Control-Allow-Origin']  = origin;
    headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS';
    headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
    headers['Access-Control-Max-Age']       = '86400';
    headers['Vary'] = 'Origin';
  }

  return new Response(body, { status, headers });
}
