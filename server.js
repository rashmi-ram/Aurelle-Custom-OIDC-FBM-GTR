// Aurelle — zero-dependency Node server with Okta OIDC (Authorization Code + PKCE)
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dir = path.dirname(fileURLToPath(import.meta.url));

// --- minimal .env loader
try {
  for (const line of fs.readFileSync(path.join(__dir, '.env'), 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z_]+)\s*=\s*(.*?)\s*$/);
    if (m && !line.trim().startsWith('#') && !(m[1] in process.env)) process.env[m[1]] = m[2];
  }
} catch {}

const { OKTA_ISSUER, OKTA_CLIENT_ID, OKTA_CLIENT_SECRET } = process.env;
const PORT = Number(process.env.PORT || 3000);
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const REDIRECT_URI = `${BASE_URL}/callback`;
const configured = Boolean(OKTA_ISSUER && OKTA_CLIENT_ID && !OKTA_ISSUER.includes('YOUR_DOMAIN'));
const secure = BASE_URL.startsWith('https');

// --- signed cookie sessions (stateless: the cookie holds the signed payload)
const b64u = (b) => Buffer.from(b).toString('base64url');
const sign = (v) => crypto.createHmac('sha256', SECRET).update(v).digest('base64url');
function pack(obj) { const p = b64u(JSON.stringify(obj)); return `${p}.${sign(p)}`; }
function unpack(s) {
  if (!s) return null;
  const [p, sig] = s.split('.');
  if (!p || !sig) return null;
  const good = Buffer.from(sign(p)), got = Buffer.from(sig);
  if (good.length !== got.length || !crypto.timingSafeEqual(good, got)) return null;
  try { const o = JSON.parse(Buffer.from(p, 'base64url').toString()); return o.exp && o.exp < Date.now() ? null : o; } catch { return null; }
}
const parseCookies = (h = '') => Object.fromEntries(h.split(';').map((c) => c.trim().split(/=(.*)/s).slice(0, 2)).filter(([k]) => k));
function setCookie(res, name, value, maxAgeSec) {
  const c = `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSec}${secure ? '; Secure' : ''}`;
  const prev = res.getHeader('Set-Cookie') || [];
  res.setHeader('Set-Cookie', [...[].concat(prev), c]);
}

// --- OIDC discovery + JWKS
let discovery, jwks;
async function getDiscovery() {
  discovery ??= await (await fetch(`${OKTA_ISSUER.replace(/\/$/, '')}/.well-known/openid-configuration`)).json();
  return discovery;
}
async function verifyIdToken(idToken, nonce) {
  const [h, p, s] = idToken.split('.');
  const header = JSON.parse(Buffer.from(h, 'base64url')), claims = JSON.parse(Buffer.from(p, 'base64url'));
  if (header.alg !== 'RS256') throw new Error('Unsupported alg');
  const d = await getDiscovery();
  let key = jwks?.keys.find((k) => k.kid === header.kid);
  if (!key) { jwks = await (await fetch(d.jwks_uri)).json(); key = jwks.keys.find((k) => k.kid === header.kid); }
  if (!key) throw new Error('Signing key not found');
  const ok = crypto.verify('RSA-SHA256', Buffer.from(`${h}.${p}`), crypto.createPublicKey({ key, format: 'jwk' }), Buffer.from(s, 'base64url'));
  if (!ok) throw new Error('Bad signature');
  const now = Date.now() / 1000;
  if (claims.iss !== d.issuer) throw new Error('Issuer mismatch');
  if (![].concat(claims.aud).includes(OKTA_CLIENT_ID)) throw new Error('Audience mismatch');
  if (claims.exp < now - 60) throw new Error('Token expired');
  if (claims.nonce !== nonce) throw new Error('Nonce mismatch');
  return claims;
}

// --- Global Token Revocation (Okta Universal Logout)
// Revocations are remembered per identifier (Okta sub and/or email). Any session created before the
// revocation time is rejected. Persisted to disk so a server restart doesn't resurrect sessions.
const GTR_SECRET = process.env.GTR_SECRET; // optional shared bearer secret (handy for curl testing)
const REVOKE_FILE = path.join(__dir, '.revocations.json');
let revoked = {};
try { revoked = JSON.parse(fs.readFileSync(REVOKE_FILE, 'utf8')); } catch {}
const revokeId = (id) => { revoked[String(id).toLowerCase()] = Date.now(); try { fs.writeFileSync(REVOKE_FILE, JSON.stringify(revoked)); } catch {} };
const isRevoked = (user, at) => [user?.sub, user?.email, user?.username].some((k) => k && (revoked[String(k).toLowerCase()] ?? 0) >= at);

const orgOrigin = () => new URL(OKTA_ISSUER).origin;
const gtrJwks = {};
async function authorizeGtr(req) {
  const m = (req.headers.authorization || '').match(/^Bearer (.+)$/i);
  if (!m) return false;
  const tok = m[1];
  if (GTR_SECRET) {
    const a = Buffer.from(tok), b = Buffer.from(GTR_SECRET);
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) return true;
  }
  if (!configured) return false;
  try { // otherwise accept a JWT signed by the Okta org authorization server
    const [h, p, sig] = tok.split('.');
    const header = JSON.parse(Buffer.from(h, 'base64url')), claims = JSON.parse(Buffer.from(p, 'base64url'));
    if (header.alg !== 'RS256' || claims.iss !== orgOrigin() || claims.exp < Date.now() / 1000) return false;
    const uri = `${orgOrigin()}/oauth2/v1/keys`;
    let key = gtrJwks[uri]?.keys.find((k) => k.kid === header.kid);
    if (!key) { gtrJwks[uri] = await (await fetch(uri)).json(); key = gtrJwks[uri].keys.find((k) => k.kid === header.kid); }
    return Boolean(key) && crypto.verify('RSA-SHA256', Buffer.from(`${h}.${p}`), crypto.createPublicKey({ key, format: 'jwk' }), Buffer.from(sig, 'base64url'));
  } catch { return false; }
}
const readBody = (req) => new Promise((ok) => { let d = ''; req.on('data', (c) => (d += c)); req.on('end', () => { try { ok(JSON.parse(d || '{}')); } catch { ok(null); } }); });
// sub_id formats from the Universal Logout / GTR spec: email, iss_sub, account, opaque
const subjectOf = (b) => { const s = b?.sub_id || b; return s?.email || s?.sub || s?.id || (s?.uri || '').replace(/^acct:/, '') || null; };

// --- Server-side sessions + token validity check against Okta (works without a public URL)
// Tokens stay on the server (cookie only holds an opaque session id). Every INTROSPECT_MS we ask Okta
// whether the access/refresh token is still active; after Global Token Revocation it is not.
const sessions = new Map();
const INTROSPECT_MS = Number(process.env.INTROSPECT_MS ?? 5000);
async function tokenActive(token, hint) {
  const d = await getDiscovery();
  if (!d.introspection_endpoint) return true;
  const body = new URLSearchParams({ token, token_type_hint: hint });
  const headers = { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' };
  if (OKTA_CLIENT_SECRET) headers.Authorization = 'Basic ' + Buffer.from(`${encodeURIComponent(OKTA_CLIENT_ID)}:${encodeURIComponent(OKTA_CLIENT_SECRET)}`).toString('base64');
  else body.set('client_id', OKTA_CLIENT_ID);
  const r = await fetch(d.introspection_endpoint, { method: 'POST', headers, body });
  if (!r.ok) throw new Error(`introspection HTTP ${r.status}`);
  return (await r.json()).active === true;
}

// --- catalogue
const PRODUCTS = JSON.parse(fs.readFileSync(path.join(__dir, 'products.json'), 'utf8'));

const MIME = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml' };
const json = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
const redirect = (res, loc) => { res.writeHead(302, { Location: loc }); res.end(); };

http.createServer(async (req, res) => {
  const url = new URL(req.url, BASE_URL);
  const cookies = parseCookies(req.headers.cookie);
  let session = sessions.get(cookies.sid) || null;
  let wasRevoked = false;
  if (session && session.exp < Date.now()) { sessions.delete(cookies.sid); session = null; }
  if (session && configured && Date.now() - session.checked >= INTROSPECT_MS) {
    session.checked = Date.now();
    try {
      const active = (await tokenActive(session.accessToken, 'access_token')) && (!session.refreshToken || (await tokenActive(session.refreshToken, 'refresh_token')));
      if (!active) { // Okta says the tokens were revoked (GTR / Universal Logout)
        console.log(`Tokens revoked by Okta for ${session.user.email || session.user.sub}`);
        sessions.delete(cookies.sid); session = null; wasRevoked = true;
        setCookie(res, 'sid', '', 0); setCookie(res, 'revoked', '1', 86400);
      }
    } catch (e) { console.warn('Token check failed (keeping session):', e.message); }
  }
  if (session && isRevoked(session.user, session.at || 0)) { // tokens revoked via GTR
    session = null; wasRevoked = true;
    setCookie(res, 'sid', '', 0); setCookie(res, 'revoked', '1', 86400);
  }
  try {
    if (url.pathname === '/login') {
      if (!configured) return redirect(res, '/?setup=1');
      const d = await getDiscovery();
      const state = b64u(crypto.randomBytes(16)), nonce = b64u(crypto.randomBytes(16)), verifier = b64u(crypto.randomBytes(32));
      const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
      setCookie(res, 'oidc', pack({ state, nonce, verifier, ret: url.searchParams.get('return') || '/', exp: Date.now() + 600000 }), 600);
      const q = new URLSearchParams({ client_id: OKTA_CLIENT_ID, response_type: 'code', scope: process.env.OKTA_SCOPES || 'openid profile email', redirect_uri: REDIRECT_URI, state, nonce, code_challenge: challenge, code_challenge_method: 'S256' });
      return redirect(res, `${d.authorization_endpoint}?${q}`);
    }
    if (url.pathname === '/callback') {
      const tx = unpack(cookies.oidc);
      if (url.searchParams.get('error')) return redirect(res, `/?autherror=${encodeURIComponent(url.searchParams.get('error_description') || url.searchParams.get('error'))}`);
      if (!tx || tx.state !== url.searchParams.get('state')) return redirect(res, '/?autherror=Invalid%20or%20expired%20sign-in%20attempt');
      const d = await getDiscovery();
      const body = new URLSearchParams({ grant_type: 'authorization_code', code: url.searchParams.get('code'), redirect_uri: REDIRECT_URI, code_verifier: tx.verifier });
      const headers = { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' };
      // Okta allows only one client credential method: Basic header (confidential) or client_id in body (public/PKCE)
      if (OKTA_CLIENT_SECRET) headers.Authorization = 'Basic ' + Buffer.from(`${encodeURIComponent(OKTA_CLIENT_ID)}:${encodeURIComponent(OKTA_CLIENT_SECRET)}`).toString('base64');
      else body.set('client_id', OKTA_CLIENT_ID);
      const tok = await (await fetch(d.token_endpoint, { method: 'POST', headers, body })).json();
      if (!tok.id_token) throw new Error(tok.error_description || 'Token exchange failed');
      const c = await verifyIdToken(tok.id_token, tx.nonce);
      let info = {};
      try { info = await (await fetch(d.userinfo_endpoint, { headers: { Authorization: `Bearer ${tok.access_token}` } })).json(); } catch {}
      const user = { sub: c.sub, name: info.name || c.name || c.preferred_username || c.email, email: info.email || c.email, username: c.preferred_username, locale: info.locale, zoneinfo: info.zoneinfo };
      const sid = b64u(crypto.randomBytes(32));
      sessions.set(sid, { user, idToken: tok.id_token, accessToken: tok.access_token, refreshToken: tok.refresh_token, claims: c, at: Date.now(), checked: Date.now(), exp: Date.now() + 8 * 3600e3 });
      setCookie(res, 'sid', sid, 8 * 3600);
      setCookie(res, 'revoked', '', 0);
      setCookie(res, 'oidc', '', 0);
      return redirect(res, tx.ret.startsWith('/') && !tx.ret.startsWith('//') ? tx.ret : '/');
    }
    if (url.pathname === '/logout') {
      setCookie(res, 'sid', '', 0); sessions.delete(cookies.sid);
      if (configured && session?.idToken) {
        const d = await getDiscovery();
        if (d.end_session_endpoint) return redirect(res, `${d.end_session_endpoint}?${new URLSearchParams({ id_token_hint: session.idToken, post_logout_redirect_uri: BASE_URL + '/' })}`);
      }
      return redirect(res, '/');
    }
    if (url.pathname === '/global-token-revocation' && req.method === 'POST') {
      if (!(await authorizeGtr(req))) { res.writeHead(401, { 'WWW-Authenticate': 'Bearer' }); return res.end(); }
      const id = subjectOf(await readBody(req));
      if (!id) return json(res, 400, { error: 'invalid_request', error_description: 'sub_id missing or unsupported' });
      revokeId(id);
      console.log(`GTR: revoked all sessions for ${id}`);
      res.writeHead(204); return res.end();
    }
    if (url.pathname === '/api/me') return json(res, 200, { loggedOut: !session && (wasRevoked || cookies.revoked === '1'), configured, user: session?.user || null, claims: session ? { iss: session.claims.iss, aud: session.claims.aud, iat: session.claims.iat, exp: session.claims.exp, amr: session.claims.amr } : null });
    if (url.pathname === '/api/products') return json(res, 200, PRODUCTS);

    // static
    let f = path.normalize(path.join(__dir, 'public', url.pathname === '/' ? 'index.html' : url.pathname));
    if (!f.startsWith(path.join(__dir, 'public')) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) f = path.join(__dir, 'public', 'index.html');
    res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] || 'application/octet-stream' });
    fs.createReadStream(f).pipe(res);
  } catch (e) {
    console.error(e);
    redirect(res, `/?autherror=${encodeURIComponent(e.message)}`);
  }
}).listen(PORT, () => {
  console.log(`Aurelle running at ${BASE_URL}`);
  console.log(configured ? `Okta issuer: ${OKTA_ISSUER}\nRedirect URI: ${REDIRECT_URI}` : 'Okta not configured — copy .env.example to .env (see README)');
});
