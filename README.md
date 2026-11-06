# Aurelle — Fashion storefront with Okta OIDC login

Zero-dependency Node.js (18+) app. Uses **Authorization Code flow with PKCE**, validates the ID token
(signature via JWKS, issuer, audience, nonce, expiry), and keeps a signed HttpOnly session cookie.

## 1. Create the Okta app
Okta Admin → Applications → Create App Integration → **OIDC – OpenID Connect → Web Application**
- Sign-in redirect URI: `http://localhost:3000/callback`
- Sign-out redirect URI: `http://localhost:3000/`
- Assign yourself / a group to the app.

## 2. Configure
```
cp .env.example .env     # fill in OKTA_ISSUER, OKTA_CLIENT_ID, OKTA_CLIENT_SECRET, SESSION_SECRET
npm start
```
`OKTA_ISSUER` is your authorization server, e.g. `https://dev-123456.okta.com/oauth2/default`
(use `https://<domain>.okta.com` for the org server, or a custom auth server URL / custom domain).

Open http://localhost:3000. Without `.env` the shop still works; the Sign in button shows setup help.

## Features
Sign in with Okta · member-only 10% pricing · wishlist (login-gated) · bag & checkout (demo) ·
search, filters, sorting · account panel with ID-token claims · RP-initiated logout.
