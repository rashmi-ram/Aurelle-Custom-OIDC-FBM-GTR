const $ = (s) => document.querySelector(s);
const inr = (n) => '₹' + n.toLocaleString('en-IN');
const MEMBER_DISCOUNT = 0.10;
const store = { get: (k, d) => { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; } }, set: (k, v) => localStorage.setItem(k, JSON.stringify(v)) };
let me = { user: null, configured: false }, products = [], filter = 'All', query = '', sort = '';
let cart = store.get('cart', []), wish = store.get('wish', []);

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const shade = (hex, p) => { const n = parseInt(hex.slice(1), 16); const f = (v) => Math.max(0, Math.min(255, Math.round(v + (p > 0 ? (255 - v) : v) * p))); return `rgb(${f(n >> 16)},${f((n >> 8) & 255)},${f(n & 255)})`; };
const SHAPES = {
  dress: 'M80 40 L100 28 L120 40 L128 90 L150 215 Q100 235 50 215 L72 90 Z',
  shirt: 'M60 45 L85 32 Q100 48 115 32 L140 45 L170 95 L148 108 L140 90 L140 205 L60 205 L60 90 L52 108 L30 95 Z',
  skirt: 'M70 70 L130 70 L160 215 Q100 232 40 215 Z',
  pant: 'M68 55 L132 55 L142 215 L108 215 L100 120 L92 215 L58 215 Z',
  top: 'M65 50 L85 38 Q100 56 115 38 L135 50 L162 90 L140 105 L135 92 L135 170 L65 170 L65 92 L60 105 L38 90 Z',
  jacket: 'M62 45 L88 34 L100 60 L112 34 L138 45 L172 100 L150 112 L142 96 L142 205 L58 205 L58 96 L50 112 L28 100 Z',
};
const art = (p) => `<svg viewBox="0 0 200 267" preserveAspectRatio="xMidYMid slice"><defs><linearGradient id="g${p.id}" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="${shade(p.color, .75)}"/><stop offset="1" stop-color="${shade(p.color, .35)}"/></linearGradient></defs><rect width="200" height="267" fill="url(#g${p.id})"/><circle cx="165" cy="45" r="38" fill="#fff" opacity=".25"/><g transform="translate(0 18)"><path d="${SHAPES[p.shape]}" fill="${p.color}" stroke="${shade(p.color, -.25)}" stroke-width="2" stroke-linejoin="round"/><path d="${SHAPES[p.shape]}" fill="url(#g${p.id})" opacity=".18"/></g></svg>`;

function toast(m) { const t = $('#toast'); t.textContent = m; t.classList.add('on'); setTimeout(() => t.classList.remove('on'), 2200); }
function banner(msg, cls) { const b = $('#banner'); b.className = 'banner ' + (cls || ''); b.textContent = msg; b.hidden = false; }

// ---------- auth
function renderAuth() {
  const a = $('#auth');
  if (!me.user) {
    a.innerHTML = `<button class="btn primary sm" id="signin">Sign in</button>`;
    $('#signin').onclick = () => loginModal();
    $('#heroLogin').innerHTML = `<button class="btn ghost" id="heroSignin">Sign in for 10% off</button>`;
    $('#heroSignin').onclick = () => loginModal();
  } else {
    const n = me.user.name || me.user.email || 'Member', first = n.split(/[ @]/)[0];
    a.innerHTML = `<div class="user"><button id="ubtn"><span class="avatar">${esc(n[0].toUpperCase())}</span>Hi, ${esc(first)}</button>
      <div class="menu" id="umenu"><b>${esc(n)}</b><small>${esc(me.user.email || '')}</small><hr>
      <button id="acct">👤 My account &amp; token</button><button id="ord">📦 Orders</button><button id="out">⎋ Sign out</button></div></div>`;
    $('#ubtn').onclick = (e) => { e.stopPropagation(); $('#umenu').classList.toggle('open'); };
    $('#acct').onclick = accountModal; $('#ord').onclick = () => toast('No orders yet — go treat yourself!');
    $('#out').onclick = () => (location.href = '/logout');
    $('#heroLogin').innerHTML = `<span class="member">✨ Member pricing applied</span>`;
  }
}
document.addEventListener('click', () => $('#umenu')?.classList.remove('open'));

function modal(html) { const m = $('#modal'); m.innerHTML = html; m.classList.add('on'); m.onclick = (e) => { if (e.target === m) closeModal(); }; const c = m.querySelector('.close'); if (c) c.onclick = closeModal; }
function closeModal() { $('#modal').classList.remove('on'); }

function loginModal(ret) {
  modal(`<div class="sheet login"><button class="x close">✕</button>
    <h2>Welcome to Aurelle</h2><p>Sign in securely to see member prices, save your wishlist and check out faster.</p>
    <a class="btn primary okta" href="/login?return=${encodeURIComponent(ret || location.pathname)}">🔐 Continue with Okta</a>
    <p style="font-size:12px">We never see your password. Authentication is handled by Okta via OpenID Connect.</p>
    ${me.configured ? '' : `<div class="setup"><b>Okta isn't configured yet.</b><br>Copy <code>.env.example</code> to <code>.env</code>, fill in your Okta issuer and client ID, then restart. See the README.</div>`}</div>`);
}
function accountModal() {
  const c = me.claims || {}, d = (t) => (t ? new Date(t * 1000).toLocaleString() : '—');
  modal(`<div class="sheet login"><button class="x close">✕</button><div class="avatar" style="width:64px;height:64px;font-size:26px;margin:auto">${esc((me.user.name || 'M')[0].toUpperCase())}</div>
    <h2>${esc(me.user.name || 'Member')}</h2><p style="margin:0">${esc(me.user.email || '')}</p>
    <div class="claims"><div><span>Okta user ID</span><span>${esc(me.user.sub)}</span></div><div><span>Issuer</span><span>${esc(c.iss || '')}</span></div><div><span>Signed in</span><span>${d(c.iat)}</span></div><div><span>Session expires</span><span>${d(c.exp)}</span></div></div>
    <a class="btn ghost" style="margin-top:16px" href="/logout">Sign out</a></div>`);
}

// ---------- catalogue
function visible() {
  let l = products.filter((p) => (filter === 'All' || p.gender === filter || p.category === filter) && (p.name + p.category + p.gender).toLowerCase().includes(query.toLowerCase()));
  if (sort === 'lh') l.sort((a, b) => a.price - b.price); if (sort === 'hl') l.sort((a, b) => b.price - a.price); if (sort === 'rt') l.sort((a, b) => b.rating - a.rating);
  return l;
}
const price = (p) => me.user ? Math.round(p.price * (1 - MEMBER_DISCOUNT)) : p.price;
function renderGrid() {
  const l = visible();
  $('#title').textContent = query ? `Results for “${query}”` : filter === 'All' ? 'Trending now' : filter;
  $('#grid').innerHTML = l.length ? l.map((p) => `<div class="card" data-id="${p.id}"><div class="img">${art(p)}${p.badge ? `<span class="badge">${p.badge}</span>` : ''}<button class="heart ${wish.includes(p.id) ? 'on' : ''}" data-h="${p.id}" aria-label="Wishlist">${wish.includes(p.id) ? '♥' : '♡'}</button><span class="rate"><i>★</i> ${p.rating} | ${p.reviews}</span></div>
    <h3>${esc(p.name)}</h3><div class="cat">${p.gender} · ${p.category}</div>
    <div class="price"><b>${inr(price(p))}</b><s>${inr(p.mrp)}</s><em>(${Math.round((1 - price(p) / p.mrp) * 100)}% OFF)</em></div>
    ${me.user ? '<div class="member">✨ Member price</div>' : ''}</div>`).join('') : '<div class="empty">No styles found. Try another search.</div>';
}
function renderCats() {
  const c = ['All', 'Women', 'Men', 'Ethnic', 'Dresses'];
  $('#cats').innerHTML = c.map((x) => `<button class="${x === filter ? 'on' : ''}" data-c="${x}">${x}</button>`).join('');
}
$('#cats').onclick = (e) => { const c = e.target.dataset.c; if (c) { filter = c; query = ''; $('#q').value = ''; renderCats(); renderGrid(); } };
$('#q').oninput = (e) => { query = e.target.value; renderGrid(); };
$('#sort').onchange = (e) => { sort = e.target.value; renderGrid(); };
$('#grid').onclick = (e) => {
  const h = e.target.closest('[data-h]');
  if (h) { e.stopPropagation(); return toggleWish(+h.dataset.h); }
  const c = e.target.closest('.card'); if (c) productModal(+c.dataset.id);
};
function toggleWish(id) {
  if (!me.user) return loginModal(), toast('Sign in to save your wishlist');
  wish = wish.includes(id) ? wish.filter((x) => x !== id) : [...wish, id]; store.set('wish', wish); renderGrid(); counts();
}
function productModal(id) {
  const p = products.find((x) => x.id === id); let size = 'M';
  modal(`<div class="sheet"><button class="x close">✕</button><div class="pic">${art(p)}</div><div class="info">
    <h2>${esc(p.name)}</h2><div class="cat" style="color:var(--muted)">${p.gender} · ${p.category} · ★ ${p.rating} (${p.reviews})</div>
    <div class="price" style="font-size:22px;margin:14px 0"><b>${inr(price(p))}</b><s>${inr(p.mrp)}</s><em>(${Math.round((1 - price(p) / p.mrp) * 100)}% OFF)</em></div>
    ${me.user ? '<div class="member">✨ Includes your 10% member discount</div>' : `<div class="member"><a href="#" id="mlogin" style="text-decoration:underline">Sign in</a> to save an extra 10%</div>`}
    <p style="color:var(--muted);line-height:1.6;font-size:14px">Soft, breathable fabric with a flattering fit. Machine washable. Inclusive of all taxes.</p>
    <b style="font-size:13px">SELECT SIZE</b><div class="sizes">${['XS', 'S', 'M', 'L', 'XL'].map((s) => `<button class="${s === 'M' ? 'on' : ''}">${s}</button>`).join('')}</div>
    <button class="btn primary" id="add" style="width:100%">Add to bag</button>
    <button class="btn ghost" id="wl" style="width:100%;margin-top:10px">${wish.includes(id) ? '♥ Wishlisted' : '♡ Wishlist'}</button></div></div>`);
  $('.sizes').onclick = (e) => { if (e.target.tagName === 'BUTTON') { size = e.target.textContent; document.querySelectorAll('.sizes button').forEach((b) => b.classList.toggle('on', b === e.target)); } };
  $('#add').onclick = () => { const k = cart.find((x) => x.id === id && x.size === size); k ? k.q++ : cart.push({ id, size, q: 1 }); store.set('cart', cart); counts(); closeModal(); openDrawer(); };
  $('#wl').onclick = () => { closeModal(); toggleWish(id); };
  $('#mlogin')?.addEventListener('click', (e) => { e.preventDefault(); loginModal(); });
}

// ---------- bag
function counts() { $('#cartCount').textContent = cart.reduce((a, b) => a + b.q, 0) || ''; $('#wishCount').textContent = wish.length || ''; }
function openDrawer() { renderDrawer(); $('#drawer').classList.add('on'); $('#overlay').classList.add('on'); }
function closeDrawer() { $('#drawer').classList.remove('on'); $('#overlay').classList.remove('on'); }
$('#overlay').onclick = closeDrawer; $('#cartBtn').onclick = openDrawer;
$('#wishBtn').onclick = () => { if (!me.user) return loginModal(); filter = 'All'; const w = products.filter((p) => wish.includes(p.id)); w.length ? (query = '', renderWishOnly(w)) : toast('Your wishlist is empty'); };
function renderWishOnly(w) { $('#title').textContent = 'Your wishlist'; const keep = visible; const ids = w.map((p) => p.id); const orig = products; products = orig.filter((p) => ids.includes(p.id)); renderGrid(); products = orig; document.getElementById('shop').scrollIntoView(); }
function renderDrawer() {
  const items = cart.map((c) => ({ ...c, p: products.find((p) => p.id === c.id) }));
  const mrp = items.reduce((a, i) => a + i.p.price * i.q, 0), tot = items.reduce((a, i) => a + price(i.p) * i.q, 0), save = mrp - tot, ship = tot >= 1999 || !tot ? 0 : 99;
  $('#drawer').innerHTML = `<header><h3>Your bag (${items.reduce((a, b) => a + b.q, 0)})</h3><button class="x" id="dx">✕</button></header>
  <div class="body">${items.length ? items.map((i, n) => `<div class="row"><div class="t">${art(i.p)}</div><div class="i"><b>${esc(i.p.name)}</b><small>Size ${i.size}</small><b>${inr(price(i.p))}</b>
    <div><div class="qty"><button data-d="${n}" data-v="-1">−</button><span>${i.q}</span><button data-d="${n}" data-v="1">+</button></div></div></div></div>`).join('') : '<div class="empty">🛍️<br>Your bag is empty</div>'}</div>
  ${items.length ? `<div class="foot">${me.user ? `<div class="sum disc"><span>Member savings</span><span>− ${inr(save)}</span></div>` : `<div class="sum member"><span>Sign in to save 10% on this bag</span></div>`}
    <div class="sum"><span>Delivery</span><span>${ship ? inr(ship) : 'FREE'}</span></div><div class="sum tot"><span>Total</span><span>${inr(tot + ship)}</span></div>
    <button class="btn primary" id="co" style="width:100%;margin-top:12px">${me.user ? 'Checkout' : 'Sign in to checkout'}</button></div>` : ''}`;
  $('#dx').onclick = closeDrawer;
  $('#drawer').querySelectorAll('[data-d]').forEach((b) => (b.onclick = () => { const i = cart[+b.dataset.d]; i.q += +b.dataset.v; if (i.q <= 0) cart.splice(+b.dataset.d, 1); store.set('cart', cart); counts(); renderDrawer(); }));
  $('#co')?.addEventListener('click', () => { if (!me.user) { closeDrawer(); return loginModal(); } cart = []; store.set('cart', cart); counts(); closeDrawer(); toast('🎉 Order placed! (demo)'); });
}

// ---------- boot
async function init() {
  const qs = new URLSearchParams(location.search);
  [me, products] = await Promise.all([fetch('/api/me').then((r) => r.json()), fetch('/api/products').then((r) => r.json())]);
  if (me.loggedOut) {
    banner('🔒 You\'ve been signed out. Your session was ended for security reasons by your administrator. Please sign in again to continue.', 'err');
    const b = document.createElement('button'); b.className = 'btn primary sm'; b.style.marginLeft = '14px'; b.textContent = 'Sign in again'; b.onclick = () => loginModal(); $('#banner').append(b);
  } else if (qs.get('autherror')) banner('Sign-in failed: ' + qs.get('autherror'), 'err');
  else if (qs.get('setup')) banner('Okta is not configured yet — add your credentials to .env and restart the server.');
  else if (me.user && sessionStorage.getItem('justLogin') !== '1' && document.referrer === '' && qs.size === 0) { /* normal load */ }
  if (qs.size) history.replaceState({}, '', location.pathname);
  renderAuth(); renderCats(); renderGrid(); counts();
  if (qs.get('setup')) loginModal();
}
init();
// notice a revocation without waiting for a manual refresh
setInterval(async () => { if (me.user && !(await fetch('/api/me').then((r) => r.json())).user) location.reload(); }, 20000);
