'use strict';
// RBF Forum ERP — zero-dependency Node app (member portal, admin, receipts, verification).
const http = require('http'), crypto = require('crypto'), fs = require('fs');
const { DatabaseSync } = require('node:sqlite');
const DATA = process.env.DATA_DIR || '/data';
fs.mkdirSync(DATA, { recursive: true });
const db = new DatabaseSync(DATA + '/rbf.db');
db.exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS members(id TEXT PRIMARY KEY, seq INTEGER, name_en TEXT, name_bn TEXT, role TEXT, role_bn TEXT, mobile TEXT UNIQUE, email TEXT, nominee TEXT, shares INTEGER DEFAULT 1, status TEXT DEFAULT 'active', pw TEXT, is_admin INTEGER DEFAULT 0, joined TEXT);
CREATE TABLE IF NOT EXISTS payments(no TEXT PRIMARY KEY, seq INTEGER, member_id TEXT, amount INTEGER, kind TEXT, paid_on TEXT, note TEXT, status TEXT DEFAULT 'valid', created TEXT, by TEXT);
CREATE TABLE IF NOT EXISTS notices(id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, body TEXT, created TEXT);
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);`);
const q = (s, ...a) => db.prepare(s).all(...a);
const q1 = (s, ...a) => db.prepare(s).get(...a);
const run = (s, ...a) => db.prepare(s).run(...a);
const today = () => new Date(Date.now() + 6 * 3600e3).toISOString().slice(0, 10);
const digits = s => String(s || '').replace(/\D/g, '');
const normMobile = s => { let d = digits(s); if (d.length === 13 && d.startsWith('880')) d = '0' + d.slice(3); return d; };

// ---- crypto
function hash(pw) { const salt = crypto.randomBytes(16).toString('hex'); return 'scrypt$' + salt + '$' + crypto.scryptSync(pw, salt, 32).toString('hex'); }
function check(pw, h) { try { const [, salt, x] = h.split('$'); const y = crypto.scryptSync(pw, salt, 32); return crypto.timingSafeEqual(y, Buffer.from(x, 'hex')); } catch { return false; } }
let secret = (q1("SELECT v FROM kv WHERE k='secret'") || {}).v;
if (!secret) { secret = crypto.randomBytes(32).toString('hex'); run("INSERT INTO kv VALUES('secret',?)", secret); }
const sign = s => crypto.createHmac('sha256', secret).update(s).digest('base64url');
function mkSession(uid) { const p = Buffer.from(JSON.stringify({ u: uid, e: Date.now() + 7 * 864e5 })).toString('base64url'); return p + '.' + sign(p); }
function readSession(req) {
  const m = /(?:^|;\s*)s=([^;]+)/.exec(req.headers.cookie || ''); if (!m) return null;
  const [p, sg] = m[1].split('.'); if (!p || !sg || sign(p) !== sg) return null;
  try { const o = JSON.parse(Buffer.from(p, 'base64url')); if (o.e < Date.now()) return null; return q1('SELECT * FROM members WHERE id=? AND status=?', o.u, 'active'); } catch { return null; }
}

// ---- seed (only when empty). ERP_SEED = base64(gzip(JSON)); never stored in git.
if (!q1('SELECT COUNT(*) c FROM members').c && process.env.ERP_SEED) {
  const seed = JSON.parse(require('zlib').gunzipSync(Buffer.from(process.env.ERP_SEED, 'base64')).toString());
  const ins = db.prepare('INSERT INTO members(id,seq,name_en,name_bn,role,role_bn,mobile,email,nominee,shares,pw,is_admin,joined) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)');
  seed.members.forEach((m, i) => ins.run(m.id, i + 1, m.en, m.bn, m.role, m.role_bn, normMobile(m.mobile), m.email || '', m.nominee || '', 1, hash(normMobile(m.mobile)), m.admin ? 1 : 0, '2026-11-01'));
  ins.run('admin', 0, 'Administrator', 'অ্যাডমিন', 'Administrator', 'অ্যাডমিনিস্ট্রেটর', 'admin', '', '', 0, hash(seed.admin_pw), 1, '2026-11-01');
  console.log('Seeded', seed.members.length, 'members');
}

// ---- html helpers
const e = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const money = n => 'BDT ' + Number(n || 0).toLocaleString('en-US');
const CSS = `*{box-sizing:border-box}body{margin:0;font-family:Inter,'Hind Siliguri',system-ui,sans-serif;background:#F5F6F8;color:#262B38}a{color:#12815A}
input,select,textarea,button{font-family:inherit}input:focus-visible,select:focus-visible,textarea:focus-visible,button:focus-visible,a:focus-visible{outline:3px solid #1CA270;outline-offset:2px}
.bn{font-family:'Hind Siliguri',Inter,sans-serif}.wrap{max-width:1100px;margin:0 auto;padding:0 20px}
.card{background:#fff;border:1px solid #E3E6EC;border-radius:18px;padding:22px}.grid{display:grid;gap:16px}
.btn{display:inline-flex;align-items:center;justify-content:center;min-height:46px;padding:0 20px;border-radius:12px;border:0;background:#12815A;color:#fff;font-weight:600;font-size:15px;cursor:pointer;text-decoration:none}
.btn.o{background:#fff;color:#262B38;border:1px solid #CBD0DA}.btn.d{background:#B3261E}.btn.s{min-height:36px;padding:0 12px;font-size:13.5px}
label{display:flex;flex-direction:column;gap:6px;font-size:13.5px;font-weight:600;color:#414859}
input,select,textarea{border:1px solid #CBD0DA;border-radius:12px;padding:0 14px;font-size:16px;min-height:48px;background:#fff}textarea{padding:12px 14px;min-height:96px}
table{width:100%;border-collapse:collapse;font-size:14.5px}th,td{text-align:left;padding:10px 8px;border-bottom:1px solid #E3E6EC;vertical-align:top}th{color:#5A6172;font-size:13px;font-weight:600}
.tag{display:inline-block;font-size:12.5px;font-weight:700;border-radius:999px;padding:3px 10px;background:#E3F5EC;color:#0D6446}.tag.x{background:#FDE7E5;color:#B3261E}
header.top{background:#fff;border-bottom:1px solid #E3E6EC}header.top .wrap{display:flex;align-items:center;gap:14px;min-height:64px;flex-wrap:wrap}
nav a{display:inline-flex;align-items:center;min-height:44px;padding:0 12px;border-radius:10px;text-decoration:none;color:#414859;font-weight:500;font-size:14.5px}nav a.on{background:#E3F5EC;color:#0D6446;font-weight:600}
.msg{padding:12px 16px;border-radius:12px;background:#E3F5EC;color:#0D6446;font-weight:600;margin-bottom:14px}.msg.err{background:#FDE7E5;color:#B3261E}
.stat{font-size:28px;font-weight:700;color:#12815A}.mut{color:#5A6172;font-size:14px}.scroll{overflow-x:auto}
@media print{header.top,nav,.noprint{display:none!important}body{background:#fff}.card{border:0}}`;
const page = (title, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${e(title)} · Riazuddin Bazar Forum</title><link rel="icon" href="https://rbdf.org/favicon.png"><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Hind+Siliguri:wght@400;600&family=Inter:wght@400;500;600;700&display=swap"><style>${CSS}</style></head><body>${body}</body></html>`;
const authBox = (title, sub, inner) => page(title, `<div style="min-height:100vh;background:linear-gradient(180deg,#fff,#EEF8F3);display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px 16px"><div style="width:100%;max-width:440px;background:#fff;border:1px solid #E3E6EC;border-radius:24px;padding:36px;box-shadow:0 18px 50px rgba(38,43,56,.1)"><img src="https://rbdf.org/logo.png" alt="Riazuddin Bazar Business Development Forum" style="display:block;width:190px;height:auto;margin:0 auto 20px"><h1 style="margin:0 0 6px;text-align:center;font-size:27px">${e(title)}</h1><p style="margin:0 0 22px;text-align:center;color:#5A6172;font-size:15px">${sub}</p>${inner}</div><div style="margin-top:22px;font-size:14px;color:#5A6172;text-align:center">Riazuddin Bazar Business Development Forum</div><a href="https://rbdf.org" style="display:flex;align-items:center;min-height:44px;font-size:14px;font-weight:600;text-decoration:none">← Back to website</a></div>`);
const loginPage = (err, user) => authBox('Member Login', 'Sign in with your registered mobile number or Member ID.', `${err ? `<div class="msg err">${e(err)}</div>` : ''}<form method="post" action="/login" style="display:grid;gap:16px"><label>Mobile number or Member ID<input name="username" value="${e(user)}" placeholder="01XXXXXXXXX or RBF-101" autocomplete="username" required></label><label>Password<input name="password" type="password" placeholder="Enter your password" autocomplete="current-password" required></label><button class="btn" style="min-height:52px;font-size:16px">Login</button></form><p class="mut" style="text-align:center;margin:16px 0 0">Your first password is your registered mobile number. Please change it after signing in.</p>`);

function shell(u, active, body, msg) {
  const adm = u.is_admin;
  const tabs = [['/', 'Home'], ['/payments', 'Payments'], ['/notices', 'Notices'], ['/password', 'Password']];
  const atabs = [['/admin', 'Dashboard'], ['/admin/members', 'Members'], ['/admin/payments', 'Payments'], ['/admin/notices', 'Notices']];
  const set = (adm && active.startsWith('/admin')) ? atabs : tabs;
  return page('Portal', `<header class="top"><div class="wrap"><img src="https://rbdf.org/logo.png" alt="RBF" style="height:38px"><nav style="flex:1;display:flex;flex-wrap:wrap;gap:4px">${set.map(([h, l]) => `<a href="${h}" class="${active === h ? 'on' : ''}">${l}</a>`).join('')}${adm ? (active.startsWith('/admin') ? '<a href="/">My Portal</a>' : '<a href="/admin">Admin</a>') : ''}</nav><span class="mut">${e(u.name_en)} · ${e(u.id)}</span><form method="post" action="/logout"><button class="btn o s">Logout</button></form></div></header><main class="wrap" style="padding:26px 20px 60px">${msg ? `<div class="msg ${msg.startsWith('!') ? 'err' : ''}">${e(msg.replace(/^!/, ''))}</div>` : ''}${body}</main>`);
}

// ---- request plumbing
const fails = new Map();
function body(req) { return new Promise((res, rej) => { let b = ''; req.on('data', c => { b += c; if (b.length > 30000) { rej(new Error('big')); req.destroy(); } }); req.on('end', () => res(Object.fromEntries(new URLSearchParams(b)))); }); }
function send(res, code, html, extra = {}) { res.writeHead(code, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin', 'Strict-Transport-Security': 'max-age=31536000', ...extra }); res.end(html); }
const redirect = (res, to, extra = {}) => { res.writeHead(303, { Location: to, ...extra }); res.end(); };
const cookie = v => `s=${v}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${v ? 604800 : 0}`;
const flash = m => encodeURIComponent(m);

function receiptCard(p, m, verifyUrl) {
  return `<div class="card" style="max-width:640px;margin:0 auto"><div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap"><img src="https://rbdf.org/logo.png" style="height:44px" alt="RBF"><span class="tag ${p.status === 'valid' ? '' : 'x'}">${p.status === 'valid' ? 'VALID' : 'CANCELLED'}</span></div><h2 style="margin:18px 0 4px">Payment Receipt</h2><div class="mut">Receipt No. <b>${e(p.no)}</b></div><table style="margin-top:14px"><tr><th>Member</th><td>${e(m.name_en)} (${e(m.id)})</td></tr><tr><th>Amount</th><td><b>${money(p.amount)}</b></td></tr><tr><th>For</th><td>${e(p.kind)}</td></tr><tr><th>Date</th><td>${e(p.paid_on)}</td></tr>${p.note ? `<tr><th>Note</th><td>${e(p.note)}</td></tr>` : ''}</table><p class="mut" style="margin-top:14px">Verify this receipt: ${e(verifyUrl)}</p><p class="mut">Riazuddin Bazar Business Development Forum, 92 Station Road, Kotwali, Chattogram.</p><button class="btn o noprint" onclick="print()">Print</button></div>`;
}

async function memberApp(req, res, url) {
  const p = url.pathname, msg = url.searchParams.get('m') || '';
  if (p === '/login' && req.method === 'POST') {
    const f = await body(req).catch(() => ({})); const raw = String(f.username || '').trim();
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0];
    const key = ip + '|' + raw.toLowerCase(); const rec = fails.get(key) || { n: 0, t: Date.now() };
    if (Date.now() - rec.t > 9e5) { rec.n = 0; rec.t = Date.now(); }
    if (rec.n >= 8) return send(res, 429, loginPage('Too many attempts. Please wait 15 minutes and try again.', raw));
    const isNum = /^[0-9+\s-]+$/.test(raw);
    const u = isNum ? q1('SELECT * FROM members WHERE mobile=? AND status=?', normMobile(raw), 'active') : q1('SELECT * FROM members WHERE lower(id)=lower(?) AND status=?', raw, 'active');
    if (!u || !check(String(f.password || ''), u.pw)) { rec.n++; fails.set(key, rec); return send(res, 401, loginPage('Wrong mobile number / Member ID or password.', raw)); }
    fails.delete(key); return redirect(res, u.is_admin && u.id === 'admin' ? '/admin' : '/', { 'Set-Cookie': cookie(mkSession(u.id)) });
  }
  if (p === '/logout') return redirect(res, '/login', { 'Set-Cookie': cookie('') });
  const u = readSession(req);
  if (p === '/login') return u ? redirect(res, '/') : send(res, 200, loginPage('', ''));
  if (p === '/healthz') return send(res, 200, 'ok');
  if (!u) return redirect(res, '/login');
  const post = req.method === 'POST' ? await body(req).catch(() => ({})) : {};
  const back = (to, m) => redirect(res, to + '?m=' + flash(m));

  // ---- member pages
  if (p === '/') {
    const mine = q('SELECT * FROM payments WHERE member_id=? AND status=? ORDER BY seq DESC', u.id, 'valid');
    const paid = mine.reduce((s, x) => s + x.amount, 0);
    return send(res, 200, shell(u, '/', `<div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(280px,1fr))"><div class="card"><div class="mut">Member ID</div><div class="stat">${e(u.id)}</div><h2 style="margin:10px 0 2px">${e(u.name_en)}</h2><div class="bn">${e(u.name_bn)}</div><div class="tag" style="margin-top:8px">${e(u.role)}</div></div><div class="card"><div class="mut">Shares</div><div class="stat">${u.shares}</div><div class="mut" style="margin-top:12px">Total paid</div><div class="stat">${money(paid)}</div></div><div class="card"><div class="mut">Registered mobile</div><div style="font-weight:600;margin:4px 0 12px">${e(u.mobile)}</div><div class="mut">Member since</div><div style="font-weight:600">${e(u.joined)}</div></div></div><h2 style="margin:28px 0 12px">Latest payments</h2>${payTable(mine.slice(0, 5))}`, msg));
  }
  if (p === '/payments') return send(res, 200, shell(u, '/payments', `<h1>My payments</h1>${payTable(q('SELECT * FROM payments WHERE member_id=? ORDER BY seq DESC', u.id))}`, msg));
  if (p === '/notices') return send(res, 200, shell(u, '/notices', `<h1>Notices</h1><div class="grid">${q('SELECT * FROM notices ORDER BY id DESC').map(n => `<div class="card"><div class="mut">${e(n.created)}</div><h3 style="margin:4px 0 8px">${e(n.title)}</h3><div style="white-space:pre-wrap;line-height:1.6">${e(n.body)}</div></div>`).join('') || '<div class="card mut">No notices yet.</div>'}</div>`, msg));
  if (p === '/password') {
    if (req.method === 'POST') {
      if (!check(String(post.old || ''), u.pw)) return back('/password', '!Current password is wrong.');
      if (String(post.new1 || '').length < 6 || post.new1 !== post.new2) return back('/password', '!New passwords must match and be at least 6 characters.');
      run('UPDATE members SET pw=? WHERE id=?', hash(post.new1), u.id); return back('/password', 'Password changed.');
    }
    return send(res, 200, shell(u, '/password', `<h1>Change password</h1><form method="post" class="card grid" style="max-width:440px"><label>Current password<input type="password" name="old" required></label><label>New password (min 6)<input type="password" name="new1" required minlength="6"></label><label>Repeat new password<input type="password" name="new2" required></label><button class="btn">Change password</button></form>`, msg));
  }
  let m2 = /^\/receipt\/([A-Za-z0-9-]+)$/.exec(p);
  if (m2) { const r = q1('SELECT * FROM payments WHERE no=?', m2[1]); if (!r || (r.member_id !== u.id && !u.is_admin)) return send(res, 404, shell(u, '', '<div class="card">Receipt not found.</div>')); return send(res, 200, shell(u, '', receiptCard(r, q1('SELECT * FROM members WHERE id=?', r.member_id), 'https://verify.rbdf.org/?r=' + r.no))); }

  // ---- admin
  if (p.startsWith('/admin')) {
    if (!u.is_admin) return send(res, 403, shell(u, '', '<div class="card">Admin access only.</div>'));
    if (p === '/admin') {
      const s = q1("SELECT (SELECT COUNT(*) FROM members WHERE id!='admin' AND status='active') mc, (SELECT COALESCE(SUM(shares),0) FROM members) sh, (SELECT COALESCE(SUM(amount),0) FROM payments WHERE status='valid') tot, (SELECT COUNT(*) FROM payments WHERE status='valid') pc");
      return send(res, 200, shell(u, '/admin', `<h1>Admin dashboard</h1><div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(200px,1fr))"><div class="card"><div class="mut">Members</div><div class="stat">${s.mc}</div></div><div class="card"><div class="mut">Total shares</div><div class="stat">${s.sh}</div></div><div class="card"><div class="mut">Total collected</div><div class="stat">${money(s.tot)}</div></div><div class="card"><div class="mut">Receipts issued</div><div class="stat">${s.pc}</div></div></div><h2 style="margin:28px 0 12px">Recent payments</h2>${payTable(q('SELECT * FROM payments ORDER BY seq DESC LIMIT 8'), true)}`, msg));
    }
    if (p === '/admin/members') return send(res, 200, shell(u, '/admin/members', `<h1>Members</h1><div class="card scroll"><table><tr><th>ID</th><th>Name</th><th>Role</th><th>Mobile</th><th>Shares</th><th>Status</th><th></th></tr>${q("SELECT * FROM members WHERE id!='admin' ORDER BY seq").map(m => `<tr><td>${e(m.id)}</td><td>${e(m.name_en)}<div class="bn mut">${e(m.name_bn)}</div></td><td>${e(m.role)}</td><td>${e(m.mobile)}</td><td>${m.shares}</td><td><span class="tag ${m.status === 'active' ? '' : 'x'}">${e(m.status)}</span></td><td><a href="/admin/members/${e(m.id)}">Edit</a></td></tr>`).join('')}</table></div>`, msg));
    let m3 = /^\/admin\/members\/([A-Za-z0-9-]+)$/.exec(p);
    if (m3) {
      const m = q1('SELECT * FROM members WHERE id=?', m3[1]); if (!m) return back('/admin/members', '!Member not found.');
      if (req.method === 'POST') {
        if (post.act === 'reset') { run('UPDATE members SET pw=? WHERE id=?', hash(m.mobile), m.id); return back('/admin/members/' + m.id, 'Password reset to the mobile number.'); }
        run('UPDATE members SET name_en=?,name_bn=?,role=?,mobile=?,email=?,nominee=?,shares=?,status=? WHERE id=?', String(post.name_en).trim(), String(post.name_bn).trim(), String(post.role).trim(), normMobile(post.mobile) || m.mobile, String(post.email || ''), String(post.nominee || ''), Math.max(0, parseInt(post.shares) || 0), post.status === 'inactive' ? 'inactive' : 'active', m.id);
        return back('/admin/members/' + m.id, 'Saved.');
      }
      return send(res, 200, shell(u, '/admin/members', `<h1>${e(m.id)} · ${e(m.name_en)}</h1><form method="post" class="card grid" style="max-width:560px"><label>Name (English)<input name="name_en" value="${e(m.name_en)}" required></label><label>Name (বাংলা)<input name="name_bn" value="${e(m.name_bn)}"></label><label>Role<input name="role" value="${e(m.role)}"></label><label>Mobile<input name="mobile" value="${e(m.mobile)}" required></label><label>Email<input name="email" value="${e(m.email)}"></label><label>Nominee<input name="nominee" value="${e(m.nominee)}"></label><label>Shares<input name="shares" type="number" min="0" value="${m.shares}"></label><label>Status<select name="status"><option ${m.status === 'active' ? 'selected' : ''}>active</option><option ${m.status === 'inactive' ? 'selected' : ''}>inactive</option></select></label><button class="btn">Save</button></form><form method="post" style="margin-top:14px"><input type="hidden" name="act" value="reset"><button class="btn o">Reset password to mobile number</button></form>`, msg));
    }
    if (p === '/admin/payments') {
      if (req.method === 'POST') {
        if (post.act === 'cancel') { run("UPDATE payments SET status='cancelled' WHERE no=?", post.no); return back('/admin/payments', 'Receipt ' + post.no + ' cancelled.'); }
        const m = q1('SELECT * FROM members WHERE id=?', post.member_id); const amt = parseInt(post.amount);
        if (!m || !(amt > 0)) return back('/admin/payments', '!Choose a member and enter a valid amount.');
        const yy = today().slice(2, 4), seq = q1("SELECT COALESCE(MAX(seq),0)+1 n FROM payments WHERE no LIKE ?", `RBF-${yy}-%`).n;
        const no = `RBF-${yy}-${String(seq).padStart(4, '0')}`;
        run('INSERT INTO payments(no,seq,member_id,amount,kind,paid_on,note,created,by) VALUES(?,?,?,?,?,?,?,?,?)', no, seq, m.id, amt, String(post.kind || 'Other'), String(post.paid_on || today()), String(post.note || ''), new Date().toISOString(), u.id);
        return redirect(res, '/receipt/' + no);
      }
      return send(res, 200, shell(u, '/admin/payments', `<h1>Record payment</h1><form method="post" class="card grid" style="max-width:560px"><label>Member<select name="member_id" required><option value="">Select…</option>${q("SELECT id,name_en FROM members WHERE id!='admin' AND status='active' ORDER BY seq").map(m => `<option value="${e(m.id)}">${e(m.id)} · ${e(m.name_en)}</option>`).join('')}</select></label><label>Amount (BDT)<input name="amount" type="number" min="1" required></label><label>For<select name="kind"><option>Share</option><option>Monthly Contribution</option><option>Registration</option><option>Other</option></select></label><label>Date<input name="paid_on" type="date" value="${today()}"></label><label>Note<input name="note"></label><button class="btn">Save &amp; issue receipt</button></form><h2 style="margin:28px 0 12px">All payments</h2>${payTable(q('SELECT * FROM payments ORDER BY seq DESC LIMIT 200'), true)}`, msg));
    }
    if (p === '/admin/notices') {
      if (req.method === 'POST') {
        if (post.act === 'del') run('DELETE FROM notices WHERE id=?', parseInt(post.id));
        else if (post.title) run('INSERT INTO notices(title,body,created) VALUES(?,?,?)', String(post.title).slice(0, 200), String(post.body || '').slice(0, 5000), today());
        return back('/admin/notices', 'Done.');
      }
      return send(res, 200, shell(u, '/admin/notices', `<h1>Notices</h1><form method="post" class="card grid" style="max-width:640px"><label>Title<input name="title" required></label><label>Details<textarea name="body"></textarea></label><button class="btn">Publish notice</button></form><div class="grid" style="margin-top:20px">${q('SELECT * FROM notices ORDER BY id DESC').map(n => `<div class="card"><div class="mut">${e(n.created)}</div><b>${e(n.title)}</b><div style="white-space:pre-wrap;margin:6px 0">${e(n.body)}</div><form method="post"><input type="hidden" name="act" value="del"><input type="hidden" name="id" value="${n.id}"><button class="btn d s">Delete</button></form></div>`).join('')}</div>`, msg));
    }
  }
  return send(res, 404, shell(u, '', '<div class="card">Page not found.</div>'));
}
function payTable(rows, admin) {
  if (!rows.length) return '<div class="card mut">No payments recorded yet.</div>';
  return `<div class="card scroll"><table><tr><th>Receipt</th>${admin ? '<th>Member</th>' : ''}<th>Date</th><th>For</th><th>Amount</th><th>Status</th>${admin ? '<th></th>' : ''}</tr>${rows.map(r => `<tr><td><a href="/receipt/${e(r.no)}">${e(r.no)}</a></td>${admin ? `<td>${e(r.member_id)}</td>` : ''}<td>${e(r.paid_on)}</td><td>${e(r.kind)}</td><td>${money(r.amount)}</td><td><span class="tag ${r.status === 'valid' ? '' : 'x'}">${r.status === 'valid' ? 'Valid' : 'Cancelled'}</span></td>${admin ? `<td>${r.status === 'valid' ? `<form method="post" action="/admin/payments"><input type="hidden" name="act" value="cancel"><input type="hidden" name="no" value="${e(r.no)}"><button class="btn d s">Cancel</button></form>` : ''}</td>` : ''}</tr>`).join('')}</table></div>`;
}

// ---- verification (public) — shows no private data
function verifyPage(no) {
  let result = '';
  if (no) {
    const r = q1('SELECT * FROM payments WHERE no=?', no.trim().toUpperCase());
    if (r && r.status === 'valid') { const m = q1('SELECT name_en,id FROM members WHERE id=?', r.member_id); result = `<div style="margin-top:22px;border:1px solid #BFE3D1;background:#F3FBF7;border-radius:16px;padding:18px 20px"><span class="tag" style="background:#12815A;color:#fff">VALID</span><table style="margin-top:10px"><tr><th>Receipt</th><td>${e(r.no)}</td></tr><tr><th>Member</th><td>${e(m.name_en)} (${e(m.id)})</td></tr><tr><th>Amount</th><td>${money(r.amount)}</td></tr><tr><th>Date</th><td>${e(r.paid_on)}</td></tr></table></div>`; }
    else result = `<div style="margin-top:22px;border:1px solid #F1B8B4;background:#FDE7E5;border-radius:16px;padding:18px 20px"><span class="tag x">INVALID</span><p style="margin:8px 0 0">This receipt number was not found or has been cancelled.</p></div>`;
  }
  return authBox('Receipt Verification', 'Scan the QR code on the receipt, or type the receipt number.', `<form method="get" action="/" style="display:grid;gap:16px"><label>Receipt number<input name="r" value="${e(no)}" placeholder="RBF-26-0001" required></label><button class="btn" style="min-height:52px;font-size:16px">Verify</button></form>${result}`);
}

http.createServer(async (req, res) => {
  try {
    const host = (req.headers.host || '').split(':')[0].toLowerCase();
    const url = new URL(req.url, 'https://' + host);
    if (req.method === 'POST') { const o = req.headers.origin; if (o && new URL(o).host !== host) return send(res, 403, 'Bad origin'); }
    if (host === 'verify.rbdf.org') return send(res, 200, verifyPage(url.searchParams.get('r') || ''));
    if (host === 'api.rbdf.org') {
      res.setHeader('Access-Control-Allow-Origin', '*');
      const j = (c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
      if (url.pathname === '/health' || url.pathname === '/') return j(200, { ok: true, service: 'rbf-api' });
      if (url.pathname === '/v1/verify') { const r = q1('SELECT no,amount,paid_on,status,member_id FROM payments WHERE no=?', (url.searchParams.get('no') || '').toUpperCase()); return j(200, r && r.status === 'valid' ? { valid: true, no: r.no, member_id: r.member_id, amount: r.amount, date: r.paid_on } : { valid: false }); }
      return j(404, { error: 'not found' });
    }
    return await memberApp(req, res, url);
  } catch (err) { console.error(err); send(res, 500, page('Error', '<div style="padding:40px">Something went wrong. Please try again.</div>')); }
}).listen(3000, () => console.log('RBF ERP listening on 3000'));
