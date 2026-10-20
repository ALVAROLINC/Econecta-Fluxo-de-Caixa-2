// Servidor do Fluxo Fácil: cadastro, login por e-mail e senha, sessão segura,
// dados de cada pessoa separados, avisos por e-mail. Só usa recursos do próprio Node.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { openDb } from './db.js';
import { hashPassword, verifyPassword, checkPolicy, DUMMY_HASH } from './passwords.js';
import { createMailer } from './mailer.js';
import { sha256, rand, hmac, safeEq, normEmail, parseCookies, serializeCookie, MIN, HOUR, DAY, ymd } from './util.js';
import { emailConfirmar, emailContaJaExiste, emailRedefinir, emailSenhaAlterada, emailContaApagada, emailAvisos } from './emails.js';
import { computeDigest, digestCount } from './digest.js';

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json; charset=utf-8', '.txt': 'text/plain; charset=utf-8' };
const MAX_BODY = 1024 * 1024;
const GENERICO = 'Algo deu errado. Tente de novo em instantes.';

export function createApp(cfg) {
  const db = openDb(cfg.dbPath);
  const mailer = createMailer(cfg);
  const COOKIE = cfg.prod ? '__Host-ff_sid' : 'ff_sid';
  const now = () => Date.now();
  const log = (...a) => { if (!cfg.quiet) console.log(...a); };

  /* ---------- limites de tentativas (guardados no banco, valem após reiniciar) ---------- */
  const hit = (kind, key) => db.prepare('INSERT INTO attempts(kind,key,at) VALUES(?,?,?)').run(kind, key, now());
  const count = (kind, key, win) => db.prepare('SELECT COUNT(*) AS c FROM attempts WHERE kind=? AND key=? AND at>?').get(kind, key, now() - win).c;
  const clearAttempts = (kind, key) => db.prepare('DELETE FROM attempts WHERE kind=? AND key=?').run(kind, key);
  const audit = (event, who, ip) => db.prepare('INSERT INTO audit(at,event,who,ip) VALUES(?,?,?,?)').run(now(), event, who ? sha256(who).slice(0, 12) : null, ip || null);

  function cleanup() {
    const t = now();
    db.prepare('DELETE FROM attempts WHERE at<?').run(t - DAY);
    db.prepare('DELETE FROM sessions WHERE expires_at<? OR last_seen<?').run(t, t - cfg.idleDays * DAY);
    db.prepare('DELETE FROM tokens WHERE expires_at<?').run(t - DAY);
    // contas que nunca confirmaram o e-mail somem depois de 7 dias
    db.prepare('DELETE FROM users WHERE email_verified_at IS NULL AND created_at<?').run(t - 7 * DAY);
  }

  /* ---------- sessões ---------- */
  function newSession(userId, req) {
    const token = rand(32), t = now();
    db.prepare('INSERT INTO sessions(id_hash,user_id,created_at,last_seen,expires_at,ip,ua) VALUES(?,?,?,?,?,?,?)')
      .run(sha256(token), userId, t, t, t + cfg.sessionDays * DAY, req.ip, String(req.headers['user-agent'] || '').slice(0, 200));
    return token;
  }
  function sessionFrom(req) {
    const tok = parseCookies(req.headers.cookie)[COOKIE];
    if (!tok || tok.length > 100) return null;
    const row = db.prepare('SELECT s.id_hash, s.user_id, s.last_seen, s.expires_at, u.email, u.notify FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = ?').get(sha256(tok));
    if (!row) return null;
    const t = now();
    if (row.expires_at < t || row.last_seen < t - cfg.idleDays * DAY) { db.prepare('DELETE FROM sessions WHERE id_hash=?').run(row.id_hash); return null; }
    if (t - row.last_seen > 5 * MIN) db.prepare('UPDATE sessions SET last_seen=? WHERE id_hash=?').run(t, row.id_hash);
    return { hash: row.id_hash, userId: row.user_id, email: row.email, notify: !!row.notify };
  }
  const sessionCookie = (token) => serializeCookie(COOKIE, token, { maxAge: cfg.sessionDays * DAY / 1000, secure: cfg.prod, httpOnly: true, sameSite: 'Lax' });
  const expiredCookie = () => serializeCookie(COOKIE, '', { maxAge: 0, secure: cfg.prod, httpOnly: true, sameSite: 'Lax' });

  /* ---------- códigos de uso único (confirmar e-mail, trocar senha) ---------- */
  function createToken(userId, kind, ttl) {
    db.prepare('DELETE FROM tokens WHERE user_id=? AND kind=? AND used_at IS NULL').run(userId, kind);
    const raw = rand(32);
    db.prepare('INSERT INTO tokens(hash,user_id,kind,expires_at) VALUES(?,?,?,?)').run(sha256(raw), userId, kind, now() + ttl);
    return raw;
  }
  function consumeToken(raw, kind) {
    if (typeof raw !== 'string' || raw.length < 20 || raw.length > 100) return null;
    const h = sha256(raw);
    const row = db.prepare('SELECT user_id, expires_at FROM tokens WHERE hash=? AND kind=? AND used_at IS NULL').get(h, kind);
    if (!row || row.expires_at < now()) return null;
    const r = db.prepare('UPDATE tokens SET used_at=? WHERE hash=? AND used_at IS NULL').run(now(), h);
    return r.changes === 1 ? row.user_id : null;
  }

  async function mail(to, tpl) {
    try { await mailer.send({ to, ...tpl }); return true; }
    catch (e) { console.error('Falha ao enviar e-mail:', e.message); return false; }
  }
  const unsubUrl = (id) => `${cfg.appUrl}/sair-emails?u=${id}&t=${hmac(cfg.secret, 'unsub:' + id)}`;
  const quando = () => new Date().toLocaleString('pt-BR', { dateStyle: 'long', timeStyle: 'short' });

  /* ---------- rotas da API ---------- */
  const routes = {};
  const route = (method, p, handler, { auth = false } = {}) => { routes[`${method} ${p}`] = { handler, auth }; };
  const bad = (code, message, status = 400) => ({ status, body: { error: code, message } });
  const ok = (body = { ok: true }, extra = {}) => ({ status: 200, body, ...extra });

  route('POST', '/api/auth/criar-conta', async ({ body, ip }) => {
    const email = normEmail(body.email), senha = String(body.senha ?? '');
    if (!email) return bad('email_invalido', 'Confira o e-mail: ele parece estar incompleto.');
    const pol = checkPolicy(senha, email); if (pol) return bad('senha_fraca', pol);
    if (body.consentimento !== true) return bad('sem_consentimento', 'Para criar a conta, marque que você leu e aceita os termos.');
    if (count('signup_ip', ip, HOUR) >= 10) return bad('muitas_tentativas', 'Muitas tentativas. Tente de novo mais tarde.', 429);
    hit('signup_ip', ip);
    const hash = await hashPassword(senha); // sempre calcula, para o tempo de resposta ser igual
    const existente = db.prepare('SELECT id, email_verified_at FROM users WHERE email=?').get(email);
    const aviso = ok({ ok: true, message: `Enviamos um e-mail para ${email}. Abra o e-mail e toque em “Confirmar”. Se não achar, olhe também a caixa de spam.` });
    if (existente) {
      if (count('mail_email', sha256(email), HOUR) < 3) {
        hit('mail_email', sha256(email));
        if (existente.email_verified_at) {
          await mail(email, emailContaJaExiste({ url: `${cfg.appUrl}/?esqueci=1` }));
        } else {
          // ainda não confirmou: vale a senha do pedido mais recente, com um link novo.
          // (evita que alguém "reserve" o e-mail de outra pessoa com uma senha que só ele conhece)
          db.prepare('UPDATE users SET pass_hash=?, consent_at=? WHERE id=?').run(hash, now(), existente.id);
          await mail(email, emailConfirmar({ url: `${cfg.appUrl}/?verificar=${createToken(existente.id, 'verify', 24 * HOUR)}` }));
        }
      }
      return aviso;
    }
    const r = db.prepare('INSERT INTO users(email,pass_hash,notify,consent_at,created_at) VALUES(?,?,1,?,?)').run(email, hash, now(), now());
    const token = createToken(Number(r.lastInsertRowid), 'verify', 24 * HOUR);
    hit('mail_email', sha256(email));
    await mail(email, emailConfirmar({ url: `${cfg.appUrl}/?verificar=${token}` }));
    audit('conta_criada', email, ip);
    return aviso;
  });

  route('POST', '/api/auth/confirmar-email', ({ body, ip }) => {
    if (count('token_ip', ip, HOUR) >= 30) return bad('muitas_tentativas', 'Muitas tentativas. Tente de novo mais tarde.', 429);
    hit('token_ip', ip);
    const uid = consumeToken(body.token, 'verify');
    if (!uid) return bad('link_invalido', 'Este link não vale mais. Peça um novo e-mail de confirmação.');
    db.prepare('UPDATE users SET email_verified_at=? WHERE id=?').run(now(), uid);
    audit('email_confirmado', String(uid), ip);
    return ok({ ok: true, message: 'E-mail confirmado! Agora é só entrar.' });
  });

  route('POST', '/api/auth/reenviar', async ({ body, ip }) => {
    const email = normEmail(body.email);
    const resp = ok({ ok: true, message: 'Se este e-mail tiver uma conta esperando confirmação, enviamos um novo e-mail.' });
    if (!email || count('mail_ip', ip, HOUR) >= 10) return resp;
    hit('mail_ip', ip);
    const u = db.prepare('SELECT id, email_verified_at FROM users WHERE email=?').get(email);
    if (u && !u.email_verified_at && count('mail_email', sha256(email), HOUR) < 3) {
      hit('mail_email', sha256(email));
      await mail(email, emailConfirmar({ url: `${cfg.appUrl}/?verificar=${createToken(u.id, 'verify', 24 * HOUR)}` }));
    }
    return resp;
  });

  route('POST', '/api/auth/entrar', async ({ body, ip, req }) => {
    const email = normEmail(body.email), senha = String(body.senha ?? '');
    if (!email || !senha || senha.length > 128) return bad('dados_invalidos', 'Preencha o e-mail e a senha.');
    if (count('login_ip', ip, 15 * MIN) >= 30) return bad('muitas_tentativas', 'Muitas tentativas. Aguarde alguns minutos e tente de novo.', 429);
    const ek = sha256(email);
    if (count('login_fail', ek, 15 * MIN) >= 5) return bad('muitas_tentativas', 'Muitas tentativas erradas. Por segurança, aguarde 15 minutos ou use “Esqueci minha senha”.', 429);
    hit('login_ip', ip);
    const u = db.prepare('SELECT id, pass_hash, email_verified_at FROM users WHERE email=?').get(email);
    const certo = await verifyPassword(senha, u ? u.pass_hash : DUMMY_HASH);
    if (!u || !certo) { hit('login_fail', ek); audit('login_falhou', email, ip); return bad('credenciais', 'E-mail ou senha incorretos.', 401); }
    if (!u.email_verified_at) return bad('email_nao_confirmado', 'Falta confirmar o seu e-mail. Abra a mensagem que enviamos e toque em “Confirmar”.', 403);
    clearAttempts('login_fail', ek);
    const token = newSession(u.id, req);
    audit('login_ok', email, ip);
    return ok({ ok: true, email }, { cookie: sessionCookie(token) });
  });

  route('POST', '/api/auth/sair', ({ session }) => {
    db.prepare('DELETE FROM sessions WHERE id_hash=?').run(session.hash);
    return ok({ ok: true }, { cookie: expiredCookie() });
  }, { auth: true });

  route('POST', '/api/auth/esqueci', async ({ body, ip }) => {
    const email = normEmail(body.email);
    const resp = ok({ ok: true, message: `Se ${email || 'este e-mail'} tiver conta, enviamos um e-mail com o link para criar uma nova senha.` });
    if (!email || count('mail_ip', ip, HOUR) >= 10) return resp;
    hit('mail_ip', ip);
    const u = db.prepare('SELECT id, email_verified_at FROM users WHERE email=?').get(email);
    if (u && count('mail_email', sha256(email), HOUR) < 3) {
      hit('mail_email', sha256(email));
      if (u.email_verified_at) await mail(email, emailRedefinir({ url: `${cfg.appUrl}/?redefinir=${createToken(u.id, 'reset', 30 * MIN)}` }));
      else await mail(email, emailConfirmar({ url: `${cfg.appUrl}/?verificar=${createToken(u.id, 'verify', 24 * HOUR)}` }));
      audit('senha_solicitada', email, ip);
    }
    return resp;
  });

  route('POST', '/api/auth/redefinir', async ({ body, ip }) => {
    if (count('token_ip', ip, HOUR) >= 30) return bad('muitas_tentativas', 'Muitas tentativas. Tente de novo mais tarde.', 429);
    hit('token_ip', ip);
    const senha = String(body.senha ?? '');
    // confere o link antes de gastar o código: se a senha for fraca a pessoa pode tentar de novo
    const h = sha256(String(body.token ?? ''));
    const row = db.prepare('SELECT u.id, u.email FROM tokens t JOIN users u ON u.id=t.user_id WHERE t.hash=? AND t.kind=? AND t.used_at IS NULL AND t.expires_at>?').get(h, 'reset', now());
    if (!row) return bad('link_invalido', 'Este link não vale mais. Peça um novo em “Esqueci minha senha”.');
    const pol = checkPolicy(senha, row.email); if (pol) return bad('senha_fraca', pol);
    const uid = consumeToken(body.token, 'reset');
    if (!uid) return bad('link_invalido', 'Este link não vale mais. Peça um novo em “Esqueci minha senha”.');
    const hash = await hashPassword(senha);
    db.prepare('UPDATE users SET pass_hash=?, email_verified_at=COALESCE(email_verified_at,?) WHERE id=?').run(hash, now(), uid);
    db.prepare('DELETE FROM sessions WHERE user_id=?').run(uid); // derruba todos os aparelhos
    clearAttempts('login_fail', sha256(row.email));
    audit('senha_redefinida', row.email, ip);
    await mail(row.email, emailSenhaAlterada({ quando: quando(), url: `${cfg.appUrl}/?esqueci=1` }));
    return ok({ ok: true, message: 'Senha criada! Agora é só entrar com a nova senha.' });
  });

  route('GET', '/api/eu', ({ session }) => ok({ email: session.email, avisos: session.notify }), { auth: true });

  route('PUT', '/api/eu/avisos', ({ body, session }) => {
    if (typeof body.ligado !== 'boolean') return bad('dados_invalidos', 'Pedido inválido.');
    db.prepare('UPDATE users SET notify=? WHERE id=?').run(body.ligado ? 1 : 0, session.userId);
    return ok({ ok: true, avisos: body.ligado });
  }, { auth: true });

  route('POST', '/api/eu/senha', async ({ body, session, ip }) => {
    const atual = String(body.atual ?? ''), nova = String(body.nova ?? '');
    if (count('pw_fail', String(session.userId), 15 * MIN) >= 5) return bad('muitas_tentativas', 'Muitas tentativas erradas. Aguarde 15 minutos.', 429);
    const u = db.prepare('SELECT pass_hash FROM users WHERE id=?').get(session.userId);
    if (!(await verifyPassword(atual, u.pass_hash))) { hit('pw_fail', String(session.userId)); return bad('senha_atual', 'A senha atual está incorreta.', 403); }
    const pol = checkPolicy(nova, session.email); if (pol) return bad('senha_fraca', pol);
    if (nova === atual) return bad('senha_igual', 'A nova senha precisa ser diferente da atual.');
    db.prepare('UPDATE users SET pass_hash=? WHERE id=?').run(await hashPassword(nova), session.userId);
    db.prepare('DELETE FROM sessions WHERE user_id=? AND id_hash<>?').run(session.userId, session.hash); // sai dos outros aparelhos
    clearAttempts('pw_fail', String(session.userId));
    audit('senha_trocada', session.email, ip);
    await mail(session.email, emailSenhaAlterada({ quando: quando(), url: `${cfg.appUrl}/?esqueci=1` }));
    return ok({ ok: true, message: 'Senha trocada. Os outros aparelhos foram desconectados.' });
  }, { auth: true });

  route('DELETE', '/api/eu', async ({ body, session, ip }) => {
    if (count('del_fail', String(session.userId), HOUR) >= 5) return bad('muitas_tentativas', 'Muitas tentativas erradas. Aguarde uma hora.', 429);
    const u = db.prepare('SELECT pass_hash FROM users WHERE id=?').get(session.userId);
    if (!(await verifyPassword(String(body.senha ?? ''), u.pass_hash))) { hit('del_fail', String(session.userId)); return bad('senha_atual', 'A senha está incorreta.', 403); }
    db.prepare('DELETE FROM users WHERE id=?').run(session.userId); // apaga sessões, códigos e dados junto
    audit('conta_apagada', session.email, ip);
    await mail(session.email, emailContaApagada());
    return ok({ ok: true }, { cookie: expiredCookie() });
  }, { auth: true });

  route('GET', '/api/dados', ({ session }) => {
    const r = db.prepare('SELECT json, updated_at FROM user_data WHERE user_id=?').get(session.userId);
    return ok({ dados: r ? JSON.parse(r.json) : null, atualizadoEm: r ? r.updated_at : null });
  }, { auth: true });

  const dadosValidos = (d) => d && typeof d === 'object' && !Array.isArray(d) && Array.isArray(d.cats) && Array.isArray(d.lanc)
    && d.cats.length <= 500 && d.lanc.length <= 20000 && typeof d.saldoInicial === 'number' && Number.isFinite(d.saldoInicial);
  route('PUT', '/api/dados', ({ body, session }) => {
    if (!dadosValidos(body.dados)) return bad('dados_invalidos', 'Os dados enviados não são válidos.');
    // o "dono" dos dados vem sempre da sessão, nunca do que o navegador envia
    db.prepare('INSERT INTO user_data(user_id,json,updated_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET json=excluded.json, updated_at=excluded.updated_at')
      .run(session.userId, JSON.stringify(body.dados), now());
    return ok({ ok: true });
  }, { auth: true });

  route('GET', '/api/exportar', ({ session }) => {
    const r = db.prepare('SELECT json FROM user_data WHERE user_id=?').get(session.userId);
    return { status: 200, body: { email: session.email, exportadoEm: new Date().toISOString(), dados: r ? JSON.parse(r.json) : null }, headers: { 'Content-Disposition': 'attachment; filename="fluxo-facil-meus-dados.json"' } };
  }, { auth: true });

  /* ---------- avisos por e-mail ---------- */
  async function runDigest({ now: when = new Date(), force = false } = {}) {
    if (!force && when.getHours() < cfg.digestHour) return { sent: 0 };
    const today = ymd(when);
    const users = db.prepare('SELECT id, email FROM users WHERE email_verified_at IS NOT NULL AND notify=1 AND (last_digest_on IS NULL OR last_digest_on<>?)').all(today);
    let sent = 0;
    for (const u of users) {
      db.prepare('UPDATE users SET last_digest_on=? WHERE id=?').run(today, u.id);
      const row = db.prepare('SELECT json FROM user_data WHERE user_id=?').get(u.id);
      if (!row) continue;
      let data; try { data = JSON.parse(row.json); } catch { continue; }
      const d = computeDigest(data, today);
      if (!digestCount(d)) continue;
      const okSend = await mail(u.email, emailAvisos({ d, appUrl: cfg.appUrl, unsubUrl: unsubUrl(u.id) }));
      if (okSend) sent++; else db.prepare('UPDATE users SET last_digest_on=NULL WHERE id=?').run(u.id);
    }
    return { sent };
  }

  /* ---------- servidor HTTP ---------- */
  function securityHeaders(res) {
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    if (cfg.prod) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  function send(res, status, body, headers = {}) {
    const isStr = typeof body === 'string';
    const data = isStr ? body : JSON.stringify(body);
    res.writeHead(status, { 'Content-Type': isStr ? 'text/html; charset=utf-8' : 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(data), ...headers });
    res.end(data);
  }
  function readBody(req) {
    return new Promise((resolve, reject) => {
      const chunks = []; let size = 0;
      req.on('data', (c) => { size += c.length; if (size > MAX_BODY) { reject(Object.assign(new Error('grande'), { status: 413 })); req.destroy(); } else chunks.push(c); });
      req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      req.on('error', reject);
    });
  }
  function clientIp(req) {
    if (cfg.trustProxy) { const x = String(req.headers['x-forwarded-for'] || '').split(',').pop().trim(); if (x) return x; }
    return req.socket.remoteAddress || 'desconhecido';
  }

  async function handleApi(req, res, url) {
    const method = req.method;
    send0: {
      const r = routes[`${method} ${url.pathname}`];
      if (!r) break send0;
      // CSRF: pedidos que mudam algo precisam do cabeçalho próprio e vir do mesmo site
      if (method !== 'GET') {
        if (req.headers['x-requested-with'] !== 'fluxo-facil') return send(res, 403, { error: 'pedido_bloqueado', message: 'Pedido bloqueado por segurança.' });
        const origin = req.headers.origin;
        if (origin) { let ho = ''; try { ho = new URL(origin).host; } catch { /* ok */ } if (ho !== req.headers.host) return send(res, 403, { error: 'pedido_bloqueado', message: 'Pedido bloqueado por segurança.' }); }
      }
      let body = {};
      if (method === 'POST' || method === 'PUT' || method === 'DELETE') {
        const raw = await readBody(req);
        if (raw) {
          if (!String(req.headers['content-type'] || '').startsWith('application/json')) return send(res, 415, { error: 'formato', message: 'Formato não aceito.' });
          try { body = JSON.parse(raw); } catch { return send(res, 400, { error: 'json_invalido', message: 'Pedido inválido.' }); }
          if (!body || typeof body !== 'object' || Array.isArray(body)) return send(res, 400, { error: 'json_invalido', message: 'Pedido inválido.' });
        }
      }
      const session = sessionFrom(req);
      if (r.auth && !session) return send(res, 401, { error: 'nao_autenticado', message: 'Entre na sua conta para continuar.' });
      const out = await r.handler({ req, body, session, ip: req.ip, query: url.searchParams });
      const headers = { ...(out.headers || {}) };
      if (out.cookie) headers['Set-Cookie'] = out.cookie;
      return send(res, out.status, out.body, headers);
    }
    return send(res, method === 'GET' ? 404 : 405, { error: 'nao_encontrado', message: 'Endereço não encontrado.' });
  }

  const pageHtml = (titulo, corpo) => `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${titulo}</title></head><body style="font-family:Arial,sans-serif;font-size:20px;line-height:1.5;max-width:560px;margin:0 auto;padding:24px;color:#10201c;background:#f1f6f3"><h1 style="font-size:26px">${titulo}</h1>${corpo}</body></html>`;
  function handleUnsub(req, res, url) {
    const raw = req.method === 'POST' ? readBody(req) : Promise.resolve('');
    return raw.then((txt) => {
      const params = new URLSearchParams(txt && !txt.startsWith('{') ? txt : '');
      const u = url.searchParams.get('u') || params.get('u') || '', t = url.searchParams.get('t') || params.get('t') || '';
      if (!/^\d{1,12}$/.test(u) || !safeEq(t, hmac(cfg.secret, 'unsub:' + u))) return send(res, 400, pageHtml('Link inválido', '<p>Este link não é válido.</p>'));
      if (req.method === 'POST') {
        db.prepare('UPDATE users SET notify=0 WHERE id=?').run(Number(u));
        return send(res, 200, pageHtml('Pronto!', '<p>Você não vai mais receber avisos por e-mail. Você pode ligar de novo quando quiser, no Menu do Fluxo Fácil.</p>'));
      }
      return send(res, 200, pageHtml('Parar de receber avisos?', `<p>Você deixará de receber os avisos diários por e-mail.</p><form method="post" action="/sair-emails?u=${u}&t=${t}"><button style="font-size:20px;font-weight:bold;padding:16px 24px;border-radius:12px;border:0;background:#0f6b5c;color:#fff;cursor:pointer">Sim, parar de receber</button></form>`));
    });
  }

  function serveStatic(req, res, pathname) {
    if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, { error: 'metodo' });
    let rel; try { rel = decodeURIComponent(pathname); } catch { return send(res, 400, { error: 'invalido' }); }
    if (rel === '/') rel = '/index.html';
    const file = path.join(cfg.publicDir, path.normalize(rel));
    const ext = path.extname(file).toLowerCase();
    if (!file.startsWith(cfg.publicDir + path.sep) || !MIME[ext]) return send(res, 404, { error: 'nao_encontrado' });
    fs.readFile(file, (err, data) => {
      if (err) return send(res, 404, { error: 'nao_encontrado' });
      res.writeHead(200, { 'Content-Type': MIME[ext], 'Content-Length': data.length, 'Cache-Control': ext === '.html' ? 'no-cache' : (cfg.prod ? 'public, max-age=3600' : 'no-cache') });
      res.end(req.method === 'HEAD' ? undefined : data);
    });
  }

  const server = http.createServer(async (req, res) => {
    securityHeaders(res);
    req.ip = clientIp(req);
    try {
      const url = new URL(req.url, 'http://localhost');
      if (url.pathname.startsWith('/api/')) { res.setHeader('Cache-Control', 'no-store'); return await handleApi(req, res, url); }
      if (url.pathname === '/sair-emails') return await handleUnsub(req, res, url);
      return serveStatic(req, res, url.pathname);
    } catch (e) {
      if (e.status === 413) return send(res, 413, { error: 'grande', message: 'Os dados são grandes demais.' });
      console.error('Erro:', e);
      if (!res.headersSent) send(res, 500, { error: 'erro_interno', message: GENERICO });
    }
  });
  server.requestTimeout = 30000;
  server.headersTimeout = 15000;

  const timers = [];
  function startJobs() {
    cleanup();
    timers.push(setInterval(cleanup, HOUR).unref());
    timers.push(setInterval(() => runDigest().catch((e) => console.error('Erro nos avisos:', e.message)), 10 * MIN).unref());
  }
  function close() { timers.forEach(clearInterval); server.close(); try { db.close(); } catch { /* ok */ } }

  return { server, db, mailer, runDigest, startJobs, close, cleanup, unsubUrl };
}
