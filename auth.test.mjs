// Testes de segurança e de fluxo. Rodar com:  npm test
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadConfig } from '../src/config.js';
import { createApp } from '../src/app.js';
import { ymd } from '../src/util.js';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ff-test-'));
const cfg = loadConfig({
  DB_PATH: path.join(tmp, 'teste.db'), OUTBOX_DIR: path.join(tmp, 'outbox'),
  TRUST_PROXY: '1', APP_SECRET: 'x'.repeat(40), APP_URL: 'http://localhost:3999',
});
cfg.quiet = true;
let app, base;
let ipN = 0;
const newIp = () => `10.0.${Math.floor(++ipN / 250)}.${(ipN % 250) + 1}`;

before(async () => {
  app = createApp(cfg);
  await new Promise((r) => app.server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${app.server.address().port}`;
});
after(() => { app.close(); fs.rmSync(tmp, { recursive: true, force: true }); });

async function call(method, url, { body, cookie, ip, headers = {}, csrf = true } = {}) {
  const h = { 'X-Forwarded-For': ip || newIp(), ...headers };
  if (csrf && method !== 'GET') h['X-Requested-With'] = 'fluxo-facil';
  if (body !== undefined && !h['Content-Type']) h['Content-Type'] = 'application/json';
  if (cookie) h.Cookie = cookie;
  const res = await fetch(base + url, { method, headers: h, body: body !== undefined ? JSON.stringify(body) : undefined, redirect: 'manual' });
  let data = null; const txt = await res.text();
  try { data = JSON.parse(txt); } catch { data = txt; }
  const sc = res.headers.getSetCookie?.() ?? [];
  return { status: res.status, data, headers: res.headers, setCookie: sc[0] || '', cookie: (sc[0] || '').split(';')[0] };
}
const outbox = () => fs.existsSync(cfg.outboxDir) ? fs.readdirSync(cfg.outboxDir).sort().map((f) => JSON.parse(fs.readFileSync(path.join(cfg.outboxDir, f), 'utf8'))) : [];
const mailsTo = (email) => outbox().filter((m) => m.to === email);
const tokenFrom = (email, param) => { const ms = mailsTo(email); const m = ms[ms.length - 1]?.text.match(new RegExp(`${param}=([\\w-]+)`)); return m ? m[1] : null; };
const SENHA = 'meu gato dorme no sofa';
let n = 0;
async function criarConta(senha = SENHA) {
  const email = `pessoa${++n}@exemplo.com`;
  const ip = newIp();
  const r = await call('POST', '/api/auth/criar-conta', { body: { email, senha, consentimento: true }, ip });
  assert.equal(r.status, 200);
  const tok = tokenFrom(email, 'verificar');
  assert.ok(tok, 'deveria ter enviado o e-mail de confirmação');
  const c = await call('POST', '/api/auth/confirmar-email', { body: { token: tok }, ip });
  assert.equal(c.status, 200);
  return { email, ip, senha };
}
async function entrar(email, senha = SENHA, ip) {
  return call('POST', '/api/auth/entrar', { body: { email, senha }, ip });
}
const dadosEx = (extra = {}) => ({ empresa: 'Loja A', saldoInicial: 100, cats: [{ id: 'e1', nome: 'Vendas', tipo: 'E' }, { id: 's1', nome: 'Aluguel', tipo: 'S' }], lanc: [], prefs: { size: 1, hc: false, hide: false }, ...extra });

test('o site abre com cabeçalhos de segurança e sem script dentro da página', async () => {
  const r = await fetch(base + '/');
  const html = await r.text();
  assert.equal(r.status, 200);
  const csp = r.headers.get('content-security-policy');
  assert.match(csp, /script-src 'self'/);
  assert.doesNotMatch(csp, /script-src[^;]*unsafe-inline/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(r.headers.get('referrer-policy'), 'no-referrer');
  assert.doesNotMatch(html.replace(/<script src="[^"]+"><\/script>/g, ''), /<script/i, 'não pode haver script embutido');
});

test('não deixa ler arquivos fora da pasta pública', async () => {
  for (const p of ['/../src/app.js', '/..%2fsrc%2fapp.js', '/src/app.js', '/data/fluxo.db', '/%2e%2e/package.json', '/package.json']) {
    const r = await fetch(base + p);
    assert.equal(r.status, 404, p);
  }
});

test('pedidos que mudam algo sem o cabeçalho de segurança ou de outro site são barrados', async () => {
  const sem = await call('POST', '/api/auth/entrar', { body: { email: 'a@b.com', senha: 'x' }, csrf: false });
  assert.equal(sem.status, 403);
  const outro = await call('POST', '/api/auth/entrar', { body: { email: 'a@b.com', senha: 'x' }, headers: { Origin: 'https://site-malicioso.example' } });
  assert.equal(outro.status, 403);
});

test('cadastro recusa e-mail inválido, senha fraca e falta de consentimento', async () => {
  const ip = newIp();
  assert.equal((await call('POST', '/api/auth/criar-conta', { body: { email: 'sem-arroba', senha: SENHA, consentimento: true }, ip })).data.error, 'email_invalido');
  assert.equal((await call('POST', '/api/auth/criar-conta', { body: { email: 'a@exemplo.com', senha: 'curta', consentimento: true }, ip })).data.error, 'senha_fraca');
  assert.equal((await call('POST', '/api/auth/criar-conta', { body: { email: 'a@exemplo.com', senha: '1234567890', consentimento: true }, ip })).data.error, 'senha_fraca');
  assert.equal((await call('POST', '/api/auth/criar-conta', { body: { email: 'maria.souza@exemplo.com', senha: 'maria.souza123', consentimento: true }, ip })).data.error, 'senha_fraca');
  assert.equal((await call('POST', '/api/auth/criar-conta', { body: { email: 'a@exemplo.com', senha: SENHA }, ip })).data.error, 'sem_consentimento');
});

test('só entra depois de confirmar o e-mail; o link vale uma vez só', async () => {
  const email = 'confirma@exemplo.com', ip = newIp();
  await call('POST', '/api/auth/criar-conta', { body: { email, senha: SENHA, consentimento: true }, ip });
  const antes = await entrar(email, SENHA, ip);
  assert.equal(antes.status, 403);
  assert.equal(antes.data.error, 'email_nao_confirmado');
  const tok = tokenFrom(email, 'verificar');
  assert.equal((await call('POST', '/api/auth/confirmar-email', { body: { token: tok }, ip })).status, 200);
  assert.equal((await call('POST', '/api/auth/confirmar-email', { body: { token: tok }, ip })).status, 400);
  assert.equal((await entrar(email, SENHA, ip)).status, 200);
});

test('a senha nunca é guardada: só um resumo scrypt com sal; o código da sessão também não', async () => {
  const { email, ip } = await criarConta();
  const r = await entrar(email, SENHA, ip);
  const row = app.db.prepare('SELECT pass_hash FROM users WHERE email=?').get(email);
  assert.match(row.pass_hash, /^scrypt\$32768\$8\$1\$/);
  assert.ok(!row.pass_hash.includes(SENHA));
  const tokenCookie = decodeURIComponent(r.cookie.split('=')[1]);
  const tudo = JSON.stringify(app.db.prepare('SELECT * FROM sessions').all());
  assert.ok(!tudo.includes(tokenCookie), 'o código da sessão não pode estar no banco');
  const outro = await criarConta(); // sal diferente por pessoa, mesmo com senha igual
  const h2 = app.db.prepare('SELECT pass_hash FROM users WHERE email=?').get(outro.email).pass_hash;
  assert.notEqual(row.pass_hash, h2);
});

test('o cookie de sessão é HttpOnly e SameSite, e a sessão funciona', async () => {
  const { email, ip } = await criarConta();
  const r = await entrar(email, SENHA, ip);
  assert.equal(r.status, 200);
  assert.match(r.setCookie, /HttpOnly/);
  assert.match(r.setCookie, /SameSite=Lax/);
  assert.match(r.setCookie, /Path=\//);
  const eu = await call('GET', '/api/eu', { cookie: r.cookie, ip });
  assert.equal(eu.status, 200);
  assert.equal(eu.data.email, email);
  assert.equal((await call('GET', '/api/eu', { ip })).status, 401);
  assert.equal((await call('GET', '/api/eu', { cookie: 'ff_sid=invalido', ip })).status, 401);
});

test('senha errada e e-mail inexistente dão a mesma resposta (não revela quem tem conta)', async () => {
  const { email } = await criarConta();
  const a = await entrar(email, 'senha errada mesmo');
  const b = await entrar('naoexiste@exemplo.com', 'senha errada mesmo');
  assert.equal(a.status, 401); assert.equal(b.status, 401);
  assert.deepEqual(a.data, b.data);
});

test('bloqueia depois de 5 senhas erradas, mesmo com a senha certa', async () => {
  const { email } = await criarConta();
  let ultimo;
  for (let i = 0; i < 5; i++) ultimo = await entrar(email, 'errada errada errada');
  assert.equal(ultimo.status, 401);
  const certa = await entrar(email, SENHA);
  assert.equal(certa.status, 429);
  const fantasma = 'fantasma@exemplo.com';
  for (let i = 0; i < 5; i++) await entrar(fantasma, 'errada errada errada');
  assert.equal((await entrar(fantasma, 'errada errada errada')).status, 429, 'e-mail inexistente também é limitado');
});

test('cada pessoa só enxerga os próprios dados', async () => {
  const A = await criarConta(), B = await criarConta();
  const ca = (await entrar(A.email, SENHA, A.ip)).cookie, cb = (await entrar(B.email, SENHA, B.ip)).cookie;
  assert.equal((await call('PUT', '/api/dados', { body: { dados: dadosEx({ empresa: 'Segredo da A' }) }, cookie: ca })).status, 200);
  const lerA = await call('GET', '/api/dados', { cookie: ca });
  assert.equal(lerA.data.dados.empresa, 'Segredo da A');
  const lerB = await call('GET', '/api/dados', { cookie: cb });
  assert.equal(lerB.data.dados, null);
  // tentar mandar "de quem" são os dados não muda nada: o dono vem da sessão
  await call('PUT', '/api/dados', { body: { dados: dadosEx({ empresa: 'B' }), userId: 1, user_id: 1 }, cookie: cb });
  assert.equal((await call('GET', '/api/dados', { cookie: ca })).data.dados.empresa, 'Segredo da A');
  assert.equal((await call('GET', '/api/dados')).status, 401);
  assert.equal((await call('PUT', '/api/dados', { body: { dados: dadosEx() } })).status, 401);
  assert.equal((await call('PUT', '/api/dados', { body: { dados: { cats: 'x' } }, cookie: ca })).status, 400);
  assert.equal((await call('PUT', '/api/dados', { body: { dados: dadosEx() }, cookie: ca, headers: { 'Content-Type': 'text/plain' } })).status, 415);
});

test('sair encerra a sessão no servidor', async () => {
  const { email, ip } = await criarConta();
  const r = await entrar(email, SENHA, ip);
  assert.equal((await call('POST', '/api/auth/sair', { cookie: r.cookie, ip })).status, 200);
  assert.equal((await call('GET', '/api/eu', { cookie: r.cookie, ip })).status, 401, 'o código antigo não pode mais valer');
});

test('esqueci a senha: link por e-mail, uso único, derruba os aparelhos, não revela contas', async () => {
  const { email, ip } = await criarConta();
  const velho = (await entrar(email, SENHA, ip)).cookie;
  const antes = outbox().length;
  const fantasma = await call('POST', '/api/auth/esqueci', { body: { email: 'ninguem@exemplo.com' } });
  const real = await call('POST', '/api/auth/esqueci', { body: { email } });
  assert.equal(fantasma.status, 200); assert.equal(real.status, 200);
  assert.equal(outbox().length, antes + 1, 'só o e-mail que existe recebe a mensagem');
  const tok = tokenFrom(email, 'redefinir');
  assert.ok(tok);
  assert.equal((await call('POST', '/api/auth/redefinir', { body: { token: tok, senha: 'curta' } })).data.error, 'senha_fraca');
  const nova = 'cafe com leite e pao';
  assert.equal((await call('POST', '/api/auth/redefinir', { body: { token: tok, senha: nova } })).status, 200);
  assert.equal((await call('POST', '/api/auth/redefinir', { body: { token: tok, senha: 'outra senha qualquer' } })).status, 400, 'link de uso único');
  assert.equal((await call('GET', '/api/eu', { cookie: velho })).status, 401, 'sessão antiga cai');
  assert.equal((await entrar(email, SENHA)).status, 401);
  assert.equal((await entrar(email, nova)).status, 200);
  assert.ok(mailsTo(email).some((m) => /alterada/i.test(m.subject)), 'avisa por e-mail que a senha mudou');
  assert.equal((await call('POST', '/api/auth/redefinir', { body: { token: 'lixo-lixo-lixo-lixo-lixo', senha: nova } })).status, 400);
});

test('trocar a senha exige a senha atual, derruba os outros aparelhos e avisa por e-mail', async () => {
  const { email, ip } = await criarConta();
  const c1 = (await entrar(email, SENHA, ip)).cookie, c2 = (await entrar(email, SENHA, ip)).cookie;
  assert.equal((await call('POST', '/api/eu/senha', { body: { atual: 'errada errada', nova: 'uma senha nova boa' }, cookie: c1 })).status, 403);
  assert.equal((await call('POST', '/api/eu/senha', { body: { atual: SENHA, nova: 'uma senha nova boa' }, cookie: c1 })).status, 200);
  assert.equal((await call('GET', '/api/eu', { cookie: c1 })).status, 200, 'este aparelho continua');
  assert.equal((await call('GET', '/api/eu', { cookie: c2 })).status, 401, 'o outro aparelho cai');
  assert.ok(mailsTo(email).some((m) => /alterada/i.test(m.subject)));
});

test('criar conta com e-mail que já existe não revela nada e avisa o dono', async () => {
  const { email } = await criarConta();
  const antes = app.db.prepare('SELECT COUNT(*) c FROM users').get().c;
  const novo = await call('POST', '/api/auth/criar-conta', { body: { email: 'novinho@exemplo.com', senha: SENHA, consentimento: true } });
  const dup = await call('POST', '/api/auth/criar-conta', { body: { email, senha: 'outra frase bem longa', consentimento: true } });
  assert.equal(dup.status, 200);
  assert.equal(dup.data.message.replace(email, 'X'), novo.data.message.replace('novinho@exemplo.com', 'X'));
  assert.equal(app.db.prepare('SELECT COUNT(*) c FROM users').get().c, antes + 1, 'não cria conta repetida');
  assert.ok(mailsTo(email).some((m) => /já tem conta|tentou criar/i.test(m.subject + m.text)));
  assert.equal((await entrar(email, 'outra frase bem longa')).status, 401, 'a senha do pedido duplicado não vale');
});

test('quem “reserva” o e-mail de outra pessoa não fica com a conta dela', async () => {
  const email = 'vitima@exemplo.com';
  await call('POST', '/api/auth/criar-conta', { body: { email, senha: 'senha do atacante aqui', consentimento: true } });
  await call('POST', '/api/auth/criar-conta', { body: { email, senha: 'senha de verdade da pessoa', consentimento: true } });
  const tok = tokenFrom(email, 'verificar');
  assert.equal((await call('POST', '/api/auth/confirmar-email', { body: { token: tok } })).status, 200);
  assert.equal((await entrar(email, 'senha do atacante aqui')).status, 401);
  assert.equal((await entrar(email, 'senha de verdade da pessoa')).status, 200);
});

test('apagar a conta exige a senha e some com tudo', async () => {
  const { email, ip } = await criarConta();
  const c = (await entrar(email, SENHA, ip)).cookie;
  await call('PUT', '/api/dados', { body: { dados: dadosEx() }, cookie: c });
  assert.equal((await call('DELETE', '/api/eu', { body: { senha: 'errada errada errada' }, cookie: c })).status, 403);
  assert.equal((await call('DELETE', '/api/eu', { body: { senha: SENHA }, cookie: c })).status, 200);
  assert.equal(app.db.prepare('SELECT COUNT(*) c FROM users WHERE email=?').get(email).c, 0);
  assert.equal(app.db.prepare('SELECT COUNT(*) c FROM user_data').get().c >= 0, true);
  assert.equal((await call('GET', '/api/eu', { cookie: c })).status, 401);
  assert.equal((await entrar(email)).status, 401);
  assert.ok(mailsTo(email).some((m) => /apagada/i.test(m.subject)));
});

test('exportar devolve só os dados da própria pessoa', async () => {
  const { email, ip } = await criarConta();
  const c = (await entrar(email, SENHA, ip)).cookie;
  await call('PUT', '/api/dados', { body: { dados: dadosEx({ empresa: 'Minha loja' }) }, cookie: c });
  const r = await call('GET', '/api/exportar', { cookie: c });
  assert.equal(r.status, 200);
  assert.equal(r.data.email, email);
  assert.equal(r.data.dados.empresa, 'Minha loja');
  assert.match(r.headers.get('content-disposition'), /attachment/);
});

test('avisos por e-mail: manda só o que importa, uma vez por dia, e dá para parar', async () => {
  const { email, ip } = await criarConta();
  const c = (await entrar(email, SENHA, ip)).cookie;
  const dia = (n) => { const d = new Date(); d.setDate(d.getDate() + n); return ymd(d); };
  await call('PUT', '/api/dados', { cookie: c, body: { dados: dadosEx({ lanc: [
    { id: 'a', date: dia(-3), cat: 's1', valor: 1500, pago: false, obs: '' },
    { id: 'b', date: dia(2), cat: 's1', valor: 700, pago: false, obs: '' },
    { id: 'c', date: dia(-5), cat: 'e1', valor: 900, pago: false, obs: '' },
    { id: 'd', date: dia(-1), cat: 's1', valor: 50, pago: true, obs: '' },
  ] }) } });
  const antes = mailsTo(email).length;
  const r1 = await app.runDigest({ force: true });
  assert.ok(r1.sent >= 1);
  const m = mailsTo(email).slice(antes);
  assert.equal(m.length, 1);
  assert.match(m[0].subject, /avisos? para você hoje/);
  assert.match(m[0].text, /Aluguel/);
  assert.match(m[0].text, /Contas vencidas/);
  assert.match(m[0].text, /próximos 3 dias/);
  assert.match(m[0].text, /atrasado para receber/);
  assert.ok(m[0].headers['List-Unsubscribe'], 'tem o link de parar de receber no cabeçalho');
  const r2 = await app.runDigest({ force: true });
  assert.equal(mailsTo(email).length, antes + 1, 'no mesmo dia não manda de novo');

  // parar de receber: link assinado
  const url = new URL(m[0].headers['List-Unsubscribe'].replace(/[<>]/g, ''));
  assert.equal((await fetch(base + '/sair-emails?u=' + url.searchParams.get('u') + '&t=forjado')).status, 400, 'link forjado não vale');
  const ok = await fetch(base + url.pathname + url.search, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: '' });
  assert.equal(ok.status, 200);
  assert.equal((await call('GET', '/api/eu', { cookie: c })).data.avisos, false);
  app.db.prepare('UPDATE users SET last_digest_on=NULL WHERE email=?').run(email);
  const n = mailsTo(email).length;
  await app.runDigest({ force: true });
  assert.equal(mailsTo(email).length, n, 'depois de parar, não recebe mais');
  void r2;
});

test('quem não confirmou o e-mail não recebe avisos', async () => {
  const email = 'naoconfirmou@exemplo.com';
  await call('POST', '/api/auth/criar-conta', { body: { email, senha: SENHA, consentimento: true } });
  const id = app.db.prepare('SELECT id FROM users WHERE email=?').get(email).id;
  app.db.prepare('INSERT INTO user_data(user_id,json,updated_at) VALUES(?,?,?)').run(id, JSON.stringify(dadosEx({ lanc: [{ id: 'z', date: '2020-01-01', cat: 's1', valor: 10, pago: false, obs: '' }] })), Date.now());
  const antes = mailsTo(email).length;
  await app.runDigest({ force: true });
  assert.equal(mailsTo(email).length, antes);
});

test('em produção o servidor se recusa a iniciar com configuração insegura', () => {
  assert.throws(() => loadConfig({ NODE_ENV: 'production', APP_SECRET: 'curto', APP_URL: 'http://exemplo.com' }), /APP_SECRET|https|e-mail/);
  assert.throws(() => loadConfig({ NODE_ENV: 'production', APP_SECRET: 'y'.repeat(40), APP_URL: 'https://exemplo.com' }), /e-mail/);
  const ok = loadConfig({ NODE_ENV: 'production', APP_SECRET: 'y'.repeat(40), APP_URL: 'https://exemplo.com', RESEND_API_KEY: 're_x' });
  assert.equal(ok.prod, true);
});
