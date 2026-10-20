// Envio de e-mail sem bibliotecas externas. Três modos:
//  - file   : (desenvolvimento) grava cada e-mail em data/outbox/ e mostra no terminal
//  - smtp   : SMTP com TLS direto (porta 465), usado por quase todo provedor de e-mail
//  - resend : API HTTPS do Resend (https://resend.com)
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import tls from 'node:tls';
import crypto from 'node:crypto';

const CRLF = '\r\n';
const b64 = (buf, wrap = true) => {
  const s = Buffer.from(buf).toString('base64');
  return wrap ? s.replace(/.{1,76}/g, '$&' + CRLF).trimEnd() : s;
};
const encWord = (s) => /^[\x20-\x7e]*$/.test(s) ? s : `=?UTF-8?B?${b64(s, false)}?=`;
const clean = (s) => String(s).replace(/[\r\n]+/g, ' ').trim();

function parseAddr(a) {
  const m = String(a).match(/^(.*)<([^>]+)>\s*$/);
  return m ? { name: m[1].trim().replace(/^"|"$/g, ''), email: m[2].trim() } : { name: '', email: String(a).trim() };
}
const fmtAddr = ({ name, email }) => name ? `${encWord(name)} <${email}>` : email;

export function buildMime({ from, to, subject, text, html, headers = {} }) {
  const f = parseAddr(from), t = parseAddr(to);
  const boundary = 'ff_' + crypto.randomBytes(12).toString('hex');
  const domain = (f.email.split('@')[1] || 'localhost').replace(/[^a-z0-9.-]/gi, '');
  const head = [
    `From: ${fmtAddr(f)}`,
    `To: ${fmtAddr(t)}`,
    `Subject: ${encWord(clean(subject))}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${crypto.randomBytes(12).toString('hex')}@${domain}>`,
    'MIME-Version: 1.0',
    ...Object.entries(headers).map(([k, v]) => `${clean(k)}: ${clean(v)}`),
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
  ].join(CRLF);
  const part = (type, body) => `--${boundary}${CRLF}Content-Type: ${type}; charset=UTF-8${CRLF}Content-Transfer-Encoding: base64${CRLF}${CRLF}${b64(body)}${CRLF}`;
  return `${head}${CRLF}${CRLF}${part('text/plain', text)}${part('text/html', html)}--${boundary}--${CRLF}`;
}

function smtpSend({ host, port, secure, user, pass, from, to, raw, timeoutMs = 20000 }) {
  return new Promise((resolve, reject) => {
    const sock = secure ? tls.connect({ host, port, servername: host }) : net.connect({ host, port });
    let buf = ''; const lines = []; let waiter = null; let done = false;
    const fail = (e) => { if (done) return; done = true; sock.destroy(); reject(e); };
    sock.setTimeout(timeoutMs, () => fail(new Error('SMTP: tempo esgotado')));
    sock.on('error', fail);
    const flush = () => {
      if (!waiter) return;
      const i = lines.findIndex((l) => /^\d{3}( |$)/.test(l));
      if (i < 0) return;
      const reply = lines.splice(0, i + 1); const w = waiter; waiter = null;
      w({ code: Number(reply[i].slice(0, 3)), text: reply.join('\n') });
    };
    sock.on('data', (d) => {
      buf += d.toString('utf8'); let i;
      while ((i = buf.indexOf(CRLF)) >= 0) { lines.push(buf.slice(0, i)); buf = buf.slice(i + 2); }
      flush();
    });
    const read = () => new Promise((res) => { waiter = res; flush(); });
    const cmd = async (c, ok) => {
      sock.write(c + CRLF);
      const r = await read();
      if (!ok.includes(r.code)) throw new Error(`SMTP ${r.code}: ${r.text.slice(0, 120)}`);
      return r;
    };
    (async () => {
      const hello = await read(); if (hello.code !== 220) throw new Error('SMTP: saudação inesperada');
      await cmd('EHLO fluxofacil.local', [250]);
      if (user) {
        if (!secure && !['localhost', '127.0.0.1'].includes(host)) throw new Error('SMTP: recusado enviar senha sem TLS');
        await cmd('AUTH PLAIN ' + b64(`\0${user}\0${pass}`, false), [235]);
      }
      await cmd(`MAIL FROM:<${parseAddr(from).email}>`, [250]);
      await cmd(`RCPT TO:<${parseAddr(to).email}>`, [250, 251]);
      await cmd('DATA', [354]);
      sock.write(raw.replace(/^\./gm, '..') + CRLF + '.' + CRLF);
      const r = await read(); if (r.code !== 250) throw new Error(`SMTP ${r.code}`);
      try { sock.write('QUIT' + CRLF); } catch { /* ok */ }
      done = true; sock.end(); resolve();
    })().catch(fail);
  });
}

export function createMailer(cfg) {
  const { provider, from, smtp, resendKey } = cfg.mail;
  let n = 0;
  async function send({ to, subject, text, html, headers = {} }) {
    if (provider === 'file') {
      fs.mkdirSync(cfg.outboxDir, { recursive: true, mode: 0o700 });
      const file = path.join(cfg.outboxDir, `${Date.now()}-${String(++n).padStart(4, '0')}.json`);
      fs.writeFileSync(file, JSON.stringify({ to, from, subject, text, html, headers }, null, 2), { mode: 0o600 });
      if (!cfg.quiet) console.log(`[e-mail simulado] para ${to}: ${subject}\n${text}\n`);
      return { ok: true, file };
    }
    if (provider === 'smtp') {
      await smtpSend({ ...smtp, from, to, raw: buildMime({ from, to, subject, text, html, headers }) });
      return { ok: true };
    }
    if (provider === 'resend') {
      const r = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { Authorization: `Bearer ${resendKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ from, to: [to], subject, text, html, headers }),
        signal: AbortSignal.timeout(20000),
      });
      if (!r.ok) throw new Error(`Resend respondeu ${r.status}`);
      return { ok: true };
    }
    throw new Error('MAIL_PROVIDER desconhecido');
  }
  return { send };
}
