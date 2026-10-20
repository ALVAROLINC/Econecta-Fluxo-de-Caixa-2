import crypto from 'node:crypto';

export const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
export const rand = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');
export const hmac = (secret, s) => crypto.createHmac('sha256', secret).update(String(s)).digest('hex');
export function safeEq(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const EMAIL_RE = /^[^\s@<>()[\]\\,;:"]+@[^\s@<>()[\]\\,;:"]+\.[^\s@<>()[\]\\,;:"]{2,}$/;
/** Devolve o e-mail em minúsculas, ou '' se for inválido. */
export function normEmail(e) {
  const s = String(e ?? '').trim().toLowerCase();
  if (s.length > 254 || !EMAIL_RE.test(s) || s.includes('..')) return '';
  return s;
}

export function parseCookies(header) {
  const out = {};
  String(header || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i < 0) return;
    const k = p.slice(0, i).trim(), v = p.slice(i + 1).trim();
    if (k && !(k in out)) { try { out[k] = decodeURIComponent(v); } catch { /* ignora */ } }
  });
  return out;
}

export function serializeCookie(name, value, o = {}) {
  let s = `${name}=${encodeURIComponent(value)}`;
  if (o.maxAge !== undefined) s += `; Max-Age=${Math.floor(o.maxAge)}`;
  s += `; Path=${o.path || '/'}`;
  if (o.httpOnly !== false) s += '; HttpOnly';
  if (o.secure) s += '; Secure';
  s += `; SameSite=${o.sameSite || 'Lax'}`;
  return s;
}

export const MIN = 60 * 1000, HOUR = 60 * MIN, DAY = 24 * HOUR;
export const ymd = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
