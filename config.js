// Configuração lida das variáveis de ambiente. Em produção, o servidor se recusa a
// iniciar se algo importante de segurança estiver faltando.
import path from 'node:path';
import { fileURLToPath } from 'node:url';

process.env.TZ ||= 'America/Sao_Paulo';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export function loadConfig(over = {}) {
  const env = { ...process.env, ...over };
  const prod = env.NODE_ENV === 'production';
  const port = Number(env.PORT || 3000);
  const appUrl = (env.APP_URL || `http://localhost:${port}`).replace(/\/+$/, '');
  const provider = env.MAIL_PROVIDER || (env.SMTP_HOST ? 'smtp' : env.RESEND_API_KEY ? 'resend' : 'file');

  const cfg = {
    prod,
    port,
    host: env.HOST || (prod ? '127.0.0.1' : '127.0.0.1'),
    appUrl,
    root,
    publicDir: path.join(root, 'public'),
    dbPath: env.DB_PATH || path.join(root, 'data', 'fluxo.db'),
    outboxDir: env.OUTBOX_DIR || path.join(root, 'data', 'outbox'),
    secret: env.APP_SECRET || 'somente-para-desenvolvimento-troque-em-producao-0000',
    sessionDays: Number(env.SESSION_DAYS || 14),
    idleDays: Number(env.IDLE_DAYS || 3),
    trustProxy: env.TRUST_PROXY === '1',
    digestHour: Number(env.DIGEST_HOUR || 8),
    mail: {
      provider,
      from: env.MAIL_FROM || 'Fluxo Fácil <nao-responda@localhost>',
      smtp: {
        host: env.SMTP_HOST || '',
        port: Number(env.SMTP_PORT || 465),
        secure: env.SMTP_SECURE !== '0',
        user: env.SMTP_USER || '',
        pass: env.SMTP_PASS || '',
      },
      resendKey: env.RESEND_API_KEY || '',
    },
  };

  if (prod) {
    const erros = [];
    if (!env.APP_SECRET || env.APP_SECRET.length < 32) erros.push('APP_SECRET precisa ter pelo menos 32 caracteres.');
    if (!appUrl.startsWith('https://')) erros.push('APP_URL precisa começar com https:// em produção.');
    if (provider === 'file') erros.push('Configure o envio de e-mail (SMTP_HOST ou RESEND_API_KEY). Em produção os e-mails não podem ficar só em arquivo.');
    if (erros.length) throw new Error('Configuração insegura:\n- ' + erros.join('\n- '));
  }
  return cfg;
}
