// Senhas: nunca guardamos a senha, só um "resumo" criado com scrypt (lento de propósito),
// com um sal aleatório diferente para cada pessoa.
import crypto from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(crypto.scrypt);
const N = 2 ** 15, R = 8, P = 1, KEYLEN = 64;
const MAXMEM = 128 * 1024 * 1024;

export async function hashPassword(senha) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(senha.normalize('NFKC'), salt, KEYLEN, { N, r: R, p: P, maxmem: MAXMEM });
  return `scrypt$${N}$${R}$${P}$${salt.toString('base64')}$${key.toString('base64')}`;
}

export async function verifyPassword(senha, stored) {
  try {
    const [alg, n, r, p, salt, hash] = String(stored).split('$');
    if (alg !== 'scrypt') return false;
    const expected = Buffer.from(hash, 'base64');
    const key = await scrypt(senha.normalize('NFKC'), Buffer.from(salt, 'base64'), expected.length,
      { N: Number(n), r: Number(r), p: Number(p), maxmem: MAXMEM });
    return crypto.timingSafeEqual(key, expected);
  } catch { return false; }
}

/** Resumo falso, usado quando o e-mail não existe, para o tempo de resposta ser igual. */
export const DUMMY_HASH = await hashPassword(crypto.randomBytes(12).toString('hex'));

const COMUNS = new Set(['1234567890', '12345678910', '123456789012', 'qwertyuiop', 'senha12345', 'senha123456', 'minhasenha', 'minhasenha123',
  'password123', 'password1234', 'iloveyou123', 'brasil2020', 'brasil2024', 'brasil2025', 'brasil123456', 'mudar12345', 'abcdefghij',
  'abc1234567', 'corinthians', 'flamengo123', 'palmeiras123', 'saopaulo123', 'gabriel1234', 'felipe1234', 'mariasilva', 'senhasenha',
  'qwerty12345', 'q1w2e3r4t5', '1q2w3e4r5t', 'administrador', 'admin12345', 'fluxofacil', 'fluxofacil123', '0123456789', '9876543210']);

/** Regras simples e claras (inspiradas no NIST): tamanho, nada óbvio, sem o e-mail dentro. */
export function checkPolicy(senha, email = '') {
  const s = String(senha ?? '');
  if (s.length < 10) return 'A senha precisa ter pelo menos 10 caracteres. Dica: use uma frase fácil de lembrar, como “meu gato dorme no sofa”.';
  if (s.length > 128) return 'A senha pode ter no máximo 128 caracteres.';
  if (new Set(s).size < 5) return 'Use uma senha mais variada, com mais letras ou números diferentes.';
  if (/^\d+$/.test(s)) return 'Use letras ou palavras também, não só números.';
  const low = s.toLowerCase(), clean = low.replace(/[^a-z0-9]/g, '');
  if (COMUNS.has(low) || COMUNS.has(clean)) return 'Essa senha é muito comum e fácil de adivinhar. Escolha outra.';
  const local = String(email).split('@')[0];
  if (local.length >= 4 && low.includes(local)) return 'Não coloque o seu e-mail dentro da senha.';
  return null;
}
