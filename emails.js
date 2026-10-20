// Textos dos e-mails (em português simples, letra grande, um botão só).
import { esc } from './util.js';

const BRL = new Intl.NumberFormat('pt-BR', { style: 'currency', currency: 'BRL' });
export const brl = (v) => BRL.format(v).replace(/ /g, ' ');

function layout({ titulo, paragrafos = [], bruto = '', botao, rodape = '' }) {
  const p = paragrafos.map((x) => `<p style="margin:0 0 16px">${x}</p>`).join('');
  const b = botao ? `<p style="margin:24px 0"><a href="${esc(botao.url)}" style="display:inline-block;background:#0f6b5c;color:#ffffff;padding:16px 26px;border-radius:12px;font-weight:bold;font-size:18px;text-decoration:none">${esc(botao.texto)}</a></p>
<p style="font-size:15px;color:#46564f;margin:0 0 16px">Se o botão não abrir, copie este endereço e cole no navegador:<br><span style="word-break:break-all">${esc(botao.url)}</span></p>` : '';
  return `<!doctype html><html lang="pt-BR"><body style="margin:0;background:#f1f6f3"><div style="font-family:Arial,Helvetica,sans-serif;font-size:18px;line-height:1.5;color:#10201c;max-width:580px;margin:0 auto;padding:20px">
<p style="font-weight:bold;font-size:20px;color:#0f6b5c;margin:0 0 12px">Fluxo Fácil</p>
<div style="background:#ffffff;border-radius:16px;padding:24px">
<h1 style="font-size:24px;line-height:1.25;margin:0 0 16px">${esc(titulo)}</h1>${p}${bruto}${b}</div>
<p style="font-size:14px;color:#46564f;margin:16px 0 0">${rodape}</p></div></body></html>`;
}
const txt = (linhas) => linhas.filter((x) => x !== null).join('\n\n');

export function emailConfirmar({ url }) {
  return {
    subject: 'Confirme o seu e-mail no Fluxo Fácil',
    text: txt(['Olá! Falta só um passo para usar o Fluxo Fácil.', 'Abra este endereço para confirmar o seu e-mail (vale por 24 horas):', url, 'Se não foi você que criou a conta, ignore esta mensagem. Nada será feito.']),
    html: layout({ titulo: 'Confirme o seu e-mail', paragrafos: ['Olá! Falta só um passo para usar o Fluxo Fácil.', 'Toque no botão abaixo. O link vale por 24 horas.'], botao: { texto: 'Confirmar meu e-mail', url }, rodape: 'Se não foi você que criou a conta, ignore esta mensagem. Nada será feito.' }),
  };
}
export function emailContaJaExiste({ url }) {
  return {
    subject: 'Alguém tentou criar uma conta com o seu e-mail',
    text: txt(['Recebemos um pedido para criar uma conta no Fluxo Fácil com este e-mail, mas ele já tem conta.', 'Se foi você e esqueceu a senha, peça uma nova aqui:', url, 'Se não foi você, pode ignorar. Sua conta continua segura.']),
    html: layout({ titulo: 'Você já tem uma conta', paragrafos: ['Recebemos um pedido para criar uma conta no Fluxo Fácil com este e-mail, mas ele já tem conta.', 'Se foi você e esqueceu a senha, peça uma nova pelo botão abaixo.'], botao: { texto: 'Criar uma nova senha', url }, rodape: 'Se não foi você, pode ignorar. Sua conta continua segura.' }),
  };
}
export function emailRedefinir({ url }) {
  return {
    subject: 'Crie uma nova senha no Fluxo Fácil',
    text: txt(['Recebemos um pedido para criar uma nova senha.', 'Abra este endereço (vale por 30 minutos, só funciona uma vez):', url, 'Se não foi você, ignore esta mensagem. Sua senha atual continua valendo.']),
    html: layout({ titulo: 'Crie uma nova senha', paragrafos: ['Recebemos um pedido para criar uma nova senha.', 'Toque no botão abaixo. O link vale por 30 minutos e só funciona uma vez.'], botao: { texto: 'Criar nova senha', url }, rodape: 'Se não foi você, ignore esta mensagem. Sua senha atual continua valendo.' }),
  };
}
export function emailSenhaAlterada({ quando, url }) {
  return {
    subject: 'A senha do Fluxo Fácil foi alterada',
    text: txt([`A senha da sua conta foi alterada em ${quando}.`, 'Se foi você, está tudo certo.', `Se não foi você, crie uma nova senha agora: ${url}`]),
    html: layout({ titulo: 'Sua senha foi alterada', paragrafos: [`A senha da sua conta foi alterada em ${esc(quando)}.`, 'Se foi você, está tudo certo.', 'Se não foi você, crie uma nova senha agora.'], botao: { texto: 'Criar nova senha', url } }),
  };
}
export function emailContaApagada() {
  return {
    subject: 'Sua conta no Fluxo Fácil foi apagada',
    text: txt(['Sua conta e todos os seus dados foram apagados, como você pediu.', 'Se não foi você, responda a este e-mail.', 'Obrigado por ter usado o Fluxo Fácil.']),
    html: layout({ titulo: 'Sua conta foi apagada', paragrafos: ['Sua conta e todos os seus dados foram apagados, como você pediu.', 'Se não foi você, responda a este e-mail.', 'Obrigado por ter usado o Fluxo Fácil.'] }),
  };
}
export function emailAvisos({ d, appUrl, unsubUrl }) {
  const linhas = [];
  const li = (arr, fmt) => arr.slice(0, 8).map(fmt);
  const sec = (titulo, itens, extra) => { if (itens.length) linhas.push({ titulo, itens, extra }); };
  sec('Contas vencidas e sem pagamento', li(d.contasVencidas, (l) => `${l.nome}: ${brl(l.valor)} (venceu ${l.quando})`), d.contasVencidas.length > 8 ? `e mais ${d.contasVencidas.length - 8}` : '');
  sec('Dinheiro atrasado para receber', li(d.recebimentosAtrasados, (l) => `${l.nome}: ${brl(l.valor)} (era para ${l.quando})`), d.recebimentosAtrasados.length > 8 ? `e mais ${d.recebimentosAtrasados.length - 8}` : '');
  sec('Vencem nos próximos 3 dias', li(d.vencendo, (l) => `${l.nome}: ${brl(l.valor)} (${l.quando})`), d.vencendo.length > 8 ? `e mais ${d.vencendo.length - 8}` : '');
  const neg = d.caixaNegativo ? `Pelas contas lançadas, o seu caixa pode ficar negativo em ${d.caixaNegativo.mes} (saldo de ${brl(d.caixaNegativo.saldo)}). Dê uma olhada nas Dicas para ver o que fazer.` : '';
  const n = d.contasVencidas.length + d.recebimentosAtrasados.length + d.vencendo.length + (d.caixaNegativo ? 1 : 0);
  const textos = linhas.map((s) => `${s.titulo}\n${s.itens.map((i) => '- ' + i).join('\n')}${s.extra ? '\n' + s.extra : ''}`);
  const html = linhas.map((s) => `<p style="margin:0 0 6px"><b>${esc(s.titulo)}</b></p><ul style="margin:0 0 16px;padding-left:22px">${s.itens.map((i) => `<li>${esc(i)}</li>`).join('')}${s.extra ? `<li>${esc(s.extra)}</li>` : ''}</ul>`).join('')
    + (neg ? `<p style="margin:0 0 16px;background:#fff0c9;color:#6b4700;padding:12px 14px;border-radius:10px">${esc(neg)}</p>` : '');
  return {
    subject: `Fluxo Fácil: ${n} ${n === 1 ? 'aviso' : 'avisos'} para você hoje`,
    text: txt(['Bom dia! Veja o que merece a sua atenção hoje:', ...textos, neg || null, `Abrir o Fluxo Fácil: ${appUrl}`, `Você recebe este aviso porque ligou os avisos por e-mail. Para parar de receber: ${unsubUrl}`]),
    html: layout({ titulo: 'Bom dia! Veja o que merece atenção', bruto: html, botao: { texto: 'Abrir o Fluxo Fácil', url: appUrl }, rodape: `Você recebe este aviso porque ligou os avisos por e-mail. <a href="${esc(unsubUrl)}" style="color:#46564f">Parar de receber</a>.` }),
    headers: { 'List-Unsubscribe': `<${unsubUrl}>`, 'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click' },
  };
}
