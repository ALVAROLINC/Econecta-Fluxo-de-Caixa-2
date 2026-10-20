// Resumo diário: olha os dados de cada pessoa e monta os avisos que valem um e-mail.
// Só manda e-mail se houver algo a avisar (nada de spam).
const MESES = ['janeiro', 'fevereiro', 'março', 'abril', 'maio', 'junho', 'julho', 'agosto', 'setembro', 'outubro', 'novembro', 'dezembro'];
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

function addDays(s, n) {
  const d = new Date(s + 'T12:00:00'); d.setDate(d.getDate() + n);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}
function relDate(s, today) {
  if (s === today) return 'hoje';
  const d = Math.round((new Date(s + 'T12:00:00') - new Date(today + 'T12:00:00')) / 864e5);
  if (d === 1) return 'amanhã'; if (d === -1) return 'ontem';
  const [, m, dd] = s.split('-').map(Number);
  return `dia ${dd}/${String(m).padStart(2, '0')}`;
}

export function computeDigest(data, today) {
  const cats = new Map((Array.isArray(data?.cats) ? data.cats : []).map((c) => [c.id, c]));
  const rows = (Array.isArray(data?.lanc) ? data.lanc : []).filter((l) => cats.has(l.cat) && typeof l.valor === 'number' && DATE_RE.test(l.date));
  const nome = (l) => String(cats.get(l.cat).nome).slice(0, 60);
  const item = (l) => ({ nome: nome(l), valor: l.valor, quando: relDate(l.date, today) });
  const tipo = (l) => cats.get(l.cat).tipo;
  const abertos = rows.filter((l) => !l.pago);
  const ordena = (a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : 0);
  const out = {
    contasVencidas: abertos.filter((l) => l.date < today && tipo(l) === 'S').sort(ordena).map(item),
    recebimentosAtrasados: abertos.filter((l) => l.date < today && tipo(l) === 'E').sort(ordena).map(item),
    vencendo: abertos.filter((l) => l.date >= today && l.date <= addDays(today, 3) && tipo(l) === 'S').sort(ordena).map(item),
    caixaNegativo: null,
  };
  // projeção dos próximos 12 meses (tudo: pago e em aberto), igual à aba "Meu caixa"
  const [cy, cm] = today.split('-').map(Number);
  const key = (s) => Number(s.slice(0, 4)) * 100 + Number(s.slice(5, 7));
  const sign = (l) => (tipo(l) === 'E' ? l.valor : -l.valor);
  let acc = Number(data?.saldoInicial) || 0;
  rows.forEach((l) => { if (key(l.date) < cy * 100 + cm) acc += sign(l); });
  for (let i = 0; i < 12; i++) {
    const t = cy * 12 + (cm - 1) + i, y = Math.floor(t / 12), m = (t % 12) + 1, k = y * 100 + m;
    rows.forEach((l) => { if (key(l.date) === k) acc += sign(l); });
    if (acc < 0) { out.caixaNegativo = { mes: `${MESES[m - 1]} de ${y}`, saldo: Math.round(acc * 100) / 100 }; break; }
  }
  return out;
}
export const digestCount = (d) => d.contasVencidas.length + d.recebimentosAtrasados.length + d.vencendo.length + (d.caixaNegativo ? 1 : 0);
