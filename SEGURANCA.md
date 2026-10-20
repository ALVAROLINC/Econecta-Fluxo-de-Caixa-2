# Segurança do Fluxo Fácil

## Como o login funciona

1. A pessoa escolhe **e-mail e senha**.
2. O servidor manda um e-mail com um link. Só depois de tocar nele a conta passa a valer. Isso garante que o e-mail é dela, e é para ele que os avisos vão.
3. A pessoa entra com e-mail e senha. O servidor entrega um **código de sessão** num cookie que o JavaScript não consegue ler (`HttpOnly`).
4. Todo pedido seguinte traz esse cookie. O servidor descobre **quem é a pessoa pelo cookie**, nunca por algo que o navegador diga.

Por isso a segurança está no servidor. Qualquer coisa que rode só no navegador pode ser contornada por quem abrir o código da página.

## O que está protegido

| Risco | O que foi feito | Testado |
|---|---|---|
| Vazamento do banco expor senhas | A senha nunca é guardada. Fica só um resumo scrypt (32 MB de memória por tentativa), com sal diferente por pessoa | sim |
| Roubo do código de sessão no banco | No banco fica só o SHA-256 do código, não o código | sim |
| Roubo do cookie por script malicioso | Cookie `HttpOnly`, `SameSite=Lax`; em produção `Secure` e prefixo `__Host-`. A página não tem nenhum script embutido e a política de conteúdo (CSP) só aceita scripts do próprio site | sim (cookie e CSP). `Secure` e `__Host-` só valem em produção e não foram testados em HTTPS real |
| Adivinhar senhas | 5 erros por e-mail bloqueiam por 15 min, mesmo com a senha certa. Limite também por IP. Vale para e-mails que não existem, então não dá para descobrir quem tem conta | sim |
| Descobrir quem tem conta | Mesma mensagem para senha errada e e-mail inexistente (o tempo de resposta também é igualado, mas isso não foi medido). Cadastro e "esqueci a senha" respondem igual existindo ou não a conta | sim (mensagens) |
| Senhas fracas | Mínimo de 10 caracteres, sem senhas óbvias (`1234567890`, `senha123`…), sem o e-mail dentro. Aceita frases com espaços | sim |
| Roubo de conta por "reserva" do e-mail | Se alguém cadastra o e-mail de outra pessoa e a dona cadastra depois, vale a senha da dona | sim |
| Pedidos forjados por outro site (CSRF) | Pedidos que mudam algo exigem cabeçalho próprio e origem igual à do site | sim |
| Uma pessoa ver dados de outra | O dono dos dados vem sempre da sessão. Não existe campo "usuário" que o navegador possa mandar | sim |
| Link de e-mail reaproveitado | Códigos de uso único: confirmar e-mail vale 24 h, trocar senha vale 30 min. No banco ficam só os resumos | sim |
| Senha trocada sem a pessoa saber | Trocar ou redefinir a senha derruba os outros aparelhos e manda e-mail de aviso | sim |
| Ler arquivos do servidor | Só a pasta `public/` é entregue; tentativas de sair dela dão 404 | sim |
| Configuração insegura em produção | O servidor não inicia sem `APP_SECRET` forte, sem https e sem e-mail configurado | sim |
| Direitos da pessoa (LGPD) | Baixar uma cópia dos dados e apagar a conta (pede a senha), pelo próprio site | sim |

Também enviados: HSTS (em produção), `X-Content-Type-Options`, `Referrer-Policy: no-referrer` (o link do e-mail não vaza para outros sites), `frame-ancestors 'none'` (ninguém embute o site em outra página) e `Cache-Control: no-store` na API.

## Avisos por e-mail

- Só vão para e-mails **confirmados**.
- No máximo **1 por dia**, e só quando há algo: contas vencendo em até 3 dias, contas vencidas, recebimentos atrasados, risco de caixa negativo.
- Cada e-mail traz o link para **parar de receber** (assinado, não dá para forjar) e o cabeçalho `List-Unsubscribe`.
- A pessoa liga e desliga em Menu > Minha conta.
- **Ainda não testado com um provedor de e-mail real.** Em desenvolvimento os e-mails ficam em arquivo. O envio por SMTP e por Resend está escrito, mas precisa de um teste com as suas credenciais antes de abrir ao público.

## O que ainda falta (ordem sugerida)

1. **Revisão jurídica** dos termos de uso e da política de privacidade (hoje só há a caixa de aceite, sem os textos finais).
2. **Teste do envio de e-mail real** (SMTP ou Resend) e configuração de SPF e DKIM no domínio.
3. **Segunda etapa de segurança** no login (código no celular), principalmente para quem guarda dados de empresa.
4. **Cópia de segurança** automática do banco e plano de restauração.
5. **Um servidor só**: o banco é SQLite. Serve bem para começar. Para crescer, trocar por PostgreSQL.
6. **Dados em um único bloco por pessoa** (limite de 1 MB, cerca de 9 mil lançamentos). O passo seguinte é separar em tabelas (lançamentos, categorias, clientes, contas).
7. **Registro de acessos visível** para a pessoa ("último acesso em…") e aviso de login em aparelho novo.
8. **Teste de invasão** por alguém de fora antes de abrir ao público.
