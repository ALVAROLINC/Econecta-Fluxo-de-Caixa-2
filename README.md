# Fluxo Fácil

Fluxo de caixa simples, feito para quem tem pouca prática com tecnologia. Conta com **e-mail e senha**, dados separados por pessoa e **avisos por e-mail**.

Não usa nenhuma biblioteca externa: só o Node.js 22.5 ou mais novo.

## Rodar no seu computador

```
node server.js          # abre em http://localhost:3000
npm test                # 20 testes de segurança e de fluxo
```

Em desenvolvimento, **nenhum e-mail sai de verdade**: cada mensagem aparece no terminal e fica salva em `data/outbox/`. Para testar o cadastro, abra o arquivo mais recente de lá e copie o link.

## Publicar de verdade (resumo)

1. Uma hospedagem que rode Node 22.5+ e entregue o site **só por HTTPS** (Render, Railway, Fly.io, uma VPS com Caddy ou nginx, etc.).
2. Um disco que **não seja apagado** a cada atualização, para o arquivo do banco (`DB_PATH`).
3. Um serviço de envio de e-mail e um domínio seu (veja `.env.example`). Configure SPF e DKIM no domínio, senão os e-mails caem no spam.
4. Preencher as variáveis do `.env.example`. Em produção o servidor **se recusa a iniciar** se faltar `APP_SECRET`, se `APP_URL` não for https ou se não houver envio de e-mail configurado.
5. Os avisos diários saem sozinhos enquanto o servidor estiver ligado (a partir de `DIGEST_HOUR`). Se a hospedagem "dorme" o servidor, agende `npm run avisos` todo dia de manhã.
6. Fazer cópia de segurança diária do arquivo do banco.

## Mapa do projeto

| Arquivo | O que faz |
|---|---|
| `server.js` | liga o servidor |
| `src/app.js` | rotas, sessões, proteções, avisos |
| `src/passwords.js` | senha com scrypt e regras de senha |
| `src/mailer.js` | envio de e-mail (arquivo, SMTP ou Resend) |
| `src/emails.js` | textos dos e-mails |
| `src/digest.js` | decide quais avisos entram no e-mail do dia |
| `src/db.js` | banco SQLite |
| `public/` | o site (index.html, app.css, app.js) |
| `test/auth.test.mjs` | testes automáticos |

Veja `SEGURANCA.md` para o que está protegido e o que ainda falta.
