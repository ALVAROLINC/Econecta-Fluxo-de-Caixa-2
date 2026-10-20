import { loadConfig } from './src/config.js';
import { createApp } from './src/app.js';

const cfg = loadConfig();
const app = createApp(cfg);
app.startJobs();
app.server.listen(cfg.port, cfg.host, () => {
  console.log(`Fluxo Fácil rodando em ${cfg.appUrl} (porta ${cfg.port}, ${cfg.prod ? 'produção' : 'desenvolvimento'})`);
  if (cfg.mail.provider === 'file') console.log(`E-mails em modo de teste: ficam salvos em ${cfg.outboxDir} e aparecem aqui no terminal.`);
});
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { app.close(); process.exit(0); });
