// Envia os avisos do dia uma vez e termina. Use no agendador da hospedagem (cron), por exemplo todo dia às 8h:
//   npm run avisos
import { loadConfig } from '../src/config.js';
import { createApp } from '../src/app.js';

const app = createApp(loadConfig());
const r = await app.runDigest({ force: false });
console.log(`Avisos enviados: ${r.sent}`);
app.close();
