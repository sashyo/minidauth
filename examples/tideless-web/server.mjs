// Tiny server for the browser tideless demo.
//
// The browser does the threshold crypto (doken-less), but it must not hold minidauth's operator
// token, and the decrypt voucher has to be gated on WHO is asking. So this server does two jobs:
//
//   - it knows who the user is (here: a fixed DEMO_UID standing in for "the logged-in user"), and
//   - it proxies the two vouchers to minidauth with the app token, injecting that uid+role on the
//     decrypt side. The browser never sees a token and cannot ask for a voucher for another user.
//
// Everything secret stays here; the browser gets only vouchers and public policy bytes.

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT ?? 3010);
const MC = process.env.MINIDAUTH_URL ?? 'http://localhost:8081';
const APP_TOKEN = process.env.APP_TOKEN ?? 'dev-sample-app-token';
const DEMO_UID = process.env.DEMO_UID ?? 'user_dec_final'; // the "logged-in" user, granted a role
const DEMO_ROLE = process.env.DEMO_ROLE ?? 'vault-reader';

const bearer = { Authorization: `Bearer ${APP_TOKEN}` };
const readBody = req => new Promise(res => { let b = ''; req.on('data', c => b += c); req.on('end', () => res(b)); });
const send = (res, code, body, type = 'application/json') => { res.writeHead(code, { 'Content-Type': type }); res.end(body); };

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://localhost:${PORT}`);
    const p = url.pathname;

    if (p === '/' || p === '/index.html') {
      return send(res, 200, await readFile(join(HERE, 'public/index.html')), 'text/html; charset=utf-8');
    }

    // Public config the browser needs to reach the network and encrypt.
    if (p === '/api/config') {
      const cfg = await (await fetch(`${MC}/tide/enclave/config`, { headers: bearer })).json();
      const enc = await (await fetch(`${MC}/vault/encrypt-policy`)).json();
      const dec = await (await fetch(`${MC}/vault/decrypt-policy`, { headers: bearer })).json();
      return send(res, 200, JSON.stringify({
        vvkId: cfg.vvkId, homeOrkUrl: cfg.homeOrkUrl,
        encryptPolicy: enc.policy, decryptPolicy: dec.policy,
        user: DEMO_UID, role: DEMO_ROLE,
      }));
    }

    // Encrypt voucher (vendorsign). Any configured operator may mint it; the app token is enough.
    if (p === '/api/voucher/sign' && req.method === 'POST') {
      const voucherRequest = await readBody(req);
      const r = await fetch(`${MC}/tide/vouchers`, {
        method: 'POST', headers: { ...bearer, 'Content-Type': 'application/json' },
        body: JSON.stringify({ voucherRequest }),
      });
      return send(res, r.status, await r.text());
    }

    // Decrypt voucher (vendordecrypt). Gated: minidauth issues it only if OUR user holds the role.
    // The uid is set here, not by the browser, so the page cannot voucher a read for someone else.
    if (p === '/api/voucher/decrypt' && req.method === 'POST') {
      const voucherRequest = await readBody(req);
      const r = await fetch(`${MC}/vault/voucher`, {
        method: 'POST', headers: { ...bearer, 'Content-Type': 'application/json' },
        body: JSON.stringify({ uid: DEMO_UID, role: DEMO_ROLE, voucherRequest }),
      });
      return send(res, r.status, await r.text());
    }

    send(res, 404, JSON.stringify({ error: 'not found' }));
  } catch (e) {
    send(res, 502, JSON.stringify({ error: String(e.message || e) }));
  }
});

server.listen(PORT, () => console.log(`tideless-web on http://localhost:${PORT}  (user=${DEMO_UID}, minidauth=${MC})`));
