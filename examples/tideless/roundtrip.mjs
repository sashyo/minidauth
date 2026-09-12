// Encrypt + decrypt for a user who has NO Tide account and NO doken.
//
// The user is just an id your app already has (a Clerk uid, say) that a quorum has granted a role
// through minidauth. minidauth issues the vouchers; the ORK cohort does the threshold crypto. No
// sign-in, no doken. This is the same thing a browser would do — run here in Node so it is one file
// you can read and run.
//
// It leans on two things worth stating plainly:
//
//  1. A guest-doken stub. The tide-js flows take a `doken`, but only use `doken.serialize()` as the
//     ORK bearer token. A stub whose serialize() returns "" trips NodeClient's gSessKey (no-token)
//     path, so the flows run doken-less with no change to tide-js. This is the seam a first-class
//     "guest flow" would formalise upstream.
//
//  2. tide-js carries the network's threshold/cohort size as constants (Tools/Utils). The published
//     @tideorg/js is built for the 14-of-20 network, which is what this example uses. If you target a
//     network with different numbers, point TIDE_JS_DIST at a build whose Tools/Utils matches; making
//     these runtime-configurable (from the key info minidauth already has) is tracked upstream.
//
// Usage (after `npm install`):
//   MINIDAUTH_URL=http://localhost:8081 OPS_TOKEN=… APP_TOKEN=… APP_UID=user_123 ROLE=vault-reader \
//   node --import ./register.mjs roundtrip.mjs
//
// register.mjs adds a resolve hook so Node can load tide-js's extensionless (bundler-style) imports.

import { webcrypto } from 'node:crypto';

// tide-js expects a browser: give it crypto on window and globalThis.
if (!globalThis.crypto) globalThis.crypto = webcrypto;
globalThis.window = globalThis.window || {};
globalThis.window.crypto = globalThis.crypto;

// The published @tideorg/js (installed via package.json) is built for 14-of-20. Override with
// TIDE_JS_DIST only to point at a build for a different network.
const D = process.env.TIDE_JS_DIST ?? new URL('./node_modules/@tideorg/js/dist', import.meta.url).pathname;
const MC = process.env.MINIDAUTH_URL ?? 'http://localhost:8081';
const OPS_TOKEN = process.env.OPS_TOKEN ?? 'dev-ops-token';        // mints the encrypt (vendorsign) voucher
const APP_TOKEN = process.env.APP_TOKEN ?? 'dev-sample-app-token'; // the app's relying-party token
const UID = process.env.APP_UID ?? 'user_123';
const ROLE = process.env.ROLE ?? 'vault-reader';

const NetworkClient = (await import(`${D}/Clients/NetworkClient.js`)).default;
const dVVKSigningFlow = (await import(`${D}/Flow/SigningFlows/dVVKSigningFlow.js`)).default;
const dVVKDecryptionFlow = (await import(`${D}/Flow/DecryptionFlows/dVVKDecryptionFlow.js`)).default;
const { PolicyAuthorizedEncryptionFlow } = await import(`${D}/Flow/EncryptionFlows/PolicyAuthorizedEncryptionFlow.js`);
const TideKey = (await import(`${D}/Cryptide/TideKey.js`)).default;
const Ed25519Scheme = (await import(`${D}/Cryptide/Components/Schemes/Ed25519/Ed25519Scheme.js`)).default;
const PPSF = (await import(`${D}/Models/PolicyProtectedSerializedField.js`)).default;
const AES = await import(`${D}/Cryptide/Encryption/AES.js`);

const b64ToBytes = b64 => Uint8Array.from(Buffer.from(b64, 'base64'));
async function mc(path, opts) {
  const r = await fetch(MC + path, opts);
  const t = await r.text();
  if (!r.ok) throw new Error(`${path} -> ${r.status} ${t}`);
  return t;
}
const asJson = t => JSON.parse(t);

// The two vouchers this flow needs, both from minidauth. The decrypt one goes through the
// role-gated endpoint: minidauth issues it only if UID holds ROLE in its committed grant record.
const fn_encrypt = req => mc('/tide/vouchers', { method: 'POST',
  headers: { Authorization: `Bearer ${OPS_TOKEN}`, 'Content-Type': 'application/json' },
  body: JSON.stringify({ voucherRequest: req }) });
const fn_decrypt = req => mc('/vault/voucher', { method: 'POST',
  headers: { Authorization: `Bearer ${APP_TOKEN}`, 'Content-Type': 'application/json' },
  body: JSON.stringify({ uid: UID, role: ROLE, voucherRequest: req }) });

(async () => {
  const cfg = asJson(await mc('/tide/enclave/config', { headers: { Authorization: `Bearer ${APP_TOKEN}` } }));
  const encPolicy = b64ToBytes(asJson(await mc('/vault/encrypt-policy')).policy);
  const decPolicy = b64ToBytes(asJson(await mc('/vault/decrypt-policy', { headers: { Authorization: `Bearer ${APP_TOKEN}` } })).policy);
  const keyInfo = await new NetworkClient(cfg.homeOrkUrl).GetKeyInfo(cfg.vvkId);
  console.log('vvkId', cfg.vvkId, '| cohort', keyInfo.OrkInfo.length, 'ORKs');

  const sessKey = TideKey.NewKey(Ed25519Scheme);
  const guest = { payload: { sessionKey: sessKey.get_public_component() }, serialize: () => '' };

  const plaintext = 'no account, no doken — ' + new Date().toISOString();
  console.log('\nplaintext:', plaintext);

  // Build the encryption request with the real flow; execute it doken-less with our voucher fn.
  const pae = new PolicyAuthorizedEncryptionFlow({ vendorId: cfg.vvkId, token: guest, sessionKey: sessKey, voucherURL: '', keyInfo });
  const { request: encReq, encReqs, timestamp } = await pae.createEncryptionRequest([{ data: new TextEncoder().encode(plaintext), tags: ['vault'] }]);
  encReq.addPolicy(encPolicy);

  console.log('encrypting  (vendorsign voucher from minidauth, no doken)…');
  const signFlow = new dVVKSigningFlow(cfg.vvkId, keyInfo.UserPublic, keyInfo.OrkInfo.slice(), sessKey, guest, '');
  signFlow.setVoucherRetrievalFunction(fn_encrypt);
  const sigs = await signFlow.start(encReq);
  const cipher = PPSF.create(encReqs[0].encryptedData, timestamp, encReqs[0].sizeLessThan32 ? null : encReqs[0].encryptionToSign, sigs[0]);

  console.log('decrypting  (vendordecrypt voucher, gated on UID holding ROLE, no doken)…');
  const { request: decReq } = pae.createDecryptionRequest([{ encrypted: cipher, tags: ['vault'] }]);
  decReq.addPolicy(decPolicy);
  const decFlow = new dVVKDecryptionFlow(cfg.vvkId, keyInfo.UserPublic, keyInfo.OrkInfo.slice(), sessKey, guest, '');
  decFlow.setVoucherRetrievalFunction(fn_decrypt);
  const dataKeys = await decFlow.start(decReq);

  const b = PPSF.deserialize(cipher);
  const out = b.encKey && b.encKey.length
    ? await AES.decryptDataRawOutput(b.encFieldChk, await AES.decryptDataRawOutput(b.encKey.slice(32), dataKeys[0]))
    : await AES.decryptDataRawOutput(b.encFieldChk.slice(32), dataKeys[0]);
  const recovered = new TextDecoder().decode(out);
  console.log('\nrecovered :', recovered);
  console.log(recovered === plaintext ? '\nTIDELESS ROUND TRIP OK' : '\nMISMATCH');
  process.exit(recovered === plaintext ? 0 : 1);
})().catch(e => { console.error('\nFAILED:', e.message); process.exit(1); });
