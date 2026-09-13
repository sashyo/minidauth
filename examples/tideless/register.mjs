// tide-js's dist uses extensionless, bundler-style relative imports ("./Models/Infos/KeyInfo").
// Node's ESM loader needs the extension, so register a resolve hook that appends .js / /index.js.
//   node --import ./register.mjs roundtrip.mjs
import { register } from 'node:module';
register('./loader.mjs', import.meta.url);
