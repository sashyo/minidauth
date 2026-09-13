// Resolve hook: tide-js dist imports are extensionless. Try the specifier, then +".js", then
// +"/index.js". Lets Node load a bundler-oriented ESM build without bundling it first.
export async function resolve(specifier, context, next) {
  try {
    return await next(specifier, context);
  } catch (e) {
    if (specifier.startsWith('.') || specifier.startsWith('/')) {
      for (const cand of [specifier + '.js', specifier + '/index.js']) {
        try { return await next(cand, context); } catch { /* try next */ }
      }
    }
    throw e;
  }
}
