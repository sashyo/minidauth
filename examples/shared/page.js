/** The one bit of markup every example shares, so each one is only its own integration. */
export const page = (body) => `<!doctype html><meta charset="utf-8">
<style>
  body{font:15px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;background:#ece9e2;color:#0e0e0c;
       margin:0;padding:40px;max-width:760px}
  a,button{font:inherit;border:2px solid #0e0e0c;background:#ece9e2;padding:8px 12px;cursor:pointer;
           text-decoration:none;color:inherit;display:inline-block;box-shadow:3px 3px 0 #0e0e0c}
  code{background:#dedbd4;padding:1px 4px}
  .pill{border:2px solid #0e0e0c;padding:1px 8px;font-size:13px}
  .no{color:#d6371c}
</style>${body}`;

/** The two lines every example prints about an identity, rendered the same way. */
export const identityBlock = (vuid, roles) => `
  <p>Tide identity ${vuid ? `<code>${vuid.slice(0, 16)}…</code>`
    : '<span class="no">not linked</span>'}</p>
  <p>Granted ${roles.length ? roles.map((r) => `<span class="pill">${r}</span>`).join(" ")
    : '<span class="no">nothing</span>'}</p>`;
