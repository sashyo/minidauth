// Vault — front end.
//
// There is no demo mode. Until you are signed in the app shows a sign-in gate and nothing else. Once
// signed in, records come from the server as ciphertext, and reveal / new-record run the real
// doken-less crypto against the ORK cohort, gated by the vouchers the server issues on your
// quorum-granted role. The session lives in httpOnly cookies this script cannot read; every
// state-changing call carries the CSRF token.

const $ = s => document.querySelector(s);
const el = (t, c, h) => { const e = document.createElement(t); if (c) e.className = c; if (h != null) e.innerHTML = h; return e; };
const palette = ['#6b5bff','#e6893c','#37a0d3','#c65b9a','#4caf7d','#d3813c','#8c6bff','#3ba5a0'];
const initials = n => (n||'?').split(/[\s@._-]+/).slice(0,2).map(w=>w[0]||'').join('').toUpperCase();
const hue = n => palette[[...(n||'')].reduce((a,c)=>a+c.charCodeAt(0),0)%palette.length];
const esc = s => String(s??'').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const ago = iso => { if(!iso) return ''; const s=(Date.now()-new Date(iso))/1000; if(s<60)return 'just now'; if(s<3600)return Math.floor(s/60)+'m ago'; if(s<86400)return Math.floor(s/3600)+'h ago'; return new Date(iso).toISOString().slice(0,10); };

let ROLE = 'vault-reader';
let RECORDS = [], ME = { user: '', roles: [] }, EDITING = null;

// ---- api -----------------------------------------------------------------
const csrf = () => (document.cookie.match(/(?:^|;\s*)vault_csrf=([^;]+)/) || [])[1] || '';
const getJSON = p => fetch(p, { credentials:'same-origin' }).then(r => r.ok ? r.json() : Promise.reject(r));
async function req(method, p, body) {
  const r = await fetch(p, { method, credentials:'same-origin',
    headers:{ 'Content-Type':'application/json', 'X-CSRF-Token': csrf() },
    body: body==null ? undefined : JSON.stringify(body) });
  const text = await r.text();
  if (!r.ok) throw new Error((()=>{ try { return JSON.parse(text).error; } catch { return text; } })() || r.statusText);
  return text;
}
const post = (p, body) => req('POST', p, body);
const postJSON = (p, body) => post(p, body).then(t => t ? JSON.parse(t) : null);

// ---- toasts --------------------------------------------------------------
const icons = {
  ok:'<path d="M8 12l3 3 5-6"/><circle cx="12" cy="12" r="9"/>',
  no:'<circle cx="12" cy="12" r="9"/><path d="M15 9l-6 6M9 9l6 6"/>',
  info:'<circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/>' };
function toast(kind, title, sub){
  const t = el('div','toast '+kind);
  t.innerHTML = `<svg class="ti" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${icons[kind]}</svg><div class="tt"><b>${esc(title)}</b>${sub?`<span>${esc(sub)}</span>`:''}</div>`;
  $('#toasts').append(t);
  setTimeout(()=>{ t.style.opacity='0'; t.style.transform='translateX(20px)'; setTimeout(()=>t.remove(),300); }, 3600);
}

// ---- cohort visualization ------------------------------------------------
// Instruments fetch during a crypto operation to show the real cohort responding — one dot per node,
// lit as each ORK answers (green ok, red error), with a live count. It is the threshold model made
// visible: the operation only completes once enough nodes have signed.
function instrumentFetch(onHit){
  const orig = window.fetch;
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || '';
    let host = ''; try { host = new URL(url, location.href).host; } catch {}
    const isOrk = /(?:^|\.)tideprotocol\.com$/.test(host);
    let ok = false;
    try { const res = await orig(input, init); ok = res.ok; return res; }
    finally { if (isOrk && host) onHit(host, ok); }
  };
  return () => { window.fetch = orig; };
}
function cohortPanel(total, title){
  const c = $('#cohort');
  c.querySelector('.co-title').textContent = title;
  const grid = c.querySelector('.co-grid'); grid.innerHTML = '';
  for (let i=0;i<total;i++) grid.append(el('span','co-dot'));
  const count = c.querySelector('.co-count'); count.textContent = `0 / ${total}`;
  c.classList.remove('done','fail'); c.classList.add('on');
  const seen = new Map();
  return {
    mark(host, ok){
      if (!seen.has(host)) { const d = grid.children[seen.size]; if (d) d.classList.add(ok?'ok':'bad'); }
      seen.set(host, ok || seen.get(host));
      count.textContent = `${[...seen.values()].filter(Boolean).length} / ${total}`;
    },
    finish(success, verb){
      const ok = [...seen.values()].filter(Boolean).length;
      c.classList.add(success?'done':'fail');
      c.querySelector('.co-title').textContent = success ? `${verb} · ${ok} of ${total} nodes signed` : 'The cohort declined';
      setTimeout(()=>c.classList.remove('on','done','fail'), 1600);
    },
  };
}
async function withCohort(title, verb, total, fn){
  const ui = cohortPanel(total, title);
  const restore = instrumentFetch((h,ok)=>ui.mark(h,ok));
  try { const r = await fn(); ui.finish(true, verb); return r; }
  catch (e) { ui.finish(false); throw e; }
  finally { restore(); }
}

// ---- render --------------------------------------------------------------
const chip = (cls,txt,dot)=>`<span class="chip ${cls}">${dot?'<span class="d"></span>':''}${esc(txt)}</span>`;
const fieldsOf = r => Object.keys(r.ct||{});
function renderRecords(filter=''){
  const rows = $('#rows'); rows.innerHTML='';
  const list = RECORDS.filter(r=>!filter || (r.name+r.ref).toLowerCase().includes(filter));
  if (!list.length) rows.innerHTML = `<tr><td colspan="4" style="color:var(--faint);text-align:center;padding:40px">${RECORDS.length?'No matches.':'No records yet. Create one — its sensitive fields are encrypted before they ever reach the database.'}</td></tr>`;
  for(const r of list){
    const fields = fieldsOf(r);
    const tr = el('tr'); tr.dataset.id = r.id;
    tr.innerHTML = `
      <td><div class="rec"><div class="recav" style="background:${hue(r.name)}">${esc(initials(r.name))}</div><div><div class="nm">${esc(r.name)}</div><div class="sub">${esc(r.ref||'')}</div></div></div></td>
      <td>${chip('enc',fields.length+' encrypted')}</td>
      <td><span class="mask">created ${esc(r.created||'')}</span></td>
      <td>${chip('ok','sealed',true)}</td>`;
    tr.onclick = ()=>openDrawer(r);
    rows.append(tr);
  }
  $('#ct-records').textContent = RECORDS.length;
  $('#s-rec').textContent = RECORDS.length;
  $('#s-enc').textContent = RECORDS.reduce((a,r)=>a+fieldsOf(r).length,0);
}
function renderRaw(){
  const rowsHtml = RECORDS.slice(0,4).map(r=>{
    const ct = r.ct||{};
    const line = k => ct[k] ? `,\n    <span class="ky">"${k}_ciphertext"</span>: <span class="cx">"${esc(String(ct[k]).slice(0,46))}…"</span>` : '';
    return `  {\n    <span class="ky">"id"</span>: <span class="st">"${esc(r.id)}"</span>,\n    <span class="ky">"name"</span>: <span class="st">"${esc(r.name)}"</span>${line('bank')}${line('tax')}${line('notes')}\n  }`;
  }).join(',\n');
  $('#rawpre').innerHTML = RECORDS.length
    ? `select id, name, ciphertext from vault_records;\n\n[\n${rowsHtml}\n]\n\n// every sensitive field is ciphertext the cohort sealed. no key here, and none in any backup.`
    : `select id, name, ciphertext from vault_records;\n\n[]\n\n// no records yet.`;
}
const actMeta = {
  seal:{i:'ok',t:'sealed a field'}, reveal:{i:'ok',t:'revealed a field'},
  reveal_denied:{i:'no',t:'was refused a reveal'}, delete:{i:'no',t:'deleted a record'},
  access_request:{i:'info',t:'requested access'} };
function renderActivity(list){
  const box = $('#actlist'); box.innerHTML='';
  if(!list.length){ box.innerHTML = `<div class="actempty">No activity yet. Reveals, seals, denials and access requests show up here.<br><span style="color:var(--faint)">If this stays empty after actions, the <code>vault_activity</code> table isn't created yet — see the README.</span></div>`; return; }
  for(const a of list){
    const m = actMeta[a.type] || {i:'info',t:a.type};
    const who = (a.email||a.actor||'someone').split('@')[0];
    const detail = a.detail?.field ? `${a.detail.field} field` : (a.detail?.role ? a.detail.role : '');
    const row = el('div','actrow');
    row.innerHTML = `<svg class="ai ${m.i}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${icons[m.i]}</svg>
      <div class="at"><b>${esc(who)}</b> ${esc(m.t)}${detail?` · <span class="admut">${esc(detail)}</span>`:''}</div>
      <div class="awhen">${esc(ago(a.at))}</div>`;
    box.append(row);
  }
}
function renderAccess(){
  const has = r => ME.roles.includes(r);
  const row = (role, desc) => `<div class="rolerow">${has(role)?chip('ok',role,true):chip('',role)}<div><div class="rn">${esc(desc)}</div><div class="rd">${has(role)?'held by you · granted by quorum':'not held'}</div></div></div>`;
  $('#roleList').innerHTML = row('vault-reader','decrypt client fields') + row('vault-admin','manage records');
}
function renderAccessBanner(session){
  const b = $('#accessBanner');
  if (ME.roles.includes(ROLE)) { b.hidden = true; return; }
  b.hidden = false;
  if (session.pendingRequest) {
    b.className = 'access-banner pending';
    b.innerHTML = `<span>Your request for <b>${esc(ROLE)}</b> is pending — an administrator approves it through the quorum. It takes effect here as soon as it is committed.</span>`;
  } else {
    b.className = 'access-banner';
    b.innerHTML = `<span>You do not hold <b>${esc(ROLE)}</b>, so you cannot decrypt fields yet.</span><button class="btn primary" id="reqBtn">Request access</button>`;
    $('#reqBtn').onclick = requestAccess;
  }
}
async function requestAccess(){
  try{
    const r = await postJSON('/api/vault/request-access');
    if (r?.alreadyHeld) { toast('ok','You already have access','reloading'); return location.reload(); }
    toast('ok','Access requested', 'an administrator approves it through the quorum');
    const s = await getJSON('/api/session').catch(()=>({}));
    renderAccessBanner(s); refreshActivity();
  }catch(e){ toast('no','Could not request access', e.message); }
}

// ---- drawer --------------------------------------------------------------
let relockTimers = new Set();
function clearRelocks(){ for(const id of relockTimers) clearTimeout(id); relockTimers.clear(); }
function fieldRow(rec, key, label){
  const has = (rec.ct||{})[key] != null;
  return `<div class="field" data-field="${key}">
    <span class="fk">${label}</span>
    <span class="fv ct">${has?'•• ciphertext ••':'—'}</span>
    ${has?(ME.roles.includes(ROLE)
      ? `<button class="reveal" data-k="${key}">Reveal</button>`
      : `<span class="locked"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 018 0v3"/></svg>needs ${esc(ROLE)}</span>`):''}
  </div>`;
}
function openDrawer(r){
  clearRelocks();
  const d = $('#drawer');
  const fields = fieldsOf(r);
  const canManage = ME.roles.includes('vault-admin') || true; // any signed-in user manages in this shared vault
  d.innerHTML = `
    <div class="dhead"><div class="recav" style="background:${hue(r.name)}">${esc(initials(r.name))}</div>
      <div style="flex:1"><h3>${esc(r.name)}</h3><div class="meta">${esc(r.ref||'')} · created ${esc(r.created||'')}</div>
        <div class="tags" style="margin-top:8px">${chip('enc',fields.length+' encrypted fields')} ${chip('ok','sealed',true)}</div></div>
      <button class="iconbtn" id="dClose"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 6l12 12M18 6L6 18"/></svg></button>
    </div>
    <div class="dbody">
      <div class="fieldgrp"><div class="lbl">Encrypted fields</div>
        ${fieldRow(r,'bank','Bank account')}${fieldRow(r,'tax','Tax ID')}${fieldRow(r,'notes','Private notes')}
      </div>
      <div class="fieldgrp"><div class="lbl">How a reveal works</div>
        <p style="color:var(--muted);font-size:12.5px;margin:0">Reveal asks the server for a decrypt voucher, issued only because your user id holds <b>${esc(ROLE)}</b>. The cohort then decrypts; this app never holds the key. A revealed value re-hides after 15 seconds.</p>
      </div>
    </div>
    <div class="foot">
      <button class="btn" id="dEdit"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 20h4L18 10l-4-4L4 16z"/><path d="M13 5l4 4"/></svg>Edit</button>
      <button class="btn danger" id="dDel"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 7h16M9 7V5h6v2M6 7l1 13h10l1-13"/></svg>Delete</button>
    </div>`;
  d.classList.add('on'); $('#scrim').classList.add('on');
  $('#dClose').onclick = closeDrawer;
  $('#dEdit').onclick = ()=>editRecord(r);
  $('#dDel').onclick = ()=>deleteRecord(r);
  d.querySelectorAll('.reveal').forEach(b=> b.onclick = ()=>reveal(b, r));
}
function closeDrawer(){ clearRelocks(); $('#drawer').classList.remove('on'); $('#scrim').classList.remove('on'); }
$('#scrim').onclick = closeDrawer;

async function deleteRecord(r){
  if(!confirm(`Delete “${r.name}”? The ciphertext is removed. This cannot be undone.`)) return;
  try{ await req('DELETE', '/api/vault/records/'+r.id); toast('ok','Record deleted', r.name); closeDrawer(); await loadRecords(); refreshActivity(); }
  catch(e){ toast('no','Could not delete', e.message); }
}
function editRecord(r){
  EDITING = { id: r.id, ct: {...(r.ct||{})} };
  $('#modalTitle').textContent = 'Edit record';
  $('#modalSub').innerHTML = 'Leave an encrypted field blank to keep its current value. Anything you type is re-sealed before it is stored.';
  $('#mSave').lastChild.textContent = 'Re-encrypt & save';
  $('#f-name').value = r.name || ''; $('#f-ref').value = r.ref || '';
  ['bank','tax','notes'].forEach(k=>{ $('#f-'+k).value=''; $('#f-'+k).placeholder = (r.ct||{})[k] ? 'kept encrypted — type to replace' : ($('#f-'+k).getAttribute('data-ph')||''); });
  closeDrawer();
  $('#modal').classList.add('on'); $('#f-name').focus(); validateModal();
}

// ---- live crypto ---------------------------------------------------------
let T=null;
async function tide(){
  if(T) return T;
  const [pkg, PPSF, Ed] = await Promise.all([
    import('https://esm.sh/@tideorg/js@0.14.25'),
    import('https://esm.sh/@tideorg/js@0.14.25/dist/Models/PolicyProtectedSerializedField.js'),
    import('https://esm.sh/@tideorg/js@0.14.25/dist/Cryptide/Components/Schemes/Ed25519/Ed25519Scheme.js'),
  ]);
  const cfg = await getJSON('/api/vault/config');
  const keyInfo = await new pkg.Clients.NetworkClient(cfg.homeOrkUrl).GetKeyInfo(cfg.vvkId);
  T = { pkg, PPSF:PPSF.default, Ed:Ed.default, cfg, keyInfo, total: keyInfo.OrkInfo.length,
        enc:Uint8Array.from(atob(cfg.encryptPolicy),c=>c.charCodeAt(0)),
        dec:Uint8Array.from(atob(cfg.decryptPolicy),c=>c.charCodeAt(0)) };
  return T;
}
const guestOf = (t)=>{ const k=t.pkg.Cryptide.TideKey.NewKey(t.Ed); return {k, tok:{payload:{sessionKey:k.get_public_component()},serialize:()=>''}}; };
const vfetch = (p, ctx) => reqBody => post(p, { voucherRequest: reqBody, context: ctx });
async function encryptOne(t, guest, text, ctx){
  const pae=new t.pkg.Flow.EncryptionFlows.PolicyAuthorizedEncryptionFlow({vendorId:t.cfg.vvkId,token:guest.tok,sessionKey:guest.k,voucherURL:'',keyInfo:t.keyInfo});
  const {request,encReqs,timestamp}=await pae.createEncryptionRequest([{data:new TextEncoder().encode(text),tags:['vault']}]); request.addPolicy(t.enc);
  const sf=new t.pkg.Flow.SigningFlows.dVVKSigningFlow(t.cfg.vvkId,t.keyInfo.UserPublic,t.keyInfo.OrkInfo.slice(),guest.k,guest.tok,''); sf.setVoucherRetrievalFunction(vfetch('/api/vault/voucher/sign', ctx));
  const sigs=await sf.start(request);
  const cipher=t.PPSF.create(encReqs[0].encryptedData,timestamp,encReqs[0].sizeLessThan32?null:encReqs[0].encryptionToSign,sigs[0]);
  return btoa(String.fromCharCode(...cipher));
}
async function liveDecrypt(r,k){
  const t=await tide(), guest=guestOf(t);
  const cipher=Uint8Array.from(atob(r.ct[k]),c=>c.charCodeAt(0));
  const pae=new t.pkg.Flow.EncryptionFlows.PolicyAuthorizedEncryptionFlow({vendorId:t.cfg.vvkId,token:guest.tok,sessionKey:guest.k,voucherURL:'',keyInfo:t.keyInfo});
  const {request}=pae.createDecryptionRequest([{encrypted:cipher,tags:['vault']}]); request.addPolicy(t.dec);
  const df=new t.pkg.Flow.DecryptionFlows.dVVKDecryptionFlow(t.cfg.vvkId,t.keyInfo.UserPublic,t.keyInfo.OrkInfo.slice(),guest.k,guest.tok,''); df.setVoucherRetrievalFunction(vfetch('/api/vault/voucher/decrypt', {record:r.id, field:k}));
  const keys=await withCohort('Contacting the cohort', 'Revealed', t.total, ()=>df.start(request));
  const b=t.PPSF.deserialize(cipher); const AES=t.pkg.Cryptide.Encryption.AES;
  const out=b.encKey&&b.encKey.length?await AES.decryptDataRawOutput(b.encFieldChk,await AES.decryptDataRawOutput(b.encKey.slice(32),keys[0])):await AES.decryptDataRawOutput(b.encFieldChk.slice(32),keys[0]);
  return new TextDecoder().decode(out);
}
async function liveSaveFields(name, ref, vals, existingCt){
  const ct = { ...(existingCt||{}) };
  const toSeal = ['bank','tax','notes'].filter(k=>vals[k] && vals[k].trim());
  if(!toSeal.length) return ct; // nothing to encrypt (e.g. a name-only edit) — no cohort round trip
  const t=await tide(), guest=guestOf(t);
  await withCohort('Sealing across the cohort', 'Sealed', t.total, async ()=>{
    for(const k of toSeal) ct[k] = await encryptOne(t, guest, vals[k], {field:k});
  });
  return ct;
}

// ---- reveal / create / edit ----------------------------------------------
function relock(field, r, k){
  const id = setTimeout(()=>{
    relockTimers.delete(id);
    if(!document.body.contains(field)) return;
    const fv = field.querySelector('.fv');
    fv.classList.remove('pt'); fv.classList.add('ct'); fv.textContent='•• ciphertext ••';
    const act = field.querySelector('.fact'); if(act) act.remove();
    const b = el('button','reveal'); b.dataset.k=k; b.textContent='Reveal'; b.onclick=()=>reveal(b,r); field.append(b);
  }, 15000);
  relockTimers.add(id);
}
async function reveal(btn, r){
  const k = btn.dataset.k; const field = btn.closest('.field'); const fv = field.querySelector('.fv');
  btn.classList.add('busy'); btn.textContent='Revealing…';
  try{
    const text = await liveDecrypt(r, k);
    fv.classList.remove('ct'); fv.classList.add('pt'); fv.textContent = text;
    btn.remove();
    const act = el('div','fact');
    act.innerHTML = `<button class="reveal copy">Copy</button><span class="relock">re-hides 15s</span>`;
    field.append(act);
    act.querySelector('.copy').onclick = ()=>{ (navigator.clipboard?.writeText(text)||Promise.reject()).then(()=>toast('ok','Copied to clipboard','clear it yourself when done')).catch(()=>toast('no','Copy unavailable','select the text manually')); };
    relock(field, r, k);
    refreshActivity();
  }catch(e){ btn.classList.remove('busy'); btn.textContent='Reveal'; toast('no','Reveal refused', e.message||'the network declined'); refreshActivity(); }
}
function openModal(){ EDITING=null; $('#modalTitle').textContent='New client record'; $('#modalSub').innerHTML='Fields marked <span style="color:var(--accent);font-weight:600">encrypted</span> are sealed in your browser before they are stored. The database only ever holds ciphertext.'; $('#mSave').lastChild.textContent='Encrypt & save'; ['bank','tax','notes'].forEach(k=>$('#f-'+k).placeholder=$('#f-'+k).getAttribute('data-ph')||''); $('#modal').classList.add('on'); $('#f-name').focus(); validateModal(); }
function closeModal(){ $('#modal').classList.remove('on'); ['name','ref','tax','bank','notes'].forEach(k=>{ const el=$('#f-'+k); if(el) el.value=''; }); EDITING=null; }
function validateModal(){ $('#mSave').disabled = !$('#f-name').value.trim(); }
async function saveRecord(){
  const name=$('#f-name').value.trim(), ref=$('#f-ref').value.trim();
  if(!name){ $('#f-name').focus(); return; }
  const btn=$('#mSave'); btn.disabled=true;
  const vals={bank:$('#f-bank').value,tax:$('#f-tax').value,notes:$('#f-notes').value};
  try{
    if(EDITING){
      const ct = await liveSaveFields(name, ref, vals, EDITING.ct);
      await req('PUT','/api/vault/records/'+EDITING.id,{name, ref: ref||null, ct});
      toast('ok','Record updated', name);
    } else {
      const ct = await liveSaveFields(name, ref, vals, {});
      await postJSON('/api/vault/records',{name, ref: ref||null, ct});
      toast('ok','Record sealed', Object.keys(ct).length+' field(s) encrypted before storage');
    }
    await loadRecords(); refreshActivity(); closeModal();
  }catch(e){ toast('no','Could not save', e.message); }
  btn.disabled=false;
}

// ---- nav / chrome --------------------------------------------------------
const subs={records:'Confidential client records',raw:'What the database really holds',activity:'Every read, seal and request',access:'Roles and governance'};
document.querySelectorAll('.nav').forEach(n=> n.onclick=()=>{
  document.querySelectorAll('.nav').forEach(x=>x.classList.remove('on')); n.classList.add('on');
  const v=n.dataset.view; document.querySelectorAll('.view').forEach(x=>x.classList.toggle('on',x.dataset.view===v));
  $('#crumb').firstChild.textContent = n.textContent.replace(/\d+$/,'').trim();
  $('#crumbsub').textContent = subs[v];
  if(v==='activity') refreshActivity();
});
$('#q').oninput = e => renderRecords(e.target.value.toLowerCase());
$('#newBtn').onclick = openModal; $('#mCancel').onclick = closeModal; $('#mSave').onclick = saveRecord;
$('#f-name').oninput = validateModal;
$('#modal').onclick = e => { if(e.target.id==='modal') closeModal(); };
$('#theme').onclick = ()=>{ const b=document.body; b.dataset.theme = b.dataset.theme==='dark'?'light':'dark'; };
document.onkeydown = e => { if(e.key==='Escape'){ closeDrawer(); closeModal(); } };
$('#userChip').onclick = async ()=>{ if(!confirm('Sign out?')) return; try{ await post('/api/logout'); }catch{} location.reload(); };

// ---- sign-in gate --------------------------------------------------------
async function doLogin(){
  const email=$('#g-email').value.trim(), password=$('#g-pass').value;
  const go=$('#gGo'); $('#g-err').textContent=''; go.disabled=true; go.textContent='Signing in…';
  try{ await post('/api/login', { email, password }); location.reload(); }
  catch(e){ $('#g-err').textContent = e.message || 'sign-in failed'; go.disabled=false; go.textContent='Sign in'; }
}
$('#gGo').onclick = doLogin;
$('#g-pass').onkeydown = e => { if(e.key==='Enter') doLogin(); };

// ---- data ----------------------------------------------------------------
async function loadRecords(){
  try{ RECORDS = await getJSON('/api/vault/records'); }catch{ RECORDS = []; }
  renderRecords($('#q').value.toLowerCase()); renderRaw();
}
let actTimer=null;
async function refreshActivity(){
  clearTimeout(actTimer);
  actTimer = setTimeout(async ()=>{ try{ renderActivity(await getJSON('/api/vault/activity')); }catch{} }, 250);
}

// ---- boot ----------------------------------------------------------------
(async ()=>{
  let s = null;
  try{ s = await getJSON('/api/session'); }catch{ s = null; }
  if(!(s && s.user)){ $('#gate').classList.add('on'); $('#g-email').focus(); return; }
  ME = { user: s.user, roles: s.roles || [] };
  if(s.gateRole) ROLE = s.gateRole;
  $('#gate').classList.remove('on');
  $('#app').style.visibility='visible';
  $('#uname').textContent = s.user.split('@')[0];
  $('#uav').textContent = initials(s.user);
  $('#urole').textContent = (s.roles && s.roles.length ? s.roles.join(' · ') : 'no roles yet');
  const held = ME.roles.includes(ROLE);
  const rc = $('#uroleChip'); rc.className = 'chip ' + (held ? 'ok' : ''); rc.innerHTML = (held?'<span class="d"></span>':'') + esc(ME.roles[0] || 'no roles');
  renderAccess(); renderAccessBanner(s);
  await loadRecords(); refreshActivity();
})();
