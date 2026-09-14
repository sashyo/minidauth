// Vault — front end.
//
// There is no demo mode. Until you are signed in (GET /api/session returns a user) the app shows a
// sign-in gate and nothing else. Once signed in, records come from the server as ciphertext, and
// reveal / new-record run the real doken-less Tide crypto against the ORK cohort, gated by the
// vouchers the server issues on your quorum-granted role. The Supabase session lives in httpOnly
// cookies this script cannot read; every state-changing call carries the CSRF token.

const $ = s => document.querySelector(s);
const el = (t, c, h) => { const e = document.createElement(t); if (c) e.className = c; if (h != null) e.innerHTML = h; return e; };
const palette = ['#6b5bff','#e6893c','#37a0d3','#c65b9a','#4caf7d','#d3813c','#8c6bff','#3ba5a0'];
const initials = n => (n||'?').split(/[\s@._-]+/).slice(0,2).map(w=>w[0]||'').join('').toUpperCase();
const hue = n => palette[[...(n||'')].reduce((a,c)=>a+c.charCodeAt(0),0)%palette.length];
const esc = s => String(s??'').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

const ROLE = 'vault-reader';
let RECORDS = [], ME = { user: '', roles: [] };

// ---- api -----------------------------------------------------------------
const csrf = () => (document.cookie.match(/(?:^|;\s*)vault_csrf=([^;]+)/) || [])[1] || '';
const getJSON = p => fetch(p, { credentials:'same-origin' }).then(r => r.ok ? r.json() : Promise.reject(r));
async function post(p, body) {
  const r = await fetch(p, { method:'POST', credentials:'same-origin',
    headers:{ 'Content-Type':'application/json', 'X-CSRF-Token': csrf() },
    body: body==null ? undefined : JSON.stringify(body) });
  const text = await r.text();
  if (!r.ok) throw new Error((()=>{ try { return JSON.parse(text).error; } catch { return text; } })() || r.statusText);
  return text;
}
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

// ---- render --------------------------------------------------------------
const chip = (cls,txt,dot)=>`<span class="chip ${cls}">${dot?'<span class="d"></span>':''}${esc(txt)}</span>`;
const fieldsOf = r => Object.keys(r.ct||{});
function renderRecords(filter=''){
  const rows = $('#rows'); rows.innerHTML='';
  const list = RECORDS.filter(r=>!filter || (r.name+r.ref).toLowerCase().includes(filter));
  if (!list.length) rows.innerHTML = `<tr><td colspan="4" style="color:var(--faint);text-align:center;padding:40px">No records yet. Create one — its sensitive fields are encrypted before they ever reach the database.</td></tr>`;
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
function renderAccess(){
  const has = r => ME.roles.includes(r);
  const row = (role, desc) => `<div class="rolerow">${has(role)?chip('ok',role,true):chip('',role)}<div><div class="rn">${esc(desc)}</div><div class="rd">${has(role)?'held by you · granted by quorum':'not held'}</div></div></div>`;
  $('#roleList').innerHTML = row('vault-reader','decrypt client fields') + row('vault-admin','manage records');
}

// ---- drawer --------------------------------------------------------------
function fieldRow(rec, key, label){
  const has = (rec.ct||{})[key] != null;
  return `<div class="field" data-field="${key}">
    <span class="fk">${label}</span>
    <span class="fv ct">${has?'•• ciphertext ••':'—'}</span>
    ${has?(ME.roles.includes(ROLE)
      ? `<button class="reveal" data-k="${key}">Reveal</button>`
      : `<span class="locked"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 018 0v3"/></svg>needs vault-reader</span>`):''}
  </div>`;
}
function openDrawer(r){
  const d = $('#drawer');
  const fields = fieldsOf(r);
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
        <p style="color:var(--muted);font-size:12.5px;margin:0">Reveal asks the server for a decrypt voucher, which is issued only because your user id holds <b>vault-reader</b>. The cohort then decrypts; this app never holds the key.</p>
      </div>
    </div>`;
  d.classList.add('on'); $('#scrim').classList.add('on');
  $('#dClose').onclick = closeDrawer;
  d.querySelectorAll('.reveal').forEach(b=> b.onclick = ()=>reveal(b, r));
}
function closeDrawer(){ $('#drawer').classList.remove('on'); $('#scrim').classList.remove('on'); }
$('#scrim').onclick = closeDrawer;

// ---- live Tide crypto ----------------------------------------------------
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
  T = { pkg, PPSF:PPSF.default, Ed:Ed.default, cfg, keyInfo,
        enc:Uint8Array.from(atob(cfg.encryptPolicy),c=>c.charCodeAt(0)),
        dec:Uint8Array.from(atob(cfg.decryptPolicy),c=>c.charCodeAt(0)) };
  return T;
}
const guestOf = (t)=>{ const k=t.pkg.Cryptide.TideKey.NewKey(t.Ed); return {k, tok:{payload:{sessionKey:k.get_public_component()},serialize:()=>''}}; };
const vfetch = p => req => post(p, { voucherRequest: req });
async function liveEncryptField(t, guest, text){
  const pae=new t.pkg.Flow.EncryptionFlows.PolicyAuthorizedEncryptionFlow({vendorId:t.cfg.vvkId,token:guest.tok,sessionKey:guest.k,voucherURL:'',keyInfo:t.keyInfo});
  const {request,encReqs,timestamp}=await pae.createEncryptionRequest([{data:new TextEncoder().encode(text),tags:['vault']}]); request.addPolicy(t.enc);
  const sf=new t.pkg.Flow.SigningFlows.dVVKSigningFlow(t.cfg.vvkId,t.keyInfo.UserPublic,t.keyInfo.OrkInfo.slice(),guest.k,guest.tok,''); sf.setVoucherRetrievalFunction(vfetch('/api/vault/voucher/sign'));
  const sigs=await sf.start(request);
  const cipher=t.PPSF.create(encReqs[0].encryptedData,timestamp,encReqs[0].sizeLessThan32?null:encReqs[0].encryptionToSign,sigs[0]);
  return btoa(String.fromCharCode(...cipher));
}
async function liveDecrypt(r,k){
  const t=await tide(), guest=guestOf(t);
  const cipher=Uint8Array.from(atob(r.ct[k]),c=>c.charCodeAt(0));
  const pae=new t.pkg.Flow.EncryptionFlows.PolicyAuthorizedEncryptionFlow({vendorId:t.cfg.vvkId,token:guest.tok,sessionKey:guest.k,voucherURL:'',keyInfo:t.keyInfo});
  const {request}=pae.createDecryptionRequest([{encrypted:cipher,tags:['vault']}]); request.addPolicy(t.dec);
  const df=new t.pkg.Flow.DecryptionFlows.dVVKDecryptionFlow(t.cfg.vvkId,t.keyInfo.UserPublic,t.keyInfo.OrkInfo.slice(),guest.k,guest.tok,''); df.setVoucherRetrievalFunction(vfetch('/api/vault/voucher/decrypt'));
  const keys=await df.start(request);
  const b=t.PPSF.deserialize(cipher); const AES=t.pkg.Cryptide.Encryption.AES;
  const out=b.encKey&&b.encKey.length?await AES.decryptDataRawOutput(b.encFieldChk,await AES.decryptDataRawOutput(b.encKey.slice(32),keys[0])):await AES.decryptDataRawOutput(b.encFieldChk.slice(32),keys[0]);
  return new TextDecoder().decode(out);
}
async function liveCreate(name,ref,vals,fields){
  const t=await tide(), guest=guestOf(t), ct={};
  for(const k of fields) if(vals[k]) ct[k]=await liveEncryptField(t,guest,vals[k]);
  return postJSON('/api/vault/records',{name,ref,ct});
}

// ---- reveal / create -----------------------------------------------------
async function reveal(btn, r){
  const k = btn.dataset.k; const field = btn.closest('.field'); const fv = field.querySelector('.fv');
  btn.classList.add('busy'); btn.textContent='Asking cohort…';
  try{
    const text = await liveDecrypt(r, k);
    fv.classList.remove('ct'); fv.classList.add('pt'); fv.textContent = text;
    btn.remove();
    toast('ok','Decrypted by the cohort', k+' · vault-reader verified');
  }catch(e){ btn.classList.remove('busy'); btn.textContent='Reveal'; toast('no','Reveal refused', e.message||'the network declined'); }
}
function openModal(){ $('#modal').classList.add('on'); $('#f-name').focus(); }
function closeModal(){ $('#modal').classList.remove('on'); ['name','ref','tax','bank','notes'].forEach(k=>{ const el=$('#f-'+k); if(el) el.value=''; }); }
async function saveRecord(){
  const name=$('#f-name').value.trim(), ref=$('#f-ref').value.trim();
  if(!name){ $('#f-name').focus(); return; }
  const btn=$('#mSave'); btn.disabled=true; btn.textContent='Sealing…';
  const fields=['bank','tax','notes'].filter(k=>$('#f-'+k).value.trim());
  try{
    await liveCreate(name, ref, {bank:$('#f-bank').value,tax:$('#f-tax').value,notes:$('#f-notes').value}, fields);
    await loadRecords();
    toast('ok','Record sealed', fields.length+' field(s) encrypted before storage');
    closeModal();
  }catch(e){ toast('no','Could not save', e.message); }
  btn.disabled=false; btn.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M8 12l3 3 5-6"/></svg>Encrypt & save';
}

// ---- nav / chrome --------------------------------------------------------
const subs={records:'Confidential client records',raw:'What the database really holds',access:'Roles and governance'};
document.querySelectorAll('.nav').forEach(n=> n.onclick=()=>{
  document.querySelectorAll('.nav').forEach(x=>x.classList.remove('on')); n.classList.add('on');
  const v=n.dataset.view; document.querySelectorAll('.view').forEach(x=>x.classList.toggle('on',x.dataset.view===v));
  $('#crumb').firstChild.textContent = n.textContent.replace(/\d+$/,'').trim();
  $('#crumbsub').textContent = subs[v];
});
$('#q').oninput = e => renderRecords(e.target.value.toLowerCase());
$('#newBtn').onclick = openModal; $('#mCancel').onclick = closeModal; $('#mSave').onclick = saveRecord;
$('#modal').onclick = e => { if(e.target.id==='modal') closeModal(); };
$('#theme').onclick = ()=>{ const b=document.body; b.dataset.theme = b.dataset.theme==='dark'?'light':'dark'; };
document.onkeydown = e => { if(e.key==='Escape'){ closeDrawer(); closeModal(); } };
$('#userChip').onclick = async ()=>{
  if(!confirm('Sign out?')) return;
  try{ await post('/api/logout'); }catch{}
  location.reload();
};

// ---- sign-in gate --------------------------------------------------------
async function doLogin(){
  const email=$('#g-email').value.trim(), password=$('#g-pass').value;
  const go=$('#gGo'); $('#g-err').textContent=''; go.disabled=true; go.textContent='Signing in…';
  try{
    await post('/api/login', { email, password });
    location.reload();
  }catch(e){ $('#g-err').textContent = e.message || 'sign-in failed'; go.disabled=false; go.textContent='Sign in'; }
}
$('#gGo').onclick = doLogin;
$('#g-pass').onkeydown = e => { if(e.key==='Enter') doLogin(); };

// ---- data ----------------------------------------------------------------
async function loadRecords(){
  try{ RECORDS = await getJSON('/api/vault/records'); }catch{ RECORDS = []; }
  renderRecords($('#q').value.toLowerCase()); renderRaw();
}

// ---- boot ----------------------------------------------------------------
(async ()=>{
  let s = null;
  try{ s = await getJSON('/api/session'); }catch{ s = null; }
  if(!(s && s.user)){
    $('#gate').classList.add('on');
    $('#g-email').focus();
    return;
  }
  ME = { user: s.user, roles: s.roles || [] };
  $('#gate').classList.remove('on');
  $('#app').style.visibility='visible';
  $('#uname').textContent = s.user.split('@')[0];
  $('#uav').textContent = initials(s.user);
  $('#urole').textContent = (s.roles && s.roles.length ? s.roles.join(' · ') : 'no roles yet');
  const held = ME.roles.includes(ROLE);
  const rc = $('#uroleChip'); rc.className = 'chip ' + (held ? 'ok' : ''); rc.innerHTML = (held?'<span class="d"></span>':'') + (ME.roles[0] || 'no roles');
  renderAccess();
  await loadRecords();
})();
