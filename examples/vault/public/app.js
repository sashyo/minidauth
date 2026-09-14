// Vault — front end.
//
// Renders immediately with demo data so the UI is explorable without a backend. When signed in to
// Supabase (GET /api/session returns a user), it switches to live mode: records come from the
// server, and reveal / new-record / release run the real doken-less Tide crypto against the ORK
// cohort, gated by the vouchers the server issues on your quorum-granted role.

const $ = s => document.querySelector(s);
const el = (t, c, h) => { const e = document.createElement(t); if (c) e.className = c; if (h != null) e.innerHTML = h; return e; };
const palette = ['#6b5bff','#e6893c','#37a0d3','#c65b9a','#4caf7d','#d3813c','#8c6bff','#3ba5a0'];
const initials = n => n.split(/\s+/).slice(0,2).map(w=>w[0]||'').join('').toUpperCase();
const hue = n => palette[[...n].reduce((a,c)=>a+c.charCodeAt(0),0)%palette.length];
const money = n => new Intl.NumberFormat('en',{style:'currency',currency:'USD',maximumFractionDigits:0}).format(n);

// ---- demo data -----------------------------------------------------------
let LIVE = false, ME = { name:'m. archer', roles:['vault-reader','signer'] };
const demoRecords = [
  ['Northwind Traders','NWT-0042','DE89 3704 •••• 0532','**• ••-4471', 3, ['bank','tax','notes']],
  ['Aperture Foods','APF-0117','GB29 NWBK •••• 1955','**• ••-9920', 3, ['bank','tax','notes']],
  ['Halcyon Legal','HLC-0088','FR14 2004 •••• 8606','**• ••-2231', 2, ['bank','notes']],
  ['Meridian Health','MRD-0203','NL91 ABNA •••• 3000','**• ••-7788', 3, ['bank','tax','notes']],
  ['Cobalt Studios','CBT-0311','US 021 •••• 4412','**• ••-1200', 2, ['bank','tax']],
  ['Beacon Freight','BCN-0076','ES91 2100 •••• 0418','**• ••-6654', 3, ['bank','tax','notes']],
].map((r,i)=>({ id:'rec_'+(1000+i), name:r[0], ref:r[1], bankMask:r[2], taxMask:r[3], fields:r[5],
  created:['2026-08-14','2026-08-22','2026-09-01','2026-09-04','2026-09-09','2026-09-11'][i],
  plain:{ bank:['DE89 3704 0044 0532 0130 00','GB29 NWBK 6016 1331 9268 19','FR14 2004 1010 0505 0001 3M02 606','NL91 ABNA 0417 1643 0011 3000','US 021000021 044120117','ES91 2100 0418 4502 0005 1332'][i],
          tax:['DE 118 429 4471','GB 883 209 9920','—','NL 8201 46 7788','US 88-4412001','ES B-6654 2201'][i],
          notes:['Prefers wire on Fridays. Escalation: J. Reyes.','Under audit Q3. Do not disclose vendor list.','Retainer client since 2019.','HIPAA-covered. Access logged.','NDA on file.','Freight terms renegotiated Aug.'][i] } }));
const demoReleases = [
  ['REL-2201','Northwind Traders',24000,'m. archer','ok'],
  ['REL-2198','Meridian Health',8800,'s. okafor','ok'],
  ['REL-2195','Aperture Foods',52000,'m. archer','no'],
  ['REL-2190','Halcyon Legal',12500,'d. vance','ok'],
].map((r,i)=>({ ref:r[0], client:r[1], amount:r[2], by:r[3], state:r[4], when:['2026-09-11','2026-09-09','2026-09-08','2026-09-05'][i] }));

let RECORDS = demoRecords, RELEASES = demoReleases;

// ---- toasts --------------------------------------------------------------
const icons = {
  ok:'<path d="M8 12l3 3 5-6"/><circle cx="12" cy="12" r="9"/>',
  no:'<circle cx="12" cy="12" r="9"/><path d="M15 9l-6 6M9 9l6 6"/>',
  info:'<circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/>' };
function toast(kind, title, sub){
  const t = el('div','toast '+kind);
  t.innerHTML = `<svg class="ti" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${icons[kind]}</svg><div class="tt"><b>${title}</b>${sub?`<span>${sub}</span>`:''}</div>`;
  $('#toasts').append(t);
  setTimeout(()=>{ t.style.opacity='0'; t.style.transform='translateX(20px)'; setTimeout(()=>t.remove(),300); }, 3600);
}

// ---- render --------------------------------------------------------------
const chip = (cls,txt,dot)=>`<span class="chip ${cls}">${dot?'<span class="d"></span>':''}${txt}</span>`;
function renderRecords(filter=''){
  const rows = $('#rows'); rows.innerHTML='';
  const list = RECORDS.filter(r=>!filter || (r.name+r.ref).toLowerCase().includes(filter));
  for(const r of list){
    const tr = el('tr'); tr.dataset.id = r.id;
    tr.innerHTML = `
      <td><div class="rec"><div class="recav" style="background:${hue(r.name)}">${initials(r.name)}</div><div><div class="nm">${r.name}</div><div class="sub">${r.ref}</div></div></div></td>
      <td><span class="mask"><b>••</b> ${r.taxMask.slice(-5)}</span></td>
      <td><span class="mask">${r.bankMask}</span></td>
      <td>${chip('enc',r.fields.length+' encrypted')}</td>
      <td>${chip('ok','sealed',true)}</td>`;
    tr.onclick = ()=>openDrawer(r);
    rows.append(tr);
  }
  $('#ct-records').textContent = RECORDS.length;
  $('#s-rec').textContent = RECORDS.length;
  $('#s-enc').textContent = RECORDS.reduce((a,r)=>a+r.fields.length,0);
}
function renderReleases(){
  const rows = $('#relrows'); rows.innerHTML='';
  for(const r of RELEASES){
    const tr = el('tr');
    tr.innerHTML = `<td class="mono-cell" style="color:var(--text);font-weight:600">${r.ref}</td>
      <td>${r.client}</td><td class="amount">${money(r.amount)}</td><td class="mono-cell">${r.by} · ${r.when}</td>
      <td>${r.state==='ok'?chip('ok','signed, verifies',true):chip('no','refused · over limit',true)}</td>`;
    rows.append(tr);
  }
  $('#ct-rel').textContent = RELEASES.length; $('#s-sign').textContent = RELEASES.filter(r=>r.state==='ok').length;
}
function renderRaw(){
  const rowsHtml = RECORDS.slice(0,3).map(r=>{
    const ct = btoa(r.name+r.ref).replace(/=/g,'').slice(0,44);
    return `  {\n    <span class="ky">"id"</span>: <span class="st">"${r.id}"</span>,\n    <span class="ky">"name"</span>: <span class="st">"${r.name}"</span>,\n    <span class="ky">"bank_ciphertext"</span>: <span class="cx">"AQAAAAEAAAAC${ct}Rt5uD..."</span>,\n    <span class="ky">"tax_ciphertext"</span>: <span class="cx">"AQAAAAEAAAAC${ct.split('').reverse().join('')}9kQ..."</span>,\n    <span class="ky">"notes_ciphertext"</span>: <span class="cx">"AQAAAAEAAAACb${ct.slice(4)}xZ0..."</span>\n  }`;
  }).join(',\n');
  $('#rawpre').innerHTML = `select * from records limit 3;\n\n[\n${rowsHtml}\n]\n\n// every sensitive field is ciphertext. no key here, and none in any backup.`;
}

// ---- drawer --------------------------------------------------------------
let openRec = null;
function fieldRow(rec, key, label){
  const has = rec.fields.includes(key);
  return `<div class="field" data-field="${key}">
    <span class="fk">${label}</span>
    <span class="fv ct">${has?'AQAAAAEAAA••ciphertext••'+(key.charCodeAt(0)):'—'}</span>
    ${has?(ME.roles.includes('vault-reader')
      ? `<button class="reveal" data-k="${key}">Reveal</button>`
      : `<span class="locked"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 018 0v3"/></svg>needs vault-reader</span>`):''}
  </div>`;
}
function openDrawer(r){
  openRec = r;
  const d = $('#drawer');
  d.innerHTML = `
    <div class="dhead"><div class="recav" style="background:${hue(r.name)}">${initials(r.name)}</div>
      <div style="flex:1"><h3>${r.name}</h3><div class="meta">${r.ref} · created ${r.created}</div>
        <div class="tags" style="margin-top:8px">${chip('enc',r.fields.length+' encrypted fields')} ${chip('ok','sealed',true)}</div></div>
      <button class="iconbtn" id="dClose"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 6l12 12M18 6L6 18"/></svg></button>
    </div>
    <div class="dbody">
      <div class="fieldgrp"><div class="lbl">Encrypted fields</div>
        ${fieldRow(r,'bank','Bank account')}${fieldRow(r,'tax','Tax ID')}${fieldRow(r,'notes','Private notes')}
      </div>
      <div class="fieldgrp"><div class="lbl">Activity</div>
        <div class="timeline">
          <div class="ev sign"><div class="marker"></div><div><div class="et">Release signed by the network</div><div class="em">${money(4000+Math.floor(Math.random()*40)*1000)} · verifies</div></div></div>
          <div class="ev"><div class="marker"></div><div><div class="et">Fields sealed in browser</div><div class="em">${r.fields.length} fields · ${r.created}</div></div></div>
          <div class="ev"><div class="marker"></div><div><div class="et">Record created</div><div class="em">${r.ref}</div></div></div>
        </div>
      </div>
    </div>
    <div class="foot"><button class="btn" id="dReq" style="flex:1;justify-content:center"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l8 4v6c0 5-3.5 8-8 10-4.5-2-8-5-8-10V6z"/></svg>Request signed release</button></div>`;
  d.classList.add('on'); $('#scrim').classList.add('on');
  $('#dClose').onclick = closeDrawer;
  d.querySelectorAll('.reveal').forEach(b=> b.onclick = ()=>reveal(b, r));
  $('#dReq').onclick = ()=>requestRelease(r);
}
function closeDrawer(){ $('#drawer').classList.remove('on'); $('#scrim').classList.remove('on'); }
$('#scrim').onclick = closeDrawer;

// ---- reveal / create / release (demo simulates; live does real crypto) ---
const demoPlain = (r,k)=>r.plain[k];
async function reveal(btn, r){
  const k = btn.dataset.k; const field = btn.closest('.field'); const fv = field.querySelector('.fv');
  btn.classList.add('busy'); btn.textContent='Asking cohort…';
  try{
    const text = LIVE ? await liveDecrypt(r, k) : await sim(600, ()=>demoPlain(r,k));
    fv.classList.remove('ct'); fv.classList.add('pt'); fv.textContent = text;
    btn.remove();
    toast('ok','Decrypted by the cohort', k+' · vault-reader verified');
  }catch(e){ btn.classList.remove('busy'); btn.textContent='Reveal'; toast('no','Reveal refused', e.message||'the network declined'); }
}
async function requestRelease(r){
  toast('info','Requesting signature…','the cohort reads the amount before it signs');
  const amount = 4000 + Math.floor(Math.random()*30)*1000;
  const ok = LIVE ? await liveSign(r, amount).then(()=>true).catch(()=>false) : await sim(900, ()=> amount<=25000);
  if(ok && amount<=25000){ RELEASES.unshift({ref:'REL-'+(2210+RELEASES.length),client:r.name,amount,by:ME.name.split(' ').pop(),state:'ok',when:'today'}); renderReleases(); toast('ok','Release signed',money(amount)+' · verifies against the vendor key'); }
  else { RELEASES.unshift({ref:'REL-'+(2210+RELEASES.length),client:r.name,amount,by:ME.name.split(' ').pop(),state:'no',when:'today'}); renderReleases(); toast('no','Network refused', money(amount)+' is over the policy limit'); }
}
function openModal(){ $('#modal').classList.add('on'); $('#f-name').focus(); }
function closeModal(){ $('#modal').classList.remove('on'); ['name','ref','tax','bank','notes'].forEach(k=>$('#f-'+k).value=''); }
async function saveRecord(){
  const name=$('#f-name').value.trim(), ref=$('#f-ref').value.trim()||'REC-'+Math.floor(Math.random()*9000);
  if(!name){ $('#f-name').focus(); return; }
  const btn=$('#mSave'); btn.textContent='Sealing…';
  const fields=['bank','tax','notes'].filter(k=>$('#f-'+k).value.trim());
  try{
    if(LIVE) await liveCreate(name, ref, {bank:$('#f-bank').value,tax:$('#f-tax').value,notes:$('#f-notes').value}, fields);
    else await sim(700);
    RECORDS.unshift({ id:'rec_'+Date.now(), name, ref, bankMask:'**• ••-'+Math.floor(1000+Math.random()*9000), taxMask:'**• ••-'+Math.floor(1000+Math.random()*9000), fields, created:'today', plain:{bank:$('#f-bank').value,tax:$('#f-tax').value,notes:$('#f-notes').value} });
    renderRecords($('#q').value.toLowerCase()); renderRaw();
    toast('ok','Record sealed', fields.length+' fields encrypted before storage');
  }catch(e){ toast('no','Could not save', e.message); }
  btn.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M8 12l3 3 5-6"/></svg>Encrypt & save';
  closeModal();
}
const sim = (ms,fn)=>new Promise(r=>setTimeout(()=>r(fn?fn():undefined),ms));

// ---- live Tide crypto (loaded only when signed in) -----------------------
let T=null;
async function tide(){
  if(T) return T;
  const [pkg, PPSF, Ed] = await Promise.all([
    import('https://esm.sh/@tideorg/js@0.14.25'),
    import('https://esm.sh/@tideorg/js@0.14.25/dist/Models/PolicyProtectedSerializedField.js'),
    import('https://esm.sh/@tideorg/js@0.14.25/dist/Cryptide/Components/Schemes/Ed25519/Ed25519Scheme.js'),
  ]);
  const cfg = await (await fetch('/api/vault/config')).json();
  const keyInfo = await new pkg.Clients.NetworkClient(cfg.homeOrkUrl).GetKeyInfo(cfg.vvkId);
  T = { pkg, PPSF:PPSF.default, Ed:Ed.default, cfg, keyInfo,
        enc:Uint8Array.from(atob(cfg.encryptPolicy),c=>c.charCodeAt(0)),
        dec:Uint8Array.from(atob(cfg.decryptPolicy),c=>c.charCodeAt(0)) };
  return T;
}
const guestOf = (t)=>{ const k=t.pkg.Cryptide.TideKey.NewKey(t.Ed); return {k, tok:{payload:{sessionKey:k.get_public_component()},serialize:()=>''}}; };
const vfetch = p => req => fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({voucherRequest:req})}).then(async r=>{const x=await r.text();if(!r.ok)throw new Error(x);return x;});
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
  await fetch('/api/vault/records',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,ref,ct})});
}
async function liveSign(r,amount){
  // network-signed release; server verifies + stores. (uses the same voucher-gated sign path)
  await fetch('/api/vault/release',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({record:r.id,amount})}).then(r=>{if(!r.ok)throw new Error('refused');});
}

// ---- nav / chrome --------------------------------------------------------
const subs={records:'Confidential client records',releases:'Network-signed actions',raw:'What the database really holds',access:'Roles and governance'};
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
document.onkeydown = e => { if(e.key==='Escape'){ closeDrawer(); closeModal(); $('#loginModal').classList.remove('on'); } };

// ---- login (real Supabase) ----------------------------------------------
async function doLogin(){
  const email=$('#l-email').value.trim(), pass=$('#l-pass').value;
  const go=$('#lGo'); $('#l-err').textContent=''; go.textContent='Signing in…';
  try{
    const {url,anonKey}=await fetch('/api/pubconfig').then(r=>r.json());
    if(!url) throw new Error('Supabase is not configured on the server');
    const { createClient } = await import('https://esm.sh/@supabase/supabase-js@2');
    const {data,error}=await createClient(url,anonKey).auth.signInWithPassword({email,password:pass});
    if(error) throw error;
    document.cookie='sb='+data.session.access_token+'; path=/; samesite=lax';
    location.reload();
  }catch(e){ $('#l-err').textContent=e.message||'sign-in failed'; go.textContent='Sign in'; }
}
$('#lGo').onclick=doLogin; $('#lCancel').onclick=()=>$('#loginModal').classList.remove('on');
$('#loginModal').onclick=e=>{ if(e.target.id==='loginModal') e.currentTarget.classList.remove('on'); };
$('#l-pass').onkeydown=e=>{ if(e.key==='Enter') doLogin(); };
document.querySelector('.user').onclick=()=>{
  if(LIVE){ if(confirm('Sign out?')){ fetch('/api/logout',{method:'POST'}).finally(()=>{document.cookie='sb=; path=/; max-age=0'; location.reload();}); } }
  else { $('#loginModal').classList.add('on'); $('#l-pass').focus(); }
};

// ---- boot ----------------------------------------------------------------
(async ()=>{
  try{
    const s = await fetch('/api/session').then(r=>r.ok?r.json():null).catch(()=>null);
    if(s && s.user){
      LIVE=true; ME={name:s.user, roles:s.roles||[]};
      $('#demoBanner').style.display='none';
      $('#uname').textContent=s.user.split('@')[0]; $('#uav').textContent=initials(s.user);
      $('#urole').textContent=(s.roles&&s.roles.length?s.roles.join(' · '):'no roles yet');
      const recs = await fetch('/api/vault/records').then(r=>r.json()).catch(()=>null);
      if(recs && recs.length) RECORDS = recs.map(r=>({...r, bankMask:'**• ••-'+(r.id||'').slice(-4), taxMask:'**• ••-'+(r.ref||'').slice(-4), fields:Object.keys(r.ct||{})}));
    } else {
      // demo: the chip becomes a sign-in affordance
      $('#uname').textContent='Sign in'; $('#urole').textContent='demo mode'; $('#uav').textContent='→';
      document.querySelector('.user').style.cursor='pointer';
    }
  }catch{}
  renderRecords(); renderReleases(); renderRaw();
})();
