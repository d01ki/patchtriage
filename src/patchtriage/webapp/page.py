"""The single-page GUI. Self-contained: inline CSS + JS, no external assets."""

INDEX_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PatchTriage — Console</title>
<style>
  :root{
    --paper:#F5F6F8; --panel:#fff; --ink:#1B1F2A; --rule:#DDE1E8;
    --slate:#1E2430; --muted:#5A6472; --accent:#4F46E5; --accent2:#4338CA;
    --p1:#DC2626; --p2:#D97706; --p3:#2563EB; --p4:#6B7280;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--paper);color:var(--ink);
       font:15px/1.55 "Segoe UI","Helvetica Neue",Arial,sans-serif}
  a{color:var(--accent)}
  header{background:var(--slate);color:#EEF1F6;padding:20px 32px;
         display:flex;align-items:center;justify-content:space-between}
  header h1{margin:0;font-size:22px;font-weight:600;letter-spacing:.4px}
  header .sub{color:#9AA4B2;font-size:12.5px;font-family:ui-monospace,Menlo,monospace}
  .toolbar{display:flex;gap:10px;align-items:center}
  select,input,button{font:inherit}
  select,input[type=text]{padding:7px 9px;border:1px solid var(--rule);
       border-radius:6px;background:#fff;color:var(--ink)}
  button{cursor:pointer;border:1px solid var(--rule);background:#fff;
       border-radius:6px;padding:7px 12px;color:var(--ink)}
  button.primary{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600}
  button.primary:hover{background:var(--accent2)}
  button.danger{color:var(--p1);border-color:#f0c9c9}
  button:disabled{opacity:.5;cursor:not-allowed}
  main{max-width:1200px;margin:0 auto;padding:26px 32px 60px;
       display:grid;grid-template-columns:400px 1fr;gap:26px}
  .col h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;
       color:var(--muted);margin:0 0 12px}
  .panel{background:var(--panel);border:1px solid var(--rule);border-radius:9px;padding:16px}
  .addform{display:grid;gap:9px;margin-bottom:16px}
  .row2{display:grid;grid-template-columns:1fr 1fr;gap:9px}
  label.chk{display:flex;align-items:center;gap:7px;font-size:13.5px;color:var(--muted)}
  .tlist{display:flex;flex-direction:column;gap:10px}
  .tcard{border:1px solid var(--rule);border-radius:8px;padding:12px 14px}
  .tcard .top{display:flex;justify-content:space-between;align-items:flex-start;gap:8px}
  .tname{font-weight:600;font-size:15px}
  .tname a{text-decoration:none}
  .tname a:hover{text-decoration:underline}
  .tmeta{font-size:12px;color:var(--muted);margin-top:2px;font-family:ui-monospace,Menlo,monospace}
  .badge{font-size:11px;font-weight:700;padding:2px 7px;border-radius:11px;color:#fff}
  .exposed{background:var(--p2)}
  .crit-critical{background:var(--p1)}.crit-high{background:var(--p2)}
  .crit-medium{background:var(--p3)}.crit-low{background:var(--p4)}.crit-unknown{background:var(--p4)}
  .src{font-size:12px;margin-top:8px;color:var(--muted)}
  .src.has{color:var(--accent)}
  .tactions{display:flex;gap:6px;margin-top:10px;flex-wrap:wrap}
  .tactions button{padding:5px 10px;font-size:13px}
  .empty{color:var(--muted);font-size:13.5px;padding:8px 2px}
  .results{display:flex;flex-direction:column;gap:12px}
  .rcard{border:1px solid var(--rule);border-radius:8px;padding:14px 16px;background:#fff}
  .rcard .rtop{display:flex;justify-content:space-between;align-items:center;gap:10px}
  .rcard .rname{font-weight:600}
  .pills{display:flex;gap:8px;margin:10px 0;flex-wrap:wrap}
  .pill{font-family:ui-monospace,Menlo,monospace;font-size:12px;padding:3px 9px;
        border-radius:6px;background:#EEF0F4;color:var(--ink)}
  .pill.p1{background:#fdeaea;color:var(--p1);font-weight:700}
  .pill.kev{background:#fdeaea;color:var(--p1);font-weight:700}
  .pill.audit{background:#eaf0fd;color:var(--p3)}
  .topaction{font-size:13.5px;color:var(--muted)}
  .spin{color:var(--muted);font-size:13.5px}
  .hint{color:var(--muted);font-size:12.5px;margin-top:6px}
  .filehidden{display:none}
  @media(max-width:900px){main{grid-template-columns:1fr}}
</style></head>
<body>
<header>
  <div><h1>PatchTriage <span style="opacity:.6">Console</span></h1>
    <div class="sub" id="sub">auditable AI patch triage · local</div></div>
  <div class="toolbar">
    <select id="backend" title="triage backend"></select>
    <button class="primary" id="runall">Run all targets</button>
  </div>
</header>
<main>
  <section class="col">
    <h2>Targets</h2>
    <div class="panel">
      <div class="addform">
        <input type="text" id="f-name" placeholder="System name (e.g. checkout-api)">
        <input type="text" id="f-url" placeholder="Link URL (dashboard / repo / runbook)">
        <div class="row2">
          <select id="f-crit">
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
            <option value="unknown" selected>unknown</option>
          </select>
          <label class="chk"><input type="checkbox" id="f-exposed"> internet-exposed</label>
        </div>
        <button class="primary" id="add">+ Add target</button>
        <div class="hint">Register each internal system once. Attach a scan or
          an SBOM (CycloneDX / SPDX) per target — SBOMs are resolved online via
          OSV.dev, no scanner needed.</div>
      </div>
      <div class="tlist" id="tlist"></div>
    </div>
  </section>
  <section class="col">
    <h2>Results</h2>
    <div class="results" id="results">
      <div class="empty">Add targets, attach scans or SBOMs, then
        <b>Run all targets</b>. Each result links to its full report, and every
        target name links out to the system you registered.</div>
    </div>
  </section>
</main>
<input type="file" id="filepick" class="filehidden" accept=".json,.spdx,.cdx,.xml">
<script>
let CFG = {backends:["rules"], has_key:false};
let pickTarget = null;

async function api(method, path, body){
  const opt = {method, headers:{}};
  if(body!==undefined){opt.headers["Content-Type"]="application/json";opt.body=JSON.stringify(body);}
  const r = await fetch(path, opt);
  if(!r.ok){throw new Error((await r.json().catch(()=>({error:r.statusText}))).error||r.statusText);}
  return r.status===204?null:r.json();
}
function esc(s){return String(s==null?"":s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}

async function loadConfig(){
  CFG = await api("GET","/api/config");
  const sel = document.getElementById("backend");
  sel.innerHTML = CFG.backends.map(b=>`<option value="${b}">${b}</option>`).join("");
  document.getElementById("sub").textContent =
    "auditable AI patch triage · local · " + (CFG.has_key?"API key detected":"rules backend (no key)");
}

function critBadge(c){return `<span class="badge crit-${esc(c)}">${esc(c)}</span>`;}

async function loadTargets(){
  const ts = await api("GET","/api/targets");
  const el = document.getElementById("tlist");
  if(!ts.length){el.innerHTML=`<div class="empty">No targets yet. Add one above.</div>`;return;}
  el.innerHTML = ts.map(t=>{
    const nameHtml = t.url
      ? `<a href="${esc(t.url)}" target="_blank" rel="noopener">${esc(t.name)} ↗</a>`
      : esc(t.name);
    const src = t.source_file
      ? `<div class="src has">✓ ${esc(t.source_format||"scan")} attached</div>`
      : `<div class="src">no scan / SBOM attached</div>`;
    return `<div class="tcard" data-id="${t.id}">
      <div class="top">
        <div><div class="tname">${nameHtml}</div>
          <div class="tmeta">${esc(t.id)}</div></div>
        <div>${critBadge(t.criticality)} ${t.internet_exposed?'<span class="badge exposed">exposed</span>':''}</div>
      </div>
      ${src}
      <div class="tactions">
        <button data-act="import">Import scan / SBOM</button>
        <button data-act="run" ${t.source_file?"":"disabled"}>Run</button>
        <button data-act="report" ${t.source_file?"":"disabled"}>Report</button>
        <button class="danger" data-act="delete">Delete</button>
      </div></div>`;
  }).join("");
}

document.getElementById("add").onclick = async ()=>{
  const name=document.getElementById("f-name").value.trim();
  if(!name){alert("Give the system a name");return;}
  await api("POST","/api/targets",{
    name, url:document.getElementById("f-url").value.trim(),
    criticality:document.getElementById("f-crit").value,
    internet_exposed:document.getElementById("f-exposed").checked});
  document.getElementById("f-name").value="";document.getElementById("f-url").value="";
  document.getElementById("f-exposed").checked=false;
  loadTargets();
};

document.getElementById("tlist").onclick = async (e)=>{
  const btn=e.target.closest("button"); if(!btn)return;
  const id=e.target.closest(".tcard").dataset.id, act=btn.dataset.act;
  if(act==="delete"){if(confirm("Delete this target?")){await api("DELETE","/api/targets/"+id);loadTargets();}}
  else if(act==="import"){pickTarget=id;document.getElementById("filepick").click();}
  else if(act==="report"){window.open("/report/"+id,"_blank");}
  else if(act==="run"){await runTargets([id]);}
};

document.getElementById("filepick").onchange = async (e)=>{
  const file=e.target.files[0]; if(!file||!pickTarget)return;
  const content=await file.text();
  try{
    await api("POST","/api/targets/"+pickTarget+"/source",{content, filename:file.name});
    loadTargets();
  }catch(err){alert("Import failed: "+err.message);}
  e.target.value="";pickTarget=null;
};

document.getElementById("runall").onclick = async ()=>{
  const ts=await api("GET","/api/targets");
  const ids=ts.filter(t=>t.source_file).map(t=>t.id);
  if(!ids.length){alert("Attach a scan or SBOM to at least one target first.");return;}
  runTargets(ids);
};

async function runTargets(ids){
  const backend=document.getElementById("backend").value;
  const res=document.getElementById("results");
  res.innerHTML=`<div class="spin">Running ${ids.length} target(s) via '${esc(backend)}'… (SBOMs query OSV.dev)</div>`;
  const cards=[];
  for(const id of ids){
    try{
      const s=await api("POST","/api/targets/"+id+"/run",{backend});
      cards.push(renderResult(s));
    }catch(err){
      cards.push(`<div class="rcard"><div class="rname">${esc(id)}</div>
        <div class="topaction" style="color:var(--p1)">error: ${esc(err.message)}</div></div>`);
    }
    res.innerHTML=cards.join("");
  }
}

function renderResult(s){
  const nameHtml = s.url
    ? `<a href="${esc(s.url)}" target="_blank" rel="noopener">${esc(s.name)} ↗</a>` : esc(s.name);
  return `<div class="rcard">
    <div class="rtop"><div class="rname">${nameHtml}</div>
      <a href="${esc(s.report_url)}" target="_blank">open full report →</a></div>
    <div class="pills">
      <span class="pill p1">P1 ${s.counts.P1}</span>
      <span class="pill">P2 ${s.counts.P2}</span>
      <span class="pill">P3 ${s.counts.P3}</span>
      <span class="pill">P4 ${s.counts.P4}</span>
      ${s.kev?`<span class="pill kev">KEV ${s.kev}</span>`:""}
      <span class="pill">${s.total} findings</span>
      <span class="pill">${s.actions} actions</span>
      <span class="pill audit">audit ${s.audit_verified}/${s.total}</span>
    </div>
    <div class="topaction">${s.top_priority?`<b>${esc(s.top_priority)}</b> · `:""}${esc(s.top_action||"no actionable findings")}</div>
  </div>`;
}

loadConfig().then(loadTargets);
</script>
</body></html>
"""
