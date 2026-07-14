"""The single-page GUI. Self-contained: inline CSS + JS, no external assets."""

INDEX_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#0a0d14">
<title>PatchTriage — Decision Engine</title>
<style>
  :root{
    --void:#090c12;--void2:#10141e;--panel:#151a25;--panel2:#1b2130;
    --ink:#f4f6fb;--muted:#929cad;--line:#2a3243;--hot:#ff4d3d;
    --amber:#ffb020;--blue:#6e8cff;--cyan:#49d6e9;--paper:#eef1f7;
    --dark:#171b25;--p1:#ff4d3d;--p2:#ffb020;--p3:#6e8cff;--p4:#778195;
  }
  *{box-sizing:border-box}
  html{scroll-behavior:smooth}
  body{margin:0;background:var(--void);color:var(--ink);
    font:15px/1.55 Inter,"Segoe UI",Helvetica,Arial,sans-serif}
  button,input,select{font:inherit}button{cursor:pointer}
  a{color:inherit}.mono{font-family:"SFMono-Regular",Consolas,"Liberation Mono",monospace}
  .topbar{height:64px;padding:0 clamp(20px,4vw,64px);display:flex;align-items:center;
    justify-content:space-between;border-bottom:1px solid var(--line);background:rgba(9,12,18,.96);
    position:sticky;top:0;z-index:20}
  .brand{display:flex;align-items:center;gap:12px;font-weight:800;letter-spacing:.08em}
  .brandmark{width:27px;height:27px;border:2px solid var(--hot);position:relative}
  .brandmark:before,.brandmark:after{content:"";position:absolute;background:var(--hot)}
  .brandmark:before{width:13px;height:2px;left:5px;top:7px}.brandmark:after{width:2px;height:13px;left:11px;top:5px}
  .brand span{color:var(--hot)}.topmeta{display:flex;align-items:center;gap:10px;color:var(--muted);font-size:12px}
  .statusdot{width:7px;height:7px;border-radius:50%;background:var(--cyan);box-shadow:0 0 12px var(--cyan)}
  .hero{max-width:1500px;margin:0 auto;padding:clamp(46px,7vw,92px) clamp(20px,4vw,64px) 42px;
    display:grid;grid-template-columns:minmax(340px,.95fr) minmax(520px,1.2fr);gap:clamp(36px,6vw,90px);align-items:center}
  .eyebrow{color:var(--hot);font:700 12px/1.2 "SFMono-Regular",Consolas,monospace;letter-spacing:.18em;text-transform:uppercase}
  h1{font-size:clamp(42px,6.2vw,86px);line-height:.96;letter-spacing:-.055em;margin:18px 0 24px;max-width:820px}
  h1 em{font-style:normal;color:var(--hot)}
  .hero p{color:#b3bccb;font-size:clamp(16px,1.55vw,20px);max-width:660px;margin:0 0 28px}
  .heroactions{display:flex;gap:12px;flex-wrap:wrap}
  .btn{border:1px solid var(--line);border-radius:5px;padding:10px 15px;background:var(--panel2);color:var(--ink);font-weight:650}
  .btn:hover{border-color:#526078}.btn:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}
  .btn.primary{background:var(--hot);border-color:var(--hot);color:#fff;box-shadow:0 8px 32px rgba(255,77,61,.2)}
  .btn.primary:hover{background:#ff6255}.btn.ghost{background:transparent}.btn.small{padding:6px 10px;font-size:12px}
  .btn.danger{color:#ff8a80;background:transparent}.btn:disabled{opacity:.45;cursor:not-allowed}
  .proof{border:1px solid var(--line);background:linear-gradient(145deg,#111722,#0c1018);padding:24px;position:relative;overflow:hidden}
  .proof:after{content:"";position:absolute;width:180px;height:180px;border-radius:50%;background:var(--hot);filter:blur(100px);opacity:.12;right:-60px;top:-60px}
  .proofhead{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;color:var(--muted);font:12px "SFMono-Regular",Consolas,monospace;text-transform:uppercase;letter-spacing:.1em}
  .flow{display:grid;grid-template-columns:1fr 26px 1fr 26px 1fr;align-items:stretch;gap:5px}
  .node{border:1px solid var(--line);background:var(--panel);padding:16px 14px;min-height:118px}
  .node strong{display:block;font-size:14px;margin:8px 0 5px}.node small{color:var(--muted);font-size:11.5px;display:block}
  .nodecode{color:var(--cyan);font:700 11px "SFMono-Regular",Consolas,monospace}
  .arrow{display:flex;align-items:center;justify-content:center;color:#59667a;font-size:22px}
  .decision{grid-column:1/-1;margin-top:12px;border-left:3px solid var(--hot);background:#1c171c;padding:16px 18px;display:flex;justify-content:space-between;gap:20px;align-items:center}
  .decision b{font-size:18px}.decision span{color:var(--muted);font-size:12px}.decision .p1{font:800 32px "SFMono-Regular",Consolas,monospace;color:var(--hot)}
  .kpis{max-width:1500px;margin:0 auto;padding:0 clamp(20px,4vw,64px) 34px;display:grid;grid-template-columns:repeat(4,1fr);gap:1px}
  .kpi{background:var(--panel);border:1px solid var(--line);padding:15px 18px}.kpi+.kpi{border-left:0}
  .kpi .value{font:750 27px "SFMono-Regular",Consolas,monospace}.kpi .label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em}
  .workspace{background:var(--paper);color:var(--dark);border-radius:22px 22px 0 0;min-height:720px;padding:34px clamp(20px,4vw,64px) 70px}
  .workspaceinner{max-width:1500px;margin:0 auto;display:grid;grid-template-columns:340px minmax(0,1fr);gap:28px}
  .sectiontitle{display:flex;align-items:flex-end;justify-content:space-between;margin-bottom:14px}
  .sectiontitle h2{margin:0;font-size:18px;letter-spacing:-.02em}.sectiontitle span{font:11px "SFMono-Regular",Consolas,monospace;color:#70798a;text-transform:uppercase;letter-spacing:.1em}
  .lightpanel{background:#fff;border:1px solid #d9deea;border-radius:10px;box-shadow:0 10px 28px rgba(30,40,65,.06)}
  details.add{margin-bottom:14px}details.add summary{list-style:none;padding:14px 16px;font-weight:700;cursor:pointer;display:flex;justify-content:space-between}
  details.add summary::-webkit-details-marker{display:none}details.add summary:after{content:"+";color:#697386}details.add[open] summary:after{content:"−"}
  .form{border-top:1px solid #e4e7ee;padding:14px;display:grid;gap:10px}
  input[type=text],select{width:100%;border:1px solid #cfd5e2;border-radius:5px;padding:9px 10px;background:#fff;color:#171b25}
  .row2{display:grid;grid-template-columns:1fr 1fr;gap:8px}.checks{display:grid;gap:7px;padding:5px 0}
  .check{display:flex;align-items:center;gap:8px;font-size:12.5px;color:#5e687a}.check input{accent-color:#4d65e6}
  .hint{font-size:11.5px;color:#7a8393}.targetlist{display:flex;flex-direction:column;gap:9px}
  .target{background:#fff;border:1px solid #d9deea;border-radius:8px;padding:13px;transition:.18s}
  .target:hover{border-color:#b8c1d3;transform:translateY(-1px)}.targettop{display:flex;justify-content:space-between;gap:8px}
  .targetname{font-weight:750;overflow-wrap:anywhere}.targetname a{text-decoration:none}.targetname a:hover{text-decoration:underline}
  .targetid{font:10px "SFMono-Regular",Consolas,monospace;color:#9098a6;margin-top:2px}
  .badges{display:flex;gap:5px;flex-wrap:wrap;margin-top:9px}.tag{font:700 9.5px "SFMono-Regular",Consolas,monospace;text-transform:uppercase;letter-spacing:.04em;border:1px solid #d5dae5;border-radius:20px;padding:3px 6px;color:#5c6575;background:#f7f8fb}
  .tag.hot{color:#c93025;background:#fff0ee;border-color:#ffd0ca}.tag.live{color:#1c6470;background:#eafcff;border-color:#b9edf4}.tag.demo{color:#674100;background:#fff4d8;border-color:#ffdfa0}
  .source{font-size:11.5px;color:#6f7888;margin:9px 0}.source.ready{color:#354fd1}.targetactions{display:flex;gap:6px;flex-wrap:wrap}
  .results{display:flex;flex-direction:column;gap:14px}.empty{min-height:390px;display:grid;grid-template-columns:1fr 1fr;overflow:hidden}
  .emptycopy{padding:clamp(28px,4vw,54px);display:flex;flex-direction:column;justify-content:center}.emptycopy .eyebrow{color:#5563d8}.emptycopy h3{font-size:clamp(28px,3.3vw,46px);line-height:1.04;letter-spacing:-.045em;margin:13px 0}.emptycopy p{color:#687285;max-width:50ch}
  .emptyviz{background:#121722;color:#fff;padding:32px;display:flex;flex-direction:column;justify-content:center}.versus{display:grid;grid-template-columns:1fr auto 1fr;gap:14px;align-items:center}.method{border:1px solid #30394b;padding:17px}.method strong{display:block;font-size:22px}.method small{color:#929cad}.method.miss strong{color:var(--hot)}.method.hit{border-color:#566cf0}.method.hit strong{color:#9eb0ff}.vs{font:700 11px "SFMono-Regular",Consolas,monospace;color:#667084}
  .result{background:#fff;border:1px solid #d7dce7;border-radius:10px;overflow:hidden;box-shadow:0 12px 35px rgba(30,40,65,.07)}
  .resulthead{display:grid;grid-template-columns:92px 1fr auto;gap:17px;align-items:center;padding:19px 21px;border-bottom:1px solid #e2e6ee}
  .priority{height:66px;display:flex;align-items:center;justify-content:center;border-radius:6px;color:white;font:850 28px "SFMono-Regular",Consolas,monospace;background:var(--p4)}
  .priority.P1{background:var(--p1)}.priority.P2{background:var(--p2);color:#2d1d00}.priority.P3{background:var(--p3)}
  .rname{font-size:12px;color:#737d8d;margin-bottom:4px}.action{font-size:20px;font-weight:780;line-height:1.2;letter-spacing:-.025em}.reportlink{text-decoration:none;color:#3048c5;font-weight:700;font-size:12px;white-space:nowrap}
  .metricrow{padding:12px 21px;display:flex;gap:7px;flex-wrap:wrap;background:#fafbfc;border-bottom:1px solid #e5e8ef}.metric{font:11px "SFMono-Regular",Consolas,monospace;background:#edf0f5;border-radius:4px;padding:4px 7px;color:#4f5969}.metric.alert{background:#ffebe8;color:#c42f24}.metric.audit{background:#e8f9fc;color:#226976}
  .resultbody{display:grid;grid-template-columns:minmax(320px,.85fr) minmax(430px,1.15fr);gap:0}.compare{padding:21px;border-right:1px solid #e4e7ed}.explain{padding:21px}
  .microtitle{font:750 10px "SFMono-Regular",Consolas,monospace;text-transform:uppercase;letter-spacing:.12em;color:#768093;margin-bottom:12px}
  .barrow{display:grid;grid-template-columns:92px 1fr 40px;gap:9px;align-items:center;margin:9px 0;font-size:11px}.track{height:8px;background:#e7eaf0;border-radius:2px;overflow:hidden}.fill{height:100%;background:#a7afbd}.fill.epss{background:#6f7f99}.fill.pt{background:#5368e8}.barvalue{font:700 11px "SFMono-Regular",Consolas,monospace;text-align:right}
  .comparefoot{font-size:11.5px;color:#727c8d;margin-top:13px}.factorflow{display:grid;grid-template-columns:1fr 15px 1fr 15px 1fr;gap:5px;align-items:stretch}.factor{border:1px solid #dfe3eb;background:#f8f9fb;border-radius:5px;padding:10px}.factor span{font:9px "SFMono-Regular",Consolas,monospace;text-transform:uppercase;color:#7e8796}.factor b{display:block;font-size:12px;margin-top:4px}.factorarrow{display:flex;align-items:center;justify-content:center;color:#a1a9b6}.riskline{margin-top:10px;background:#171d29;color:white;padding:11px 13px;border-radius:5px;display:flex;justify-content:space-between;align-items:center}.riskline span{color:#9aa4b5;font-size:10px;text-transform:uppercase;letter-spacing:.08em}.riskline b{color:#8fa3ff;font:800 18px "SFMono-Regular",Consolas,monospace}
  .running{padding:26px;border-left:4px solid #5368e8}.running strong{font-size:18px}.scanline{height:3px;background:#e1e5ed;margin-top:16px;overflow:hidden}.scanline:after{content:"";display:block;width:32%;height:100%;background:#5368e8;animation:scan 1s infinite ease-in-out}@keyframes scan{from{transform:translateX(-100%)}to{transform:translateX(410%)}}
  .toast{position:fixed;right:22px;bottom:22px;background:#151a25;color:#fff;border:1px solid #343d50;padding:11px 15px;border-radius:6px;box-shadow:0 12px 40px rgba(0,0,0,.28);transform:translateY(90px);opacity:0;transition:.2s;z-index:30;max-width:420px}.toast.show{transform:none;opacity:1}.toast.error{border-color:#a63d36}
  .filehidden{display:none}
  @media(max-width:1100px){.hero{grid-template-columns:1fr}.workspaceinner{grid-template-columns:300px minmax(0,1fr)}.resultbody{grid-template-columns:1fr}.compare{border-right:0;border-bottom:1px solid #e4e7ed}}
  @media(max-width:820px){.topmeta .hide-sm{display:none}.kpis{grid-template-columns:1fr 1fr}.kpi+.kpi{border-left:1px solid var(--line)}.workspaceinner{grid-template-columns:1fr}.empty{grid-template-columns:1fr}.resulthead{grid-template-columns:68px 1fr}.priority{height:54px}.reportlink{grid-column:2}.flow{grid-template-columns:1fr}.arrow{transform:rotate(90deg)}.decision{grid-column:1}.factorflow{grid-template-columns:1fr}.factorarrow{transform:rotate(90deg)}}
  @media(max-width:520px){h1{font-size:43px}.topbar{padding:0 16px}.brand{font-size:13px}.hero{padding-left:16px;padding-right:16px}.kpis{padding-left:16px;padding-right:16px}.resulthead{padding:15px}.resultbody>div,.metricrow{padding-left:15px;padding-right:15px}.versus{grid-template-columns:1fr}.vs{text-align:center}.row2{grid-template-columns:1fr}}
</style></head>
<body>
<header class="topbar">
  <div class="brand"><span class="brandmark" aria-hidden="true"></span>PATCH<span>TRIAGE</span></div>
  <div class="topmeta"><span class="statusdot"></span><span class="hide-sm">LOCAL DECISION ENGINE</span><span id="version" class="mono">v—</span></div>
</header>

<section class="hero">
  <div>
    <div class="eyebrow">Black Hat Arsenal · live decision support</div>
    <h1>Patch what matters <em>first.</em></h1>
    <p>Turn scanner noise, exploitation intelligence, and runtime evidence into one defensible remediation queue — without letting AI invent a score.</p>
    <div class="heroactions">
      <button class="btn primary run-control" id="demo">Run the offline demo</button>
      <button class="btn ghost" id="jump">Open my workspace ↓</button>
    </div>
  </div>
  <div class="proof" aria-label="PatchTriage decision flow">
    <div class="proofhead"><span>Why this patch first?</span><span>auditable signal path</span></div>
    <div class="flow">
      <div class="node"><span class="nodecode">01 / FIND</span><strong>Scanner evidence</strong><small>CVE · package · fixed version</small></div>
      <div class="arrow">→</div>
      <div class="node"><span class="nodecode">02 / PROVE</span><strong>Threat evidence</strong><small>CISA KEV · FIRST EPSS · NVD</small></div>
      <div class="arrow">→</div>
      <div class="node"><span class="nodecode">03 / CONTEXT</span><strong>Runtime relevance</strong><small>Exposure · reachability · telemetry</small></div>
      <div class="decision"><div><b>Upgrade libc6 on web-frontend</b><br><span>known exploited · ransomware use · fix available</span></div><div class="p1">P1</div></div>
    </div>
  </div>
</section>

<section class="kpis" aria-label="Workspace totals">
  <div class="kpi"><div class="value" id="k-targets">0</div><div class="label">targets in scope</div></div>
  <div class="kpi"><div class="value" id="k-kev">0</div><div class="label">known exploited</div></div>
  <div class="kpi"><div class="value" id="k-p1">0</div><div class="label">P1 decisions</div></div>
  <div class="kpi"><div class="value" id="k-audit">—</div><div class="label">decisions verified</div></div>
</section>

<section class="workspace" id="workspace">
  <div class="workspaceinner">
    <aside>
      <div class="sectiontitle"><h2>Targets</h2><span>asset context</span></div>
      <details class="add lightpanel">
        <summary>Add a target</summary>
        <div class="form">
          <input type="text" id="f-name" maxlength="120" placeholder="System name" aria-label="System name">
          <input type="text" id="f-url" placeholder="https:// dashboard, repo, or runbook" aria-label="Target link URL">
          <div class="row2">
            <select id="f-crit" aria-label="Business criticality">
              <option value="critical">critical</option><option value="high">high</option>
              <option value="medium">medium</option><option value="low">low</option>
              <option value="unknown" selected>unknown</option>
            </select>
            <input type="text" id="f-sources" placeholder="otel, falco" aria-label="Context sources">
          </div>
          <div class="checks">
            <label class="check"><input type="checkbox" id="f-exposed"> Internet-exposed</label>
            <label class="check"><input type="checkbox" id="f-reachable"> Vulnerable path is reachable</label>
            <label class="check"><input type="checkbox" id="f-runtime"> Observed at runtime</label>
          </div>
          <button class="btn primary" id="add">Add target</button>
          <div class="hint">Positive runtime evidence raises confidence. Missing telemetry never suppresses risk.</div>
        </div>
      </details>
      <div class="targetlist" id="targetlist"></div>
    </aside>

    <div>
      <div class="sectiontitle"><h2>Patch decisions</h2><span>
        <select id="backend" aria-label="Triage backend"></select>
        <button class="btn small run-control" id="runall">Run all</button>
      </span></div>
      <div class="results" id="results">
        <div class="empty lightpanel">
          <div class="emptycopy">
            <div class="eyebrow">Decision, not detection</div>
            <h3>Show the queue that a CVSS sort misses.</h3>
            <p>Load the bundled scan and threat snapshots. In one click, PatchTriage produces a package-level action, a three-way baseline comparison, and a machine-audited explanation.</p>
            <div><button class="btn primary run-control demo-trigger">Launch Arsenal demo</button></div>
          </div>
          <div class="emptyviz">
            <div class="versus">
              <div class="method miss"><small>CVSS SORT / TOP 1</small><strong>0 / 1 KEV</strong><small>high severity, wrong first move</small></div>
              <div class="vs">VS</div>
              <div class="method hit"><small>PATCHTRIAGE / TOP 1</small><strong>1 / 1 KEV</strong><small>known exploitation first</small></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</section>

<input type="file" id="filepick" class="filehidden" accept=".json,.spdx,.cdx">
<div id="toast" class="toast" role="status" aria-live="polite"></div>
<script>
let CFG={backends:["rules"],has_key:false,version:"—"};
let TARGETS=[];let RESULTS=new Map();let pickTarget=null;let toastTimer=null;

async function api(method,path,body){
  const opt={method,headers:{}};
  if(body!==undefined){opt.headers["Content-Type"]="application/json";opt.body=JSON.stringify(body);}
  const response=await fetch(path,opt);
  const payload=response.status===204?null:await response.json().catch(()=>({error:response.statusText}));
  if(!response.ok)throw new Error((payload&&payload.error)||response.statusText);
  return payload;
}
function esc(value){return String(value==null?"":value).replace(/[&<>"]/g,ch=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[ch]));}
function notify(message,error=false){
  const el=document.getElementById("toast");el.textContent=message;el.className="toast show"+(error?" error":"");
  clearTimeout(toastTimer);toastTimer=setTimeout(()=>el.className="toast",3600);
}
function setBusy(busy){document.querySelectorAll(".run-control").forEach(el=>el.disabled=busy);}
function pct(value,total){return total?Math.max(5,Math.round(value/total*100)):0;}
function sources(value){return String(value||"").split(",").map(v=>v.trim()).filter(Boolean);}

async function loadConfig(){
  CFG=await api("GET","/api/config");document.getElementById("version").textContent="v"+CFG.version;
  document.getElementById("backend").innerHTML=CFG.backends.map(b=>`<option value="${esc(b)}">${esc(b)}</option>`).join("");
}
async function loadTargets(){
  TARGETS=await api("GET","/api/targets");renderTargets();updateKpis();
}
function contextTags(target){
  const tags=[`<span class="tag">${esc(target.criticality)}</span>`];
  if(target.internet_exposed)tags.push('<span class="tag hot">exposed</span>');
  if(target.reachable)tags.push('<span class="tag live">reachable</span>');
  if(target.runtime_observed)tags.push('<span class="tag live">runtime</span>');
  if(target.demo)tags.push('<span class="tag demo">offline demo</span>');
  return tags.join("");
}
function renderTargets(){
  const list=document.getElementById("targetlist");
  if(!TARGETS.length){list.innerHTML='<div class="hint">No targets registered yet.</div>';return;}
  list.innerHTML=TARGETS.map(target=>{
    const name=target.url?`<a href="${esc(target.url)}" target="_blank" rel="noopener">${esc(target.name)} ↗</a>`:esc(target.name);
    return `<article class="target" data-id="${target.id}">
      <div class="targettop"><div><div class="targetname">${name}</div><div class="targetid">${target.id}</div></div></div>
      <div class="badges">${contextTags(target)}</div>
      <div class="source ${target.source_file?"ready":""}">${target.source_file?`● ${esc(target.source_format)} evidence attached`:"○ waiting for scan or SBOM"}</div>
      <div class="targetactions">
        <button class="btn small" data-action="import">Attach evidence</button>
        <button class="btn small run-control" data-action="run" ${target.source_file?"":"disabled"}>Run</button>
        <button class="btn small danger" data-action="delete">Delete</button>
      </div></article>`;
  }).join("");
}
function updateKpis(){
  const values=[...RESULTS.values()];
  const totalFindings=values.reduce((n,r)=>n+r.total,0);
  const verified=values.reduce((n,r)=>n+r.audit_verified,0);
  document.getElementById("k-targets").textContent=TARGETS.length;
  document.getElementById("k-kev").textContent=values.reduce((n,r)=>n+r.kev,0);
  document.getElementById("k-p1").textContent=values.reduce((n,r)=>n+r.counts.P1,0);
  document.getElementById("k-audit").textContent=totalFindings?Math.round(verified/totalFindings*100)+"%":"—";
}
function compareBlock(summary){
  const c=summary.comparison;if(!c)return '<div class="hint">No comparison available.</div>';
  const maximum=Math.max(1,c.kev_total);
  return `<div class="microtitle">Known-exploited captured at top ${c.k}</div>
    <div class="barrow"><span>CVSS only</span><div class="track"><div class="fill" style="width:${pct(c.kev.cvss,maximum)}%"></div></div><span class="barvalue">${c.kev.cvss}/${c.kev_total}</span></div>
    <div class="barrow"><span>EPSS only</span><div class="track"><div class="fill epss" style="width:${pct(c.kev.epss,maximum)}%"></div></div><span class="barvalue">${c.kev.epss}/${c.kev_total}</span></div>
    <div class="barrow"><span>PatchTriage</span><div class="track"><div class="fill pt" style="width:${pct(c.kev.patchtriage,maximum)}%"></div></div><span class="barvalue">${c.kev.patchtriage}/${c.kev_total}</span></div>
    <div class="comparefoot">EPSS is shown as a first-class baseline. PatchTriage adds asset context, concrete package actions, and a reproducible audit trail.</div>`;
}
function explainBlock(summary){
  const x=summary.explanation;if(!x)return '<div class="hint">No actionable finding.</div>';
  const f=x.factors;const likelihood=x.kev?"KEV confirmed":(x.epss==null?"EPSS n/a":`EPSS ${(x.epss*100).toFixed(1)}%`);
  const context=[f.internet_exposed?"exposed":"internal",f.reachable?"reachable":"reachability unknown",f.runtime_observed?"runtime seen":"runtime unknown"].join(" · ");
  const risk=(Number(f.likelihood)*Number(f.impact)*Number(f.asset_weight)).toFixed(3);
  return `<div class="microtitle">Why ${esc(x.vuln_id)} leads</div>
    <div class="factorflow">
      <div class="factor"><span>Likelihood</span><b>${esc(likelihood)}</b></div><div class="factorarrow">×</div>
      <div class="factor"><span>Impact</span><b>CVSS ${esc(x.cvss==null?"n/a":x.cvss)}</b></div><div class="factorarrow">×</div>
      <div class="factor"><span>Asset</span><b>${esc(context)}</b></div>
    </div>
    <div class="riskline"><span>${esc(x.package)} · deterministic risk contribution</span><b>${risk}</b></div>`;
}
function renderResult(summary){
  const name=summary.url?`<a href="${esc(summary.url)}" target="_blank" rel="noopener">${esc(summary.name)} ↗</a>`:esc(summary.name);
  return `<article class="result" data-result="${summary.target_id}">
    <div class="resulthead">
      <div class="priority ${esc(summary.top_priority)}">${esc(summary.top_priority||"—")}</div>
      <div><div class="rname">${name} · ${summary.duration_ms} ms ${summary.demo?"· offline snapshot":""}</div><div class="action">${esc(summary.top_action||"No actionable findings")}</div></div>
      <a class="reportlink" href="${esc(summary.report_url)}" target="_blank" rel="noopener">Open full report →</a>
    </div>
    <div class="metricrow">
      <span class="metric alert">P1 ${summary.counts.P1}</span><span class="metric">P2 ${summary.counts.P2}</span>
      <span class="metric">${summary.total} findings</span><span class="metric">${summary.actions} package actions</span>
      <span class="metric alert">${summary.kev} KEV</span><span class="metric audit">audit ${summary.audit_verified}/${summary.total}</span>
      <span class="metric">risk cut ${summary.risk_reduced}</span>
    </div>
    <div class="resultbody"><div class="compare">${compareBlock(summary)}</div><div class="explain">${explainBlock(summary)}</div></div>
  </article>`;
}
function renderResults(){
  const results=document.getElementById("results");
  if(!RESULTS.size){results.innerHTML='<div class="running lightpanel"><strong>No completed decisions yet.</strong><div class="hint">Run a target or launch the offline Arsenal demo.</div></div>';updateKpis();return;}
  results.innerHTML=[...RESULTS.values()].map(renderResult).join("");updateKpis();
}
async function runTargets(ids){
  if(!ids.length){notify("Attach a scan or SBOM to at least one target.",true);return;}
  setBusy(true);const results=document.getElementById("results");
  results.innerHTML=`<div class="running lightpanel"><strong>Building a defensible patch queue…</strong><div class="hint">enrich → contextualize → prioritize → audit → plan</div><div class="scanline"></div></div>`;
  const backend=document.getElementById("backend").value;
  let completed=0;
  for(const id of ids){
    try{const summary=await api("POST","/api/targets/"+id+"/run",{backend});RESULTS.set(id,summary);renderResults();}
    catch(error){notify(`Target ${id}: ${error.message}`,true);}
    if(RESULTS.has(id))completed++;
  }
  if(!completed)renderResults();
  setBusy(false);updateKpis();
}
async function launchDemo(){
  try{setBusy(true);notify("Loading bundled threat evidence…");const target=await api("POST","/api/demo",{});await loadTargets();await runTargets([target.id]);notify("Offline Arsenal demo is ready.");}
  catch(error){notify(error.message,true);setBusy(false);}
}

document.getElementById("jump").onclick=()=>document.getElementById("workspace").scrollIntoView();
document.getElementById("demo").onclick=launchDemo;
document.getElementById("results").onclick=event=>{if(event.target.closest(".demo-trigger"))launchDemo();};
document.getElementById("add").onclick=async()=>{
  const name=document.getElementById("f-name").value.trim();if(!name){notify("Give the target a system name.",true);return;}
  try{
    await api("POST","/api/targets",{name,url:document.getElementById("f-url").value.trim(),criticality:document.getElementById("f-crit").value,
      internet_exposed:document.getElementById("f-exposed").checked,reachable:document.getElementById("f-reachable").checked||null,
      runtime_observed:document.getElementById("f-runtime").checked||null,context_sources:sources(document.getElementById("f-sources").value)});
    ["f-name","f-url","f-sources"].forEach(id=>document.getElementById(id).value="");
    ["f-exposed","f-reachable","f-runtime"].forEach(id=>document.getElementById(id).checked=false);
    await loadTargets();notify("Target added.");
  }catch(error){notify(error.message,true);}
};
document.getElementById("targetlist").onclick=async event=>{
  const button=event.target.closest("button");if(!button)return;
  const card=button.closest(".target"),id=card.dataset.id,action=button.dataset.action;
  if(action==="import"){pickTarget=id;document.getElementById("filepick").click();}
  if(action==="run")runTargets([id]);
  if(action==="delete"&&confirm("Delete this target and its local evidence?")){
    try{await api("DELETE","/api/targets/"+id);RESULTS.delete(id);await loadTargets();renderResults();notify("Target deleted.");}
    catch(error){notify(error.message,true);}
  }
};
document.getElementById("filepick").onchange=async event=>{
  const file=event.target.files[0];if(!file||!pickTarget)return;
  if(file.size>48*1024*1024){notify("Evidence file must be 48 MiB or smaller.",true);event.target.value="";return;}
  try{await api("POST",`/api/targets/${pickTarget}/source`,{content:await file.text(),filename:file.name});await loadTargets();notify(`${file.name} attached.`);}
  catch(error){notify("Import failed: "+error.message,true);}
  event.target.value="";pickTarget=null;
};
document.getElementById("runall").onclick=()=>runTargets(TARGETS.filter(t=>t.source_file).map(t=>t.id));

Promise.all([loadConfig(),loadTargets()]).catch(error=>notify(error.message,true));
</script></body></html>"""
