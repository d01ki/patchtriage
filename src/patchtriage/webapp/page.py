"""The single-page GUI. Self-contained: inline CSS + JS, no external assets."""

INDEX_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#0a0d14">
<title>PatchTriage</title>
<style>
  :root{
    --void:#090c12;--void2:#10141e;--panel:#151a25;--panel2:#1b2130;
    --ink:#f4f6fb;--muted:#929cad;--line:#2a3243;--hot:#ff4d3d;
    --amber:#ffb020;--blue:#6e8cff;--cyan:#49d6e9;--paper:#eef1f7;
    --dark:#171b25;--immediate:#ff4d3d;--outofcycle:#ffb020;--scheduled:#6e8cff;--defer:#778195;
  }
  *{box-sizing:border-box}
  html{scroll-behavior:smooth}
  body{margin:0;background:var(--void);color:var(--ink);
    font:16px/1.58 Inter,"Segoe UI",Helvetica,Arial,sans-serif}
  button,input,select{font:inherit}button{cursor:pointer}
  a{color:inherit}.mono{font-family:"SFMono-Regular",Consolas,"Liberation Mono",monospace}
  .topbar{height:58px;padding:0 clamp(20px,4vw,64px);display:flex;align-items:center;
    justify-content:space-between;border-bottom:1px solid var(--line);background:rgba(9,12,18,.96);
    position:sticky;top:0;z-index:20}
  .brand{display:flex;align-items:center;gap:12px;font-weight:800;letter-spacing:.08em}
  .brandmark{width:27px;height:27px;border:2px solid var(--hot);position:relative}
  .brandmark:before,.brandmark:after{content:"";position:absolute;background:var(--hot)}
  .brandmark:before{width:13px;height:2px;left:5px;top:7px}.brandmark:after{width:2px;height:13px;left:11px;top:5px}
  .brand span{color:var(--hot)}
  .statusdot{width:7px;height:7px;border-radius:50%;background:var(--cyan);box-shadow:0 0 12px var(--cyan)}
  .hero{max-width:1500px;margin:0 auto;padding:clamp(16px,2.2vw,30px) clamp(20px,4vw,64px) 30px;
    display:grid;grid-template-columns:minmax(340px,.95fr) minmax(520px,1.2fr);gap:clamp(36px,6vw,90px);align-items:center}
  .eyebrow{color:var(--hot);font:700 13px/1.2 "SFMono-Regular",Consolas,monospace;letter-spacing:.16em;text-transform:uppercase}
  h1{font-size:clamp(42px,5.7vw,78px);line-height:.97;letter-spacing:-.052em;margin:12px 0 20px;max-width:780px}
  h1 em{font-style:normal;color:var(--hot)}
  .hero p{color:#b3bccb;font-size:clamp(17px,1.55vw,21px);max-width:680px;margin:0 0 25px}
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
  .node strong{display:block;font-size:15px;margin:8px 0 5px}.node small{color:var(--muted);font-size:12.5px;display:block}
  .nodecode{color:var(--cyan);font:700 12px "SFMono-Regular",Consolas,monospace}
  .arrow{display:flex;align-items:center;justify-content:center;color:#59667a;font-size:22px}
  .decision{grid-column:1/-1;margin-top:12px;border-left:3px solid var(--hot);background:#1c171c;padding:16px 18px;display:flex;justify-content:space-between;gap:20px;align-items:center}
  .decision b{font-size:18px}.decision span{color:var(--muted);font-size:12px}.decision .outcome-now{text-align:right;font:800 22px "SFMono-Regular",Consolas,monospace;color:var(--hot)}
  .benchmark{max-width:1500px;margin:0 auto 34px;padding:0 clamp(20px,4vw,64px);display:grid;grid-template-columns:minmax(300px,.9fr) minmax(520px,1.35fr);gap:1px}
  .benchmarkcopy{background:#111722;border:1px solid var(--line);padding:24px}.benchmarkcopy h2{font-size:clamp(23px,2.8vw,36px);line-height:1.08;letter-spacing:-.035em;margin:10px 0}.benchmarkcopy p{color:var(--muted);margin:0;font-size:13.5px}
  .outcomes{display:grid;grid-template-columns:repeat(3,1fr)}.outcome{background:var(--panel);border:1px solid var(--line);border-left:0;padding:20px 18px}.outcome strong{display:block;font:800 clamp(25px,3vw,38px) "SFMono-Regular",Consolas,monospace;color:var(--cyan)}.outcome span{display:block;font-size:13px;font-weight:700;margin:5px 0}.outcome small{display:block;color:var(--muted);font-size:11.5px}
  .kpis{max-width:1500px;margin:0 auto;padding:0 clamp(20px,4vw,64px) 34px;display:grid;grid-template-columns:repeat(4,1fr);gap:1px}
  .kpi{background:var(--panel);border:1px solid var(--line);padding:15px 18px}.kpi+.kpi{border-left:0}
  .kpi .value{font:750 28px "SFMono-Regular",Consolas,monospace}.kpi .label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.09em}
  .workspace{background:var(--paper);color:var(--dark);border-radius:22px 22px 0 0;min-height:720px;padding:34px clamp(20px,4vw,64px) 70px}
  .workspaceinner{max-width:1500px;margin:0 auto;display:grid;grid-template-columns:340px minmax(0,1fr);gap:28px}
  .sectiontitle{display:flex;align-items:flex-end;justify-content:space-between;margin-bottom:14px}
  .sectiontitle h2{margin:0;font-size:20px;letter-spacing:-.02em}.sectiontitle span{font:12px "SFMono-Regular",Consolas,monospace;color:#70798a;text-transform:uppercase;letter-spacing:.09em}
  .prioritylegend{display:grid;grid-template-columns:repeat(4,1fr);margin-bottom:14px;overflow:hidden}.prioritylegend>div{padding:10px 11px;border-right:1px solid #e2e6ee;font-size:11px;color:#687285}.prioritylegend>div:last-child{border-right:0}.prioritylegend b{display:block;font-size:12px;color:#2d3441}.prioritylegend i{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px;background:var(--defer)}.prioritylegend .immediate i{background:var(--immediate)}.prioritylegend .outofcycle i{background:var(--outofcycle)}.prioritylegend .scheduled i{background:var(--scheduled)}
  .lightpanel{background:#fff;border:1px solid #d9deea;border-radius:10px;box-shadow:0 10px 28px rgba(30,40,65,.06)}
  details.add{margin-bottom:14px}details.add summary{list-style:none;padding:14px 16px;font-weight:700;cursor:pointer;display:flex;justify-content:space-between}
  details.add summary::-webkit-details-marker{display:none}details.add summary:after{content:"+";color:#697386}details.add[open] summary:after{content:"−"}
  .form{border-top:1px solid #e4e7ee;padding:14px;display:grid;gap:11px}
  input[type=text],select{width:100%;border:1px solid #cfd5e2;border-radius:5px;padding:9px 10px;background:#fff;color:#171b25}
  .contextintro{border:1px solid #dbe0ec;background:#f7f8fc;border-radius:6px;padding:10px 11px;display:grid;gap:3px}.contextintro strong{font-size:12.5px}.contextintro span,.contextintro a{font-size:11.5px;color:#667183}.contextintro a{color:#4053ba;font-weight:700;text-decoration:none}.contextintro a:hover{text-decoration:underline}
  .fieldlabel{display:grid;gap:4px;color:#697386;font-size:11px;font-weight:750;text-transform:uppercase;letter-spacing:.055em}.fieldlabel select,.fieldlabel input{font-size:13px;text-transform:none;letter-spacing:0}.fieldhelp{color:#7b8494;font-size:10.5px;font-weight:500;text-transform:none;letter-spacing:0;line-height:1.35}.formactions{display:flex;gap:7px}.formactions .btn{flex:1}
  .row2{display:grid;grid-template-columns:1fr 1fr;gap:8px}.checks{display:grid;gap:7px;padding:5px 0}
  .supplementalcontext{border-top:1px solid #e3e6ed;padding-top:9px}.supplementalcontext b{display:block;font-size:11.5px}.supplementalcontext p{font-size:10.5px;color:#7b8494;margin:2px 0 4px}.check{display:flex;align-items:center;gap:8px;font-size:13.5px;color:#5e687a}.check input{accent-color:#4d65e6}
  .hint{font-size:12.5px;color:#7a8393}.targetlist{display:flex;flex-direction:column;gap:9px}
  .target{background:#fff;border:1px solid #d9deea;border-radius:8px;padding:13px;transition:.18s}
  .target:hover{border-color:#b8c1d3;transform:translateY(-1px)}.targettop{display:flex;justify-content:space-between;gap:8px}
  .targetname{font-weight:750;overflow-wrap:anywhere}.targetname a{text-decoration:none}.targetname a:hover{text-decoration:underline}
  .targetid{font:10px "SFMono-Regular",Consolas,monospace;color:#9098a6;margin-top:2px}
  .badges{display:flex;gap:5px;flex-wrap:wrap;margin-top:9px}.tag{font:700 9.5px "SFMono-Regular",Consolas,monospace;text-transform:uppercase;letter-spacing:.04em;border:1px solid #d5dae5;border-radius:20px;padding:3px 6px;color:#5c6575;background:#f7f8fb}
  .tag.hot{color:#c93025;background:#fff0ee;border-color:#ffd0ca}.tag.live{color:#1c6470;background:#eafcff;border-color:#b9edf4}.tag.demo{color:#674100;background:#fff4d8;border-color:#ffdfa0}.tag.warn{color:#8a5700;background:#fff5dc;border-color:#f5d487}
  .source{font-size:12px;color:#6f7888;margin:9px 0;line-height:1.4}.source.ready{color:#354fd1}.targetactions{display:flex;gap:6px;flex-wrap:wrap}.btn.attach{background:#eef1ff;color:#3048c5;border-color:#bec7f5}
  .results{display:flex;flex-direction:column;gap:14px}.empty{min-height:390px;display:grid;grid-template-columns:1fr 1fr;overflow:hidden}
  .emptycopy{padding:clamp(28px,4vw,54px);display:flex;flex-direction:column;justify-content:center}.emptycopy .eyebrow{color:#5563d8}.emptycopy h3{font-size:clamp(28px,3.3vw,46px);line-height:1.04;letter-spacing:-.045em;margin:13px 0}.emptycopy p{color:#687285;max-width:50ch}
  .emptyviz{background:#121722;color:#fff;padding:32px;display:flex;flex-direction:column;justify-content:center}.versus{display:grid;grid-template-columns:1fr auto 1fr;gap:14px;align-items:center}.method{border:1px solid #30394b;padding:17px}.method strong{display:block;font-size:22px}.method small{color:#929cad}.method.miss strong{color:var(--hot)}.method.hit{border-color:#566cf0}.method.hit strong{color:#9eb0ff}.vs{font:700 11px "SFMono-Regular",Consolas,monospace;color:#667084}
  .result{background:#fff;border:1px solid #d7dce7;border-radius:10px;overflow:hidden;box-shadow:0 12px 35px rgba(30,40,65,.07)}
  .resulthead{display:grid;grid-template-columns:154px 1fr auto;gap:17px;align-items:center;padding:19px 21px;border-bottom:1px solid #e2e6ee}
  .prioritybox{min-width:0}.prioritymeaning{text-align:center;color:#586274;font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:.065em;margin-top:5px}.prioritydue{text-align:center;color:#858e9d;font:9.5px "SFMono-Regular",Consolas,monospace;margin-top:2px}
  .priority{height:66px;display:flex;align-items:center;justify-content:center;text-align:center;border-radius:6px;color:white;font:850 16px "SFMono-Regular",Consolas,monospace;background:var(--defer);padding:8px}
  .priority.immediate{background:var(--immediate)}.priority.out-of-cycle{background:var(--outofcycle);color:#2d1d00}.priority.scheduled{background:var(--scheduled)}
  .priority.no-findings{background:#6f7888}.rname{font-size:13px;color:#737d8d;margin-bottom:4px}.action{font-size:21px;font-weight:780;line-height:1.2;letter-spacing:-.025em}.reportlink{text-decoration:none;color:#3048c5;font-weight:700;font-size:13px;white-space:nowrap}
  .metricrow{padding:12px 21px;display:flex;gap:7px;flex-wrap:wrap;background:#fafbfc;border-bottom:1px solid #e5e8ef}.metric{font:11px "SFMono-Regular",Consolas,monospace;background:#edf0f5;border-radius:4px;padding:4px 7px;color:#4f5969}.metric.alert{background:#ffebe8;color:#c42f24}.metric.audit{background:#e8f9fc;color:#226976}
  .resultbody{display:grid;grid-template-columns:minmax(320px,.85fr) minmax(430px,1.15fr);gap:0}.compare{padding:21px;border-right:1px solid #e4e7ed}.explain{padding:21px}
  .microtitle{font:750 10px "SFMono-Regular",Consolas,monospace;text-transform:uppercase;letter-spacing:.12em;color:#768093;margin-bottom:12px}
  .barrow{display:grid;grid-template-columns:92px 1fr 40px;gap:9px;align-items:center;margin:9px 0;font-size:11px}.track{height:8px;background:#e7eaf0;border-radius:2px;overflow:hidden}.fill{height:100%;background:#a7afbd}.fill.epss{background:#6f7f99}.fill.pt{background:#5368e8}.barvalue{font:700 11px "SFMono-Regular",Consolas,monospace;text-align:right}
  .outcomegrid{display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin-bottom:14px}.outcomemicro{border:1px solid #dfe3eb;background:#f8f9fb;border-radius:5px;padding:9px}.outcomemicro b{display:block;color:#344ac8;font:800 18px "SFMono-Regular",Consolas,monospace}.outcomemicro span{font-size:9.5px;color:#747e8f;text-transform:uppercase;letter-spacing:.04em}
  .comparefoot{font-size:12.5px;color:#727c8d;margin-top:13px}.basis{border-left:3px solid #5368e8;background:#f0f2ff;color:#27336f;border-radius:3px;padding:10px 12px;margin-bottom:11px;font-size:12.5px;font-weight:650}.ssvcflow{display:grid;grid-template-columns:repeat(4,1fr);gap:5px;align-items:stretch}.factor{border:1px solid #dfe3eb;background:#f8f9fb;border-radius:5px;padding:10px}.factor span{font:10px "SFMono-Regular",Consolas,monospace;text-transform:uppercase;color:#7e8796}.factor b{display:block;font-size:13px;margin-top:4px}.factor small{display:block;color:#7e8796;font-size:10px;margin-top:3px}.decisionline{margin-top:10px;background:#171d29;color:white;padding:11px 13px;border-radius:5px;display:flex;justify-content:space-between;align-items:center}.decisionline span{color:#9aa4b5;font-size:11px;text-transform:uppercase;letter-spacing:.08em}.decisionline b{color:#8fa3ff;font:800 16px "SFMono-Regular",Consolas,monospace}.decisionnote{margin-top:9px;border:1px solid #d8deeb;background:#f8f9fc;color:#5f697a;border-radius:5px;padding:9px 10px;font-size:11.5px}.decisionnote b{color:#293342}.signalgrid{display:grid;grid-template-columns:repeat(4,1fr);gap:5px;margin-top:8px}.signal{border:1px solid #dfe3eb;border-radius:5px;padding:8px 9px;background:#fff}.signal span{display:block;color:#7b8494;font-size:9.5px;text-transform:uppercase;letter-spacing:.05em}.signal b{display:block;font:750 12px "SFMono-Regular",Consolas,monospace;margin-top:2px}.confirmbar{margin-top:9px;border:1px solid #f0cf86;background:#fff7e4;color:#765017;border-radius:5px;padding:9px 11px;font-size:11.5px}.emptyresult{border:1px solid #dbe0ea;background:#f8f9fb;border-radius:6px;padding:16px}.emptyresult b{display:block;font-size:15px}.emptyresult span{display:block;color:#6c7687;font-size:12.5px;margin-top:4px}
  .evidence{list-style:none;padding:0;margin:11px 0 0;display:grid;grid-template-columns:1fr 1fr;gap:6px}.evidence li{border:1px solid #e0e4ec;border-radius:5px;padding:8px 9px;display:grid;grid-template-columns:18px 1fr;gap:5px;align-items:start}.evidenceicon{width:16px;height:16px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:#e5e8ee;color:#687386;font:800 9px "SFMono-Regular",Consolas,monospace}.evidenceicon.confirmed{background:#dff7eb;color:#15704a}.evidenceicon.attention{background:#fff0d6;color:#985d00}.evidence strong{display:block;font-size:10.5px}.evidence small{display:block;color:#737d8d;font-size:9.5px;line-height:1.35;margin-top:1px}
  .advisoryline{margin-top:9px;display:flex;gap:6px;flex-wrap:wrap}.advisoryline a,.advisoryline span{font:700 10px "SFMono-Regular",Consolas,monospace;text-decoration:none;border:1px solid #ccd3e1;background:#f7f8fb;color:#4053ba;padding:4px 7px;border-radius:4px}.advisoryline a:hover{text-decoration:underline}
  .running{padding:26px;border-left:4px solid #5368e8}.running strong{font-size:18px}.scanline{height:3px;background:#e1e5ed;margin-top:16px;overflow:hidden}.scanline:after{content:"";display:block;width:32%;height:100%;background:#5368e8;animation:scan 1s infinite ease-in-out}@keyframes scan{from{transform:translateX(-100%)}to{transform:translateX(410%)}}
  .toast{position:fixed;right:22px;bottom:22px;background:#151a25;color:#fff;border:1px solid #343d50;padding:11px 15px;border-radius:6px;box-shadow:0 12px 40px rgba(0,0,0,.28);transform:translateY(90px);opacity:0;transition:.2s;z-index:30;max-width:420px}.toast.show{transform:none;opacity:1}.toast.error{border-color:#a63d36}
  .filehidden{display:none}
  @media(max-width:1100px){.hero{grid-template-columns:1fr}.benchmark{grid-template-columns:1fr}.workspaceinner{grid-template-columns:300px minmax(0,1fr)}.resultbody{grid-template-columns:1fr}.compare{border-right:0;border-bottom:1px solid #e4e7ed}}
  @media(max-width:820px){.outcomes{grid-template-columns:1fr}.outcome{border-left:1px solid var(--line);border-top:0}.kpis{grid-template-columns:1fr 1fr}.kpi+.kpi{border-left:1px solid var(--line)}.workspaceinner{grid-template-columns:1fr}.empty{grid-template-columns:1fr}.resulthead{grid-template-columns:104px 1fr}.priority{height:54px}.reportlink{grid-column:2}.flow{grid-template-columns:1fr}.arrow{transform:rotate(90deg)}.decision{grid-column:1}.ssvcflow{grid-template-columns:1fr 1fr}}
  @media(max-width:520px){h1{font-size:43px}.topbar{padding:0 16px}.brand{font-size:13px}.hero{padding-left:16px;padding-right:16px}.kpis{padding-left:16px;padding-right:16px}.prioritylegend{grid-template-columns:1fr 1fr}.prioritylegend>div{border-bottom:1px solid #e2e6ee}.resulthead{padding:15px}.resultbody>div,.metricrow{padding-left:15px;padding-right:15px}.versus{grid-template-columns:1fr}.vs{text-align:center}.row2{grid-template-columns:1fr}}
</style></head>
<body>
<header class="topbar">
  <div class="brand"><span class="brandmark" aria-hidden="true"></span>PATCH<span>TRIAGE</span></div>
</header>

<section class="hero">
  <div>
    <div class="eyebrow">Evidence-informed deployment decisions</div>
    <h1>Patch what matters <em>first.</em></h1>
    <p>Combine global threat evidence with your system exposure, mission impact, and safety context to make one defensible SSVC deployment decision — without letting AI invent a score.</p>
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
      <div class="node"><span class="nodecode">02 / THREAT</span><strong>Exploitation state</strong><small>Active · Public PoC · None · EPSS watch signal</small></div>
      <div class="arrow">→</div>
      <div class="node"><span class="nodecode">03 / STAKEHOLDER</span><strong>SSVC factors</strong><small>Exposure · Automatable · Human impact</small></div>
      <div class="decision"><div><b>Upgrade libc6 on web-frontend</b><br><span>Active · Open · Not automatable · High human impact → Out-of-Cycle</span></div><div class="outcome-now">Out-of-Cycle</div></div>
    </div>
  </div>
</section>

<section class="benchmark" aria-label="SSVC decision model">
  <div class="benchmarkcopy">
    <div class="eyebrow">CERT/CC SSVC · Deployer model</div>
    <h2>Severity informs. Your environment decides.</h2>
    <p>KEV and PoC evidence establish what attackers are doing. SSVC combines that state with how your system is deployed and what failure means to your organization.</p>
  </div>
  <div class="outcomes">
    <div class="outcome"><strong>E</strong><span>Exploitation</span><small>KEV → Active · public exploit → PoC</small></div>
    <div class="outcome"><strong>EXP</strong><span>Your attack surface</span><small>Open · Controlled · Small</small></div>
    <div class="outcome"><strong>HI</strong><span>Human impact</span><small>Mission + safety consequences</small></div>
  </div>
</section>

<section class="kpis" aria-label="Workspace totals">
  <div class="kpi"><div class="value" id="k-targets">0</div><div class="label">targets in scope</div></div>
  <div class="kpi"><div class="value" id="k-kev">0</div><div class="label">known exploited</div></div>
  <div class="kpi"><div class="value" id="k-immediate">0</div><div class="label">Immediate decisions</div></div>
  <div class="kpi"><div class="value" id="k-audit">—</div><div class="label">decisions verified</div></div>
</section>

<section class="workspace" id="workspace">
  <div class="workspaceinner">
    <aside>
      <div class="sectiontitle"><h2>Targets</h2><span>asset context</span></div>
      <details class="add lightpanel" id="targetform">
        <summary id="form-title">Add a target</summary>
        <div class="form">
          <div class="contextintro">
            <strong>CERT/CC SSVC Deployer context</strong>
            <span>Describe this deployed system and the consequence of its failure. Automatable is evaluated separately for each vulnerability.</span>
            <a href="https://certcc.github.io/SSVC/howto/deployer_tree/" target="_blank" rel="noopener">Open the official decision-point definitions ↗</a>
          </div>
          <input type="text" id="f-name" maxlength="120" placeholder="System name" aria-label="System name">
          <input type="text" id="f-url" placeholder="https:// dashboard, repo, or runbook" aria-label="Target link URL">
          <label class="fieldlabel">System Exposure
            <span class="fieldhelp">The accessible attack surface of this deployed system or service.</span>
            <select id="f-exposure"><option value="unknown" selected>Unknown — use official Open default</option><option value="open">Open — Internet or widely accessible network</option><option value="controlled">Controlled — reliable access restrictions or mitigations</option><option value="small">Small — local service or highly controlled network</option></select>
          </label>
          <label class="fieldlabel">Mission Impact
            <span class="fieldhelp">Impact on your organization's Mission Essential Functions (MEFs).</span>
            <select id="f-mission"><option value="unknown" selected>Unknown — use official Support Crippled default</option><option value="degraded">Degraded — little impact or non-essential degradation</option><option value="mef_support_crippled">MEF Support Crippled — essential functions continue temporarily</option><option value="mef_failure">MEF Failure — one essential function fails too long</option><option value="mission_failure">Mission Failure — multiple or all essential functions fail</option></select>
          </label>
          <label class="fieldlabel">Safety Impact
            <span class="fieldhelp">Highest credible harm to people, operators, systems, environment, finances, or well-being.</span>
            <select id="f-safety"><option value="unknown" selected>Unknown — use official Marginal default</option><option value="negligible">Negligible — minor harm or small safety-margin reduction</option><option value="marginal">Marginal — major injury or safety capability failure</option><option value="critical">Critical — loss of life or system enters unsafe state</option><option value="catastrophic">Catastrophic — multiple deaths or total system loss</option></select>
          </label>
          <label class="fieldlabel">Context evidence sources (optional)
            <input type="text" id="f-sources" placeholder="CMDB, service owner, BCP, safety analysis" aria-label="Context evidence sources">
            <span class="fieldhelp">Record where these organizational answers came from.</span>
          </label>
          <div class="supplementalcontext">
            <b>Supporting evidence — not SSVC decision points</b>
            <p>These observations are retained for analyst review and do not replace the official decision path.</p>
            <div class="checks">
              <label class="check"><input type="checkbox" id="f-reachable"> Vulnerable path is confirmed reachable</label>
              <label class="check"><input type="checkbox" id="f-runtime"> Component or path observed at runtime</label>
            </div>
          </div>
          <div class="formactions"><button class="btn primary" id="add">Add target</button><button class="btn" id="cancel-edit" type="button" hidden>Cancel</button></div>
          <div class="hint">Unknown is a PatchTriage capture state, not an SSVC value. The official conservative default is applied and visibly flagged for confirmation.</div>
        </div>
      </details>
      <div class="targetlist" id="targetlist"></div>
    </aside>

    <div>
      <div class="sectiontitle"><h2>Patch decisions</h2><span>
        <select id="backend" aria-label="Triage backend"></select>
        <button class="btn small run-control" id="runall">Run all</button>
      </span></div>
      <div class="prioritylegend lightpanel" aria-label="SSVC outcome meanings">
        <div class="immediate"><b><i></i>Immediate</b>Act now · default target 3 days</div>
        <div class="outofcycle"><b><i></i>Out-of-Cycle</b>Next available opportunity · 14 days</div>
        <div class="scheduled"><b><i></i>Scheduled</b>Normal maintenance · 30 days</div>
        <div class="defer"><b><i></i>Defer</b>Monitor and reassess · 90 days</div>
      </div>
      <div class="results" id="results">
        <div class="empty lightpanel">
          <div class="emptycopy">
            <div class="eyebrow">Decision, not detection</div>
            <h3>See why the same CVE needs a different action here.</h3>
            <p>Load the bundled evidence. PatchTriage applies the official SSVC Deployer path, shows every inferred input and confidence level, then groups findings into package-level actions.</p>
            <div><button class="btn primary run-control demo-trigger">Launch Demo</button></div>
          </div>
          <div class="emptyviz">
            <div class="versus">
              <div class="method miss"><small>GLOBAL SIGNALS</small><strong>KEV · EPSS · CVSS</strong><small>what attackers can do</small></div>
              <div class="vs">VS</div>
              <div class="method hit"><small>SSVC / YOUR SYSTEM</small><strong>Immediate</strong><small>what your team should do now</small></div>
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
let CFG={backends:["rules"],has_key:false};
let TARGETS=[];let RESULTS=new Map();let pickTarget=null;let editingTarget=null;let toastTimer=null;

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
function pct(value,total){return value&&total?Math.max(5,Math.round(value/total*100)):0;}
function sources(value){return String(value||"").split(",").map(v=>v.trim()).filter(Boolean);}

async function loadConfig(){
  CFG=await api("GET","/api/config");
  const labels={rules:"SSVC deterministic",claude:"SSVC + AI explanation",cascade:"SSVC + AI cascade"};
  document.getElementById("backend").innerHTML=CFG.backends.map(b=>`<option value="${esc(b)}">${esc(labels[b]||b)}</option>`).join("");
}
async function loadTargets(){
  TARGETS=await api("GET","/api/targets");renderTargets();updateKpis();
}
function contextTags(target){
  const exposure=target.system_exposure||"unknown",mission=target.mission_impact||"unknown",safety=target.safety_impact||"unknown";
  const tags=[`<span class="tag ${exposure==="open"?"hot":exposure==="unknown"?"warn":""}">EXP ${esc(exposure)}</span>`,`<span class="tag ${mission==="unknown"?"warn":""}">MI ${esc(mission)}</span>`,`<span class="tag ${safety==="unknown"?"warn":""}">SI ${esc(safety)}</span>`];
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
      <div class="source ${target.source_file?"ready":""}">${target.source_file?`● ${esc(target.source_format)} file attached`:"○ Attach Trivy / Grype / OSV JSON, or a CycloneDX / SPDX SBOM"}</div>
      <div class="targetactions">
        <button class="btn small" data-action="edit">Review SSVC context</button>
        <button class="btn small attach" data-action="import" title="Attach vulnerability scan JSON or a CycloneDX/SPDX SBOM">Attach scan / SBOM</button>
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
  document.getElementById("k-immediate").textContent=values.reduce((n,r)=>n+r.outcomes.immediate,0);
  document.getElementById("k-audit").textContent=totalFindings?Math.round(verified/totalFindings*100)+"%":"—";
}
function compareBlock(summary){
  const c=summary.comparison;if(!c)return `<div class="emptyresult"><b>No findings to compare</b><span>${esc(summary.result_message||"The attached evidence contained no vulnerability records.")}</span></div>`;
  const maximum=Math.max(1,c.kev_total);const o=c.outcome||{};
  const coverage=c.kev_total?`${o.kev_coverage_pct}%`:"n/a";
  const urgent=c.urgent&&c.urgent.total?`${o.urgent_coverage_pct}%`:"n/a";
  return `<div class="microtitle">Outcome at a ${c.k}-finding review budget</div>
    <div class="outcomegrid">
      <div class="outcomemicro"><b>${esc(o.review_reduction_pct==null?"n/a":o.review_reduction_pct+"%")}</b><span>smaller first-pass queue</span></div>
      <div class="outcomemicro"><b>${esc(coverage)}</b><span>KEV coverage</span></div>
      <div class="outcomemicro"><b>${esc(urgent)}</b><span>SSVC urgent coverage</span></div>
    </div>
    <div class="microtitle">Known-exploited findings surfaced</div>
    <div class="barrow"><span>CVSS only</span><div class="track"><div class="fill" style="width:${pct(c.kev.cvss,maximum)}%"></div></div><span class="barvalue">${c.kev.cvss}/${c.kev_total}</span></div>
    <div class="barrow"><span>EPSS only</span><div class="track"><div class="fill epss" style="width:${pct(c.kev.epss,maximum)}%"></div></div><span class="barvalue">${c.kev.epss}/${c.kev_total}</span></div>
    <div class="barrow"><span>KEV first</span><div class="track"><div class="fill epss" style="width:${pct(c.kev.kev,maximum)}%"></div></div><span class="barvalue">${c.kev.kev}/${c.kev_total}</span></div>
    <div class="barrow"><span>SSVC context</span><div class="track"><div class="fill pt" style="width:${pct(c.kev.ssvc,maximum)}%"></div></div><span class="barvalue">${c.kev.ssvc}/${c.kev_total}</span></div>
    <div class="comparefoot">KEV-first is now an explicit baseline. SSVC may rank a KEV below another finding when your exposure and human impact justify a different deployment action.</div>`;
}
function explainBlock(summary){
  const x=summary.explanation;if(!x)return `<div class="emptyresult"><b>${summary.result_state==="no_findings"?"No vulnerabilities found":"No decision explanation available"}</b><span>${esc(summary.result_message||"Inspect the full report for input and processing details.")}</span></div>`;
  const s=x.ssvc||{};const pointKeys=[["exploitation","Exploitation"],["system_exposure","System Exposure"],["automatable","Automatable"],["human_impact","Human Impact"]];
  const flow=pointKeys.map(([key,label])=>{const p=s[key]||{};return `<div class="factor"><span>${esc(label)}</span><b>${esc(p.label||"Unknown")}</b><small>${esc(p.confidence||"low")} confidence · ${esc(p.source||"missing")}</small></div>`;}).join("");
  const cvss=x.cvss==null?"Not available":Number(x.cvss).toFixed(1);
  const epss=x.epss==null?"Not available":`${(Number(x.epss)*100).toFixed(1)}%`;
  const signals=[["CVSS",cvss],["EPSS (30 day)",epss],["CISA KEV",x.kev?"Listed":"Not listed"],["Fix",x.has_fix?"Available":"Not supplied"]].map(([label,value])=>`<div class="signal"><span>${esc(label)}</span><b>${esc(value)}</b></div>`).join("");
  const marks={confirmed:"✓",attention:"!",unknown:"?","not-observed":"–"};
  const checks=(x.checks||[]).map(item=>`<li><span class="evidenceicon ${esc(item.status)}">${marks[item.status]||"·"}</span><span><strong>${esc(item.label)}</strong><small>${esc(item.value)}</small></span></li>`).join("");
  const advisories=(x.advisories||[]).map(a=>a.url
    ?`<a href="${esc(a.url)}" target="_blank" rel="noopener">${esc(a.source.toUpperCase())} · ${esc(a.advisory_id)} ↗</a>`
    :`<span>${esc(a.source.toUpperCase())} · ${esc(a.advisory_id)}</span>`).join("");
  return `<div class="microtitle">Why ${esc(s.decision_label||x.outcome_label)}?</div>
    <div class="basis">${esc(x.basis)}</div>
    <div class="ssvcflow">${flow}</div>
    <div class="decisionline"><span>SSVC Deployer · ${esc(s.model||"")}</span><b>${esc(s.decision_label||"Unknown")}</b></div>
    <div class="decisionnote"><b>Categorical outcome — no aggregate SSVC score.</b> Supporting signals remain visible. Inside the same outcome, SSVC decision points are compared first, followed by EPSS and CVSS tie-breakers; none are added together into a score.</div>
    <div class="signalgrid">${signals}</div>
    ${(x.needs_confirmation||[]).length?`<div class="confirmbar">Confirm inferred inputs: ${esc(x.needs_confirmation.map(v=>String(v).replaceAll("_"," ")).join(", "))}. Conservative defaults remain active until reviewed.</div>`:""}
    ${checks?`<ul class="evidence" aria-label="Decision evidence checklist">${checks}</ul>`:""}
    ${advisories?`<div class="advisoryline">${advisories}</div>`:""}`;
}
function renderResult(summary){
  const name=summary.url?`<a href="${esc(summary.url)}" target="_blank" rel="noopener">${esc(summary.name)} ↗</a>`:esc(summary.name);
  const context=summary.evaluated_context||{};
  const contextText=[["Exposure",context.system_exposure],["Mission",context.mission_impact],["Safety",context.safety_impact]].map(([label,value])=>`${label} ${String(value||"unknown").replaceAll("_"," ")}`).join(" · ");
  const hasFindings=summary.total>0;const outcome=hasFindings?(summary.top_ssvc_decision||"No decision"):"No findings";const outcomeClass=hasFindings?String(outcome).toLowerCase().replaceAll(" ","-"):"no-findings";
  return `<article class="result" data-result="${summary.target_id}">
    <div class="resulthead">
      <div class="prioritybox"><div class="priority ${esc(outcomeClass)}">${esc(outcome)}</div><div class="prioritymeaning">${hasFindings?"SSVC outcome":"Input result"}</div><div class="prioritydue">${summary.top_deadline_days==null?"":`target: ≤ ${esc(summary.top_deadline_days)} days`}</div></div>
      <div><div class="rname">${name} · ${summary.duration_ms} ms ${summary.demo?"· offline snapshot":""}</div><div class="action">${esc(summary.top_action||summary.result_message||"Assessment completed")}</div></div>
      <a class="reportlink" href="${esc(summary.report_url)}" target="_blank" rel="noopener">Open full report →</a>
    </div>
    <div class="metricrow">
      <span class="metric alert">Immediate ${summary.outcomes.immediate}</span><span class="metric">Out-of-Cycle ${summary.outcomes.out_of_cycle}</span>
      <span class="metric">${summary.total} findings</span><span class="metric">${summary.actions} package actions</span>
      <span class="metric alert">${summary.kev} KEV</span><span class="metric audit">audit ${summary.audit_verified}/${summary.total}</span>
      <span class="metric">${summary.vendor_advisories||0} vendor advisories</span>
      ${(summary.vendor_sources||[]).map(s=>`<span class="metric">${esc(s.toUpperCase())}</span>`).join("")}
      ${(summary.vendor_errors||[]).length?`<span class="metric alert" title="${esc(summary.vendor_errors.join(" | "))}">${summary.vendor_errors.length} connector warnings</span>`:""}
      <span class="metric">SSVC ${esc(summary.top_ssvc_decision||"not evaluated")}</span>
      ${(summary.ssvc_confirmation_fields||[]).length?`<span class="metric alert">confirm ${esc(summary.ssvc_confirmation_fields.map(v=>String(v).replaceAll("_"," ")).join(", "))}</span>`:""}
    </div>
    <div class="confirmbar">Target context used · ${esc(contextText)}${(context.context_sources||[]).length?` · Sources ${esc(context.context_sources.join(", "))}`:""}</div>
    <div class="resultbody"><div class="compare">${compareBlock(summary)}</div><div class="explain">${explainBlock(summary)}</div></div>
  </article>`;
}
function renderResults(){
  const results=document.getElementById("results");
  if(!RESULTS.size){results.innerHTML='<div class="running lightpanel"><strong>No completed decisions yet.</strong><div class="hint">Run a target or launch the offline Demo.</div></div>';updateKpis();return;}
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
  try{setBusy(true);notify("Loading bundled threat evidence…");const target=await api("POST","/api/demo",{});await loadTargets();await runTargets([target.id]);notify("Offline Demo is ready.");}
  catch(error){notify(error.message,true);setBusy(false);}
}

document.getElementById("jump").onclick=()=>document.getElementById("workspace").scrollIntoView();
document.getElementById("demo").onclick=launchDemo;
document.getElementById("results").onclick=event=>{if(event.target.closest(".demo-trigger"))launchDemo();};
function contextPayload(){return {system_exposure:document.getElementById("f-exposure").value,mission_impact:document.getElementById("f-mission").value,safety_impact:document.getElementById("f-safety").value,reachable:document.getElementById("f-reachable").checked||null,runtime_observed:document.getElementById("f-runtime").checked||null,context_sources:sources(document.getElementById("f-sources").value)};}
function resetForm(){editingTarget=null;document.getElementById("form-title").textContent="Add a target";document.getElementById("add").textContent="Add target";document.getElementById("cancel-edit").hidden=true;["f-name","f-url"].forEach(id=>{document.getElementById(id).disabled=false;document.getElementById(id).value="";});document.getElementById("f-sources").value="";["f-exposure","f-mission","f-safety"].forEach(id=>document.getElementById(id).value="unknown");["f-reachable","f-runtime"].forEach(id=>document.getElementById(id).checked=false);}
function editContext(target){editingTarget=target.id;document.getElementById("targetform").open=true;document.getElementById("form-title").textContent="Review SSVC context";document.getElementById("add").textContent="Save context";document.getElementById("cancel-edit").hidden=false;document.getElementById("f-name").value=target.name;document.getElementById("f-url").value=target.url||"";["f-name","f-url"].forEach(id=>document.getElementById(id).disabled=true);document.getElementById("f-exposure").value=target.system_exposure||"unknown";document.getElementById("f-mission").value=target.mission_impact||"unknown";document.getElementById("f-safety").value=target.safety_impact||"unknown";document.getElementById("f-reachable").checked=target.reachable===true;document.getElementById("f-runtime").checked=target.runtime_observed===true;document.getElementById("f-sources").value=(target.context_sources||[]).join(", ");document.getElementById("targetform").scrollIntoView({behavior:"smooth",block:"start"});}
document.getElementById("add").onclick=async()=>{
  const name=document.getElementById("f-name").value.trim();if(!editingTarget&&!name){notify("Give the target a system name.",true);return;}
  try{
    const wasEditing=editingTarget;if(editingTarget){await api("POST",`/api/targets/${editingTarget}/context`,contextPayload());RESULTS.delete(editingTarget);}else{await api("POST","/api/targets",{name,url:document.getElementById("f-url").value.trim(),...contextPayload()});}
    resetForm();await loadTargets();renderResults();notify(wasEditing?"SSVC context saved. Run the target again to apply it.":"Target added.");
  }catch(error){notify(error.message,true);}
};
document.getElementById("cancel-edit").onclick=resetForm;
document.getElementById("targetlist").onclick=async event=>{
  const button=event.target.closest("button");if(!button)return;
  const card=button.closest(".target"),id=card.dataset.id,action=button.dataset.action;
  if(action==="edit")editContext(TARGETS.find(target=>target.id===id));
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
