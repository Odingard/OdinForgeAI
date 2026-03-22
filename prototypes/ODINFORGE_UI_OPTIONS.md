# OdinForge AEV — UI Prototype Options

Three self-contained HTML files. Open any in a browser — no build step needed.
Each simulates a full engagement when you click "begin engagement".

---

## Which to pick

| Option | Best for |
|--------|----------|
| Option 1 — Three-panel console | Default operator view. Flexible layout. Shows everything. |
| Option 2 — Graph-first | Demo mode. Graph is the hero. Floating overlays stay out of the way. |
| Option 3 — Operator terminal | Technical audience. Live action feed reads like watching a real pentest. |

---

## How to use with VS Code Claude

Paste this prompt:

```
Read ODINFORGE_UI_OPTIONS.md in the prototypes/ directory.
For each ### FILE section, create that file at the specified path.
Use ACTION: CREATE for new files.
After creating all files, confirm each path exists.
```

---


---

### FILE: prototypes/option1-three-panel.html
ACTION: CREATE

Open in browser. Three resizable panels: surface map / breach chain / AI reasoning.
Layout toggle switches between graph-only, split, all-three, surface+graph.

```html
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>OdinForge — Option 1</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:monospace;font-size:12px;background:#0a0a0f;color:#e2e8f0;padding:16px}
.root{border:1px solid #1e293b;border-radius:8px;overflow:hidden;background:#0d1117;max-width:1100px;margin:0 auto}
.eng-bar{display:flex;align-items:center;gap:12px;padding:8px 14px;border-bottom:1px solid #1e293b;background:#111827}
.eng-label{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#475569}
.eng-target{font-size:11px;color:#60a5fa;flex:1;padding:0 8px}
.dot{width:7px;height:7px;border-radius:50%;background:#334155}
.dot.run{background:#22c55e;animation:blink 1.2s infinite}
.dot.done{background:#ef4444}.dot.rdy{background:#f59e0b}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.25}}
@keyframes fadein{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
@keyframes popin{from{opacity:0;transform:scale(.5)}to{opacity:1;transform:scale(1)}}
@keyframes slidein{from{opacity:0;transform:translateX(-5px)}to{opacity:1;transform:translateX(0)}}
.phase-bar{display:flex;border-bottom:1px solid #1e293b}
.ph{flex:1;padding:5px 2px;font-size:8px;text-transform:uppercase;letter-spacing:.04em;text-align:center;color:#475569;border-right:1px solid #1e293b;transition:all .3s}
.ph:last-child{border-right:none}.ph.act{color:#f59e0b;background:#1a1f2e}.ph.done{color:#22c55e}.ph.breach{color:#ef4444}
.stats-bar{display:flex;border-bottom:1px solid #1e293b}
.stat{flex:1;padding:6px 10px;border-right:1px solid #1e293b}.stat:last-child{border-right:none}
.stat-v{font-size:15px;font-weight:700}.stat-l{font-size:9px;text-transform:uppercase;letter-spacing:.06em;color:#475569}
.lay-bar{display:flex;align-items:center;gap:6px;padding:5px 10px;border-bottom:1px solid #1e293b;background:#111827}
.lay-label{font-size:9px;text-transform:uppercase;letter-spacing:.08em;color:#475569;margin-right:2px}
.lbtn{padding:2px 8px;font-size:9px;border:1px solid #1e293b;border-radius:4px;background:transparent;color:#64748b;cursor:pointer}
.lbtn.on{border-color:#3b82f6;color:#60a5fa}
.wrap{position:relative;min-height:380px}
.ov{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px;z-index:10;background:#0d1117;transition:opacity .4s}
.ov.gone{opacity:0;pointer-events:none}
.ov-title{font-size:11px;color:#64748b}.ov-target{font-size:12px;color:#60a5fa}.ov-meta{font-size:10px;color:#334155}
.go-btn{padding:8px 20px;font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;border:1px solid #dc2626;border-radius:4px;background:transparent;color:#ef4444;cursor:pointer}
.go-btn:hover{background:rgba(220,38,38,.1)}
.panels{display:flex;height:380px;overflow:hidden}
.panel{display:flex;flex-direction:column;border-right:1px solid #1e293b;overflow:hidden;min-width:0;transition:flex .3s}
.panel:last-child{border-right:none}.panel.off{flex:0!important;overflow:hidden}
.ph-hdr{display:flex;align-items:center;justify-content:space-between;padding:6px 10px;border-bottom:1px solid #1e293b;background:#111827;flex-shrink:0}
.ph-title{font-size:9px;text-transform:uppercase;letter-spacing:.1em;font-weight:700;color:#64748b}
.badge{font-size:8px;padding:1px 5px;border-radius:3px}
.b-blue{background:rgba(59,130,246,.15);color:#60a5fa;border:1px solid rgba(59,130,246,.25)}
.b-red{background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.25)}
.b-green{background:rgba(34,197,94,.15);color:#22c55e;border:1px solid rgba(34,197,94,.25)}
.ph-body{flex:1;overflow:hidden;position:relative}
.surf-list{padding:8px;display:flex;flex-direction:column;gap:4px;height:100%;overflow-y:auto}
.si{display:flex;align-items:flex-start;gap:6px;padding:5px 7px;border:1px solid #1e293b;border-radius:4px;animation:fadein .35s ease;animation-fill-mode:both}
.stag{font-size:8px;padding:1px 5px;border-radius:3px;font-weight:700;flex-shrink:0;margin-top:1px}
.t-stack{background:rgba(59,130,246,.15);color:#60a5fa}.t-cloud{background:rgba(245,158,11,.15);color:#f59e0b}
.t-cred{background:rgba(239,68,68,.15);color:#ef4444}.t-ep{background:rgba(34,197,94,.15);color:#22c55e}
.si-label{font-size:10px;color:#e2e8f0;line-height:1.4}.si-sub{font-size:9px;color:#475569;margin-top:1px}
.chain-body{width:100%;height:100%}#csvg{width:100%;height:100%}
.reason{padding:8px;height:100%;overflow-y:auto;display:flex;flex-direction:column;gap:5px}
.thought{padding:5px 8px;border-left:2px solid #1e293b;font-size:10px;line-height:1.6;color:#94a3b8;animation:slidein .3s ease;animation-fill-mode:both}
.thought.ok{border-color:#22c55e;color:#22c55e}.thought.warn{border-color:#f59e0b;color:#f59e0b}
.thought.crit{border-color:#ef4444;color:#ef4444}.thought.info{border-color:#3b82f6;color:#e2e8f0}
.t-ts{font-size:8px;color:#334155;margin-bottom:2px;text-transform:uppercase;letter-spacing:.05em}
</style></head><body>
<div class="root">
<div class="eng-bar">
  <span class="eng-label">OdinForge AEV</span>
  <span class="eng-target" id="etarget">— awaiting target —</span>
  <div class="dot rdy" id="sdot"></div>
  <span id="stxt" style="font-size:10px;color:#475569">ready</span>
</div>
<div class="phase-bar">
  <div class="ph" id="ph0">1 · app</div><div class="ph" id="ph1">2 · creds</div>
  <div class="ph" id="ph2">3 · iam</div><div class="ph" id="ph3">4 · k8s</div>
  <div class="ph" id="ph4">5 · lateral</div><div class="ph" id="ph5">6 · impact</div>
</div>
<div class="stats-bar">
  <div class="stat"><div class="stat-v" id="sf" style="color:#ef4444">0</div><div class="stat-l">findings</div></div>
  <div class="stat"><div class="stat-v" id="sc" style="color:#f59e0b">0</div><div class="stat-l">credentials</div></div>
  <div class="stat"><div class="stat-v" id="sp" style="color:#22c55e">0/6</div><div class="stat-l">phases</div></div>
  <div class="stat"><div class="stat-v" id="st" style="color:#64748b">00:00</div><div class="stat-l">elapsed</div></div>
  <div class="stat"><div class="stat-v" id="sg" style="color:#334155">—</div><div class="stat-l">risk grade</div></div>
</div>
<div class="lay-bar">
  <span class="lay-label">layout</span>
  <button class="lbtn" onclick="setL('chain',this)">graph</button>
  <button class="lbtn" onclick="setL('split',this)">graph + reasoning</button>
  <button class="lbtn on" onclick="setL('three',this)">all three</button>
  <button class="lbtn" onclick="setL('sc',this)">surface + graph</button>
</div>
<div class="wrap">
  <div class="ov" id="ov">
    <div class="ov-title">OdinForge AEV — engagement console</div>
    <div class="ov-target">target: https://target.acme.corp</div>
    <div class="ov-meta">profile: full-chain · mode: live · evidence: contract v2</div>
    <button class="go-btn" onclick="begin()">begin engagement</button>
  </div>
  <div class="panels" id="panels">
    <div class="panel" id="p-surf" style="flex:1">
      <div class="ph-hdr"><span class="ph-title">surface map</span><span class="badge b-blue" id="surf-ct">0 signals</span></div>
      <div class="ph-body"><div class="surf-list" id="surf-list"></div></div>
    </div>
    <div class="panel" id="p-chain" style="flex:1.3">
      <div class="ph-hdr"><span class="ph-title">live breach chain</span><span class="badge b-red" id="chain-badge">awaiting</span></div>
      <div class="ph-body chain-body">
        <svg id="csvg" viewBox="0 0 260 380" preserveAspectRatio="xMidYMid meet">
          <defs><marker id="ar" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round"/></marker></defs>
          <text id="idle-msg" x="130" y="192" text-anchor="middle" font-family="monospace" font-size="10" fill="#334155">chain initializing...</text>
        </svg>
      </div>
    </div>
    <div class="panel" id="p-reason" style="flex:1">
      <div class="ph-hdr"><span class="ph-title">ai reasoning</span><span class="badge b-green" id="rbadge">standby</span></div>
      <div class="ph-body"><div class="reason" id="rfeed"></div></div>
    </div>
  </div>
</div>
</div>
<script>
const phY=[35,95,155,215,275,335],cx=130;
let running=false,elapsed=0,tint=null,findings=0,creds=0,phases=0,surfN=0;
const L={chain:{s:false,c:true,r:false},split:{s:false,c:true,r:true},three:{s:true,c:true,r:true},sc:{s:true,c:true,r:false}};
function setL(n,btn){document.querySelectorAll('.lbtn').forEach(b=>b.classList.remove('on'));btn.classList.add('on');const l=L[n];document.getElementById('p-surf').classList.toggle('off',!l.s);document.getElementById('p-chain').classList.toggle('off',!l.c);document.getElementById('p-reason').classList.toggle('off',!l.r);}
function initSVG(){const s=document.getElementById('csvg');document.getElementById('idle-msg')?.remove();phY.forEach((y,i)=>{if(i<5){const ln=document.createElementNS('http://www.w3.org/2000/svg','line');ln.setAttribute('x1',cx);ln.setAttribute('y1',y+20);ln.setAttribute('x2',cx);ln.setAttribute('y2',phY[i+1]-20);ln.setAttribute('stroke','#1e293b');ln.setAttribute('stroke-width','1');ln.setAttribute('marker-end','url(#ar)');s.appendChild(ln);}const g=document.createElementNS('http://www.w3.org/2000/svg','g');g.id='pg'+i;g.style.opacity='.2';const c=document.createElementNS('http://www.w3.org/2000/svg','circle');c.setAttribute('cx',cx);c.setAttribute('cy',y);c.setAttribute('r','18');c.setAttribute('fill','#0d1117');c.setAttribute('stroke','#1e293b');c.setAttribute('stroke-width','1');c.id='pc'+i;const t=document.createElementNS('http://www.w3.org/2000/svg','text');t.setAttribute('x',cx);t.setAttribute('y',y);t.setAttribute('text-anchor','middle');t.setAttribute('dominant-baseline','central');t.setAttribute('font-size','11');t.setAttribute('font-family','monospace');t.setAttribute('fill','#334155');t.textContent=i+1;g.appendChild(c);g.appendChild(t);s.appendChild(g);});}
function actP(i){document.getElementById('pg'+i).style.opacity='1';document.getElementById('pg'+i).style.transition='opacity .4s';document.getElementById('pc'+i).setAttribute('stroke','#f59e0b');document.getElementById('pc'+i).setAttribute('stroke-width','2');document.getElementById('ph'+i).className='ph act';document.getElementById('chain-badge').textContent='phase '+(i+1)+' active';}
function doneP(i,b){const col=b?'#ef4444':'#22c55e';document.getElementById('pc'+i).setAttribute('stroke',col);document.getElementById('pc'+i).setAttribute('stroke-width','2');document.getElementById('ph'+i).className=b?'ph breach':'ph done';phases++;document.getElementById('sp').textContent=phases+'/6';if(phases===6){document.getElementById('sg').textContent='F';document.getElementById('sg').style.color='#ef4444';}}
function addN(ph,lbl,side,sev){const s=document.getElementById('csvg');const nx=side==='r'?cx+90:cx-90,ny=phY[ph],col=sev==='crit'?'#ef4444':'#f59e0b';const ln=document.createElementNS('http://www.w3.org/2000/svg','line');ln.setAttribute('x1',side==='r'?cx+18:cx-18);ln.setAttribute('y1',ny);ln.setAttribute('x2',side==='r'?nx-12:nx+12);ln.setAttribute('y2',ny);ln.setAttribute('stroke',col);ln.setAttribute('stroke-width','1');s.appendChild(ln);setTimeout(()=>{const g=document.createElementNS('http://www.w3.org/2000/svg','g');g.style.transformOrigin=nx+'px '+ny+'px';g.style.animation='popin .35s cubic-bezier(.34,1.56,.64,1) forwards';g.style.opacity='0';const c=document.createElementNS('http://www.w3.org/2000/svg','circle');c.setAttribute('cx',nx);c.setAttribute('cy',ny);c.setAttribute('r','13');c.setAttribute('fill','#0d1117');c.setAttribute('stroke',col);c.setAttribute('stroke-width','1.5');const t=document.createElementNS('http://www.w3.org/2000/svg','text');t.setAttribute('x',nx);t.setAttribute('y',ny);t.setAttribute('text-anchor','middle');t.setAttribute('dominant-baseline','central');t.setAttribute('font-size','7');t.setAttribute('font-family','monospace');t.setAttribute('fill',col);t.textContent=lbl;g.appendChild(c);g.appendChild(t);s.appendChild(g);findings++;document.getElementById('sf').textContent=findings;},500);}
function addSig(tag,tc,lbl,sub,d){setTimeout(()=>{const l=document.getElementById('surf-list');const el=document.createElement('div');el.className='si';el.innerHTML=`<span class="stag ${tc}">${tag}</span><div><div class="si-label">${lbl}</div><div class="si-sub">${sub}</div></div>`;l.appendChild(el);l.scrollTop=l.scrollHeight;surfN++;document.getElementById('surf-ct').textContent=surfN+' signals';},d);}
function addT(type,ts,txt,d){setTimeout(()=>{const f=document.getElementById('rfeed');const el=document.createElement('div');el.className='thought '+type;el.innerHTML=`<div class="t-ts">${ts}</div>${txt}`;f.appendChild(el);f.scrollTop=f.scrollHeight;document.getElementById('rbadge').textContent='live';},d);}
function begin(){if(running)return;running=true;document.getElementById('ov').classList.add('gone');document.getElementById('etarget').textContent='https://target.acme.corp';document.getElementById('sdot').className='dot run';document.getElementById('stxt').textContent='scanning';initSVG();elapsed=0;tint=setInterval(()=>{elapsed++;document.getElementById('st').textContent=String(Math.floor(elapsed/60)).padStart(2,'0')+':'+String(elapsed%60).padStart(2,'0');},1000);
[['STACK','t-stack','Node.js 20 + Express','X-Powered-By',0],['STACK','t-stack','React 18 SPA','JS bundle',300],['CLOUD','t-cloud','AWS us-east-1','EC2 IMDS',600],['STACK','t-stack','PostgreSQL 15','port 5432',900],['CLOUD','t-cloud','Kubernetes v1.28','kube-api :6443',1150],['EP','t-ep','47 endpoints','/api/users +45',1400],['CRED','t-cred','/.env exposed','HTTP 200',1600],['CLOUD','t-cloud','3 S3 buckets','1 public ACL',1850],['CRED','t-cred','JWT RS256','JWKS endpoint',2100]].forEach(([t,tc,l,s,d])=>addSig(t,tc,l,s,d));
[['info','00:03','Surface: 47 endpoints, 9 signals. SQLi testing /api/users/search.',3000],['info','00:04','Firing 12 SQLi variants against param q.',4200],['ok','00:05','SQLi confirmed — HTTP 200, 847 rows. EvidenceContract sealed.',5300],['info','00:06','Credential pattern in body. Pivoting to phase 2.',6000],['warn','00:07','/.env: DB_PASSWORD, AWS keys, JWT_SECRET extracted.',7200],['ok','00:08','AWS key confirmed via sts:GetCallerIdentity.',8200],['crit','00:09','sts:AssumeRole → AdministratorAccess. Cloud root in 9 min.',9200],['crit','00:11','K8s: privileged pod. Host filesystem confirmed.',10700],['crit','00:13','Lateral: 4 services via east-west pivot.',12200],['crit','00:14','2.3M records reachable. Blast radius: ORG. Grade: F.',13700]].forEach(([tp,ts,tx,d])=>addT(tp,ts,tx,d));
[[2800,()=>actP(0)],[5400,()=>addN(0,'SQLi','r','crit')],[6000,()=>doneP(0,true)],[6100,()=>actP(1)],[7300,()=>addN(1,'.env','l','crit')],[8200,()=>{addN(1,'AWS','r','crit');creds+=3;document.getElementById('sc').textContent=creds;}],[8400,()=>doneP(1,true)],[8500,()=>actP(2)],[9300,()=>addN(2,'IAM','l','crit')],[10000,()=>doneP(2,true)],[10100,()=>actP(3)],[10800,()=>addN(3,'K8s','r','crit')],[11200,()=>doneP(3,true)],[11300,()=>actP(4)],[12300,()=>addN(4,'pivot','l','high')],[13000,()=>doneP(4,true)],[13100,()=>actP(5)],[13800,()=>addN(5,'2.3M','r','crit')],[14600,()=>{doneP(5,true);clearInterval(tint);document.getElementById('sdot').className='dot done';document.getElementById('stxt').textContent='complete — grade F';document.getElementById('chain-badge').textContent='breach confirmed';document.getElementById('rbadge').textContent='complete';}]].forEach(([d,fn])=>setTimeout(fn,d));}
</script></body></html>
```

---

### FILE: prototypes/option2-graph-hero.html
ACTION: CREATE

Open in browser. The breach chain graph fills the screen.
Surface signals and reasoning float as compact overlays on the right.
Phase progress shown as a horizontal pip strip at the bottom.


```html
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>OdinForge — Option 2</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:monospace;font-size:12px;background:#0a0a0f;color:#e2e8f0;padding:16px}
.root{border:1px solid #1e293b;border-radius:8px;overflow:hidden;background:#0d1117;max-width:1100px;margin:0 auto;position:relative;height:560px}
.top-bar{display:flex;align-items:center;gap:12px;padding:8px 14px;border-bottom:1px solid #1e293b;background:#111827;position:relative;z-index:10}
.tb-brand{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#475569}
.tb-tgt{font-size:11px;color:#60a5fa;flex:1;padding:0 10px}
.tb-stats{display:flex;gap:16px}
.ts{display:flex;align-items:center;gap:5px;font-size:10px;color:#475569}
.ts-v{font-weight:700;font-size:12px}
.dot{width:6px;height:6px;border-radius:50%;background:#334155}
.dot.run{background:#22c55e;animation:blink 1.2s infinite}.dot.done{background:#ef4444}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.2}}
@keyframes popn{from{opacity:0;transform:scale(0)}to{opacity:1;transform:scale(1)}}
@keyframes drawedge{from{stroke-dashoffset:200}to{stroke-dashoffset:0}}
@keyframes floatin{from{opacity:0;transform:translateX(10px)}to{opacity:1;transform:translateX(0)}}
.canvas{position:absolute;top:40px;left:0;right:0;bottom:0}
#mg{width:100%;height:100%}
.overlay{position:absolute;top:50px;right:10px;width:195px;display:flex;flex-direction:column;gap:6px;z-index:5}
.ov-card{background:rgba(17,24,39,.92);border:1px solid #1e293b;border-radius:6px;padding:8px 10px;animation:floatin .4s ease}
.ov-card-t{font-size:8px;text-transform:uppercase;letter-spacing:.1em;color:#475569;margin-bottom:4px}
.surf-row{display:flex;align-items:center;gap:5px;padding:3px 0;border-bottom:1px solid #1e293b;font-size:9px}
.surf-row:last-child{border-bottom:none}
.pill{font-size:7px;padding:1px 4px;border-radius:2px;font-weight:700;flex-shrink:0}
.p-stack{background:rgba(59,130,246,.2);color:#60a5fa}.p-cloud{background:rgba(245,158,11,.2);color:#f59e0b}
.p-cred{background:rgba(239,68,68,.2);color:#ef4444}.p-ep{background:rgba(34,197,94,.2);color:#22c55e}
.thought{font-size:9px;line-height:1.5;padding:3px 0;border-bottom:1px solid #1e293b;color:#94a3b8}
.thought:last-child{border-bottom:none}.thought.ok{color:#22c55e}.thought.crit{color:#ef4444}.thought.warn{color:#f59e0b}
.pips{position:absolute;bottom:10px;left:10px;right:215px;display:flex;gap:4px;z-index:5}
.pip{flex:1;height:4px;border-radius:2px;background:#1e293b;transition:background .4s}
.pip.act{background:#f59e0b}.pip.done{background:#22c55e}.pip.breach{background:#ef4444}
.plbls{position:absolute;bottom:18px;left:10px;right:215px;display:flex;justify-content:space-between}
.pl{font-size:7px;text-transform:uppercase;letter-spacing:.05em;color:#475569;flex:1;text-align:center}
.pl.act{color:#f59e0b}.pl.done{color:#22c55e}.pl.breach{color:#ef4444}
.start-ov{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;z-index:20;background:#0d1117;transition:opacity .5s}
.start-ov.gone{opacity:0;pointer-events:none}
.so-sub{font-size:10px;color:#475569}.so-tgt{font-size:12px;color:#60a5fa}
.go{padding:9px 22px;font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;border:1px solid #dc2626;border-radius:4px;background:transparent;color:#ef4444;cursor:pointer}
.go:hover{background:rgba(220,38,38,.1)}
</style></head><body>
<div class="root">
<div class="top-bar">
  <span class="tb-brand">OdinForge AEV</span>
  <span class="tb-tgt" id="tbt">—</span>
  <div class="tb-stats">
    <div class="ts"><div class="dot" id="tdot"></div><span id="ttxt" style="text-transform:uppercase;letter-spacing:.06em">ready</span></div>
    <div class="ts"><span class="ts-v" id="tf" style="color:#ef4444">0</span>&nbsp;findings</div>
    <div class="ts"><span class="ts-v" id="tc" style="color:#f59e0b">0</span>&nbsp;creds</div>
    <div class="ts"><span class="ts-v" id="tt">00:00</span>&nbsp;elapsed</div>
    <div class="ts"><span class="ts-v" id="tg" style="color:#334155">—</span>&nbsp;grade</div>
  </div>
</div>
<div class="canvas">
  <svg id="mg" viewBox="0 0 600 500" preserveAspectRatio="xMidYMid meet">
    <defs><marker id="ar" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round"/></marker></defs>
    <text id="idle" x="210" y="250" text-anchor="middle" font-family="monospace" font-size="11" fill="#334155">chain initializing...</text>
  </svg>
</div>
<div class="overlay" id="overlay">
  <div class="ov-card" id="sig-card" style="display:none"><div class="ov-card-t">surface map</div><div id="sfeed"></div></div>
  <div class="ov-card" id="reason-card" style="display:none"><div class="ov-card-t">ai reasoning</div><div id="rfeed"></div></div>
</div>
<div class="plbls"><span class="pl" id="pl0">app</span><span class="pl" id="pl1">creds</span><span class="pl" id="pl2">iam</span><span class="pl" id="pl3">k8s</span><span class="pl" id="pl4">lateral</span><span class="pl" id="pl5">impact</span></div>
<div class="pips"><div class="pip" id="pp0"></div><div class="pip" id="pp1"></div><div class="pip" id="pp2"></div><div class="pip" id="pp3"></div><div class="pip" id="pp4"></div><div class="pip" id="pp5"></div></div>
<div class="start-ov" id="so">
  <div class="so-sub">OdinForge AEV — engagement console</div>
  <div class="so-tgt">https://target.acme.corp</div>
  <div class="so-sub" style="font-size:9px">graph-first · full-chain · live evidence</div>
  <button class="go" onclick="begin()">begin engagement</button>
</div>
</div>
<script>
const SX=200,PY=[50,130,210,290,370,445];
let e=0,ti=null,f=0,cr=0,ph=0;
function begin(){
  document.getElementById('so').classList.add('gone');
  document.getElementById('tbt').textContent='https://target.acme.corp';
  document.getElementById('tdot').className='dot run';document.getElementById('ttxt').textContent='scanning';
  document.getElementById('sig-card').style.display='block';document.getElementById('reason-card').style.display='block';
  e=0;ti=setInterval(()=>{e++;document.getElementById('tt').textContent=String(Math.floor(e/60)).padStart(2,'0')+':'+String(e%60).padStart(2,'0');},1000);
  init();run();
}
function init(){
  const s=document.getElementById('mg');document.getElementById('idle')?.remove();
  const L=['App\nCompromise','Cred\nExtract','Cloud IAM','K8s\nBreakout','Lateral\nMove','Impact'];
  PY.forEach((y,i)=>{
    if(i<5){const ln=document.createElementNS('http://www.w3.org/2000/svg','line');ln.setAttribute('x1',SX);ln.setAttribute('y1',y+22);ln.setAttribute('x2',SX);ln.setAttribute('y2',PY[i+1]-22);ln.setAttribute('stroke','#1e293b');ln.setAttribute('stroke-width','1');ln.setAttribute('marker-end','url(#ar)');s.appendChild(ln);}
    const g=document.createElementNS('http://www.w3.org/2000/svg','g');g.id='sg'+i;g.style.opacity='.15';
    const c=document.createElementNS('http://www.w3.org/2000/svg','circle');c.setAttribute('cx',SX);c.setAttribute('cy',y);c.setAttribute('r','20');c.setAttribute('fill','#0d1117');c.setAttribute('stroke','#1e293b');c.setAttribute('stroke-width','1');c.id='sc'+i;
    const t=document.createElementNS('http://www.w3.org/2000/svg','text');t.setAttribute('x',SX);t.setAttribute('y',y);t.setAttribute('text-anchor','middle');t.setAttribute('dominant-baseline','central');t.setAttribute('font-size','11');t.setAttribute('font-family','monospace');t.setAttribute('fill','#334155');t.textContent=i+1;
    L[i].split('\n').forEach((lb,li)=>{const tl=document.createElementNS('http://www.w3.org/2000/svg','text');tl.setAttribute('x',SX-28);tl.setAttribute('y',y+(li-Math.floor(L[i].split('\n').length/2))*11);tl.setAttribute('text-anchor','end');tl.setAttribute('font-size','8');tl.setAttribute('font-family','monospace');tl.setAttribute('fill','#334155');tl.textContent=lb;g.appendChild(tl);});
    g.appendChild(c);g.appendChild(t);s.appendChild(g);
  });
}
function ap(i){document.getElementById('sg'+i).style.opacity='1';document.getElementById('sg'+i).style.transition='opacity .4s';document.getElementById('sc'+i).setAttribute('stroke','#f59e0b');document.getElementById('sc'+i).setAttribute('stroke-width','2');document.getElementById('pp'+i).className='pip act';document.getElementById('pl'+i).className='pl act';}
function dp(i,b){const col=b?'#ef4444':'#22c55e';document.getElementById('sc'+i).setAttribute('stroke',col);document.getElementById('pp'+i).className='pip '+(b?'breach':'done');document.getElementById('pl'+i).className='pl '+(b?'breach':'done');ph++;if(ph===6){document.getElementById('tg').textContent='F';document.getElementById('tg').style.color='#ef4444';}}
function addBN(pi,lbl,xOff,sev){
  const s=document.getElementById('mg');const px=SX,py=PY[pi],nx=px+xOff,ny=py,col=sev==='crit'?'#ef4444':'#f59e0b';
  const ln=document.createElementNS('http://www.w3.org/2000/svg','line');ln.setAttribute('x1',xOff>0?px+20:px-20);ln.setAttribute('y1',py);ln.setAttribute('x2',xOff>0?nx-12:nx+12);ln.setAttribute('y2',ny);ln.setAttribute('stroke',col);ln.setAttribute('stroke-width','1');ln.setAttribute('stroke-dasharray','80');ln.setAttribute('stroke-dashoffset','80');ln.style.animation='drawedge .5s ease forwards';s.appendChild(ln);
  setTimeout(()=>{const g=document.createElementNS('http://www.w3.org/2000/svg','g');g.style.transformOrigin=nx+'px '+ny+'px';g.style.animation='popn .35s cubic-bezier(.34,1.56,.64,1) forwards';g.style.opacity='0';const c=document.createElementNS('http://www.w3.org/2000/svg','circle');c.setAttribute('cx',nx);c.setAttribute('cy',ny);c.setAttribute('r','14');c.setAttribute('fill','#0d1117');c.setAttribute('stroke',col);c.setAttribute('stroke-width','1.5');const t=document.createElementNS('http://www.w3.org/2000/svg','text');t.setAttribute('x',nx);t.setAttribute('y',ny);t.setAttribute('text-anchor','middle');t.setAttribute('dominant-baseline','central');t.setAttribute('font-size','7');t.setAttribute('font-family','monospace');t.setAttribute('fill',col);t.textContent=lbl;g.appendChild(c);g.appendChild(t);s.appendChild(g);f++;document.getElementById('tf').textContent=f;},500);
}
function addS(tag,tc,lbl,d){setTimeout(()=>{const fd=document.getElementById('sfeed');const rows=fd.querySelectorAll('.surf-row');if(rows.length>=5)rows[0].remove();const p=document.createElement('div');p.className='surf-row';p.innerHTML=`<span class="pill ${tc}">${tag}</span><span style="color:#94a3b8">${lbl}</span>`;fd.appendChild(p);},d);}
function addR(type,txt,d){setTimeout(()=>{const fd=document.getElementById('rfeed');const rows=fd.querySelectorAll('.thought');if(rows.length>=4)rows[0].remove();const p=document.createElement('div');p.className='thought '+type;p.textContent=txt;fd.appendChild(p);},d);}
function run(){
  [['STACK','p-stack','Node.js + Express',600],['CLOUD','p-cloud','AWS us-east-1',900],['STACK','p-stack','PostgreSQL 15',1200],['CLOUD','p-cloud','Kubernetes v1.28',1500],['EP','p-ep','47 endpoints',1800],['CRED','p-cred','/.env exposed',2100],['CLOUD','p-cloud','3 S3 buckets',2400]].forEach(([t,tc,l,d])=>addS(t,tc,l,d));
  [['','SQLi firing on /api/users/search...',3200],['ok','SQLi confirmed. EvidenceContract sealed.',5200],['','Credential pattern detected. Pivoting.',6100],['warn','/.env: DB_PASSWORD, AWS keys extracted.',7300],['ok','AWS sts:GetCallerIdentity confirmed.',8300],['crit','AssumeRole → AdministratorAccess.',9300],['crit','K8s: container escape confirmed.',10800],['crit','Lateral: 4 services reached.',12300],['crit','2.3M records. Grade: F.',13800]].forEach(([tp,tx,d])=>addR(tp,tx,d));
  [[2800,()=>ap(0)],[5300,()=>addBN(0,'SQLi',80,'crit')],[6000,()=>{dp(0,true);ap(1);}],[7400,()=>addBN(1,'.env',-80,'crit')],[8400,()=>{addBN(1,'AWS',80,'crit');cr+=3;document.getElementById('tc').textContent=cr;}],[8600,()=>{dp(1,true);ap(2);}],[9400,()=>addBN(2,'IAM',-80,'crit')],[10200,()=>{dp(2,true);ap(3);}],[11000,()=>addBN(3,'K8s',80,'crit')],[11500,()=>{dp(3,true);ap(4);}],[12500,()=>addBN(4,'pivot',-80,'high')],[13300,()=>{dp(4,true);ap(5);}],[14000,()=>addBN(5,'2.3M',80,'crit')],[14900,()=>{dp(5,true);clearInterval(ti);document.getElementById('tdot').className='dot done';document.getElementById('ttxt').textContent='breach confirmed';}]].forEach(([d,fn])=>setTimeout(fn,d));
}
</script></body></html>
```

---

### FILE: prototypes/option3-operator-terminal.html
ACTION: CREATE

Open in browser. Top half is a live terminal-style action feed showing every agent decision.
Bottom half is the breach chain building in real time.
Feels like watching an actual pentest operator work.

```html
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>OdinForge — Option 3</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:monospace;font-size:12px;background:#0a0a0f;color:#e2e8f0;padding:16px}
.root{border:1px solid #1e293b;border-radius:8px;overflow:hidden;background:#0d1117;max-width:1100px;margin:0 auto}
.top{display:flex;align-items:center;gap:10px;padding:7px 12px;border-bottom:1px solid #1e293b;background:#111827}
.brand{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#475569}
.tgt{font-size:10px;color:#60a5fa;flex:1;padding:0 8px}
.stats{display:flex;gap:14px}
.st{font-size:9px;color:#475569}.st-v{font-weight:700;font-family:monospace}
.chip{display:flex;align-items:center;gap:5px;padding:2px 8px;border-radius:3px;border:1px solid #1e293b;font-size:9px;text-transform:uppercase;letter-spacing:.07em;color:#475569}
.dot{width:5px;height:5px;border-radius:50%;background:#334155}
.dot.run{background:#22c55e;animation:blink 1.2s infinite}.dot.done{background:#ef4444}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.2}}
@keyframes typerow{from{opacity:0}to{opacity:1}}
@keyframes popn{from{opacity:0;transform:scale(0)}to{opacity:1;transform:scale(1)}}
.t-half{height:240px;border-bottom:1px solid #1e293b;display:flex;flex-direction:column}
.t-hdr{display:flex;align-items:center;gap:8px;padding:5px 10px;border-bottom:1px solid #1e293b;background:#111827;flex-shrink:0}
.t-hdr-t{font-size:8px;text-transform:uppercase;letter-spacing:.1em;color:#475569}
.t-pbadge{font-size:8px;padding:1px 6px;border-radius:3px;background:rgba(245,158,11,.15);color:#f59e0b;display:none}
.t-body{flex:1;overflow-y:auto;padding:8px 10px;display:flex;flex-direction:column;gap:2px}
.trow{display:flex;gap:8px;font-size:10px;line-height:1.5;animation:typerow .15s ease;animation-fill-mode:both}
.trow-ts{color:#334155;flex-shrink:0;font-size:9px;margin-top:1px}
.trow-a{flex-shrink:0;font-size:8px;padding:1px 4px;border-radius:2px;font-weight:700;margin-top:2px}
.a-exploit{background:rgba(239,68,68,.15);color:#ef4444}.a-recon{background:rgba(59,130,246,.15);color:#60a5fa}
.a-cloud{background:rgba(245,158,11,.15);color:#f59e0b}.a-lateral{background:rgba(34,197,94,.15);color:#22c55e}
.a-sys{background:#1e293b;color:#64748b}
.trow-m{color:#e2e8f0;flex:1}.trow-m.ok{color:#22c55e}.trow-m.crit{color:#ef4444}.trow-m.warn{color:#f59e0b}.trow-m.dim{color:#475569}
.cursor{display:inline-block;width:7px;height:11px;background:#334155;animation:bc .8s step-end infinite;vertical-align:middle}
@keyframes bc{0%,100%{opacity:1}50%{opacity:0}}
.c-half{height:210px;display:flex;flex-direction:column}
.c-hdr{display:flex;align-items:center;gap:8px;padding:5px 10px;border-bottom:1px solid #1e293b;background:#111827;flex-shrink:0}
.c-hdr-t{font-size:8px;text-transform:uppercase;letter-spacing:.1em;color:#475569}
.c-stats{display:flex;gap:14px;margin-left:auto}
.cs{font-size:9px;color:#475569}.cs-v{font-weight:700}
.c-body{flex:1;overflow:hidden}#csvg{width:100%;height:100%}
.start-ov{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px;z-index:10;background:#0d1117;transition:opacity .5s;border-radius:8px}
.start-ov.gone{opacity:0;pointer-events:none}
.so-l{font-size:9px;text-transform:uppercase;letter-spacing:.1em;color:#475569}.so-t{font-size:12px;color:#60a5fa}
.go{padding:7px 18px;font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;border:1px solid #dc2626;border-radius:4px;background:transparent;color:#ef4444;cursor:pointer}
.go:hover{background:rgba(220,38,38,.1)}
</style></head><body>
<div class="root" style="position:relative">
<div class="top">
  <span class="brand">OdinForge AEV</span>
  <span class="tgt" id="tgt">—</span>
  <div class="stats">
    <div class="st"><span class="cs-v" id="sf" style="color:#ef4444">0</span> findings</div>
    <div class="st"><span class="cs-v" id="scr" style="color:#f59e0b">0</span> creds</div>
    <div class="st"><span class="cs-v" id="sel">00:00</span> elapsed</div>
    <div class="st"><span class="cs-v" id="sgr" style="color:#334155">—</span> grade</div>
  </div>
  <div class="chip" id="chip"><div class="dot" id="sd"></div><span id="stxt">ready</span></div>
</div>
<div class="t-half">
  <div class="t-hdr">
    <span class="t-hdr-t">live action feed</span>
    <span class="t-pbadge" id="tpb">phase 1</span>
    <span style="font-size:8px;color:#334155;margin-left:auto" id="act"></span>
  </div>
  <div class="t-body" id="tbody">
    <div class="trow"><span class="trow-ts"></span><span class="trow-a a-sys">SYS</span><span class="trow-m dim">awaiting engagement start...</span></div>
    <div class="trow"><span class="trow-ts"></span><span class="trow-m dim"><span class="cursor"></span></span></div>
  </div>
</div>
<div class="c-half">
  <div class="c-hdr">
    <span class="c-hdr-t">breach chain</span>
    <div class="c-stats">
      <div class="cs">phases: <span class="cs-v" id="phct">0/6</span></div>
      <div class="cs">nodes: <span class="cs-v" id="ndct">0</span></div>
      <div class="cs">risk: <span class="cs-v" id="rsk" style="color:#334155">—</span></div>
    </div>
  </div>
  <div class="c-body">
    <svg id="csvg" viewBox="0 0 750 195" preserveAspectRatio="xMidYMid meet">
      <defs><marker id="ar" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round"/></marker></defs>
      <text id="idle" x="375" y="97" text-anchor="middle" font-family="monospace" font-size="10" fill="#334155">chain initializing...</text>
    </svg>
  </div>
</div>
<div class="start-ov" id="so">
  <div class="so-l">OdinForge AEV — operator console</div>
  <div class="so-t">https://target.acme.corp</div>
  <div class="so-l" style="font-size:8px">terminal mode · full-chain · live evidence</div>
  <button class="go" onclick="begin()">begin engagement</button>
</div>
</div>
<script>
let e=0,ti=null,f=0,cr=0,ph=0,nd=0;
const PX=[60,170,280,390,500,610],SY1=70,SY2=135;
function addRow(agent,aClass,msg,mClass,ts,delay){
  setTimeout(()=>{
    const body=document.getElementById('tbody');
    body.querySelector('.cursor')?.closest('.trow')?.remove();
    const row=document.createElement('div');row.className='trow';row.style.animationDelay='0ms';
    row.innerHTML=`<span class="trow-ts">${ts}</span><span class="trow-a ${aClass}">${agent}</span><span class="trow-m ${mClass}">${msg}</span>`;
    body.appendChild(row);
    const cur=document.createElement('div');cur.className='trow';
    cur.innerHTML=`<span class="trow-ts"></span><span class="trow-m dim"><span class="cursor"></span></span>`;
    body.appendChild(cur);body.scrollTop=body.scrollHeight;
  },delay);
}
function initChain(){
  const s=document.getElementById('csvg');document.getElementById('idle')?.remove();
  const L=['app','creds','iam','k8s','lateral','impact'];
  PX.forEach((x,i)=>{
    if(i<5){const ln=document.createElementNS('http://www.w3.org/2000/svg','line');ln.setAttribute('x1',x+20);ln.setAttribute('y1',SY1);ln.setAttribute('x2',PX[i+1]-20);ln.setAttribute('y2',SY1);ln.setAttribute('stroke','#1e293b');ln.setAttribute('stroke-width','1');ln.setAttribute('marker-end','url(#ar)');s.appendChild(ln);}
    const g=document.createElementNS('http://www.w3.org/2000/svg','g');g.id='g'+i;g.style.opacity='.15';
    const c=document.createElementNS('http://www.w3.org/2000/svg','circle');c.setAttribute('cx',x);c.setAttribute('cy',SY1);c.setAttribute('r','18');c.setAttribute('fill','#0d1117');c.setAttribute('stroke','#1e293b');c.setAttribute('stroke-width','1');c.id='ci'+i;
    const t=document.createElementNS('http://www.w3.org/2000/svg','text');t.setAttribute('x',x);t.setAttribute('y',SY1);t.setAttribute('text-anchor','middle');t.setAttribute('dominant-baseline','central');t.setAttribute('font-size','9');t.setAttribute('font-family','monospace');t.setAttribute('fill','#334155');t.textContent=i+1;
    const tl=document.createElementNS('http://www.w3.org/2000/svg','text');tl.setAttribute('x',x);tl.setAttribute('y',SY1+28);tl.setAttribute('text-anchor','middle');tl.setAttribute('font-size','7');tl.setAttribute('font-family','monospace');tl.setAttribute('fill','#334155');tl.textContent=L[i];
    g.appendChild(c);g.appendChild(t);g.appendChild(tl);s.appendChild(g);
  });
}
function ap(i){document.getElementById('g'+i).style.opacity='1';document.getElementById('g'+i).style.transition='opacity .4s';document.getElementById('ci'+i).setAttribute('stroke','#f59e0b');document.getElementById('ci'+i).setAttribute('stroke-width','2');document.getElementById('tpb').textContent='phase '+(i+1);document.getElementById('tpb').style.display='block';}
function dp(i,b){const col=b?'#ef4444':'#22c55e';document.getElementById('ci'+i).setAttribute('stroke',col);document.getElementById('ci'+i).setAttribute('stroke-width','2');ph++;document.getElementById('phct').textContent=ph+'/6';if(ph===6){document.getElementById('sgr').textContent='F';document.getElementById('sgr').style.color='#ef4444';document.getElementById('rsk').textContent='F';document.getElementById('rsk').style.color='#ef4444';}}
function addN(pi,lbl,row,sev){
  const s=document.getElementById('csvg');const px=PX[pi],py=row===1?SY1:SY2,col=sev==='crit'?'#ef4444':'#f59e0b';
  if(row===2){const ln=document.createElementNS('http://www.w3.org/2000/svg','line');ln.setAttribute('x1',px);ln.setAttribute('y1',SY1+18);ln.setAttribute('x2',px);ln.setAttribute('y2',SY2-12);ln.setAttribute('stroke',col);ln.setAttribute('stroke-width','1');s.appendChild(ln);}
  const g=document.createElementNS('http://www.w3.org/2000/svg','g');g.style.transformOrigin=px+'px '+py+'px';g.style.animation='popn .35s cubic-bezier(.34,1.56,.64,1) forwards';g.style.opacity='0';
  const c=document.createElementNS('http://www.w3.org/2000/svg','circle');c.setAttribute('cx',px);c.setAttribute('cy',py);c.setAttribute('r','12');c.setAttribute('fill','#0d1117');c.setAttribute('stroke',col);c.setAttribute('stroke-width','1.5');
  const t=document.createElementNS('http://www.w3.org/2000/svg','text');t.setAttribute('x',px);t.setAttribute('y',py);t.setAttribute('text-anchor','middle');t.setAttribute('dominant-baseline','central');t.setAttribute('font-size','6');t.setAttribute('font-family','monospace');t.setAttribute('fill',col);t.textContent=lbl;
  g.appendChild(c);g.appendChild(t);s.appendChild(g);f++;nd++;document.getElementById('sf').textContent=f;document.getElementById('ndct').textContent=nd;
}
function begin(){
  document.getElementById('so').classList.add('gone');document.getElementById('tgt').textContent='https://target.acme.corp';document.getElementById('sd').className='dot run';document.getElementById('stxt').textContent='scanning';document.getElementById('act').textContent='50 concurrent agents';
  e=0;ti=setInterval(()=>{e++;document.getElementById('sel').textContent=String(Math.floor(e/60)).padStart(2,'0')+':'+String(e%60).padStart(2,'0');},1000);
  initChain();
  [['SYS','a-sys','engagement started — target: https://target.acme.corp','dim','00:00',100],['RECON','a-recon','crawling robots.txt and sitemap.xml...','dim','00:01',800],['RECON','a-recon','47 endpoints discovered across 3 API prefixes','ok','00:02',1600],['RECON','a-recon','tech: Node.js 20, Express 4, React 18','dim','00:02',2200],['RECON','a-recon','cloud signals: AWS us-east-1, Kubernetes v1.28','warn','00:03',2800],['RECON','a-recon','/.env returning HTTP 200 — no auth required','crit','00:03',3200],['EXPLOIT','a-exploit','dispatching 12 SQLi variants → /api/users/search?q=','dim','00:04',3800],['EXPLOIT','a-exploit','union-based SQLi — HTTP 200, 847 rows returned','ok','00:05',5000],['EXPLOIT','a-exploit','EvidenceContract sealed: statusCode=200, rows=847','ok','00:05',5400],['EXPLOIT','a-exploit','credential pattern in response body','warn','00:06',6000],['EXPLOIT','a-exploit','/.env: DB_PASSWORD, AWS_SECRET_ACCESS_KEY, JWT_SECRET','crit','00:07',7000],['CLOUD','a-cloud','AWS sts:GetCallerIdentity → account 123456789012','ok','00:08',8000],['CLOUD','a-cloud','sts:AssumeRole → AdministratorAccess CONFIRMED','crit','00:09',9000],['CLOUD','a-cloud','K8s: privileged pod deployed on cluster','crit','00:10',10200],['CLOUD','a-cloud','container escape — host filesystem read confirmed','crit','00:11',10800],['LATERAL','a-lateral','east-west scan: redis:6379, postgres:5432 reachable','warn','00:12',11800],['LATERAL','a-lateral','pivot confirmed: 4 internal services accessible','crit','00:13',12800],['SYS','a-sys','impact: 2.3M records accessible — blast radius: ORGANIZATION','crit','00:14',13800],['SYS','a-sys','risk grade: F · sealing engagement package...','crit','00:15',14600]].forEach(r=>addRow(...r));
  [[2600,()=>ap(0)],[5200,()=>addN(0,'SQLi',2,'crit')],[6100,()=>{dp(0,true);ap(1);}],[7200,()=>addN(1,'.env',2,'crit')],[8300,()=>{addN(1,'AWS',2,'crit');cr+=3;document.getElementById('scr').textContent=cr;}],[8600,()=>{dp(1,true);ap(2);}],[9200,()=>addN(2,'IAM',2,'crit')],[10100,()=>{dp(2,true);ap(3);}],[10900,()=>addN(3,'K8s',2,'crit')],[11400,()=>{dp(3,true);ap(4);}],[12400,()=>addN(4,'pivot',2,'high')],[13200,()=>{dp(4,true);ap(5);}],[13900,()=>addN(5,'2.3M',2,'crit')],[14800,()=>{dp(5,true);clearInterval(ti);document.getElementById('sd').className='dot done';document.getElementById('stxt').textContent='breach confirmed';}]].forEach(([d,fn])=>setTimeout(fn,d));
}
</script></body></html>
```
