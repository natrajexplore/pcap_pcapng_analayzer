/* PacketLens Studio: library, capture replay, simulator and live capture views. */
(function(){
"use strict";
const $ = (s, r=document) => r.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const view = $("#view");
const api = {
  async get(path){ const r = await fetch(path); const j = await r.json(); if(!r.ok) throw new Error(j.error||r.statusText); return j; },
  async post(path, body, raw=false){
    const r = await fetch(path, {method:"POST", headers:{"X-PacketLens":"1", "Content-Type": raw?"application/octet-stream":"application/json"},
                                 body: raw ? body : JSON.stringify(body||{})});
    const j = await r.json(); if(!r.ok) throw new Error(j.error||r.statusText); return j; }
};
function toast(msg, ms=4000){ const t = $("#toast"); t.textContent = msg; t.style.display = "block"; clearTimeout(toast.h); toast.h = setTimeout(()=>t.style.display="none", ms); }
const sev = s => `<span class="sev ${esc(s)}">${esc(s)}</span>`;
const fmtT = s => s==null ? "—" : s >= 60 ? `${Math.floor(s/60)}m ${(s%60).toFixed(1)}s` : s >= 1 ? s.toFixed(2)+" s" : (s*1000).toFixed(1)+" ms";
const healthColor = h => h >= 85 ? "var(--lime)" : h >= 60 ? "var(--amber)" : h >= 35 ? "#ff7a4b" : "var(--red)";
function ring(h){ const r = 20, c = 2*Math.PI*r, k = Math.max(0, Math.min(100, h ?? 0))/100;
  return `<svg class="ring" viewBox="0 0 48 48" role="img" aria-label="health ${h ?? "not analyzed"}"><circle cx="24" cy="24" r="${r}" fill="none" stroke="rgba(120,160,255,.15)" stroke-width="4"/>
    ${h==null?"":`<circle cx="24" cy="24" r="${r}" fill="none" stroke="${healthColor(h)}" stroke-width="4" stroke-linecap="round" stroke-dasharray="${c*k} ${c}" transform="rotate(-90 24 24)" style="filter:drop-shadow(0 0 4px ${healthColor(h)})"/>`}
    <text x="24" y="28" text-anchor="middle">${h==null?"…":h}</text></svg>`; }

const fmtB = n => n==null ? "—" : n >= 1e9 ? (n/1e9).toFixed(2)+" GB" : n >= 1e6 ? (n/1e6).toFixed(2)+" MB" : n >= 1e3 ? (n/1e3).toFixed(1)+" kB" : n+" B";
const store = (k, v) => { try{ if(v === undefined) return JSON.parse(localStorage.getItem(k)); localStorage.setItem(k, JSON.stringify(v)); }catch(e){ return null; } };

/* skeleton placeholders and empty / error states */
function skeleton(kind="page"){
  const lines = n => Array.from({length:n}, (_,i)=>`<div class="sk sk-line" style="width:${92 - i*9 % 40}%"></div>`).join("");
  if(kind === "library") return `<div class="sk sk-title"></div><div class="libgrid">${Array.from({length:6},()=>`<div class="panel">${lines(5)}</div>`).join("")}</div>`;
  return `<div class="sk sk-title"></div><div class="sk-grid">${Array.from({length:5},()=>'<div class="sk sk-tile"></div>').join("")}</div>
    <div class="studio"><div class="sk sk-block"></div><div class="panel">${lines(7)}</div></div>`;
}
function state({icon="◌", title, msg="", tone="var(--cyan)", actions=[]}){
  return `<div class="panel state" style="--c:${tone}" role="${tone==="var(--red)"?"alert":"status"}"><div class="ic" aria-hidden="true">${icon}</div><h2>${esc(title)}</h2>
    ${msg?`<p>${esc(msg)}</p>`:""}<div class="row">${actions.map((a,i)=>a.href?`<a class="btn ${i?"ghost":""}" href="${esc(a.href)}">${esc(a.label)}</a>`
      :`<button class="${i?"ghost":""}" data-act="${i}">${esc(a.label)}</button>`).join("")}</div></div>`;
}
function showState(el, opts){ el.innerHTML = state(opts); (opts.actions||[]).forEach((a,i)=>{ const b = el.querySelector(`[data-act="${i}"]`); if(b) b.onclick = a.onclick; }); }
const errorState = (el, e) => showState(el, {icon:"⚠", tone:"var(--red)", title:"Something went wrong", msg:e.message||String(e),
  actions:[{label:"Retry", onclick:()=>route()}, {label:"Back to library", href:"#/library"}]});

/* hand a packet number / display filter to the Analyze view */
let handoff = null;
function openPackets(id, opts={}){ handoff = {id, ...opts}; const h = "#/analyze/"+encodeURIComponent(id); if(location.hash === h) route(); else location.hash = h; }
function takeHandoff(id){ const h = handoff; handoff = null; return h && h.id === id ? h : null; }

/* ------------------------------------------------------- findings panel */
const SEVS = ["critical","high","medium","low","info"];
const SEVC = {critical:"var(--red)", high:"#ff7a4b", medium:"var(--amber)", low:"var(--cyan)", info:"var(--muted)"};
function findingsPanel(el, d, {id, protocols=null, compact=false}={}){
  const keep = f => !protocols || protocols.has(f.protocol);
  const all = d.findings.filter(keep), rcs = protocols ? d.root_causes.filter(r=>r.evidence.some(u=>all.some(f=>f.uid===u))) : d.root_causes;
  const S = {q:"", sev:new Set(store("pl-fsev") || SEVS), group:store("pl-fgroup") || "category"};
  const pk = list => list && list.length ? `<div class="pk-chips">${list.slice(0, compact?12:30).map(n=>`<button data-no="${n}" title="Show packet ${n} in Analyze">#${n}</button>`).join("")}</div>` : "";
  el.innerHTML = `<div class="fp-bar"><input type="search" class="fp-q" placeholder="Search findings…" aria-label="Search findings">
      <select class="fp-g" aria-label="Group findings by"><option value="category">Group: category</option><option value="protocol">Group: protocol</option><option value="none">No grouping</option></select></div>
    <div class="fp-bar fp-sev" role="group" aria-label="Severity filter">${SEVS.map(s=>`<button class="chip-btn" data-s="${s}" style="--c:${SEVC[s]}" aria-pressed="${S.sev.has(s)}">${s} <b>${all.filter(f=>f.severity===s).length + rcs.filter(r=>r.severity===s).length}</b></button>`).join("")}</div>
    <div class="fp-out"></div>`;
  const out = el.querySelector(".fp-out");
  el.querySelector(".fp-g").value = S.group;
  const rcHTML = r => `<details class="fd rc" style="--c:${SEVC[r.severity]}"><summary>${sev(r.severity)}<span class="t">${esc(r.title)}</span><span class="chip">${Math.round(r.confidence*100)}%</span>
      <span class="m">Root cause · fault domain: ${esc(r.fault_domain||"—")}</span></summary><div class="body"><p><b>${esc(r.verdict)}</b></p><p class="muted">${esc(r.narrative)}</p>
      ${r.chain.length?`<h4>Chain of events</h4><ol class="chain">${r.chain.map(s=>`<li><span class="tm">${s.t==null?"":"t="+s.t.toFixed(3)+"s"}</span>${s.no?`<button class="lnk" data-no="${s.no}">#${s.no}</button> `:""}<span class="chip">${esc(s.layer)}</span>${esc(s.text)}</li>`).join("")}</ol>`:""}
      ${r.remediation.length?`<h4>Fix</h4><ul>${r.remediation.map(x=>`<li>${esc(x)}</li>`).join("")}</ul>`:""}
      ${!compact&&Object.keys(r.perspectives||{}).length?`<h4>Perspectives</h4><div class="persp">${Object.entries(r.perspectives).map(([k,v])=>`<b>${esc(k)}</b><span>${esc(v)}</span>`).join("")}</div>`:""}</div></details>`;
  const fHTML = f => `<details class="fd"><summary>${sev(f.severity)}<span class="t">${esc(f.title)}</span><span class="chip">${esc(f.protocol)}${f.count>1?" ×"+f.count:""}</span>
      <span class="m">${esc(f.summary.length>160?f.summary.slice(0,160)+"…":f.summary)}</span></summary><div class="body"><p>${esc(f.summary)}</p>
      ${f.causes.length?`<h4>Likely causes</h4><ul>${f.causes.slice(0,compact?3:6).map(x=>`<li>${esc(x)}</li>`).join("")}</ul>`:""}
      ${f.remediation.length?`<h4>Fix</h4><ul>${f.remediation.slice(0,compact?2:5).map(x=>`<li>${esc(x)}</li>`).join("")}</ul>`:""}
      ${!compact&&Object.keys(f.perspectives||{}).length?`<h4>Perspectives</h4><div class="persp">${Object.entries(f.perspectives).map(([k,v])=>`<b>${esc(k)}</b><span>${esc(v)}</span>`).join("")}</div>`:""}
      ${f.filter?`<h4>Display filter</h4><code class="flt">${esc(f.filter)}</code> ${f.filter_ok?`<button class="lnk" data-filter="${esc(f.filter)}">Apply in Analyze</button>`
        :`<button class="lnk" data-copy="${esc(f.filter)}" title="Wireshark syntax the built-in filter engine does not support">Copy for Wireshark</button>`}`:""}
      ${f.packets.length?`<h4>Evidence packets</h4>${pk(f.packets)}`:""}</div></details>`;
  function draw(){
    const q = S.q.toLowerCase(), hit = x => S.sev.has(x.severity) && (!q || (x.title+" "+(x.summary||x.verdict)+" "+(x.protocol||"")+" "+(x.category||"")).toLowerCase().includes(q));
    const R = rcs.filter(hit), F = all.filter(hit);
    let h = R.length ? `<div class="fp-group"><span>Root causes</span><span>${R.length}</span></div>${R.map(rcHTML).join("")}` : "";
    if(S.group === "none") h += F.map(fHTML).join("");
    else { const g = {}; F.forEach(f=>(g[f[S.group]] ||= []).push(f));
      h += Object.entries(g).sort((a,b)=>SEVS.indexOf(a[1][0].severity)-SEVS.indexOf(b[1][0].severity)).map(([k,v])=>`<div class="fp-group"><span>${esc(k)}</span><span>${v.length}</span></div>${v.map(fHTML).join("")}`).join(""); }
    out.innerHTML = h || `<p class="muted small" style="padding:8px">${all.length||rcs.length?"Nothing matches these filters.":"No findings: this capture looks healthy."}</p>`;
    out.querySelectorAll("[data-no]").forEach(b=>b.onclick = e=>{ e.preventDefault(); openPackets(id, {no:+b.dataset.no}); });
    out.querySelectorAll("[data-filter]").forEach(b=>b.onclick = e=>{ e.preventDefault(); openPackets(id, {filter:b.dataset.filter}); });
    out.querySelectorAll("[data-copy]").forEach(b=>b.onclick = e=>{ e.preventDefault();
      navigator.clipboard ? navigator.clipboard.writeText(b.dataset.copy).then(()=>toast("Filter copied"), ()=>toast(b.dataset.copy)) : toast(b.dataset.copy); });
  }
  el.querySelector(".fp-q").oninput = e => { S.q = e.target.value; draw(); };
  el.querySelector(".fp-g").onchange = e => { S.group = e.target.value; store("pl-fgroup", S.group); draw(); };
  el.querySelectorAll(".fp-sev button").forEach(b=>b.onclick = ()=>{ const s = b.dataset.s; S.sev.has(s) ? S.sev.delete(s) : S.sev.add(s);
    b.setAttribute("aria-pressed", S.sev.has(s)); store("pl-fsev", [...S.sev]); draw(); });
  draw();
}

/* ---------------------------------------------------------------- routing */
let cleanup = [];
function onLeave(fn){ cleanup.push(fn); }
const PL = window.PL = {api, esc, toast, onLeave, views:{}, sev, fmtT, fmtB, store, skeleton, state, showState, errorState,
                        openPackets, takeHandoff, findingsPanel, ring, lastCapture: store("pl-last") };   // shared with analyze.js / insights.js
PL.setCapture = id => { if(id){ PL.lastCapture = id; store("pl-last", id); } };
function route(){
  cleanup.forEach(f=>{ try{ f(); }catch(e){} }); cleanup = [];
  const h = location.hash.slice(2) || "library";
  const [name, ...rest] = h.split("/"); const arg = decodeURIComponent(rest.join("/"));
  document.querySelectorAll(".views a").forEach(a=>{ const on = a.dataset.view === name || (name === "capture" && a.dataset.view === "library");
    a.classList.toggle("on", on); on ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current"); });
  view.innerHTML = "";
  ({library, capture, sim, live, ...PL.views}[name] || library)(arg);
}
PL.route = route;
addEventListener("hashchange", route);
async function uploadFile(f){
  if(!f) return; toast(`Analyzing ${f.name}…`);
  try{ const r = await api.post("/api/upload?name="+encodeURIComponent(f.name), await f.arrayBuffer(), true); PL.setCapture(r.id); location.hash = "#/analyze/"+encodeURIComponent(r.id); }
  catch(err){ toast("Upload failed: "+err.message); }
}
$("#upload").addEventListener("change", async e=>{ await uploadFile(e.target.files[0]); e.target.value = ""; });

/* drop a capture anywhere (views with their own drop zone handle it first) */
let dragDepth = 0;
const hasFiles = e => [...(e.dataTransfer?.types||[])].includes("Files");
addEventListener("dragenter", e=>{ if(!hasFiles(e)) return; dragDepth++; $("#drop-ov").classList.add("on"); });
addEventListener("dragleave", e=>{ if(!hasFiles(e)) return; if(--dragDepth <= 0){ dragDepth = 0; $("#drop-ov").classList.remove("on"); } });
addEventListener("dragover", e=>{ if(hasFiles(e)) e.preventDefault(); });
addEventListener("drop", e=>{ dragDepth = 0; $("#drop-ov").classList.remove("on"); if(!hasFiles(e) || e.defaultPrevented) return;
  e.preventDefault(); uploadFile(e.dataTransfer.files[0]); });

/* theme */
function setTheme(t, save=true){ document.documentElement.dataset.theme = t; if(save) store("pl-theme", t); $("#theme-ic").textContent = t === "light" ? "☀" : "☾";
  $("#btn-theme").setAttribute("aria-label", `Switch to ${t === "light" ? "dark" : "light"} theme`); }
const toggleTheme = () => setTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light");
$("#btn-theme").onclick = toggleTheme;
setTheme(document.documentElement.dataset.theme || "dark", false);   // keep following the OS until the user picks

/* ---------------------------------------------------------------- library */
async function library(){
  view.innerHTML = `<div class="hero"><div><h1>Capture library</h1><div class="muted" id="lib-meta">Loading…</div></div><div class="spacer"></div>
    <input type="search" id="lib-q" placeholder="Filter folders, files, protocols…  ( / )" aria-label="Filter captures" style="width:min(380px,100%)"></div><div id="lib">${skeleton("library")}</div>`;
  let data;
  try{ data = await api.get("/api/library"); } catch(e){ errorState(view, e); return; }
  if(!data.root){ $("#lib-meta").textContent = "";
    showState($("#lib"), {icon:"⌂", title:"No library folder", msg:"Start the Studio with a folder (packetlens app <folder>), drop a capture file anywhere on this page, or build one in the Simulator.",
      actions:[{label:"Open capture…", onclick:()=>$("#upload").click()}, {label:"Simulator", href:"#/sim"}]}); return; }
  $("#lib").className = "libgrid";
  const render = d => {
    const n = d.folders.reduce((a,f)=>a+f.captures.length,0);
    $("#lib-meta").innerHTML = `<span class="stat mono" style="color:var(--cyan)">${n}</span> captures in ${d.folders.length} folders · <span class="mono small">${esc(d.root)}</span>`
      + (d.pkt_skipped?` · ${d.pkt_skipped} Packet Tracer .pkt files ignored (not captures)`:"");
    $("#lib").innerHTML = d.folders.map(f=>`<section class="panel folder" data-q="${esc((f.name+" "+f.captures.map(c=>c.name+" "+(c.protocols||[]).join(" ")).join(" ")).toLowerCase())}">
      <h2>${esc(f.name)} <span class="chip">${f.captures.length}</span></h2>
      ${f.captures.map(c=>`<div class="cap-tile" data-id="${esc(c.id)}" tabindex="0" role="link">${ring(c.health)}<div><div class="name">${esc(c.name)}</div>
        <div class="small muted">${c.packets!=null?`${sev(c.worst)} ${c.packets.toLocaleString()} pkts · ${c.findings} findings · ${esc(c.top)}`
          : c.error ? `<span style="color:var(--red)">cannot analyze: ${esc(c.error)}</span>` : "analyzing…"}</div>
        ${(c.protocols||[]).map(p=>`<span class="chip">${esc(p)}</span>`).join("")}
        <a class="chip pk-link" href="#/analyze/${encodeURIComponent(c.id)}" title="Wireshark-style packet view">▤ Packets</a></div></div>`).join("")}</section>`).join("");
    view.querySelectorAll(".cap-tile").forEach(t=>{ const go = e=>{ if(e && e.target.closest(".pk-link")) return; PL.setCapture(t.dataset.id); location.hash = "#/capture/"+encodeURIComponent(t.dataset.id); };
      t.onclick = go; t.onkeydown = e=>{ if(e.key==="Enter") go(); }; });
    filter();
  };
  const filter = () => { const q = ($("#lib-q")||{}).value?.toLowerCase() || ""; let shown = 0;
    view.querySelectorAll(".folder").forEach(s=>{ const on = s.dataset.q.includes(q); s.style.display = on ? "" : "none"; shown += on; });
    let none = $("#lib-none"); if(!shown && !none){ $("#lib").insertAdjacentHTML("afterend", `<p class="muted" id="lib-none" style="padding:12px">No capture matches \u201c${esc(q)}\u201d.</p>`); }
    else if(shown && none) none.remove(); };
  $("#lib-q").oninput = filter;
  render(data);
  try{ const full = await api.get("/api/library?analyze=1"); if(view.contains($("#lib"))) render(full); } catch(e){ toast(e.message); }
}

/* ------------------------------------------------------------ capture view */
async function capture(id){
  view.innerHTML = skeleton();
  let d;
  try{ d = await api.get("/api/capture?id="+encodeURIComponent(id)); } catch(e){ errorState(view, e); return; }
  PL.setCapture(id);
  const H = d.stats.health.overall;
  view.innerHTML = `<div class="hero"><div>${ring(H)}</div><div><h1>${esc(d.meta.source)}</h1><div class="muted small">${d.stats.packets.toLocaleString()} packets · ${fmtT(d.stats.duration)} ·
      ${d.findings.length} findings · ${d.root_causes.length} root causes</div></div><div class="spacer"></div>
      ${d.path_folder?`<div class="row"><span class="small muted">Path:</span><button class="ghost" data-v="0">This capture</button><button class="ghost" data-v="1">Whole folder</button></div>`:""}
      <a class="btn ghost" href="#/analyze/${encodeURIComponent(id)}">▤ Packets</a>
      <a class="btn ghost" href="#/insights/${encodeURIComponent(id)}">◈ Insights${d.crypto&&d.crypto.readiness.score!=null?` · PQC ${d.crypto.readiness.score}`:""}</a>
      <a class="btn ghost" target="_blank" rel="noopener" href="/api/report?id=${encodeURIComponent(id)}">Full report ↗</a></div>
    <div class="studio"><div><div class="stage" id="stage"><div class="hud"><button id="play">▶ Replay capture</button><button class="ghost" id="rot">Auto-rotate</button><button class="ghost" id="refit">Fit</button></div>
      <div class="legend"><span><i style="color:var(--lime);background:var(--lime)"></i>ok</span><span><i style="color:var(--amber);background:var(--amber)"></i>retransmission / warning</span>
        <span><i style="color:var(--red);background:var(--red)"></i>failed / dropped</span><span><i style="color:var(--cyan);background:var(--cyan)"></i>capture point</span></div>
      <div class="caption" id="cap">Replay plays every captured packet across the inferred path in capture-time order.</div></div>
      <div class="timeline"><button class="ghost" id="tl-play" aria-label="Play or pause">▶</button><select class="speed" id="speed" aria-label="Speed"></select><canvas id="tl" height="46"></canvas><span class="clock" id="clock">0.00 s</span></div></div>
    <div class="side"><div class="panel"><div class="tabs" role="tablist"><button data-t="flows" class="on">Flows</button><button data-t="find">Findings (${d.findings.length + d.root_causes.length})</button><button data-t="streams">TCP streams</button><button data-t="notes">How inferred</button></div><div id="tab"></div></div>
      <div class="panel" id="detail"><span class="muted small">Select a flow or a device.</span></div></div></div>
    <div class="ribbon" id="ribbon"><div class="stage" id="rib-stage"><button class="close" id="rib-close">Close ✕</button><div class="caption" id="rib-cap"></div></div></div>`;
  let graph = d.path || {nodes:[], links:[], flows:[], notes:[]};
  const eng = Neon($("#stage")); onLeave(()=>eng.dispose());
  eng.onPick(n=>{ $("#detail").innerHTML = nodeCard(n); eng.highlight([n.id]); });
  const load = g => { graph = g; eng.setGraph(g); tabs.flows(); };
  const bins = d.stats.timeline.map(b=>({v:b.pkts, bad:b.bad>0}));
  eng.setHeat(bins, 0);
  // ---- tabs
  const tabs = {
    flows(){ $("#tab").innerHTML = `<div class="list">${graph.flows.map((f,i)=>`<div class="item" data-f="${i}"><span class="dot st-${esc(f.status)}"></span><div>${esc(f.label)}
      <div class="small muted">${esc(f.status)} · ${f.packets} pkt${f.captures&&f.captures.length>1?` · ${f.captures.length} capture points`:""}</div></div></div>`).join("")||'<div class="muted small">No flows inferred.</div>'}</div>`;
      $("#tab").querySelectorAll(".item").forEach(it=>it.onclick=()=>selectFlow(+it.dataset.f)); },
    find(){ findingsPanel($("#tab"), d, {id, compact:true}); },
    streams(){ $("#tab").innerHTML = `<div class="list">${d.streams.slice(0,200).map(s=>`<div class="item" data-s="${s.id}"><span class="dot ${Object.keys(s.flags).some(k=>/retrans|lost|zero|dup/.test(k))?"st-warn":s.rst?"st-fail":"st-ok"}"></span>
      <div>#${s.id} ${esc(s.client)} → ${esc(s.server)} <span class="chip">${esc(s.app)}</span><div class="small muted">${s.packets} pkts · iRTT ${s.irtt_ms??"—"} ms · ${esc(Object.entries(s.flags).map(([k,v])=>k+" "+v).join(", ")||"clean")}</div></div></div>`).join("")||'<div class="muted small">No TCP streams.</div>'}</div>
      <p class="small muted">Click a stream for its 3D sequence ribbon.</p>`;
      $("#tab").querySelectorAll(".item").forEach(it=>it.onclick=()=>openRibbon(d.streams.find(s=>s.id===+it.dataset.s))); },
    notes(){ $("#tab").innerHTML = `<ul class="small">${(graph.notes||[]).map(n=>`<li>${esc(n)}</li>`).join("")}</ul>`; }
  };
  view.querySelectorAll(".tabs button").forEach(b=>b.onclick=()=>{ view.querySelectorAll(".tabs button").forEach(x=>x.classList.toggle("on", x===b)); tabs[b.dataset.t](); });
  view.querySelectorAll("[data-v]").forEach(b=>b.onclick=()=>load(+b.dataset.v ? d.path_folder : d.path));
  function selectFlow(i){
    const f = graph.flows[i]; if(!f) return;
    $("#tab").querySelectorAll(".item").forEach(it=>it.classList.toggle("on", +it.dataset.f===i));
    eng.highlight(f.hops);
    const lab = new Map(graph.nodes.map(n=>[n.id,n]));
    $("#detail").innerHTML = `<h2><span class="dot st-${esc(f.status)}"></span> ${esc(f.label)}</h2><div class="hops">${f.hops.map((h,k)=>`${k?"→":""}<span class="h ${lab.get(h)?.observed===false?"inf":""} ${f.break_at===h?"brk":""}">${esc(lab.get(h)?.label||h)}</span>`).join(" ")}</div>
      <p class="small">${esc(f.why)}</p><button id="flow-play">▶ Replay this flow</button>`;
    $("#flow-play").onclick = () => playSteps(f);
  }
  function playSteps(f){
    stopReplay(); eng.clear();
    const st = f.steps||[], span = Math.max(1e-6, st.length ? st[st.length-1].t : 1);
    st.forEach(s=>{ const tm = setTimeout(()=>{ let path = s.dir==="fwd" ? f.hops : [...f.hops].reverse(), dieAt = null;
      if(f.break_at && s.status==="fail" && s.dir==="fwd") dieAt = f.break_at;
      if(f.status==="fail" && f.break_at && s.dir==="fwd" && !st.some(x=>x.dir==="rev")) dieAt = f.break_at;
      eng.packet({path, status:s.status, dieAt}); $("#cap").innerHTML = `<b class="mono">#${s.no}</b> ${esc(s.label)}`; }, Math.min(12, s.t/span*12)*1000);
      timers.push(tm); });
  }
  // ---- whole-capture replay
  const rows = d.replay.rows, dur = Math.max(.001, rows.length ? rows[rows.length-1][0] : 1);
  const speeds = [.25,.5,1,2,5,10,25,50,100,250,1000], def = speeds.find(s=>dur/s <= 30) || 1000;
  $("#speed").innerHTML = speeds.map(s=>`<option value="${s}" ${s===def?"selected":""}>${s}×</option>`).join("");
  let t = 0, playing = false, idx = 0, lastWall = 0, raf = 0; const timers = [];
  const tl = $("#tl");
  function drawTimeline(){
    const r = tl.getBoundingClientRect(), w = tl.width = Math.max(200, r.width*devicePixelRatio), h = tl.height = 46*devicePixelRatio, g = tl.getContext("2d");
    const tlb = d.stats.timeline, max = Math.max(1, ...tlb.map(b=>b.pkts)), bw = w/Math.max(1,tlb.length);
    g.clearRect(0,0,w,h);
    tlb.forEach((b,i)=>{ const x = i*bw, k = b.pkts/max; g.fillStyle = "rgba(62,242,255,.55)"; g.fillRect(x, h-k*h*.9, Math.max(1,bw-1), k*h*.9);
      if(b.bad){ g.fillStyle = "rgba(255,75,92,.9)"; g.fillRect(x, h-(b.bad/max)*h*.9, Math.max(1,bw-1), (b.bad/max)*h*.9); } });
    const x = t/dur*w; g.fillStyle = "#ff3fd8"; g.shadowColor = "#ff3fd8"; g.shadowBlur = 12; g.fillRect(x-1, 0, 3, h); g.shadowBlur = 0;
  }
  // replay rows index this capture's own flows; in the whole-folder view use the stitched flow with the same endpoints
  const pairKey = f => [f.src_ip, f.dst_ip].sort().join("|") + (f.kind === "control" ? "|" + f.label.split(" ")[0] : "");
  function flowFor(fi){
    const own = (d.path || {flows:[]}).flows[fi];
    if(!own || graph === d.path) return own;
    return graph.flows.find(g=>pairKey(g) === pairKey(own)) || null;
  }
  function stopReplay(){ playing = false; cancelAnimationFrame(raf); timers.forEach(clearTimeout); timers.length = 0; $("#tl-play").textContent = "▶"; }
  function tick(now){
    if(!playing) return;
    const dt = (now-lastWall)/1000; lastWall = now; t = Math.min(dur, t + dt*(+$("#speed").value));
    let n = 0;
    while(idx < rows.length && rows[idx][0] <= t){
      const [, fi, fwd, st] = rows[idx]; idx++;
      const f = flowFor(fi); if(!f || n > 10) continue;              // at most ~10 new sparks per frame keeps dense captures readable
      const status = ["ok","warn","fail"][st], path = fwd ? f.hops : [...f.hops].reverse();
      eng.packet({path, status, dieAt: st===2 && fwd && f.break_at ? f.break_at : null, speed:60, size:st?1.15:.8}); n++;
    }
    $("#clock").textContent = fmtT(t); eng.setHeat(bins, t/dur); drawTimeline();
    if(t >= dur){ stopReplay(); $("#cap").textContent = "Replay finished."; return; }
    raf = requestAnimationFrame(tick);
  }
  function play(){ if(t >= dur){ t = 0; idx = 0; } playing = true; lastWall = performance.now(); $("#tl-play").textContent = "❚❚"; $("#cap").textContent = `Replaying ${rows.length.toLocaleString()} packets${d.replay.truncated?" (first 20,000)":""}…`; raf = requestAnimationFrame(tick); }
  $("#tl-play").onclick = () => playing ? stopReplay() : play();
  $("#play").onclick = () => { stopReplay(); t = 0; idx = 0; eng.clear(); play(); };
  tl.onclick = e => { const r = tl.getBoundingClientRect(); t = (e.clientX-r.left)/r.width*dur; idx = rows.findIndex(x=>x[0] >= t); if(idx<0) idx = rows.length; $("#clock").textContent = fmtT(t); drawTimeline(); eng.setHeat(bins, t/dur); };
  let rot = true; $("#rot").onclick = () => { rot = !rot; eng.setAutoRotate(rot); $("#rot").classList.toggle("ghost", !rot); };
  $("#refit").onclick = () => eng.fit();
  onLeave(stopReplay);
  load(graph); drawTimeline(); addEventListener("resize", drawTimeline); onLeave(()=>removeEventListener("resize", drawTimeline));
  // ---- TCP sequence ribbon
  let rib = null;
  $("#rib-close").onclick = () => { $("#ribbon").classList.remove("on"); if(rib){ rib.dispose(); rib = null; } };
  onLeave(()=>{ if(rib) rib.dispose(); });
  function openRibbon(s){
    if(!s) return; $("#ribbon").classList.add("on"); if(rib) rib.dispose();
    rib = Neon($("#rib-stage"), {autoRotate:false}); rib.setGraph({nodes:[], links:[], flows:[]});
    const Tj = window.THREE, lad = s.ladder, tmax = Math.max(1e-6, ...lad.map(e=>e.t)), smax = Math.max(1, ...lad.map(e=>e.seq+e.len));
    const grp = new Tj.Group(), glowTex = (()=>{ const c = document.createElement("canvas"); c.width = c.height = 64; const g = c.getContext("2d");
      const r = g.createRadialGradient(32,32,0,32,32,32); r.addColorStop(0,"#fff"); r.addColorStop(.3,"rgba(255,255,255,.5)"); r.addColorStop(1,"rgba(255,255,255,0)");
      g.fillStyle = r; g.fillRect(0,0,64,64); return new Tj.CanvasTexture(c); })();
    const P = e => new Tj.Vector3(e.t/tmax*60-30, (e.seq/smax)*24-12, e.dir==="s2c"?5:-5);
    let flagged = 0;
    ["c2s","s2c"].forEach((dir,k)=>{
      const col = k ? 0xff3fd8 : 0x3ef2ff, ev = lad.filter(e=>e.dir===dir), pts = ev.map(P);
      if(pts.length > 1){                                   // the sequence ribbon: a glowing tube through every packet
        const tube = new Tj.TubeGeometry(new Tj.CatmullRomCurve3(pts, false, "centripetal"), Math.min(600, pts.length*4), .12, 8, false);
        grp.add(new Tj.Mesh(tube, new Tj.MeshBasicMaterial({color:col, transparent:true, opacity:.7, blending:Tj.AdditiveBlending, depthWrite:false})));
      }
      ev.forEach(e=>{
        const bad = e.analysis.some(a=>/retrans|lost|zero|dup|out_of/.test(a)), rst = e.flags.includes("RST");
        const c = rst ? 0xff4b5c : bad ? 0xffc23e : col, p = P(e);
        const m = new Tj.Mesh(new Tj.SphereGeometry(e.len ? .32 : .18, 12, 10), new Tj.MeshBasicMaterial({color:c})); m.position.copy(p); grp.add(m);
        const h = new Tj.Sprite(new Tj.SpriteMaterial({map:glowTex, color:c, transparent:true, blending:Tj.AdditiveBlending, depthWrite:false}));
        h.position.copy(p); h.scale.setScalar(bad||rst ? 2.6 : e.len ? 1.5 : .9); grp.add(h);
        if((bad || rst) && flagged++ < 12) rib.label(e.analysis.join(", ").replace(/_/g," ") || "RST", p, "lbl");
      });
    });
    rib.add(grp);
    rib.add(new Tj.GridHelper(80, 16, 0x1c3b6e, 0x0f1c38).translateY(-13.5));
    rib.label(`client → server (${s.client})`, new Tj.Vector3(-30,-13,-5), "lbl cap"); rib.label(`server → client (${s.server})`, new Tj.Vector3(-30,-13,5), "lbl cap");
    rib.fitTo(grp);
    $("#rib-cap").innerHTML = `<b>Stream #${s.id}</b> ${esc(s.client)} ↔ ${esc(s.server)} — x: time (${fmtT(s.duration)}), y: relative sequence number, z: direction.
      Amber = retransmission / loss / window event, red = RST. ${s.ladder.length>=400?"(first 400 packets)":""}`;
  }
}

function nodeCard(n){
  return `<h2>${esc(n.label)} <span class="chip">${esc(n.kind)}</span>${n.observed===false?'<span class="chip">inferred</span>':""}</h2><div class="kv">
    ${n.ips&&n.ips.length?`<b>IP</b><span class="mono">${esc(n.ips.slice(0,4).join(", "))}</span>`:""}
    ${n.macs&&n.macs.length?`<b>MAC</b><span class="mono">${esc(n.macs.slice(0,3).join(", "))}</span>`:""}
    ${n.roles&&n.roles.length?`<b>Roles</b><span>${esc(n.roles.join(", "))}</span>`:""}
    <b>Evidence</b><span>${esc((n.evidence||[]).join("; ")||"—")}</span></div>`;
}

/* -------------------------------------------------------------- simulator */
async function sim(){
  let opts;
  try{ opts = await api.get("/api/sim/options"); } catch(e){ view.innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
  view.innerHTML = `<div class="studio sim"><div class="side"><div class="panel"><h2>Build a scenario</h2>
      <label class="f">Traffic<select id="s-traffic">${Object.entries(opts.traffic).map(([k,v])=>`<option value="${k}">${esc(v)}</option>`).join("")}</select></label>
      <label class="f">Inject fault<select id="s-fault"></select></label>
      <label class="f" id="s-where-l">Where<select id="s-where"></select></label>
      <label class="f">Routers on the path <span class="val" id="v-routers">3</span><input type="range" id="s-routers" min="1" max="6" value="3"></label>
      <label class="row small" style="margin-bottom:10px"><input type="checkbox" id="s-switch" checked> Access switch between client and first router</label>
      <label class="f">Capture point (link)<select id="s-capture"></select></label>
      <div id="s-params"></div>
      <label class="f">Link latency <span class="val" id="v-link">4 ms</span><input type="range" id="s-link" min="1" max="40" value="4"></label>
      <label class="f">Random seed<input type="number" id="s-seed" value="7" min="0" max="99999"></label>
      <button class="hot" id="s-run" style="width:100%">⚡ Simulate &amp; analyze</button></div>
      <div class="panel small muted">The simulator walks every packet hop by hop (routers decrement TTL and rewrite MACs), applies the fault where you placed it,
        records what a capture on the chosen link would contain, then runs the real PacketLens analyzer on that capture.</div></div>
    <div><div class="stage" id="stage"><div class="hud"><button id="s-replay" disabled>↻ Replay</button><select id="s-speed" aria-label="Speed"><option value=".5">0.5×</option><option value="1" selected>1×</option><option value="2">2×</option><option value="4">4×</option></select></div>
      <div class="legend"><span><i style="color:var(--lime);background:var(--lime)"></i>packet</span><span><i style="color:var(--amber);background:var(--amber)"></i>retransmission / probe</span>
      <span><i style="color:var(--red);background:var(--red)"></i>dropped</span><span><i style="color:var(--magenta);background:var(--magenta)"></i>rejected / error reply</span><span><i style="color:var(--cyan);background:var(--cyan)"></i>capture point</span></div>
      <div class="caption" id="cap">Pick traffic and a fault, then Simulate. The capture lens shows where the analyzer is "listening".</div></div>
      <div class="livestats" style="margin-top:10px"><div><b id="c-sent">0</b><span class="small muted">hops animated</span></div><div><b id="c-drop" style="color:var(--red)">0</b><span class="small muted">dropped / rejected</span></div><div><b id="c-cap" style="color:var(--cyan)">0</b><span class="small muted">frames captured</span></div></div></div>
    <div class="side" id="s-result"><div class="panel muted small">Results appear here: the injected fault, what the analyzer detected from the capture point, root causes and the downloadable pcap.</div></div></div>`;
  const eng = Neon($("#stage")); onLeave(()=>eng.dispose());
  const F = opts.faults;
  const val = id => $("#"+id).value;
  function topo(){
    const r = +val("s-routers"), sw = $("#s-switch").checked, nodes = [{id:"client", label:"Client", kind:"host"}];
    if(sw) nodes.push({id:"sw1", label:"SW1", kind:"switch"});
    for(let i=1;i<=r;i++) nodes.push({id:"r"+i, label:"R"+i, kind:"router"});
    nodes.push({id:"server", label:"Server", kind:"server"});
    return nodes;
  }
  function refreshForm(keep){
    const tr = val("s-traffic");
    const prevFault = keep ? val("s-fault") : null;
    $("#s-fault").innerHTML = Object.entries(F).filter(([,f])=>f.traffic.includes(tr)).map(([k,f])=>`<option value="${k}">${esc(f.label)}</option>`).join("");
    if(prevFault && F[prevFault] && F[prevFault].traffic.includes(tr)) $("#s-fault").value = prevFault;
    const nodes = topo(), f = F[val("s-fault")], where = f.where;
    $("#s-where-l").style.display = where==="router"||where==="link" ? "" : "none";
    const prevWhere = val("s-where");
    $("#s-where").innerHTML = where==="router" ? nodes.filter(n=>n.kind==="router").map(n=>`<option value="${n.id}">${n.label}</option>`).join("")
      : where==="link" ? nodes.slice(0,-1).map((n,i)=>`<option value="${i}">${n.label} ↔ ${nodes[i+1].label}</option>`).join("") : "";
    if([...$("#s-where").options].some(o=>o.value===prevWhere)) $("#s-where").value = prevWhere;
    else if($("#s-where").options.length) $("#s-where").selectedIndex = Math.floor($("#s-where").options.length/2);
    const prevCap = val("s-capture");
    $("#s-capture").innerHTML = nodes.slice(0,-1).map((n,i)=>`<option value="${i}">${n.label} ↔ ${nodes[i+1].label}</option>`).join("");
    $("#s-capture").value = [...$("#s-capture").options].some(o=>o.value===prevCap) ? prevCap : (nodes[1].kind==="switch"?"1":"0");
    const k = val("s-fault");
    const P = {loss:[["loss_rate","Loss rate",.02,.8,.02,.2,v=>Math.round(v*100)+"%"]], latency:[["latency_ms","Added latency",20,1500,10,250,v=>v+" ms"]],
               mtu_blackhole:[["mtu","Link MTU",576,1480,4,1400,v=>v+" B"]], mtu_icmp:[["mtu","Link MTU",576,1480,4,1400,v=>v+" B"]],
               slow_server:[["think_s","Server think time",1.1,15,.1,3,v=>(+v).toFixed(1)+" s"]]}[k] || [];
    if(["http","tls"].includes(tr)) P.push(["size_kb","Download size",4,1024,4,64,v=>v+" KB"]);
    $("#s-params").innerHTML = P.map(([id,l,mi,ma,st,dv,fmt])=>`<label class="f">${l} <span class="val" id="v-${id}">${fmt(dv)}</span><input type="range" id="p-${id}" min="${mi}" max="${ma}" step="${st}" value="${dv}"></label>`).join("");
    P.forEach(([id,,,,,,fmt])=>{ $("#p-"+id).oninput = e=>$("#v-"+id).textContent = fmt(e.target.value); });
    preview();
  }
  function preview(){
    const nodes = topo(), c = +val("s-capture");
    const f = F[val("s-fault")];
    const g = {nodes:nodes.map(n=>({...n, observed:true})), links:nodes.slice(1).map((n,i)=>({a:nodes[i].id, b:n.id, kind:"l2", observed:true})),
               capture_links:[[nodes[c].id, nodes[c+1].id]], flows:[]};
    eng.setGraph(g, "line");
    if(f.where==="router") eng.pulse(val("s-where"), 0xff3fd8);
  }
  ["s-traffic"].forEach(id=>$("#"+id).onchange = ()=>refreshForm(true));
  ["s-fault","s-where","s-capture","s-switch"].forEach(id=>$("#"+id).onchange = ()=>refreshForm(true));
  $("#s-routers").oninput = e=>{ $("#v-routers").textContent = e.target.value; refreshForm(true); };
  $("#s-link").oninput = e=>$("#v-link").textContent = e.target.value+" ms";
  refreshForm(false);

  let last = null, timers = [];
  const stop = () => { timers.forEach(clearTimeout); timers = []; };
  onLeave(stop);
  $("#s-run").onclick = async () => {
    const cfg = {traffic:val("s-traffic"), fault:val("s-fault"), routers:+val("s-routers"), switch:$("#s-switch").checked, capture:+val("s-capture"),
                 link_ms:+val("s-link"), seed:+val("s-seed")};
    if(F[cfg.fault].where==="router"||F[cfg.fault].where==="link") cfg.where = val("s-where");
    view.querySelectorAll("#s-params input").forEach(i=>cfg[i.id.slice(2)] = +i.value);
    $("#s-run").disabled = true; $("#s-run").textContent = "Simulating…";
    try{ last = await api.post("/api/sim", cfg); showResult(last); animate(last); }
    catch(e){ toast("Simulation failed: "+e.message); }
    finally{ $("#s-run").disabled = false; $("#s-run").innerHTML = "⚡ Simulate &amp; analyze"; }
  };
  $("#s-replay").onclick = () => last && animate(last);
  function animate(r){
    stop(); eng.clear();
    const nodes = r.topology.nodes.map(n=>({id:n.id, label:n.name, kind:n.kind, observed:true}));
    const links = nodes.slice(1).map((n,i)=>({a:nodes[i].id, b:n.id, kind:"l2", observed:true}));
    if(r.topology.rogue){ const at = nodes.find(n=>n.kind==="switch") || nodes[0];
      nodes.push({id:"rogue", label:"Rogue DHCP", kind:"rogue", observed:true, pos:[(nodes.findIndex(n=>n.id===at.id)-(nodes.length-2)/2)*9, -1.2, 9]}); links.push({a:at.id, b:"rogue", kind:"l2"}); }
    const c = r.topology.capture_link;
    eng.setGraph({nodes, links, capture_links:[[nodes[c].id, nodes[c+1].id]], flows:[]}, "line");
    $("#s-replay").disabled = false;
    // compress simulated time: long idle gaps (RTO back-off, think time) are shortened so the story stays watchable
    const ev = r.journey, speed = +val("s-speed"); let clock = 0, prev = ev.length ? ev[0].t : 0, sent = 0, drops = 0, caps = 0;
    const HOP = .45;                                                  // seconds of animation per hop
    ev.forEach((e,i)=>{
      clock += Math.min(e.t - prev, .5) * 6 + (i ? .04 : 0); prev = e.t;
      const at = Math.max(0, (clock - HOP)) / speed * 1000;
      timers.push(setTimeout(()=>{
        if(e.from === e.to){ eng.burst(e.from, e.status==="reject"?0xff3fd8:0xff4b5c); drops++; $("#c-drop").textContent = drops; }
        else{ const st = e.status==="ok" ? (e.kind==="retrans"||e.kind==="probe" ? "warn" : e.kind==="icmp-error"||e.kind==="rst" ? "reject" : "ok") : e.status;
          eng.packet({path:[e.from, e.to], status:st, speed:9/HOP*speed, size: e.captured?1.1:.85, trail:true});
          sent++; $("#c-sent").textContent = sent; if(e.captured){ caps++; $("#c-cap").textContent = caps; } }
        if(e.status !== "ok" || i % 3 === 0) $("#cap").innerHTML = `<span class="mono small muted">t=${e.t.toFixed(3)}s</span> ${esc(e.label)} <span class="muted small">(${esc(e.from)} → ${esc(e.to)})</span>`;
      }, at));
    });
    timers.push(setTimeout(()=>{ $("#cap").innerHTML = `Done — ${sent} hops, ${drops} dropped/rejected, ${caps} frames reached the capture point. ${(r.notes||[]).map(esc).join(" ")}`; },
      (clock / speed + 1) * 1000));
    $("#c-sent").textContent = $("#c-drop").textContent = $("#c-cap").textContent = 0;
  }
  function showResult(r){
    const a = r.analysis, f = F[r.config.fault];
    const where = r.config.where == null ? "" : ` at ${r.config.where === "server" || r.config.where === "client" ? r.config.where
                  : isNaN(+r.config.where) ? String(r.config.where).toUpperCase() : "link " + r.config.where}`;
    const V = {detected:["var(--lime)","Detected ✓", `The analyzer found the injected fault from the capture point: ${r.detected.join(", ")}.`],
               missed:["var(--red)","Missed ✕", `Expected one of: ${r.expected.join(", ")}. Found: ${r.findings_all.join(", ")||"nothing"}.`],
               clean:["var(--cyan)", r.config.fault==="none" ? "Healthy ✓" : "Not visible here", r.config.fault==="none" ? "No problems injected, none reported." : "This fault leaves no trace at the chosen capture point."],
               noisy:["var(--amber)","Healthy traffic, but findings reported", "Worth checking: the analyzer reported problems for a healthy run."]}[r.verdict];
    $("#s-result").innerHTML = `<div class="verdict" style="--c:${V[0]}"><b class="big">${V[1]}</b><div class="small">${esc(V[2])}</div>
        <div class="small muted" style="margin-top:6px">Injected: <b>${esc(f.label)}</b>${esc(where)} · capture on link ${r.config.capture}
        ${r.fault_side==="before"?" · the fault is between the client and the capture point":r.fault_side==="beyond"?" · the fault is beyond the capture point":""}</div>
        ${(r.notes||[]).length?`<div class="small" style="margin-top:6px">${r.notes.map(esc).join("<br>")}</div>`:""}</div>
      <div class="panel"><h2>What the analyzer concluded</h2>
        ${a.root_causes.map(x=>`<div class="find">${sev(x.severity)} <b>${esc(x.title)}</b><div class="small">${esc(x.verdict)}</div><div class="small muted">Fix: ${esc((x.remediation||[])[0]||"—")}</div></div>`).join("")}
        ${a.findings.filter(x=>x.severity!=="info").map(x=>`<div class="find">${sev(x.severity)} <b>${esc(x.title)}</b><div class="small muted">${esc(x.summary)}</div></div>`).join("") || (a.root_causes.length?"":'<div class="muted small">No problems reported.</div>')}
        <div class="row" style="margin-top:10px"><a class="btn" href="/api/sim/pcap?id=${r.id}" download>⬇ pcapng (${r.visible_frames} IP frames)</a>
          <a class="btn ghost" href="#/capture/${encodeURIComponent(r.key)}">Open in capture view</a>
          <a class="btn ghost" target="_blank" rel="noopener" href="/api/report?id=${encodeURIComponent(r.key)}">Full report ↗</a></div></div>`;
  }
}

/* ------------------------------------------------------------------- live */
async function live(){
  let info;
  try{ info = await api.get("/api/live/interfaces"); } catch(e){ view.innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
  view.innerHTML = `<div class="studio"><div><div class="stage" id="stage"><div class="caption" id="cap">Start a capture: every host that talks appears as a node and every packet flies between them.</div></div></div>
    <div class="side"><div class="panel"><h2>Live capture</h2>
      ${info.platform==="nt"?`<p class="small muted">Windows raw-socket mode: IPv4 packets of one local address, no Ethernet/ARP/IPv6. Run PacketLens from an <b>Administrator</b> prompt.</p>`
        :`<p class="small muted">Linux AF_PACKET mode: needs root or CAP_NET_RAW.</p>`}
      <label class="f">Interface<select id="l-if">${info.interfaces.map(i=>`<option value="${esc(i.id)}">${esc(i.label)}</option>`).join("")}</select></label>
      <label class="f">Duration (s)<input type="number" id="l-dur" value="30" min="1" max="3600"></label>
      <label class="f">Only host (optional)<input id="l-host" placeholder="e.g. 192.168.1.10"></label>
      <label class="f">Only port (optional)<input type="number" id="l-port" min="1" max="65535"></label>
      <div class="row"><button class="hot" id="l-start">● Start</button><button id="l-stop" disabled>■ Stop &amp; analyze</button></div>
      <div id="l-err" class="small" style="color:var(--red);margin-top:8px"></div></div>
      <div class="panel"><div class="livestats"><div><b id="l-n">0</b><span class="small muted">packets</span></div><div><b id="l-pps">0</b><span class="small muted">pkt/s</span></div><div><b id="l-hosts">0</b><span class="small muted">hosts</span></div></div>
        <h3>Protocols</h3><div id="l-proto" class="small"></div><h3>Feed</h3><div class="feed" id="l-feed"></div></div>
      <div id="l-done"></div></div></div>`;
  const eng = Neon($("#stage")); onLeave(()=>eng.dispose()); eng.setGraph({nodes:[], links:[], flows:[]});
  let es = null, lid = null, n = 0, recent = [], protos = {}; const hosts = new Set();
  onLeave(()=>{ if(es) es.close(); if(lid) api.post("/api/live/stop?id="+lid).catch(()=>{}); });
  const kindOf = ip => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fe80|127\.)/.test(ip||"") ? "host" : "server";
  $("#l-start").onclick = async () => {
    $("#l-err").textContent = "";
    try{
      const r = await api.post("/api/live/start", {interface:$("#l-if").value, duration:+$("#l-dur").value, host:$("#l-host").value||null, port:+$("#l-port").value||null});
      lid = r.id; $("#l-start").disabled = true; $("#l-stop").disabled = false; $("#cap").textContent = "Capturing…";
      es = new EventSource("/api/live/stream?id="+lid);
      es.onmessage = m => { const {packets} = JSON.parse(m.data); const now = performance.now();
        packets.forEach((p,i)=>{ n++; recent.push(now); protos[p.proto] = (protos[p.proto]||0)+1;
          if(p.src && p.dst){ hosts.add(p.src); hosts.add(p.dst); eng.ensureNode({id:p.src, label:p.src, kind:kindOf(p.src), observed:true}); eng.ensureNode({id:p.dst, label:p.dst, kind:kindOf(p.dst), observed:true});
            eng.ensureLink(p.src, p.dst); if(i < 25) eng.packet({path:[p.src, p.dst], status:p.bad?"fail":"ok", speed:45, size:.8}); } });
        eng.relax();
        recent = recent.filter(x=>now-x < 1000);
        $("#l-n").textContent = n; $("#l-pps").textContent = recent.length; $("#l-hosts").textContent = hosts.size;
        $("#l-proto").innerHTML = Object.entries(protos).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([k,v])=>`<span class="chip">${esc(k)} ${v}</span>`).join("");
        const feed = $("#l-feed"); feed.insertAdjacentHTML("afterbegin", packets.slice(-40).reverse().map(p=>`<div class="${p.bad?"bad":""}">${p.t.toFixed(3)} ${esc(p.src)} → ${esc(p.dst)} ${esc(p.proto)} ${esc(p.info)}</div>`).join(""));
        while(feed.children.length > 200) feed.lastChild.remove(); };
      es.addEventListener("end", m => { const e = JSON.parse(m.data); if(e.error){ $("#l-err").textContent = e.error; } es.close(); es = null; if(!e.error) finish(); else reset(); });
    } catch(e){ $("#l-err").textContent = e.message; }
  };
  const reset = () => { $("#l-start").disabled = false; $("#l-stop").disabled = true; };
  async function finish(){
    if(!lid) return; const id = lid; lid = null; reset();
    const r = await api.post("/api/live/stop?id="+id);
    if(!r.id){ $("#l-done").innerHTML = `<div class="panel small muted">No packets captured. ${esc(r.error||"")}</div>`; return; }
    $("#l-done").innerHTML = `<div class="verdict" style="--c:var(--cyan)"><b class="big">${r.packets.toLocaleString()} packets analyzed</b><div class="small">${sev(r.worst)} ${esc(r.top)}</div>
      <div class="row" style="margin-top:8px"><a class="btn" href="#/capture/${encodeURIComponent(r.id)}">Open in capture view</a><a class="btn ghost" href="/api/sim/pcap?id=${r.pcap}" download>⬇ pcapng</a></div></div>`;
  }
  $("#l-stop").onclick = () => { if(es){ es.close(); es = null; } finish(); };
}

/* -------------------------------------------------------- command palette */
const PAL_FILTERS = ["tls.pqc", "tls.handshake.type == 1", "ssh", "isakmp", "esp", "macsec || mka", "quic", "wg", "infiniband || pfc",
  "http.request", "http2", "tcp.analysis.flags", "tcp.flags.reset == 1", "dns.flags.rcode != 0", "icmp || icmpv6"];
let libCache = null;
async function captures(){
  if(!libCache){ try{ const l = await api.get("/api/library"); libCache = (l.folders||[]).flatMap(f=>f.captures.map(c=>({id:c.id, name:c.name, folder:f.name}))); }catch(e){ libCache = []; } }
  return libCache;
}
function commands(caps){
  const cur = PL.lastCapture, enc = encodeURIComponent, go = h => () => location.hash = h;
  const out = [
    {g:"View", ic:"⌂", t:"Library", k:"g l", run:go("#/library")}, {g:"View", ic:"▤", t:"Analyze packets", k:"g a", run:go("#/analyze" + (cur ? "/"+enc(cur) : ""))},
    {g:"View", ic:"◈", t:"Insights: crypto, PQC, AI traffic, AI fabric", k:"g i", run:go("#/insights" + (cur ? "/"+enc(cur) : ""))},
    {g:"View", ic:"⚡", t:"Simulator", k:"g s", run:go("#/sim")}, {g:"View", ic:"●", t:"Live capture", k:"g v", run:go("#/live")},
    {g:"Action", ic:"⇪", t:"Open a capture file…", run:()=>$("#upload").click()},
    {g:"Action", ic:"◐", t:"Switch light / dark theme", k:"t", run:toggleTheme},
    {g:"Action", ic:"?", t:"Keyboard shortcuts", k:"?", run:showKeys},
  ];
  if(cur){
    const name = cur.replace(/^upload:[^:]+:/, "");
    out.push({g:"Current capture", ic:"◈", t:`Crypto & PQC dashboard · ${name}`, run:go(`#/insights/${enc(cur)}/crypto`)},
             {g:"Current capture", ic:"✦", t:`AI traffic · ${name}`, run:go(`#/insights/${enc(cur)}/ai`)},
             {g:"Current capture", ic:"⧉", t:`AI fabric (RoCE / PFC) · ${name}`, run:go(`#/insights/${enc(cur)}/fabric`)},
             {g:"Current capture", ic:"◎", t:`3D path view · ${name}`, run:go(`#/capture/${enc(cur)}`)});
    PAL_FILTERS.forEach(f=>out.push({g:"Display filter", ic:"⏷", t:f, run:()=>openPackets(cur, {filter:f})}));
  }
  caps.forEach(c=>out.push({g:"Capture", ic:"◇", t:`${c.folder} / ${c.name}`, run:()=>{ PL.setCapture(c.id); location.hash = "#/capture/"+enc(c.id); }}));
  return out;
}
function fuzzy(q, s){                       // subsequence match; returns [score, highlighted html] or null
  if(!q) return [0, esc(s)];
  const L = s.toLowerCase(); let i = 0, score = 0, last = -2, html = "";
  for(let k = 0; k < s.length; k++){
    if(i < q.length && L[k] === q[i]){ score += k === last + 1 ? 3 : 1; if(k === 0 || " /·:".includes(s[k-1])) score += 2; last = k; i++; html += `<mark>${esc(s[k])}</mark>`; }
    else html += esc(s[k]);
  }
  return i === q.length ? [score - s.length * .01, html] : null;
}
let palItems = [], palSel = 0, palPrevFocus = null;
async function openPalette(){
  const p = $("#pal"); if(!p.hidden) return;
  palPrevFocus = document.activeElement; p.hidden = false; $("#pal-q").value = ""; $("#pal-q").focus();
  const all = commands(await captures());
  const draw = () => {
    const q = $("#pal-q").value.trim().toLowerCase();
    palItems = all.map(c=>{ const m = fuzzy(q, c.t); return m && {...c, score:m[0], html:m[1]}; }).filter(Boolean)
      .sort((a,b)=>b.score - a.score).slice(0, 60);
    palSel = Math.min(palSel, Math.max(0, palItems.length - 1));
    $("#pal-list").innerHTML = palItems.map((c,i)=>`<div class="pal-item" role="option" id="pal-${i}" aria-selected="${i===palSel}" data-i="${i}">
      <span class="ic" aria-hidden="true">${c.ic}</span><span>${c.html}<div class="grp">${esc(c.g)}</div></span>${c.k?`<kbd>${esc(c.k)}</kbd>`:"<span></span>"}</div>`).join("")
      || `<div class="muted small" style="padding:12px">No match.</div>`;
    $("#pal-q").setAttribute("aria-activedescendant", palItems.length ? "pal-"+palSel : "");
    $("#pal-list").querySelectorAll(".pal-item").forEach(el=>{ el.onclick = ()=>runPal(+el.dataset.i); el.onmousemove = ()=>{ if(palSel !== +el.dataset.i){ palSel = +el.dataset.i; mark(); } }; });
  };
  const mark = () => { $("#pal-list").querySelectorAll(".pal-item").forEach((el,i)=>el.setAttribute("aria-selected", i===palSel));
    $("#pal-"+palSel)?.scrollIntoView({block:"nearest"}); $("#pal-q").setAttribute("aria-activedescendant", "pal-"+palSel); };
  $("#pal-q").oninput = () => { palSel = 0; draw(); };
  $("#pal-q").onkeydown = e => {
    if(e.key === "ArrowDown"){ e.preventDefault(); palSel = Math.min(palItems.length-1, palSel+1); mark(); }
    else if(e.key === "ArrowUp"){ e.preventDefault(); palSel = Math.max(0, palSel-1); mark(); }
    else if(e.key === "Enter"){ e.preventDefault(); runPal(palSel); }
    else if(e.key === "Escape"){ e.preventDefault(); closePalette(); }
  };
  draw();
}
function closePalette(){ $("#pal").hidden = true; if(palPrevFocus && palPrevFocus.focus) palPrevFocus.focus(); }
function runPal(i){ const c = palItems[i]; if(!c) return; closePalette(); c.run(); }
$("#pal").addEventListener("mousedown", e=>{ if(e.target.id === "pal") closePalette(); });
$("#btn-pal").onclick = openPalette;
addEventListener("hashchange", ()=>{ libCache = null; });

function showKeys(){
  const K = [["Ctrl K / ⌘ K","Command palette"],["?","This help"],["/","Focus the search or filter box"],["t","Switch light / dark theme"],
    ["g then l","Library"],["g then a","Analyze"],["g then i","Insights"],["g then s","Simulator"],["g then v","Live capture"],
    ["↑ ↓ PgUp PgDn Home End","Move in the packet list (Analyze)"],["Ctrl M","Mark packet (Analyze)"],["Esc","Close dialogs"]];
  const p = $("#pal"); palPrevFocus = document.activeElement; p.hidden = false;
  $("#pal-list").innerHTML = `<div style="padding:12px 14px"><h2>Keyboard shortcuts</h2><div class="keys">${K.map(([k,v])=>`<span>${k.split(" ").map(x=>x==="then"?" then ":`<kbd>${esc(x)}</kbd>`).join("")}</span><span>${esc(v)}</span>`).join("")}</div></div>`;
  $("#pal-q").value = ""; $("#pal-q").focus();
  $("#pal-q").oninput = () => openPaletteFrom();
  $("#pal-q").onkeydown = e => { if(e.key === "Escape"){ e.preventDefault(); closePalette(); } };
}
function openPaletteFrom(){ const q = $("#pal-q").value; $("#pal").hidden = true; openPalette().then(()=>{ $("#pal-q").value = q; $("#pal-q").dispatchEvent(new Event("input")); }); }

let gPending = 0;
addEventListener("keydown", e=>{
  if((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k"){ e.preventDefault(); $("#pal").hidden ? openPalette() : closePalette(); return; }
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName) || e.target.isContentEditable;
  if(typing || e.ctrlKey || e.metaKey || e.altKey || !$("#pal").hidden) return;
  if(gPending && Date.now() - gPending < 1200){
    gPending = 0;
    const cur = PL.lastCapture ? "/" + encodeURIComponent(PL.lastCapture) : "";
    const to = {l:"#/library", a:"#/analyze"+cur, i:"#/insights"+cur, s:"#/sim", v:"#/live"}[e.key.toLowerCase()];
    if(to){ e.preventDefault(); location.hash = to; }
    return;
  }
  if(e.key === "g"){ gPending = Date.now(); return; }
  if(e.key === "?"){ e.preventDefault(); showKeys(); }
  else if(e.key === "t"){ toggleTheme(); }
  else if(e.key === "/"){ const s = view.querySelector("input[type=search], #wb-q, .fp-q"); if(s){ e.preventDefault(); s.focus(); s.select && s.select(); } }
});

if(!window.THREE){ view.innerHTML = '<div class="empty">three.min.js failed to load — the 3D views need it.</div>'; }
else addEventListener("DOMContentLoaded", route);                   // after every view script has registered
})();
