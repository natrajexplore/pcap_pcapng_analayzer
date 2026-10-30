/* PacketLens Studio — Insights: crypto posture & post-quantum readiness, AI traffic and AI fabric (RoCEv2 / PFC)
   dashboards for one capture. Registers itself as the "insights" view (see app.js). */
(function(){
"use strict";
const PL = window.PL, {api, esc, sev, fmtB, fmtT} = PL;
const $ = (s, r=document) => r.querySelector(s);
const QS = {pqc:"Post-quantum", hybrid:"Hybrid PQC", draft:"Draft PQC", classical:"Classical", weak:"Weak", unknown:"Unknown"};
const ORDER = ["pqc","hybrid","draft","classical","weak","unknown"];
const qs = s => `<span class="qs ${esc(s||"unknown")}">${QS[s]||QS.unknown}</span>`;
const CRYPTO_P = new Set(["PQC","TLS","SSH","IKE","ESP","MACsec","MKA","X.509","WireGuard"]);
const AI_P = new Set(["AI","gRPC","QUIC"]), FAB_P = new Set(["RoCE","PFC"]);
const pct = (a, b) => b ? Math.round(a / b * 100) : 0;
const grade = s => s == null ? ["—", "no key exchanges seen"] : s >= 80 ? ["A", "quantum-safe by default"] : s >= 60 ? ["B", "mostly quantum-safe"]
  : s >= 40 ? ["C", "mixed: plan the migration"] : s >= 20 ? ["D", "mostly classical"] : ["F", "harvest-now-decrypt-later exposed"];

function gauge(score){
  const r = 46, c = 2 * Math.PI * r, k = Math.max(0, Math.min(100, score ?? 0)) / 100;
  const col = score == null ? "var(--muted)" : score >= 60 ? "var(--lime)" : score >= 30 ? "var(--amber)" : "var(--red)";
  const [g, txt] = grade(score);
  return `<div class="gauge"><svg viewBox="0 0 110 110" role="img" aria-label="PQC readiness ${score ?? "not available"} out of 100, grade ${g}">
      <circle cx="55" cy="55" r="${r}" fill="none" stroke="var(--line)" stroke-width="9"/>
      <circle cx="55" cy="55" r="${r}" fill="none" stroke="${col}" stroke-width="9" stroke-linecap="round" stroke-dasharray="${c*k} ${c}" transform="rotate(-90 55 55)"/>
      <text x="55" y="58" text-anchor="middle">${score ?? "—"}</text><text class="grade" x="55" y="78" text-anchor="middle">grade ${g}</text></svg>
    <div><div class="k">PQC readiness</div><div class="s" style="font-size:13px;color:var(--ink)">${esc(txt)}</div>
      <div class="s">Share of key exchanges that are hybrid or pure ML-KEM; draft Kyber counts half.</div></div></div>`;
}
const tile = (k, v, s, tone) => `<div class="panel kpi"><div class="k">${k}</div><div class="v" ${tone?`style="color:${tone}"`:""}>${v}</div><div class="s">${s}</div></div>`;
const mixBar = counts => { const tot = ORDER.reduce((a,k)=>a+(counts[k]||0), 0) || 1;
  return `<div class="qbar" role="img" aria-label="${ORDER.filter(k=>counts[k]).map(k=>`${QS[k]} ${counts[k]}`).join(", ")}">${ORDER.filter(k=>counts[k]).map(k=>
    `<span class="q-${k}" style="flex:${counts[k]}" title="${QS[k]}: ${counts[k]} (${pct(counts[k], tot)}%)"></span>`).join("")}</div>`; };

/* sortable, clickable table: cols [{k, t, f(v,row), num}] */
function table(el, cols, rows, {onRow, empty="Nothing here."}={}){
  let key = null, dir = 1;
  const draw = () => {
    const rs = key == null ? rows : [...rows].sort((a,b)=>{ const x = a[key], y = b[key]; return (x == null) - (y == null) || (x > y ? dir : x < y ? -dir : 0); });
    el.innerHTML = rows.length ? `<div class="tbl"><table><thead><tr>${cols.map((c,i)=>`<th scope="col" data-i="${i}" class="${c.num?"num":""}" aria-sort="${key===c.k?(dir>0?"ascending":"descending"):"none"}">${esc(c.t)}${key===c.k?(dir>0?" ▲":" ▼"):""}</th>`).join("")}</tr></thead>
      <tbody>${rs.map((r,i)=>`<tr class="${onRow?"click":""}" data-r="${rows.indexOf(r)}" ${onRow?'tabindex="0"':""}>${cols.map(c=>`<td class="${c.num?"num":""}">${c.f ? c.f(r[c.k], r) : esc(r[c.k] ?? "—")}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`
      : `<p class="muted small">${esc(empty)}</p>`;
    el.querySelectorAll("th").forEach(th=>th.onclick = () => { const c = cols[+th.dataset.i]; dir = key === c.k ? -dir : 1; key = c.k; draw(); });
    if(onRow) el.querySelectorAll("tr[data-r]").forEach(tr=>{ const go = () => onRow(rows[+tr.dataset.r]); tr.onclick = go; tr.onkeydown = e => { if(e.key === "Enter") go(); }; });
  };
  draw();
}

async function insights(arg){
  const view = $("#view");
  const [id0, tab0] = (arg || "").split(/\/(?=crypto$|ai$|fabric$)/);
  const id = id0 || PL.lastCapture;
  if(!id){ PL.showState(view, {icon:"◈", title:"Pick a capture first", msg:"Insights summarise crypto / post-quantum posture, AI traffic and AI fabric health for one capture.",
    actions:[{label:"Open the library", href:"#/library"}, {label:"Open capture…", onclick:()=>$("#upload").click()}]}); return; }
  if(!arg){ location.replace("#/insights/" + encodeURIComponent(id)); return; }
  view.innerHTML = PL.skeleton();
  let d;
  try{ d = await api.get("/api/capture?id=" + encodeURIComponent(id)); } catch(e){ PL.errorState(view, e); return; }
  PL.setCapture(id);
  const C = d.crypto || {sessions:[], certificates:[], esp:[], macsec:[], mka:[], readiness:{counts:{}, by_protocol:{}, pqc_capable_clients:[]}};
  const A = d.ai || {flows:[], mcp:[], providers:[], clients:[]}, Fb = d.fabric || {qps:[], pfc:[]};
  const has = {crypto: C.sessions.length || C.certificates.length, ai: A.flows.length || A.mcp.length, fabric: Fb.qps.length || Fb.pfc.length};
  const tab = tab0 || (has.crypto ? "crypto" : has.ai ? "ai" : has.fabric ? "fabric" : "crypto");
  const enc = encodeURIComponent(id);
  view.innerHTML = `<div class="hero"><div><h1>${esc(d.meta.source)}</h1><div class="muted small">${d.stats.packets.toLocaleString()} packets · ${fmtT(d.stats.duration)} · Insights</div></div>
      <div class="spacer"></div><div class="ins-tabs" role="tablist" aria-label="Insight">
        ${[["crypto","Crypto & PQC", C.sessions.length], ["ai","AI traffic", A.flows.length], ["fabric","AI fabric", Fb.qps.length + Fb.pfc.length]].map(([k,l,n])=>
          `<button role="tab" data-tab="${k}" aria-selected="${k===tab}" aria-controls="ins-body" ${has[k]||k===tab?"":"disabled"}>${l}${n?` <span class="chip" style="margin:0 0 0 4px">${n}</span>`:""}</button>`).join("")}</div>
      <a class="btn ghost" href="#/analyze/${enc}">▤ Packets</a><a class="btn ghost" href="#/capture/${enc}">◎ 3D view</a>
      <a class="btn ghost" target="_blank" rel="noopener" href="/api/report?id=${enc}">Report ↗</a></div><div id="ins-body" role="tabpanel"></div>`;
  view.querySelectorAll(".ins-tabs button").forEach(b=>b.onclick = () => location.replace(`#/insights/${enc}/${b.dataset.tab}`));
  view.querySelector(".ins-tabs").onkeydown = e => {                       // arrow keys move between tabs
    const bs = [...view.querySelectorAll(".ins-tabs button:not(:disabled)")], i = bs.indexOf(document.activeElement);
    if(e.key === "ArrowRight" || e.key === "ArrowLeft"){ e.preventDefault(); bs[(i + (e.key === "ArrowRight" ? 1 : bs.length - 1)) % bs.length].focus(); }
  };
  const body = $("#ins-body");
  const pk = no => no ? () => PL.openPackets(id, {no}) : null;
  ({crypto:cryptoTab, ai:aiTab, fabric:fabricTab}[tab])(body, d, C, A, Fb, id, pk);
}

/* --------------------------------------------------------------- crypto */
function cryptoTab(el, d, C, A, Fb, id, pk){
  const R = C.readiness, certIssues = C.certificates.filter(c=>c.issues && c.issues.length);
  if(!C.sessions.length && !C.certificates.length){
    PL.showState(el, {icon:"🔒", title:"No key exchanges in this capture", msg:"No TLS, QUIC, SSH, IKE/IPsec, WireGuard, MACsec/MKA or EAP-TLS handshakes were seen."}); return; }
  el.innerHTML = `<div class="kpis"><div class="panel kpi gauge-tile">${gauge(R.score)}</div>
      ${tile("Quantum-safe", R.quantum_safe ?? 0, `of ${R.known} key exchange(s) with a known algorithm`, "var(--lime)")}
      ${tile("Harvest-now-decrypt-later", R.exposed ?? 0, "classical or weak key exchange", R.exposed ? "var(--amber)" : "")}
      ${tile("Weak", R.counts.weak || 0, "broken or deprecated today", R.counts.weak ? "var(--red)" : "")}
      ${tile("PQC-capable clients", R.pqc_capable_clients.length, "offered ML-KEM at least once")}
      ${tile("Certificate issues", certIssues.length, `of ${C.certificates.length} certificate(s)`, certIssues.length ? "var(--red)" : "")}</div>
    <div class="ins-grid"><div>
      <section class="panel"><h2>Key-exchange mix</h2>${mixBar(R.counts)}
        <div class="legend-row">${ORDER.filter(k=>R.counts[k]).map(k=>`${qs(k)} ${R.counts[k]}`).join("")}${C.sessions.length-R.known?` ${qs("unknown")} ${C.sessions.length-R.known}`:""}</div>
        <h3>By protocol</h3><div class="mix">${Object.entries(R.by_protocol).map(([p,c])=>`<span class="mono">${esc(p)}</span>${mixBar(c)}<span class="mono num">${Object.values(c).reduce((a,b)=>a+b,0)}</span>`).join("")}</div></section>
      <section class="panel" style="margin-top:14px"><h2>Key exchanges</h2>
        <div class="toolbar"><input type="search" id="cx-q" placeholder="Search server, client, algorithm…" aria-label="Search key exchanges">
          <select id="cx-p" aria-label="Protocol"><option value="">All protocols</option>${Object.keys(R.by_protocol).map(p=>`<option>${esc(p)}</option>`).join("")}</select>
          <span role="group" aria-label="Quantum status">${ORDER.filter(k=>C.sessions.some(s=>s.kex_status===k)).map(k=>`<button class="chip-btn" data-q="${k}" aria-pressed="true">${QS[k]}</button>`).join("")}</span></div>
        <div id="cx-t"></div><p class="small muted">Select a row to open its handshake in Analyze.</p></section>
      ${C.esp.length||C.macsec.length||C.mka.length?`<section class="panel" style="margin-top:14px"><h2>Link and tunnel security</h2><div id="cx-l2"></div></section>`:""}
    </div><div>
      <section class="panel"><h2>Certificates</h2><div class="certs" id="cx-c"></div></section>
      <section class="panel" style="margin-top:14px"><h2>Crypto findings</h2><div id="cx-f"></div></section></div></div>`;
  const S = {q:"", p:"", st:new Set(ORDER)};
  const draw = () => {
    const q = S.q.toLowerCase();
    const rows = C.sessions.filter(s=>S.st.has(s.kex_status) && (!S.p || s.proto === S.p) &&
      (!q || [s.name, s.client, s.server, s.kex, s.auth, s.cipher, s.result].join(" ").toLowerCase().includes(q)));
    table($("#cx-t", el), [{k:"proto", t:"Protocol"}, {k:"client", t:"Client", f:v=>`<span class="mono">${esc(v)}</span>`},
      {k:"name", t:"Server / peer", f:v=>`<span class="mono">${esc(v)}</span>`}, {k:"kex", t:"Key exchange", f:(v,r)=>`<span class="mono">${esc(v||"—")}</span><br>${qs(r.kex_status)}`},
      {k:"offered_status", t:"Best offered", f:qs}, {k:"auth", t:"Authentication", f:(v,r)=>v?`<span class="mono small">${esc(v)}</span> ${qs(r.auth_status)}`:"—"},
      {k:"result", t:"Result", f:v=>v==="ok"?'<span class="sev info">ok</span>':`<span class="sev medium">${esc(v)}</span>`},
      {k:"notes", t:"Notes", f:v=>`<span class="small muted">${esc((v||[]).join("; "))}</span>`}], rows, {onRow:r=>pk(r.no)?.(), empty:"No key exchange matches these filters."});
  };
  $("#cx-q", el).oninput = e => { S.q = e.target.value; draw(); };
  $("#cx-p", el).onchange = e => { S.p = e.target.value; draw(); };
  el.querySelectorAll("[data-q]").forEach(b=>b.onclick = () => { const k = b.dataset.q; S.st.has(k) ? S.st.delete(k) : S.st.add(k); b.setAttribute("aria-pressed", S.st.has(k)); draw(); });
  draw();
  const now = d.stats.end || Date.now()/1000;
  $("#cx-c", el).innerHTML = C.certificates.map((c,i)=>{
    const span = c.not_after && c.not_before ? c.not_after - c.not_before : 0, at = span ? Math.max(0, Math.min(100, (now - c.not_before) / span * 100)) : null;
    return `<div class="cert ${c.issues.length?"bad":""}"><h4>${esc(c.cn || c.subject)}</h4><div class="small muted">issued by ${esc(c.issuer_cn || c.issuer)}</div>
      <div class="small muted">${esc(c.context)}</div>
      ${at!=null?`<div class="validity" title="validity window; the marker is the capture time"><span style="width:${Math.min(100, at)}%"></span><i style="left:${at}%"></i></div>
        <div class="small muted">${new Date(c.not_before*1000).toISOString().slice(0,10)} → ${new Date(c.not_after*1000).toISOString().slice(0,10)}</div>`:""}
      <div class="row small" style="margin-top:6px">key ${esc(c.key_alg)}${c.key_size?"-"+c.key_size:""} ${qs(c.key_status)} sig ${esc(c.sig_alg)} ${qs(c.sig_status)}</div>
      ${c.issues.length?`<div style="margin-top:6px">${c.issues.map(x=>`<span class="sev ${/^(expired|weak|not yet)/.test(x)?"high":"medium"}">${esc(x)}</span>`).join("<br>")}</div>`:""}
      <div class="pk-chips"><button data-cert="${i}">#${c.no}</button></div></div>`; }).join("") || '<p class="muted small">No certificates visible (TLS 1.3 encrypts them unless a key log is supplied).</p>';
  el.querySelectorAll("[data-cert]").forEach(b=>b.onclick = () => pk(C.certificates[+b.dataset.cert].no)());
  if($("#cx-l2", el)){
    const l2 = $("#cx-l2", el); l2.innerHTML = `${C.esp.length?'<h3>ESP security associations</h3><div id="l2-e"></div>':""}${C.macsec.length?'<h3>MACsec secure channels</h3><div id="l2-m"></div>':""}${C.mka.length?'<h3>MKA participants</h3><div id="l2-k"></div>':""}`;
    const bad = v => v ? `<span class="sev high">${v}</span>` : "0";
    if(C.esp.length) table($("#l2-e", l2), [{k:"src",t:"Source"},{k:"dst",t:"Destination"},{k:"spi",t:"SPI",f:v=>`<span class="mono">${esc(v)}</span>`},{k:"packets",t:"Packets",num:1},
      {k:"missing",t:"Missing",num:1,f:bad},{k:"duplicates",t:"Duplicate",num:1,f:bad},{k:"reordered",t:"Reordered",num:1}], C.esp);
    if(C.macsec.length) table($("#l2-m", l2), [{k:"sci",t:"SCI",f:v=>`<span class="mono">${esc(v)}</span>`},{k:"an",t:"AN",num:1},{k:"packets",t:"Frames",num:1},
      {k:"missing_pn",t:"Missing PN",num:1,f:bad},{k:"replayed_pn",t:"Replayed PN",num:1,f:bad},{k:"max_pn",t:"Highest PN",num:1,f:v=>v>=0xC0000000?`<span class="sev high">${v.toLocaleString()}</span>`:v.toLocaleString()},
      {k:"modes",t:"Protection",f:v=>v.includes("integrity-only")?'<span class="sev medium">integrity only</span>':esc(v.join(", "))}], C.macsec);
    if(C.mka.length) table($("#l2-k", l2), [{k:"mac",t:"Participant",f:v=>`<span class="mono">${esc(v)}</span>`},{k:"key_server",t:"Key server",f:v=>v?"yes":""},
      {k:"live_peers",t:"Live peers",num:1,f:v=>v?v:'<span class="sev high">0</span>'},{k:"cipher",t:"SAK cipher",f:v=>esc(v||"—")},
      {k:"ckn_mismatch",t:"CKN",f:v=>v?'<span class="sev high">mismatch</span>':"ok"}], C.mka);
  }
  PL.findingsPanel($("#cx-f", el), d, {id, protocols:CRYPTO_P, compact:true});
}

/* ------------------------------------------------------------------- AI */
function aiTab(el, d, C, A, Fb, id, pk){
  if(!A.flows.length && !A.mcp.length){
    PL.showState(el, {icon:"✦", title:"No AI traffic recognised", msg:"No AI / LLM service names (SNI, QUIC, DNS, HTTP Host, certificates), API calls, MCP or gRPC inference were found."}); return; }
  const up = A.flows.reduce((a,f)=>a+(f.up||0), 0), streaming = A.flows.filter(f=>f.streaming).length;
  const slow = A.flows.reduce((m,f)=>f.ttft_s!=null && (!m || f.ttft_s > m.ttft_s) ? f : m, null);
  el.innerHTML = `<div class="kpis">
      ${tile("AI services", A.providers.length, esc(A.providers.slice(0,3).map(p=>p.provider).join(", ")) || "—")}
      ${tile("Clients", A.clients.length, "hosts talking to AI services")}
      ${tile("Uploaded to AI", fmtB(up), "client → AI bytes", up >= 1e6 ? "var(--amber)" : "")}
      ${tile("Streamed responses", streaming, `of ${A.flows.length} flow(s)`)}
      ${tile("Slowest first response", slow ? fmtT(slow.ttft_s) : "—", slow ? esc(slow.provider) : "measured from packet timing", slow && slow.ttft_s >= 5 ? "var(--red)" : "")}
      ${tile("MCP messages", A.mcp.length, A.mcp.length ? esc([...new Set(A.mcp.map(m=>m.tool).filter(Boolean))].join(", ")) || "no tool calls" : "Model Context Protocol")}</div>
    <div class="ins-grid"><div>
      <section class="panel"><h2>AI flows</h2><p class="small muted">First response and stalls come from packet timing, so they work on encrypted traffic too. Select a row to open it in Analyze.</p><div id="ai-f"></div></section>
      ${A.mcp.length?`<section class="panel" style="margin-top:14px"><h2>Model Context Protocol</h2><div id="ai-m"></div></section>`:""}
    </div><div>
      <section class="panel"><h2>Services</h2><div class="bars" id="ai-p"></div>
        <div class="legend-row"><span><span class="mini" style="--c:var(--magenta)"><i style="width:100%"></i></span>uploaded</span><span><span class="mini"><i style="width:100%"></i></span>downloaded</span></div></section>
      <section class="panel" style="margin-top:14px"><h2>AI findings</h2><div id="ai-x"></div></section></div></div>`;
  const maxB = Math.max(1, ...A.providers.map(p=>p.up + p.down));
  $("#ai-p", el).innerHTML = A.providers.map(p=>`<div class="b"><span><b>${esc(p.provider)}</b> <span class="muted small">${esc(p.category)} · ${p.clients.length} client(s)</span></span>
      <span class="mono small">↑${fmtB(p.up)} ↓${fmtB(p.down)}</span><div class="track" title="${esc(p.names.join(", "))}"><span class="up" style="width:${p.up/maxB*100}%"></span><span class="down" style="width:${p.down/maxB*100}%"></span></div></div>`).join("");
  const maxT = Math.max(5, ...A.flows.map(f=>f.ttft_s||0));
  const secBar = (v, bad) => v == null ? "—" : `<span class="mini" style="--c:${v>=bad?"var(--red)":"var(--cyan)"}"><i style="width:${Math.min(100, v/maxT*100)}%"></i></span><span class="mono">${fmtT(v)}</span>`;
  table($("#ai-f", el), [{k:"provider", t:"Service", f:(v,r)=>`<b>${esc(v)}</b><br><span class="small muted">${esc(r.category)}</span>`},
    {k:"client", t:"Client", f:v=>`<span class="mono">${esc(v)}</span>`}, {k:"name", t:"Endpoint", f:(v,r)=>`<span class="mono small">${esc(v)}</span><br><span class="small muted">via ${esc(r.evidence.join(", "))}</span>`},
    {k:"api", t:"API", f:v=>`<span class="small">${esc((v||[]).join(", "))}</span>`}, {k:"up", t:"↑ Up", num:1, f:v=>v==null?"—":`<span style="${v>=1e6?"color:var(--amber);font-weight:600":""}">${fmtB(v)}</span>`},
    {k:"down", t:"↓ Down", num:1, f:fmtB}, {k:"ttft_s", t:"First response", f:v=>secBar(v, 5)},
    {k:"max_gap_s", t:"Longest stall", f:(v,r)=>r.streaming ? secBar(v, 5) : "—"}], A.flows, {onRow:r=>pk(r.no)?.()});
  if(A.mcp.length) table($("#ai-m", el), [{k:"client",t:"Client",f:v=>`<span class="mono">${esc(v)}</span>`},{k:"server",t:"MCP server",f:v=>`<span class="mono">${esc(v)}</span>`},
    {k:"method",t:"Method",f:v=>`<span class="mono">${esc(v)}</span>`},{k:"tool",t:"Tool",f:v=>v?`<b class="mono">${esc(v)}</b>`:""},
    {k:"tls",t:"Transport",f:v=>v?"TLS":'<span class="sev medium">cleartext</span>'},{k:"status",t:"HTTP",num:1}], A.mcp, {onRow:r=>pk(r.no)?.()});
  PL.findingsPanel($("#ai-x", el), d, {id, protocols:AI_P, compact:true});
}

/* --------------------------------------------------------------- fabric */
function fabricTab(el, d, C, A, Fb, id, pk){
  if(!Fb.qps.length && !Fb.pfc.length){
    PL.showState(el, {icon:"⧉", title:"No RDMA fabric traffic", msg:"No RoCEv2 (UDP 4791) or PFC / PAUSE frames in this capture."}); return; }
  const sum = k => Fb.qps.reduce((a,q)=>a+(q[k]||0), 0), pfcN = Fb.pfc.reduce((a,s)=>a+s.frames, 0), storm = Fb.pfc.filter(s=>s.rate_per_s >= 50);
  el.innerHTML = `<div class="kpis">${tile("Queue pairs", Fb.qps.length, "RoCEv2 RC/UD flows")}
      ${tile("Missing PSNs", sum("gaps"), "lost RDMA packets", sum("gaps") ? "var(--red)" : "")}
      ${tile("Go-back-N", sum("retx"), "retransmitted packets", sum("retx") ? "var(--red)" : "")}
      ${tile("Congestion", `${sum("cnps")} / ${sum("ce")}`, "CNP / ECN-CE marked", sum("cnps") + sum("ce") ? "var(--amber)" : "")}
      ${tile("PFC frames", pfcN, storm.length ? `${storm.length} pause storm(s)` : "pause / resume", storm.length ? "var(--red)" : "")}</div>
    <div class="ins-grid"><div><section class="panel"><h2>RoCEv2 queue pairs</h2><div id="fb-q"></div></section>
      <section class="panel" style="margin-top:14px"><h2>Priority Flow Control</h2><div id="fb-p"></div></section></div>
      <div><section class="panel"><h2>Fabric findings</h2><div id="fb-x"></div></section></div></div>`;
  const bad = (v, tone="high") => v ? `<span class="sev ${tone}">${v}</span>` : "0";
  table($("#fb-q", el), [{k:"src",t:"Sender",f:v=>`<span class="mono">${esc(v)}</span>`},{k:"dst",t:"Receiver",f:v=>`<span class="mono">${esc(v)}</span>`},
    {k:"qp",t:"QP",f:v=>`<span class="mono">${esc(v)}</span>`},{k:"packets",t:"Packets",num:1},{k:"bytes",t:"Bytes",num:1,f:fmtB},
    {k:"gaps",t:"Missing PSN",num:1,f:v=>bad(v)},{k:"retx",t:"Go-back-N",num:1,f:v=>bad(v)},{k:"naks",t:"NAK",num:1,f:v=>bad(v)},
    {k:"cnps",t:"CNP",num:1,f:v=>bad(v,"medium")},{k:"ce",t:"ECN-CE",num:1,f:v=>bad(v,"medium")},
    {k:"not_ect",t:"Not ECT",num:1,f:(v,r)=>v&&v===r.packets?'<span class="sev medium">all</span>':v}], Fb.qps, {onRow:r=>pk(r.first)?.()});
  table($("#fb-p", el), [{k:"mac",t:"Sender MAC",f:v=>`<span class="mono">${esc(v)}</span>`},{k:"kind",t:"Type"},{k:"priority",t:"Priority"},
    {k:"frames",t:"Frames",num:1},{k:"pausing",t:"Pausing",num:1},{k:"resumes",t:"Resume",num:1},{k:"max_quanta",t:"Max quanta",num:1},
    {k:"rate_per_s",t:"Frames/s",num:1,f:v=>v>=50?`<span class="sev high">${v}</span>`:v}], Fb.pfc, {empty:"No PFC or PAUSE frames."});
  PL.findingsPanel($("#fb-x", el), d, {id, protocols:FAB_P, compact:true});
}

PL.views.insights = insights;
})();
