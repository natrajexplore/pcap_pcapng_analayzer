/* PacketLens Studio — Analyze tab: Wireshark-style packet list, details tree, bytes, filters, follow stream,
   statistics and export. Registers itself as the "analyze" view (see app.js). */
(function(){
"use strict";
const PL = window.PL, {api, esc, toast} = PL;
const $ = (s, r=document) => r.querySelector(s);
const ROW = 22, PAGE = 400;
const COMMON = ["tcp.analysis.flags", "tcp.analysis.retransmission", "tcp.flags.syn == 1 && tcp.flags.ack == 0", "tcp.flags.reset == 1",
  "dns", "dns.flags.rcode != 0", "http.request", "http.response.code >= 400", "tls.handshake.type == 1", "icmp || icmpv6",
  "arp", "dhcp", "!(arp || stp || cdp || lldp || dtp || loop)", "frame.len > 1400", "frame.marked"];
const store = (k, v) => { try{ if(v === undefined) return JSON.parse(localStorage.getItem(k)); localStorage.setItem(k, JSON.stringify(v)); }catch(e){ return null; } };
const fmtBytes = n => n >= 1e9 ? (n/1e9).toFixed(1)+" GB" : n >= 1e6 ? (n/1e6).toFixed(1)+" MB" : n >= 1e3 ? (n/1e3).toFixed(1)+" kB" : n+" B";

async function analyze(id){
  const view = $("#view");
  let lib = null;
  try{ lib = await api.get("/api/library"); }catch(e){}
  const caps = lib && lib.folders ? lib.folders.flatMap(f=>f.captures.map(c=>c.id)) : [];
  if(!id){
    view.innerHTML = `<div class="hero"><div><h1>Analyze packets</h1><div class="muted">Open a .pcap / .pcapng file or pick one from the library to inspect it packet by packet, Wireshark-style.</div></div></div>
      <div class="panel wb-pick"><label class="btn hot">Open capture file…<input type="file" id="wb-open" accept=".pcap,.pcapng,.cap" hidden></label>
      <div class="drop" id="wb-drop">…or drop a capture file here</div>
      ${caps.length?`<h3>Library</h3><div class="wb-caps">${caps.map(c=>`<a href="#/analyze/${encodeURIComponent(c)}">${esc(c)}</a>`).join("")}</div>`:""}</div>`;
    const open = async f => { if(!f) return; toast(`Loading ${f.name}…`);
      try{ const r = await api.post("/api/upload?name="+encodeURIComponent(f.name), await f.arrayBuffer(), true); location.hash = "#/analyze/"+encodeURIComponent(r.id); }
      catch(err){ toast("Could not open: "+err.message); } };
    $("#wb-open").onchange = e => open(e.target.files[0]);
    const dz = $("#wb-drop"); ["dragenter","dragover"].forEach(ev=>dz.addEventListener(ev, e=>{ e.preventDefault(); dz.classList.add("over"); }));
    ["dragleave","drop"].forEach(ev=>dz.addEventListener(ev, e=>{ e.preventDefault(); dz.classList.remove("over"); }));
    dz.addEventListener("drop", e=>open(e.dataTransfer.files[0]));
    return;
  }

  // ------------------------------------------------------------------ layout
  const Q = s => "/api/pkt/" + s + (s.includes("?") ? "&" : "?") + "id=" + encodeURIComponent(id);
  view.innerHTML = `<div class="wb">
    <div class="wb-bar">
      <select id="wb-file" aria-label="Capture">${[id, ...caps.filter(c=>c!==id)].map(c=>`<option value="${esc(c)}">${esc(c.replace(/^upload:[^:]+:/,"📄 ").replace(/^sim:.*/,"🧪 simulation").replace(/^live:.*/,"● live capture"))}</option>`).join("")}</select>
      <label class="btn ghost small-btn">Open…<input type="file" id="wb-open" accept=".pcap,.pcapng,.cap" hidden></label>
      <span class="sep"></span>
      <button class="ghost small-btn" data-stat="hierarchy">Protocol Hierarchy</button><button class="ghost small-btn" data-stat="conversations">Conversations</button>
      <button class="ghost small-btn" data-stat="endpoints">Endpoints</button><button class="ghost small-btn" data-stat="io">I/O Graph</button>
      <button class="ghost small-btn" data-stat="expert">Expert Info</button>
      <span class="sep"></span>
      <button class="ghost small-btn" id="wb-follow" disabled>Follow stream</button>
      <button class="ghost small-btn" id="wb-export">Export…</button>
      <span class="spacer"></span>
      <select id="wb-time" aria-label="Time display format"><option value="rel">Seconds since start</option><option value="delta">Since previous displayed</option>
        <option value="utc">UTC date and time</option><option value="epoch">Seconds since epoch</option></select>
      <label class="small muted row" style="gap:4px"><input type="checkbox" id="wb-color" checked> Colorize</label>
      <a class="btn ghost small-btn" href="#/capture/${encodeURIComponent(id)}">3D view</a>
    </div>
    <div class="wb-filter"><button class="ghost small-btn" id="wb-bm" aria-label="Saved filters">★ ▾</button>
      <input id="wb-q" spellcheck="false" autocomplete="off" placeholder="Apply a display filter … &lt;Enter&gt;   e.g.  ip.addr == 10.0.0.1 && tcp.port == 443" aria-label="Display filter">
      <button id="wb-apply" class="small-btn">Apply</button><button id="wb-clear" class="ghost small-btn">Clear</button>
      <input id="wb-goto" class="goto" placeholder="Go to #" aria-label="Go to packet number" inputmode="numeric"></div>
    <div class="wb-menu" id="wb-bmenu" hidden></div>
    <div class="wb-panes">
      <div class="wb-list" id="wb-list" tabindex="0" role="grid" aria-label="Packet list"><div class="wb-head"><span>No.</span><span>Time</span><span>Source</span><span>Destination</span><span>Protocol</span><span>Length</span><span>Info</span></div>
        <div class="wb-scroll" id="wb-scroll"><div class="wb-spacer" id="wb-spacer"></div></div></div>
      <div class="wb-split" data-split="0" role="separator" aria-label="Resize"></div>
      <div class="wb-lower"><div class="wb-tree" id="wb-tree"><div class="muted small" style="padding:10px">Select a packet.</div></div>
        <div class="wb-split v" data-split="1" role="separator" aria-label="Resize"></div>
        <div class="wb-bytes" id="wb-bytes"></div></div>
    </div>
    <div class="wb-status" id="wb-status">Loading…</div>
    <div class="wb-ctx" id="wb-ctx" hidden></div>
    <div class="wb-modal" id="wb-modal" hidden><div class="panel"><div class="wb-modal-head"><h2 id="wb-mtitle"></h2><span class="spacer"></span><button class="ghost small-btn" id="wb-mclose">Close ✕</button></div><div id="wb-mbody"></div></div></div>
  </div>`;
  const S = {filter:"", matched:0, total:0, pages:new Map(), sel:null, marked:new Set(store("pl-marks:"+id)||[]), firstTs:0,
             time:store("pl-time")||"rel", color:true, detail:null, fieldSel:null, loading:new Set()};
  $("#wb-time").value = S.time;
  const listEl = $("#wb-scroll"), spacer = $("#wb-spacer");
  const saveMarks = () => store("pl-marks:"+id, [...S.marked]);
  const markedParam = () => [...S.marked].join(",");

  $("#wb-file").onchange = e => location.hash = "#/analyze/"+encodeURIComponent(e.target.value);
  $("#wb-open").onchange = async e => { const f = e.target.files[0]; if(!f) return; toast(`Loading ${f.name}…`);
    try{ const r = await api.post("/api/upload?name="+encodeURIComponent(f.name), await f.arrayBuffer(), true); location.hash = "#/analyze/"+encodeURIComponent(r.id); }
    catch(err){ toast("Could not open: "+err.message); } };

  // ------------------------------------------------------------ packet list
  async function loadPage(pi){
    if(S.pages.has(pi) || S.loading.has(pi)) return;
    S.loading.add(pi);
    const gen = S.gen;
    try{
      const d = await api.get(Q(`list?offset=${pi*PAGE}&limit=${PAGE}&filter=${encodeURIComponent(S.filter)}&marked=${markedParam()}`));
      if(gen !== S.gen) return;
      S.pages.set(pi, d.rows); S.firstTs = d.first_ts; render();
    }catch(e){ toast(e.message); }
    finally{ S.loading.delete(pi); }
  }
  const rowAt = i => { const pg = S.pages.get(Math.floor(i/PAGE)); return pg ? pg[i % PAGE] : null; };
  function timeCell(r, i){
    if(S.time === "utc") return new Date(r.ts*1000).toISOString().replace("T"," ").replace("Z","");
    if(S.time === "epoch") return r.ts.toFixed(6);
    if(S.time === "delta"){ const p = i > 0 ? rowAt(i-1) : null; return i === 0 ? "0.000000" : p ? (r.t - p.t).toFixed(6) : "…"; }
    return r.t.toFixed(6);
  }
  function render(){
    spacer.style.height = (S.matched*ROW) + "px";
    const top = listEl.scrollTop, h = listEl.clientHeight, first = Math.max(0, Math.floor(top/ROW) - 10), last = Math.min(S.matched, Math.ceil((top+h)/ROW) + 10);
    const need = new Set(); for(let i=first;i<last;i++) need.add(Math.floor(i/PAGE)); need.forEach(pi=>loadPage(pi));
    let html = "";
    for(let i=first;i<last;i++){
      const r = rowAt(i);
      if(!r){ html += `<div class="wb-row loading" style="top:${i*ROW}px"><span>…</span></div>`; continue; }
      html += `<div class="wb-row ${S.color?"c-"+esc(r.color):""} ${S.sel===r.no?"sel":""} ${S.marked.has(r.no)?"marked":""}" style="top:${i*ROW}px" data-i="${i}" data-no="${r.no}" role="row">
        <span>${r.no}</span><span>${timeCell(r,i)}</span><span>${esc(r.src??"")}</span><span>${esc(r.dst??"")}</span><span>${esc(r.proto)}</span><span>${r.len}</span><span>${esc(r.info)}</span></div>`;
    }
    [...listEl.querySelectorAll(".wb-row")].forEach(x=>x.remove());
    spacer.insertAdjacentHTML("beforeend", html);
    status();
  }
  listEl.addEventListener("scroll", ()=>requestAnimationFrame(render));
  listEl.addEventListener("click", e=>{ const r = e.target.closest(".wb-row"); if(r && r.dataset.no) select(+r.dataset.no, +r.dataset.i); });
  listEl.addEventListener("contextmenu", e=>{ const r = e.target.closest(".wb-row"); if(!r || !r.dataset.no) return; e.preventDefault();
    select(+r.dataset.no, +r.dataset.i); rowMenu(e.clientX, e.clientY, rowAt(+r.dataset.i)); });
  $("#wb-list").addEventListener("keydown", e=>{
    const i = S.selIndex ?? -1, vis = Math.floor(listEl.clientHeight/ROW);
    const go = j => { j = Math.max(0, Math.min(S.matched-1, j)); const r = rowAt(j); if(r) select(r.no, j, true); else { listEl.scrollTop = j*ROW; loadPage(Math.floor(j/PAGE)).then(()=>{ const r2 = rowAt(j); if(r2) select(r2.no, j, true); }); } };
    if(e.key==="ArrowDown"){ e.preventDefault(); go(i+1); } else if(e.key==="ArrowUp"){ e.preventDefault(); go(i-1); }
    else if(e.key==="PageDown"){ e.preventDefault(); go(i+vis); } else if(e.key==="PageUp"){ e.preventDefault(); go(i-vis); }
    else if(e.key==="Home"){ e.preventDefault(); go(0); } else if(e.key==="End"){ e.preventDefault(); go(S.matched-1); }
    else if((e.ctrlKey||e.metaKey) && e.key.toLowerCase()==="m" && S.sel){ e.preventDefault(); toggleMark(S.sel); }
  });
  function toggleMark(no){ S.marked.has(no) ? S.marked.delete(no) : S.marked.add(no); saveMarks(); render(); }
  function ensureVisible(i){ const top = listEl.scrollTop, h = listEl.clientHeight;
    if(i*ROW < top) listEl.scrollTop = i*ROW; else if((i+1)*ROW > top+h) listEl.scrollTop = (i+1)*ROW - h; }

  async function applyFilter(text){
    S.filter = text.trim(); S.gen = (S.gen||0)+1; S.pages.clear(); S.loading.clear();
    const t0 = performance.now();
    try{
      const d = await api.get(Q(`list?offset=0&limit=${PAGE}&filter=${encodeURIComponent(S.filter)}&marked=${markedParam()}`));
      S.pages.set(0, d.rows); S.matched = d.matched; S.total = d.total; S.firstTs = d.first_ts;
      $("#wb-q").className = S.filter ? "ok" : ""; S.lastMs = Math.round(performance.now()-t0);
      if(S.filter) remember(S.filter);
      listEl.scrollTop = 0; render();
      if(S.sel != null){ const f = await api.get(Q(`find?no=${S.sel}&filter=${encodeURIComponent(S.filter)}&marked=${markedParam()}`));
        if(f.index != null){ S.selIndex = f.index; listEl.scrollTop = Math.max(0, f.index*ROW - listEl.clientHeight/2); render(); } }
      else if(d.rows.length) select(d.rows[0].no, 0);
    }catch(e){ $("#wb-q").className = "bad"; $("#wb-status").innerHTML = `<span style="color:var(--red)">${esc(e.message)}</span>`; }
  }

  // ---------------------------------------------------------- details + bytes
  async function select(no, i, keyboard){
    S.sel = no; S.selIndex = i; if(keyboard) ensureVisible(i); render();
    $("#wb-follow").disabled = true;
    try{
      const d = await api.get(Q(`detail?no=${no}`)); if(S.sel !== no) return;
      S.detail = d; S.fieldSel = null;
      const r = rowAt(i); $("#wb-follow").disabled = !(r && r.l4); $("#wb-follow").dataset.proto = r && r.l4 || "";
      drawTree(); drawBytes();
    }catch(e){ $("#wb-tree").innerHTML = `<div class="muted small" style="padding:10px">${esc(e.message)}</div>`; }
  }
  const openState = store("pl-tree-open") || {};
  function drawTree(){
    let k = 0; const nodes = [];
    const walk = (list, depth, path) => list.map(n=>{ const idx = k++; nodes[idx] = n; const key = path + "/" + n.label.split(/[,:(]/)[0];
      const kids = n.children && n.children.length; const open = kids && openState[key] === true;   // collapsed like Wireshark unless opened before
      return `<li class="${kids?"has":""} ${open?"open":""}" data-k="${idx}" data-key="${esc(key)}"><div class="tn ${S.fieldSel===idx?"sel":""}" tabindex="-1">
        <span class="tw">${kids?(open?"▾":"▸"):""}</span><span class="tl ${n.range?"":"gen"}">${esc(n.label)}</span>
        ${n.field?`<span class="tact"><button class="ghost mini" data-act="apply" title="Apply as filter">⊕</button><button class="ghost mini" data-act="prep" title="Prepare as filter (append with &&)">＋</button></span>`:""}</div>
        ${kids?`<ul>${walk(n.children, depth+1, key)}</ul>`:""}</li>`; }).join("");
    $("#wb-tree").innerHTML = `<ul class="tree">${walk(S.detail.tree, 0, "")}</ul>`;
    S.nodes = nodes;
    $("#wb-tree").querySelectorAll(".tn").forEach(el=>el.onclick = e=>{
      const li = el.parentElement, n = nodes[+li.dataset.k];
      const act = e.target.dataset.act;
      if(act && n.field){ const expr = filterFor(n); if(act === "apply") setFilter(expr); else { const q = $("#wb-q"); q.value = q.value.trim() ? `${q.value.trim()} && ${expr}` : expr; q.focus(); } return; }
      if(e.target.classList.contains("tw") || e.detail === 2 || !n.range){ li.classList.toggle("open"); openState[li.dataset.key] = li.classList.contains("open");
        el.querySelector(".tw").textContent = li.classList.contains("open") ? "▾" : (li.classList.contains("has") ? "▸" : ""); store("pl-tree-open", openState); }
      S.fieldSel = +li.dataset.k; $("#wb-tree").querySelectorAll(".tn.sel").forEach(x=>x.classList.remove("sel")); el.classList.add("sel");
      drawBytes(n.range); status(n);
    });
  }
  const filterFor = n => { const v = n.value; if(v === null || v === undefined) return n.field;
    return typeof v === "number" ? `${n.field} == ${v}` : /^[\w.:\-\/]+$/.test(String(v)) && /\d/.test(String(v)) && !/^\d+$/.test(String(v)) ? `${n.field} == ${v}` : `${n.field} == "${String(v).replace(/"/g,'\\"')}"`; };
  function drawBytes(range){
    const hex = S.detail.bytes, n = hex.length/2, [a,len] = range || [-1,0], b = a+len;
    let html = "";
    for(let off=0; off<n; off+=16){
      let h = "", s = "";
      for(let j=0;j<16;j++){ const i = off+j;
        if(i >= n){ h += "   "; continue; }
        const byte = parseInt(hex.substr(i*2,2),16), inR = i >= a && i < b, cls = inR ? ' class="hl"' : "";
        h += `<span${cls} data-o="${i}">${hex.substr(i*2,2)}</span>${j===7?"  ":" "}`;
        s += `<span${cls} data-o="${i}">${byte>=32&&byte<127?esc(String.fromCharCode(byte)):"·"}</span>`; }
      html += `<div><span class="off">${off.toString(16).padStart(4,"0")}</span>  ${h} ${s}</div>`;
    }
    $("#wb-bytes").innerHTML = html;
    const hl = $("#wb-bytes .hl"); if(hl) hl.scrollIntoView({block:"nearest"});
  }
  $("#wb-bytes").addEventListener("click", e=>{       // clicking a byte selects the most specific field covering it
    const o = +e.target.dataset?.o; if(isNaN(o) || !S.nodes) return;
    let best = -1, bestLen = 1e9; S.nodes.forEach((n,i)=>{ if(n.range && o >= n.range[0] && o < n.range[0]+n.range[1] && n.range[1] <= bestLen){ best = i; bestLen = n.range[1]; } });
    if(best < 0) return;
    let li = $(`#wb-tree li[data-k="${best}"]`); for(let p = li?.parentElement?.closest("li"); p; p = p.parentElement.closest("li")) p.classList.add("open");
    li?.querySelector(".tn")?.click(); li?.scrollIntoView({block:"nearest"});
  });

  // ---------------------------------------------------------------- filters
  function setFilter(text){ $("#wb-q").value = text; applyFilter(text); }
  let vt = null;
  $("#wb-q").addEventListener("input", ()=>{ clearTimeout(vt); const v = $("#wb-q").value;
    vt = setTimeout(async ()=>{ if(!v.trim()){ $("#wb-q").className = ""; return; }
      try{ await api.get(Q(`list?offset=0&limit=0&filter=${encodeURIComponent(v)}&marked=${markedParam()}`)); $("#wb-q").className = v.trim() === S.filter ? "ok" : "valid"; }
      catch(e){ $("#wb-q").className = "bad"; $("#wb-q").title = e.message; } }, 350); });
  $("#wb-q").addEventListener("keydown", e=>{ if(e.key === "Enter") applyFilter($("#wb-q").value); });
  $("#wb-apply").onclick = () => applyFilter($("#wb-q").value);
  $("#wb-clear").onclick = () => setFilter("");
  const recent = () => store("pl-filters") || [];
  function remember(f){ const r = [f, ...recent().filter(x=>x!==f)].slice(0, 12); store("pl-filters", r); }
  $("#wb-bm").onclick = e => { const m = $("#wb-bmenu"); if(!m.hidden){ m.hidden = true; return; }
    m.innerHTML = (recent().length?`<div class="mh">Recent</div>${recent().map(f=>`<a data-f="${esc(f)}">${esc(f)}</a>`).join("")}`:"") + `<div class="mh">Common</div>${COMMON.map(f=>`<a data-f="${esc(f)}">${esc(f)}</a>`).join("")}`;
    m.hidden = false; m.querySelectorAll("a").forEach(a=>a.onclick = ()=>{ m.hidden = true; setFilter(a.dataset.f); }); e.stopPropagation(); };
  document.addEventListener("click", closeMenus); PL.onLeave(()=>document.removeEventListener("click", closeMenus));
  function closeMenus(){ $("#wb-bmenu") && ($("#wb-bmenu").hidden = true); $("#wb-ctx") && ($("#wb-ctx").hidden = true); }
  $("#wb-goto").addEventListener("keydown", async e=>{ if(e.key !== "Enter") return; const no = +e.target.value; if(!no) return;
    const f = await api.get(Q(`find?no=${no}&filter=${encodeURIComponent(S.filter)}&marked=${markedParam()}`));
    if(f.index == null){ toast(`Packet ${no} is not displayed with the current filter`); return; }
    listEl.scrollTop = Math.max(0, f.index*ROW - listEl.clientHeight/2); await loadPage(Math.floor(f.index/PAGE)); select(no, f.index); });
  $("#wb-time").onchange = e => { S.time = e.target.value; store("pl-time", S.time); render(); };
  $("#wb-color").onchange = e => { S.color = e.target.checked; render(); };

  // ------------------------------------------------------------- context menu
  function rowMenu(x, y, r){
    const m = $("#wb-ctx"); if(!r) return;
    const conv = r.src && r.dst ? (String(r.src).includes(":") && !String(r.src).includes(".") && String(r.src).split(":").length === 6 ? `eth.addr == ${r.src} && eth.addr == ${r.dst}`
                 : `${String(r.src).includes(":") ? "ipv6" : "ip"}.addr == ${r.src} && ${String(r.src).includes(":") ? "ipv6" : "ip"}.addr == ${r.dst}`) : null;
    const items = [[S.marked.has(r.no) ? "Unmark packet" : "Mark packet (Ctrl+M)", ()=>toggleMark(r.no)],
      ...(r.l4 ? [[`Follow ${r.l4.toUpperCase()} stream`, ()=>follow(r.no, r.l4)]] : []),
      ...(r.stream != null ? [[`Filter on TCP stream ${r.stream}`, ()=>setFilter(`tcp.stream eq ${r.stream}`)]] : []),
      ...(conv ? [["Filter on this conversation", ()=>setFilter(conv)], ["Exclude this conversation", ()=>setFilter(S.filter ? `(${S.filter}) && !(${conv})` : `!(${conv})`)]] : []),
      [`Filter on protocol ${r.proto}`, ()=>setFilter(r.proto.toLowerCase())],
      ["Show 3D path view", ()=>location.hash = "#/capture/"+encodeURIComponent(id)]];
    m.innerHTML = items.map(([t],i)=>`<a data-i="${i}">${esc(t)}</a>`).join("");
    m.querySelectorAll("a").forEach(a=>a.onclick = ()=>{ m.hidden = true; items[+a.dataset.i][1](); });
    m.style.left = Math.min(x, innerWidth-260)+"px"; m.style.top = Math.min(y, innerHeight-m.childElementCount*30-20)+"px"; m.hidden = false;
  }

  // ------------------------------------------------------------------ modals
  function modal(title, html){ $("#wb-mtitle").textContent = title; $("#wb-mbody").innerHTML = html; $("#wb-modal").hidden = false; }
  $("#wb-mclose").onclick = () => $("#wb-modal").hidden = true;
  $("#wb-modal").addEventListener("click", e=>{ if(e.target.id === "wb-modal") $("#wb-modal").hidden = true; });
  addEventListener("keydown", escClose); PL.onLeave(()=>removeEventListener("keydown", escClose));
  function escClose(e){ if(e.key === "Escape" && $("#wb-modal")) $("#wb-modal").hidden = true; }
  $("#wb-follow").onclick = () => S.sel && follow(S.sel, $("#wb-follow").dataset.proto);

  async function follow(no, proto){
    let d; try{ d = await api.get(Q(`follow?no=${no}&proto=${proto}`)); }catch(e){ toast(e.message); return; }
    const chunks = d.chunks.map(c=>({...c, bytes: c.hex.match(/../g)?.map(h=>parseInt(h,16)) || []}));
    const asText = () => chunks.map(c=>`<span class="${c.client?"fc":"fs"}" data-no="${c.no}">${esc(c.bytes.map(b=>b===10||b===13||b===9||(b>=32&&b<127)?String.fromCharCode(b):".").join(""))}</span>`).join("");
    const asHex = () => chunks.map(c=>{ let out = ""; for(let i=0;i<c.bytes.length;i+=16){ const sl = c.bytes.slice(i,i+16);
      out += `${i.toString(16).padStart(8,"0")}  ${sl.map(b=>b.toString(16).padStart(2,"0")).join(" ").padEnd(48)}  ${sl.map(b=>b>=32&&b<127?String.fromCharCode(b):".").join("")}\n`; }
      return `<span class="${c.client?"fc":"fs"}">${esc(out)}</span>`; }).join("");
    modal(`Follow ${proto.toUpperCase()} Stream (${d.filter})`, `<div class="row small muted" style="margin-bottom:8px">
        <span class="fc">■ ${esc(d.client)} → ${esc(d.server)} (${fmtBytes(d.bytes_client)})</span><span class="fs">■ ${esc(d.server)} → ${esc(d.client)} (${fmtBytes(d.bytes_server)})</span>
        ${d.truncated?"<span>(first 2 MB)</span>":""}<span class="spacer"></span>
        <label class="row" style="gap:4px">Show as <select id="fl-as"><option value="a">ASCII</option><option value="h">Hex dump</option></select></label>
        <button class="small-btn" id="fl-in">Filter this stream</button><button class="ghost small-btn" id="fl-out">Filter out this stream</button></div>
      <pre class="follow" id="fl-body">${asText()||"<span class='muted'>No payload in this stream.</span>"}</pre>`);
    $("#fl-as").onchange = e => $("#fl-body").innerHTML = e.target.value === "h" ? asHex() : asText();
    $("#fl-in").onclick = () => { $("#wb-modal").hidden = true; setFilter(d.filter); };
    $("#fl-out").onclick = () => { $("#wb-modal").hidden = true; setFilter(`!(${d.filter})`); };
  }

  view.querySelectorAll("[data-stat]").forEach(b=>b.onclick = () => stats(b.dataset.stat));
  async function stats(kind, opts={}){
    const limit = opts.limit ?? (S.filter ? true : false), flt = limit ? S.filter : "";
    const url = Q(`stats?kind=${kind}&filter=${encodeURIComponent(flt)}&marked=${markedParam()}${opts.interval?"&interval="+opts.interval:""}`);
    let d; try{ d = await api.get(url); }catch(e){ toast(e.message); return; }
    const lim = S.filter ? `<label class="row small" style="gap:6px;margin-bottom:8px"><input type="checkbox" id="st-lim" ${limit?"checked":""}> Limit to display filter <code>${esc(S.filter)}</code></label>` : "";
    const rebind = () => { const c = $("#st-lim"); if(c) c.onchange = () => stats(kind, {...opts, limit:c.checked}); };
    if(kind === "hierarchy"){
      const T = d.total_packets || 1, TB = d.total_bytes || 1;
      const rows = (n, depth) => `<tr><td style="padding-left:${8+depth*16}px">${esc(n.name)}</td><td class="num"><span class="bar" style="--w:${n.packets/T*100}%"></span>${(n.packets/T*100).toFixed(1)}%</td>
        <td class="num">${n.packets.toLocaleString()}</td><td class="num">${(n.bytes/TB*100).toFixed(1)}%</td><td class="num">${fmtBytes(n.bytes)}</td>
        <td><button class="ghost mini" data-f="${esc(n.name)}">filter</button></td></tr>` + n.children.map(c=>rows(c, depth+1)).join("");
      modal("Protocol Hierarchy Statistics", lim + `<div class="tbl"><table><thead><tr><th>Protocol</th><th>% Packets</th><th>Packets</th><th>% Bytes</th><th>Bytes</th><th></th></tr></thead>
        <tbody>${rows(d.tree, 0)}</tbody></table></div>`);
      $("#wb-mbody").querySelectorAll("[data-f]").forEach(b=>b.onclick = () => { if(b.dataset.f === "Frame") return; $("#wb-modal").hidden = true; setFilter(b.dataset.f); });
    } else if(kind === "conversations" || kind === "endpoints"){
      const kinds = Object.keys(d), conv = kind === "conversations";
      const cols = conv ? [["a","Address A"],["b","Address B"],["packets","Packets",1],["bytes","Bytes",1],["pkts_ab","Pkts A→B",1],["bytes_ab","Bytes A→B",1],
          ["pkts_ba","Pkts B→A",1],["bytes_ba","Bytes B→A",1],["start","Rel Start",1],["duration","Duration",1],["bps_ab","bps A→B",1],["bps_ba","bps B→A",1]]
        : [["address","Address"],["packets","Packets",1],["bytes","Bytes",1],["tx_packets","Tx Packets",1],["tx_bytes","Tx Bytes",1],["rx_packets","Rx Packets",1],["rx_bytes","Rx Bytes",1]];
      let tab = opts.tab && d[opts.tab] ? opts.tab : kinds.find(k=>d[k].length) || kinds[0], sortK = conv ? "bytes" : "bytes", dir = -1;
      const fld = {Ethernet:"eth.addr", IPv4:"ip.addr", IPv6:"ipv6.addr", TCP:"tcp", UDP:"udp"};
      const fOf = (t, r) => { if(t === "TCP" || t === "UDP"){ const p = x => { const i = x.lastIndexOf(":"); return [x.slice(0,i), x.slice(i+1)]; };
          const ipf = x => x.includes(":") ? "ipv6.addr" : "ip.addr", pr = t.toLowerCase();
          if(!conv){ const [ip, port] = p(r.address); return `${ipf(ip)} == ${ip} && ${pr}.port == ${port}`; }
          const [ia, pa] = p(r.a), [ib, pb] = p(r.b); return `${ipf(ia)} == ${ia} && ${pr}.port == ${pa} && ${ipf(ib)} == ${ib} && ${pr}.port == ${pb}`; }
        return conv ? `${fld[t]} == ${r.a} && ${fld[t]} == ${r.b}` : `${fld[t]} == ${r.address}`; };
      const draw = () => { const rows = [...d[tab]].sort((x,y)=>(x[sortK] > y[sortK] ? 1 : x[sortK] < y[sortK] ? -1 : 0)*dir);
        $("#st-body").innerHTML = `<table><thead><tr>${cols.map(([k,t,num])=>`<th class="${num?"num":""}" data-k="${k}">${t}${sortK===k?(dir<0?" ▾":" ▴"):""}</th>`).join("")}<th></th></tr></thead>
          <tbody>${rows.map((r,i)=>`<tr>${cols.map(([k,,num])=>`<td class="${num?"num":""} ${num?"":"mono"}">${k.includes("bytes")&&num?fmtBytes(r[k]):typeof r[k]==="number"?r[k].toLocaleString():esc(r[k])}</td>`).join("")}
            <td><button class="ghost mini" data-r="${i}">filter</button></td></tr>`).join("")||`<tr><td colspan="${cols.length}" class="muted">None</td></tr>`}</tbody></table>`;
        $("#st-body").querySelectorAll("th[data-k]").forEach(th=>th.onclick = () => { if(sortK === th.dataset.k) dir = -dir; else { sortK = th.dataset.k; dir = -1; } draw(); });
        $("#st-body").querySelectorAll("[data-r]").forEach(b=>b.onclick = () => { $("#wb-modal").hidden = true; setFilter(fOf(tab, rows[+b.dataset.r])); }); };
      modal(conv ? "Conversations" : "Endpoints", lim + `<div class="tabs">${kinds.map(k=>`<button data-tab="${k}" class="${k===tab?"on":""}">${k} · ${d[k].length}</button>`).join("")}</div><div class="tbl" id="st-body"></div>`);
      $("#wb-mbody").querySelectorAll("[data-tab]").forEach(b=>b.onclick = () => { tab = b.dataset.tab; $("#wb-mbody").querySelectorAll("[data-tab]").forEach(x=>x.classList.toggle("on", x===b)); draw(); });
      draw();
    } else if(kind === "io"){
      const ivs = [0.001, 0.01, 0.1, 1, 10, 60];
      modal("I/O Graph", lim + `<div class="row small" style="margin-bottom:8px">Interval <select id="io-iv">${ivs.map(v=>`<option ${v===d.interval?"selected":""} value="${v}">${v>=1?v+" s":v*1000+" ms"}</option>`).join("")}</select>
        <select id="io-unit"><option value="p">Packets / interval</option><option value="b">Bytes / interval</option></select>
        <span class="legend-i"><i style="background:var(--cyan)"></i>all packets</span>${flt?`<span class="legend-i"><i style="background:var(--magenta)"></i>${esc(flt)}</span>`:""}
        <span class="legend-i"><i style="background:var(--red)"></i>TCP errors</span><span class="muted">Click the graph to jump to that time.</span></div><canvas id="io-c" height="340"></canvas>`);
      const cv = $("#io-c"), draw = () => { const w = cv.width = cv.clientWidth*devicePixelRatio, h = cv.height = 340*devicePixelRatio, g = cv.getContext("2d"), B = d.bins, bytes = $("#io-unit").value === "b";
        const va = b => bytes ? b.all_bytes : b.all, vm = b => bytes ? b.match_bytes : b.match, max = Math.max(1, ...B.map(va)), pad = 44*devicePixelRatio, W = w-pad-10, H = h-30*devicePixelRatio;
        g.clearRect(0,0,w,h); g.font = `${11*devicePixelRatio}px system-ui`; g.fillStyle = "#6c7699"; g.strokeStyle = "rgba(120,160,255,.15)";
        [0,.5,1].forEach(k=>{ const y = 10+H*(1-k); g.beginPath(); g.moveTo(pad,y); g.lineTo(w-10,y); g.stroke(); g.fillText(bytes?fmtBytes(Math.round(max*k)):Math.round(max*k), 4, y+4); });
        const x = i => pad + i/(Math.max(1,B.length-1))*W, y = v => 10 + H*(1-v/max);
        g.fillStyle = "rgba(255,75,92,.85)"; B.forEach((b,i)=>{ if(b.bad){ const bw = Math.max(1.5, W/B.length*.8); g.fillRect(x(i)-bw/2, y(bytes?0:b.bad), bw, H+10-y(bytes?0:b.bad)); } });
        const line = (fn, col) => { g.beginPath(); B.forEach((b,i)=>i?g.lineTo(x(i),y(fn(b))):g.moveTo(x(i),y(fn(b)))); g.strokeStyle = col; g.lineWidth = 2*devicePixelRatio; g.shadowColor = col; g.shadowBlur = 8; g.stroke(); g.shadowBlur = 0; };
        line(va, "#3ef2ff"); if(flt) line(vm, "#ff3fd8");
        g.fillStyle = "#6c7699"; [0, Math.floor(B.length/2), B.length-1].forEach(i=>{ if(B[i]) g.fillText(B[i].t+"s", x(i)-12, h-8); }); };
      draw(); $("#io-unit").onchange = draw; $("#io-iv").onchange = e => stats("io", {...opts, limit, interval:e.target.value});
      cv.onclick = async e => { const r = cv.getBoundingClientRect(), pad = 44, i = Math.round((e.clientX-r.left-pad)/(r.width-pad-10)*(d.bins.length-1));
        const b = d.bins[Math.max(0, Math.min(d.bins.length-1, i))]; if(!b) return; $("#wb-modal").hidden = true;
        setFilter(`frame.time_relative >= ${b.t}` + (S.filter ? ` && (${S.filter})` : "")); };
    } else if(kind === "expert"){
      const sevCls = {Error:"critical", Warning:"high", Note:"low", Chat:"info"};
      modal("Expert Information", lim + `<div class="row" style="margin-bottom:10px">${Object.entries(d.counts).map(([k,v])=>`<span class="sev ${sevCls[k]}">${k} ${v}</span>`).join("")}</div>
        <div class="tbl"><table><thead><tr><th>Severity</th><th>Summary</th><th>Protocol</th><th class="num">Count</th></tr></thead><tbody>
        ${d.groups.map((g,i)=>`<tr class="click" data-g="${i}"><td><span class="sev ${sevCls[g.severity]}">${g.severity}</span></td><td>${esc(g.summary)}</td><td>${esc(g.protocol)}</td><td class="num">${g.count}</td></tr>
          <tr class="pk" id="eg-${i}" hidden><td colspan="4">${g.packets.slice(0,200).map(n=>`<a class="mono" data-no="${n}">#${n}</a>`).join(" ")}</td></tr>`).join("")}</tbody></table></div>
        ${d.findings.length?`<h3>PacketLens findings</h3>${d.findings.map(f=>`<div class="find"><span class="sev ${esc(f.severity)}">${esc(f.severity)}</span> <b>${esc(f.title)}</b><div class="small muted">${esc(f.summary)}</div>
          <div class="small">${f.packets.slice(0,30).map(n=>`<a class="mono" data-no="${n}">#${n}</a>`).join(" ")}</div></div>`).join("")}`:""}`);
      $("#wb-mbody").querySelectorAll("tr[data-g]").forEach(tr=>tr.onclick = () => { const x = $("#eg-"+tr.dataset.g); x.hidden = !x.hidden; });
      $("#wb-mbody").querySelectorAll("a[data-no]").forEach(a=>a.onclick = async () => { $("#wb-modal").hidden = true; $("#wb-goto").value = a.dataset.no;
        $("#wb-goto").dispatchEvent(new KeyboardEvent("keydown", {key:"Enter"})); });
    }
    rebind();
  }

  $("#wb-export").onclick = () => {
    modal("Export packets", `<p class="small">Save packets as a new pcapng file (opens in Wireshark).</p><div class="row">
      <a class="btn" href="${Q(`export?filter=${encodeURIComponent(S.filter)}&marked=${markedParam()}`)}" download>All displayed packets (${S.matched.toLocaleString()})</a>
      <a class="btn ghost ${S.marked.size?"":"disabled"}" ${S.marked.size?`href="${Q(`export?only=marked&marked=${markedParam()}`)}" download`:""}>Marked packets (${S.marked.size})</a></div>`);
  };

  // ---------------------------------------------------------------- panes
  view.querySelectorAll(".wb-split").forEach(sp=>sp.addEventListener("pointerdown", e=>{
    const vertical = sp.classList.contains("v"), panes = $(".wb-panes"), list = $("#wb-list"), tr = $("#wb-tree");
    sp.setPointerCapture(e.pointerId);
    const move = ev => { if(vertical){ const r = sp.parentElement.getBoundingClientRect(); tr.style.flex = `0 0 ${Math.max(150, Math.min(r.width-150, ev.clientX-r.left))}px`; }
      else { const r = panes.getBoundingClientRect(); list.style.flex = `0 0 ${Math.max(120, Math.min(r.height-120, ev.clientY-r.top))}px`; } render(); };
    const up = () => { sp.removeEventListener("pointermove", move); sp.removeEventListener("pointerup", up); };
    sp.addEventListener("pointermove", move); sp.addEventListener("pointerup", up); }));

  function status(n){
    const pct = S.total ? (S.matched/S.total*100).toFixed(1) : "0";
    $("#wb-status").innerHTML = `<span>Packets: <b>${S.total.toLocaleString()}</b></span><span>Displayed: <b>${S.matched.toLocaleString()}</b> (${pct}%)</span>
      <span>Marked: <b>${S.marked.size}</b></span>${S.lastMs!=null?`<span>Filter: ${S.lastMs} ms</span>`:""}
      ${n&&n.field?`<span class="mono">${esc(n.field)}${n.value!=null?" == "+esc(n.value):""}</span>`:n&&n.range?`<span class="mono">bytes ${n.range[0]}–${n.range[0]+n.range[1]-1}</span>`:""}`;
  }

  // -------------------------------------------------------------- start
  await applyFilter("");
  $("#wb-list").focus();
}
PL.views.analyze = analyze;
})();
