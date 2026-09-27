/* PacketLens neon 3D engine (Three.js r149 UMD).
   Glow is additive-blended halo sprites (the UMD build ships no post-processing passes). */
(function(){
"use strict";
const T = window.THREE;
const KIND_COLOR = {router:0x3ef2ff, l3switch:0xa07bff, switch:0x7dff6a, host:0xcfe0ff, server:0xffc23e, ap:0xff3fd8,
                    cloud:0x6c7699, segment:0x6c7699, rogue:0xff4b5c};
const KIND_Y = {cloud:4.2, router:2, l3switch:1.6, switch:0.4, segment:0, ap:0.6, host:-1.2, server:-1.2, rogue:-1.2};
const STATUS_COLOR = {ok:0x7dff6a, warn:0xffc23e, degraded:0xffc23e, oneway:0x3ef2ff, fail:0xff4b5c, reject:0xff3fd8, drop:0xff4b5c};

let GLOW = null;
function glowTexture(){
  if(GLOW) return GLOW;
  const c = document.createElement("canvas"); c.width = c.height = 128; const g = c.getContext("2d");
  const r = g.createRadialGradient(64,64,0,64,64,64);
  r.addColorStop(0,"rgba(255,255,255,1)"); r.addColorStop(.18,"rgba(255,255,255,.75)"); r.addColorStop(.45,"rgba(255,255,255,.18)"); r.addColorStop(1,"rgba(255,255,255,0)");
  g.fillStyle = r; g.fillRect(0,0,128,128);
  GLOW = new T.CanvasTexture(c); return GLOW;
}
function halo(color, scale, opacity=.9){
  const s = new T.Sprite(new T.SpriteMaterial({map:glowTexture(), color, transparent:true, opacity, blending:T.AdditiveBlending, depthWrite:false}));
  s.scale.setScalar(scale); return s;
}

function Neon(el, opts={}){
  const W = () => el.clientWidth || 800, H = () => el.clientHeight || 500;
  const renderer = new T.WebGLRenderer({antialias:true, alpha:true, powerPreference:"high-performance"});
  renderer.setPixelRatio(Math.min(2, devicePixelRatio||1)); renderer.setSize(W(), H());
  renderer.toneMapping = T.ACESFilmicToneMapping; renderer.toneMappingExposure = 1.15;
  el.appendChild(renderer.domElement);
  const cv = renderer.domElement;
  const scene = new T.Scene(); scene.fog = new T.FogExp2(0x05060b, 0.008);
  const camera = new T.PerspectiveCamera(45, W()/H(), .1, 3000);
  scene.add(new T.AmbientLight(0x6070a0, .55));
  const key = new T.PointLight(0x7fd8ff, 1.4, 400); key.position.set(20, 40, 30); scene.add(key);
  const rim = new T.PointLight(0xff3fd8, .9, 400); rim.position.set(-40, 10, -30); scene.add(rim);

  // ---- ambience: floor grid + starfield
  const grid = new T.GridHelper(400, 80, 0x1c3b6e, 0x0f1c38); grid.position.y = -4; grid.material.transparent = true; grid.material.opacity = .55; scene.add(grid);
  const starG = new T.BufferGeometry(), sp = new Float32Array(1800*3);
  for(let i=0;i<sp.length;i+=3){ const r = 180+Math.random()*420, th = Math.random()*Math.PI*2, ph = Math.acos(2*Math.random()-1);
    sp[i]=r*Math.sin(ph)*Math.cos(th); sp[i+1]=Math.abs(r*Math.cos(ph))*.6+10; sp[i+2]=r*Math.sin(ph)*Math.sin(th); }
  starG.setAttribute("position", new T.BufferAttribute(sp,3));
  scene.add(new T.Points(starG, new T.PointsMaterial({color:0x8fb4ff, size:1.4, sizeAttenuation:true, transparent:true, opacity:.55, depthWrite:false})));
  // heat field: a glowing floor texture fed by opts/setHeat
  const heatCanvas = document.createElement("canvas"); heatCanvas.width = 256; heatCanvas.height = 32;
  const heatTex = new T.CanvasTexture(heatCanvas);
  const heat = new T.Mesh(new T.PlaneGeometry(120, 14), new T.MeshBasicMaterial({map:heatTex, transparent:true, opacity:.85, blending:T.AdditiveBlending, depthWrite:false}));
  heat.rotation.x = -Math.PI/2; heat.position.set(0, -3.95, 9); heat.visible = false; scene.add(heat);

  const nodes = new Map(), links = [], labels = new Map(), lenses = [], live = [], free = [];
  const root = new T.Group(); scene.add(root);
  const geo = {router:new T.CylinderGeometry(1.1,1.1,.8,32), l3switch:new T.BoxGeometry(2.4,.9,1.6), switch:new T.BoxGeometry(2.6,.55,1.5),
               host:new T.BoxGeometry(1.3,1,1.1), server:new T.BoxGeometry(1.1,2.2,1.2), ap:new T.ConeGeometry(.95,1.5,24),
               cloud:new T.IcosahedronGeometry(1.8,1), segment:new T.TorusGeometry(1.3,.14,12,48), rogue:new T.OctahedronGeometry(1.1)};

  function addNode(n, pos){
    if(nodes.has(n.id)) return nodes.get(n.id);
    const color = KIND_COLOR[n.kind] ?? KIND_COLOR.host, inferred = n.observed === false || n.kind === "cloud";
    const g = new T.Group(); g.position.set(...pos); g.userData = n;
    const core = new T.Mesh(geo[n.kind]||geo.host, new T.MeshStandardMaterial({color:0x0b1020, emissive:color, emissiveIntensity:inferred?.18:.55,
                            roughness:.35, metalness:.6, transparent:inferred, opacity:inferred?.35:1}));
    if(n.kind === "segment") core.rotation.x = Math.PI/2;
    const edges = new T.LineSegments(new T.EdgesGeometry(core.geometry, 25), new T.LineBasicMaterial({color, transparent:true, opacity:inferred?.45:.95, blending:T.AdditiveBlending}));
    edges.rotation.copy(core.rotation);
    const h = halo(color, inferred?3:5.5, inferred?.35:.8);
    g.add(core, edges, h); root.add(g);
    const base = n.kind === "segment" || n.kind === "cloud" ? 1.3 : 1.7;          // devices drawn large enough to read
    g.scale.setScalar(base);
    const d = document.createElement("div"); d.className = "lbl"+(inferred?" inf":""); d.textContent = n.label||n.id; el.appendChild(d);
    const rec = {g, core, edges, halo:h, color, label:d, phase:Math.random()*6, pulse:0, base};
    nodes.set(n.id, rec); labels.set(n.id, d); return rec;
  }
  function linkBetween(a, b, kind="l2", observed=true, capture=false){
    const A = nodes.get(a), B = nodes.get(b); if(!A||!B) return;
    const pts = [A.g.position, B.g.position];
    const color = kind === "tunnel" ? 0xa07bff : (observed ? 0x3a6bd8 : 0x33406a);
    const mat = kind === "tunnel" || !observed ? new T.LineDashedMaterial({color, dashSize:.7, gapSize:.45, transparent:true, opacity:.9, blending:T.AdditiveBlending})
                                               : new T.LineBasicMaterial({color, transparent:true, opacity:.75, blending:T.AdditiveBlending});
    const line = new T.Line(new T.BufferGeometry().setFromPoints(pts), mat); line.computeLineDistances(); root.add(line);
    const L = {a, b, line, kind, activity:0}; links.push(L);
    if(capture){
      // a shared capture segment gets one lens on the segment itself, not one per attached device
      const seg = [a, b].find(id=>nodes.get(id).g.userData.kind === "segment");
      if(!seg) addLens(a, b);
      else if(!lenses.some(l=>l.a === seg && l.b === seg)) addLens(seg, seg);
    }
    return L;
  }
  function addLens(a, b){
    const A = nodes.get(a).g.position, B = nodes.get(b).g.position, mid = A.clone().add(B).multiplyScalar(.5); mid.y += a === b ? 2.6 : 1.6;
    const ring = new T.Mesh(new T.TorusGeometry(.8,.09,10,48), new T.MeshBasicMaterial({color:0x3ef2ff, transparent:true, opacity:.95, blending:T.AdditiveBlending}));
    ring.position.copy(mid); const glow = halo(0x3ef2ff, 3.2, .55); glow.position.copy(mid);
    root.add(ring, glow);
    const d = document.createElement("div"); d.className = "lbl cap"; d.textContent = "◉ capture point"; el.appendChild(d);
    const rec = {a, b, ring, glow, label:d, flash:0, pos:mid}; lenses.push(rec); return rec;
  }

  // ---- layouts
  function layoutForce(graph){
    const N = graph.nodes, idx = new Map(N.map((n,i)=>[n.id,i])), P = N.map((n,i)=>[Math.cos(i*2.39)*9, KIND_Y[n.kind]||0, Math.sin(i*2.39)*9]);
    const main = (graph.flows||[]).find(f=>f.kind!=="control"&&f.hops&&f.hops.length>1) || (graph.flows||[])[0];
    (main?main.hops:[]).forEach((h,i,arr)=>{ const k=idx.get(h); if(k!=null) P[k]=[(i-(arr.length-1)/2)*9, P[k][1], 0]; });
    const E = graph.links.map(l=>[idx.get(l.a), idx.get(l.b)]).filter(e=>e[0]!=null&&e[1]!=null);
    for(let it=0; it<380; it++){
      const F = N.map(()=>[0,0,0]), cool = 1-it/380;
      for(let i=0;i<N.length;i++) for(let j=i+1;j<N.length;j++){
        const d=[P[i][0]-P[j][0],P[i][1]-P[j][1],P[i][2]-P[j][2]], r2=Math.max(.6,d[0]*d[0]+d[1]*d[1]+d[2]*d[2]), f=70/r2, r=Math.sqrt(r2);
        for(let a=0;a<3;a++){ F[i][a]+=d[a]/r*f; F[j][a]-=d[a]/r*f; } }
      E.forEach(([i,j])=>{ const d=[P[j][0]-P[i][0],P[j][1]-P[i][1],P[j][2]-P[i][2]], r=Math.hypot(...d)||1, f=(r-8.5)*.2;
        for(let a=0;a<3;a++){ F[i][a]+=d[a]/r*f; F[j][a]-=d[a]/r*f; } });
      N.forEach((n,i)=>{ F[i][1]+=((KIND_Y[n.kind]||0)-P[i][1])*.7; F[i][2]-=P[i][2]*.035;
        for(let a=0;a<3;a++) P[i][a]+=Math.max(-2,Math.min(2,F[i][a]))*cool; });
    }
    return new Map(N.map((n,i)=>[n.id,P[i]]));
  }
  function layoutLine(graph){
    const n = graph.nodes.length, out = new Map();
    graph.nodes.forEach((nd,i)=>out.set(nd.id, nd.pos || [(i-(n-1)/2)*9, KIND_Y[nd.kind]||0, 0]));
    return out;
  }

  function setGraph(graph, mode="force"){
    clear(); root.clear(); nodes.clear(); links.length = 0;
    lenses.forEach(L=>L.label.remove()); lenses.length = 0;
    free.forEach(f=>f.d.remove()); free.length = 0;
    labels.forEach(d=>d.remove()); labels.clear();
    const pos = mode === "line" ? layoutLine(graph) : layoutForce(graph);
    graph.nodes.forEach(n=>addNode(n, pos.get(n.id)||[0,0,0]));
    const capSet = new Set((graph.capture_links||[]).map(([a,b])=>[a,b].sort().join("|")));
    graph.links.forEach(l=>linkBetween(l.a, l.b, l.kind, l.observed!==false, (l.captures&&l.captures.length>0) || capSet.has([l.a,l.b].sort().join("|"))));
    fit();
  }

  // ---- camera + controls
  let rad = 60, th = .5, ph = 1.1, auto = opts.autoRotate !== false, idle = 0; const target = new T.Vector3();
  function place(){ camera.position.set(target.x+rad*Math.sin(ph)*Math.sin(th), target.y+rad*Math.cos(ph), target.z+rad*Math.sin(ph)*Math.cos(th)); camera.lookAt(target); }
  function fit(){
    const box = new T.Box3(); nodes.forEach(r=>box.expandByPoint(r.g.position)); if(box.isEmpty()){ place(); return; }
    const c = box.getCenter(new T.Vector3()), s = box.getSize(new T.Vector3());
    camera.aspect = W()/H(); camera.updateProjectionMatrix();
    const vh = Math.tan(camera.fov*Math.PI/360), hh = vh*camera.aspect;
    rad = Math.max((Math.max(s.x, s.z)/2+9)/hh, (s.y/2+6)/vh, 18) + Math.min(s.x, s.z)/3;
    th = s.z < s.x*.25 ? .18 : .45; ph = 1.2;               // near-frontal for a straight path, 3/4 view for a spread graph
    target.copy(c); place();
  }
  let drag = null, pinch = null;
  cv.addEventListener("pointerdown", e=>{ drag={x:e.clientX,y:e.clientY,pan:e.button===2||e.shiftKey,moved:0}; cv.setPointerCapture(e.pointerId); cv.style.cursor="grabbing"; idle=0; });
  cv.addEventListener("pointermove", e=>{ if(!drag) return; const dx=e.clientX-drag.x, dy=e.clientY-drag.y; drag.x=e.clientX; drag.y=e.clientY; drag.moved+=Math.abs(dx)+Math.abs(dy);
    if(drag.pan){ const s=rad/700, r=new T.Vector3().subVectors(camera.position,target).cross(camera.up).normalize(); target.addScaledVector(r, dx*s).addScaledVector(camera.up, dy*s); }
    else { th-=dx*.006; ph=Math.max(.2,Math.min(Math.PI/2+.25, ph-dy*.006)); } place(); idle=0; });
  cv.addEventListener("pointerup", e=>{ cv.style.cursor="grab"; if(drag && drag.moved<5) pick(e); drag=null; });
  cv.addEventListener("contextmenu", e=>e.preventDefault());
  cv.addEventListener("wheel", e=>{ e.preventDefault(); rad=Math.max(6,Math.min(900, rad*(1+Math.sign(e.deltaY)*.1))); place(); idle=0; }, {passive:false});
  cv.addEventListener("touchmove", e=>{ if(e.touches.length===2){ const d=Math.hypot(e.touches[0].clientX-e.touches[1].clientX, e.touches[0].clientY-e.touches[1].clientY);
    if(pinch){ rad=Math.max(6,Math.min(900, rad*pinch/d)); place(); } pinch=d; } }, {passive:true});
  cv.addEventListener("touchend", ()=>pinch=null);
  const ray = new T.Raycaster(), mv = new T.Vector2(); let pickCb = null;
  function pick(e){ const r = cv.getBoundingClientRect(); mv.set(((e.clientX-r.left)/r.width)*2-1, -((e.clientY-r.top)/r.height)*2+1);
    ray.setFromCamera(mv, camera); const hit = ray.intersectObjects([...nodes.values()].map(n=>n.core))[0];
    if(hit && pickCb) pickCb(hit.object.parent.userData); }

  // ---- effects
  const dotGeo = new T.SphereGeometry(.26, 12, 10);
  function packet({path, status="ok", color=null, dieAt=null, speed=38, size=1, onDone=null, trail=true}){
    const pts = path.filter(id=>nodes.has(id)).map(id=>nodes.get(id).g.position.clone().add(new T.Vector3(0,1.1,0)));
    if(pts.length < 2){ if(onDone) onDone(); return; }
    const stop = dieAt!=null ? Math.max(1, path.filter(id=>nodes.has(id)).indexOf(dieAt)) : pts.length-1;
    const col = new T.Color(color ?? STATUS_COLOR[status] ?? STATUS_COLOR.ok);
    const m = new T.Mesh(dotGeo, new T.MeshBasicMaterial({color:col})); m.scale.setScalar(size);
    const h = halo(col, 2.4*size, .95); m.add(h);
    let tr = null;
    if(trail){ const n = 22, g = new T.BufferGeometry(); g.setAttribute("position", new T.BufferAttribute(new Float32Array(n*3),3));
      const c = new Float32Array(n*3); for(let i=0;i<n;i++){ const k=1-i/n; c[i*3]=col.r*k; c[i*3+1]=col.g*k; c[i*3+2]=col.b*k; }
      g.setAttribute("color", new T.BufferAttribute(c,3)); tr = new T.Line(g, new T.LineBasicMaterial({vertexColors:true, transparent:true, blending:T.AdditiveBlending, depthWrite:false}));
      tr.frustumCulled = false; root.add(tr); tr.userData.hist = []; }
    root.add(m);
    const segs = []; let total = 0;
    for(let i=0;i<pts.length-1;i++){ const l = pts[i].distanceTo(pts[i+1]); segs.push(l); total += l; }
    live.push({type:"pkt", m, tr, pts, segs, stop, t0:performance.now(), dur:Math.max(250, total/speed*1000), status, onDone,
               path:path.filter(id=>nodes.has(id)), lastSeg:-1, col});
  }
  function burst(at, color=0xff4b5c, big=1){
    const pos = at instanceof T.Vector3 ? at : nodes.get(at)?.g.position.clone().add(new T.Vector3(0,1.1,0)); if(!pos) return;
    const n = 70, g = new T.BufferGeometry(), p = new Float32Array(n*3), v = [];
    for(let i=0;i<n;i++){ p[i*3]=pos.x; p[i*3+1]=pos.y; p[i*3+2]=pos.z; const d = new T.Vector3(Math.random()-.5,Math.random()-.3,Math.random()-.5).normalize().multiplyScalar((4+Math.random()*9)*big); v.push(d); }
    g.setAttribute("position", new T.BufferAttribute(p,3));
    const pts = new T.Points(g, new T.PointsMaterial({color, size:.55*big, transparent:true, opacity:1, blending:T.AdditiveBlending, depthWrite:false}));
    const ring = new T.Mesh(new T.RingGeometry(.4,.6,48), new T.MeshBasicMaterial({color, transparent:true, opacity:.9, side:T.DoubleSide, blending:T.AdditiveBlending, depthWrite:false}));
    ring.position.copy(pos); ring.rotation.x = -Math.PI/2; const h = halo(color, 7*big, 1); h.position.copy(pos);
    root.add(pts, ring, h); live.push({type:"burst", pts, v, ring, h, t0:performance.now()});
  }
  function flashCapture(a, b){ lenses.forEach(L=>{ if((L.a===a&&L.b===b)||(L.a===b&&L.b===a)||(L.a===L.b&&(L.a===a||L.a===b))) L.flash = 1; }); }
  function pulse(id, color){ const n = nodes.get(id); if(n){ n.pulse = 1; if(color!=null) n.pulseColor = new T.Color(color); } }
  function highlight(ids){ const set = new Set(ids||[]); nodes.forEach((r,id)=>{ r.core.material.emissiveIntensity = set.size && !set.has(id) ? .12 : (r.g.userData.observed===false?.18:.55);
    r.halo.material.opacity = set.size && !set.has(id) ? .15 : (r.g.userData.observed===false?.35:.8); r.label.style.opacity = set.size && !set.has(id) ? .45 : 1; }); }
  function clear(){ live.forEach(o=>{ ["m","tr","pts","ring","h"].forEach(k=>o[k]&&root.remove(o[k])); }); live.length = 0; }
  function setHeat(bins, progress=1){
    if(!bins || !bins.length){ heat.visible = false; return; }
    const g = heatCanvas.getContext("2d"), w = heatCanvas.width, h = heatCanvas.height, max = Math.max(1,...bins.map(b=>b.v));
    g.clearRect(0,0,w,h);
    bins.forEach((b,i)=>{ const x = i/bins.length*w, bw = Math.ceil(w/bins.length)+1, k = b.v/max, dim = i/bins.length > progress ? .25 : 1;
      g.fillStyle = b.bad ? `rgba(255,75,92,${(.25+k*.75)*dim})` : `rgba(62,242,255,${(.1+k*.8)*dim})`; g.fillRect(x, h*(1-k)*.9, bw, h); });
    heatTex.needsUpdate = true; heat.visible = true;
  }

  // ---- frame loop
  const tmp = new T.Vector3(); let raf, alive = true, last = performance.now();
  function frame(now){
    if(!alive) return;
    raf = requestAnimationFrame(frame);
    const dt = Math.min(.05, (now-last)/1000); last = now; idle += dt;
    if(auto && idle > 4 && !drag){ th += dt*.06; place(); }
    nodes.forEach(r=>{ r.phase += dt; r.g.position.y += Math.sin(r.phase*1.3)*.002; r.edges.rotation.y += dt*.15; r.core.rotation.y = r.edges.rotation.y;
      if(r.pulse > 0){ r.pulse = Math.max(0, r.pulse-dt*1.6); r.g.scale.setScalar(r.base*(1+r.pulse*.35)); r.halo.material.opacity = .8+r.pulse; } });
    lenses.forEach(L=>{ L.ring.rotation.y += dt*1.2; L.ring.rotation.x = Math.sin(now/900)*.4; if(L.flash>0){ L.flash=Math.max(0,L.flash-dt*2.2); }
      const s = 1+L.flash*.9; L.ring.scale.setScalar(s); L.glow.scale.setScalar(3.2+L.flash*5); L.glow.material.opacity = .55+L.flash*.45; });
    for(let i=live.length-1;i>=0;i--){ const o = live[i];
      if(o.type === "pkt"){
        const k = Math.max(0, Math.min(1, (now-o.t0)/o.dur)); let d = k*o.segs.reduce((a,b)=>a+b,0), s = 0;
        while(s < o.segs.length-1 && d > o.segs[s]){ d -= o.segs[s]; s++; }
        if(s >= o.stop){ o.m.position.copy(o.pts[o.stop]); finishPkt(o); live.splice(i,1); continue; }
        if(s !== o.lastSeg){ if(o.lastSeg >= 0) flashCapture(o.path[o.lastSeg], o.path[o.lastSeg+1]); o.lastSeg = s; const L = links.find(l=>(l.a===o.path[s]&&l.b===o.path[s+1])||(l.b===o.path[s]&&l.a===o.path[s+1])); if(L) L.activity = 1; }
        o.m.position.lerpVectors(o.pts[s], o.pts[s+1], Math.min(1, d/(o.segs[s]||1)));
        if(o.tr){ const hist = o.tr.userData.hist; hist.unshift(o.m.position.clone()); if(hist.length > 22) hist.pop();
          const a = o.tr.geometry.attributes.position; for(let j=0;j<22;j++){ const p = hist[Math.min(j,hist.length-1)]; a.setXYZ(j,p.x,p.y,p.z); } a.needsUpdate = true; }
        if(k >= 1){ finishPkt(o); live.splice(i,1); }
      } else if(o.type === "burst"){
        const k = (now-o.t0)/1100; const a = o.pts.geometry.attributes.position;
        for(let j=0;j<o.v.length;j++){ a.setXYZ(j, a.getX(j)+o.v[j].x*dt, a.getY(j)+o.v[j].y*dt-k*dt*4, a.getZ(j)+o.v[j].z*dt); }
        a.needsUpdate = true; o.pts.material.opacity = Math.max(0,1-k); o.ring.scale.setScalar(1+k*14); o.ring.material.opacity = Math.max(0,.9-k); o.h.material.opacity = Math.max(0,1-k*2);
        if(k >= 1){ root.remove(o.pts, o.ring, o.h); live.splice(i,1); }
      }
    }
    links.forEach(L=>{ if(L.activity>0){ L.activity=Math.max(0,L.activity-dt*1.5); L.line.material.opacity = .75+L.activity*.25; L.line.material.color.setHex(L.activity>.05?0x3ef2ff:(L.kind==="tunnel"?0xa07bff:0x3a6bd8)); } });
    renderer.render(scene, camera);
    const w = W(), h = H(), placed = [];
    const put = (d, pos, dy) => { tmp.copy(pos); tmp.y += dy; tmp.project(camera); if(tmp.z>1||tmp.z<-1){ d.style.display="none"; return; }
      d.style.display = ""; let x = (tmp.x+1)/2*w, y = (1-tmp.y)/2*h; const lw = d.offsetWidth, lh = d.offsetHeight+2;
      for(const q of placed) if(Math.abs(q[0]-x) < (q[2]+lw)/2 && Math.abs(q[1]-y) < lh) y = q[1]-lh;
      placed.push([x,y,lw]); d.style.left = x+"px"; d.style.top = y+"px"; };
    nodes.forEach(r=>put(r.label, r.g.position, 1.4*r.base+.6));
    lenses.forEach(L=>put(L.label, L.pos, .9));
    free.forEach(f=>put(f.d, f.pos, 0));
  }
  function finishPkt(o){
    if(o.tr) root.remove(o.tr); root.remove(o.m);
    if(o.stop < o.pts.length-1 || o.status === "fail" || o.status === "drop"){ burst(o.pts[o.stop], STATUS_COLOR[o.status] ?? 0xff4b5c, o.status==="warn"?.6:1); }
    else if(o.path.length) pulse(o.path[o.path.length-1]);
    if(o.path[o.stop-1] != null) flashCapture(o.path[o.stop-1], o.path[o.stop]);
    if(o.onDone) o.onDone();
  }
  raf = requestAnimationFrame(frame);
  const ro = new ResizeObserver(()=>{ renderer.setSize(W(),H()); camera.aspect=W()/H(); camera.updateProjectionMatrix(); }); ro.observe(el);

  // ---- incremental graph for live mode
  function ensureNode(n){
    if(nodes.has(n.id)) return;
    const a = Math.random()*Math.PI*2, r = 6+Math.random()*18;
    addNode(n, [Math.cos(a)*r, KIND_Y[n.kind]||0, Math.sin(a)*r]);
  }
  function ensureLink(a, b){ if(!links.some(l=>(l.a===a&&l.b===b)||(l.a===b&&l.b===a))) linkBetween(a, b); }
  function relax(){
    const arr = [...nodes.values()];
    for(let i=0;i<arr.length;i++) for(let j=i+1;j<arr.length;j++){ const d = arr[i].g.position.clone().sub(arr[j].g.position); d.y = 0; const r2 = Math.max(1,d.lengthSq());
      d.normalize().multiplyScalar(Math.min(.3, 12/r2)); arr[i].g.position.add(d); arr[j].g.position.sub(d); }
    links.forEach(L=>{ const A = nodes.get(L.a).g.position, B = nodes.get(L.b).g.position, d = B.clone().sub(A); const r = d.length()||1, f = (r-10)*.01;
      d.normalize().multiplyScalar(f); d.y = 0; A.add(d); B.sub(d); L.line.geometry.setFromPoints([A,B]); });
  }

  function fitTo(obj){
    const box = new T.Box3().setFromObject(obj), c = box.getCenter(new T.Vector3()), s = box.getSize(new T.Vector3());
    const vh = Math.tan(camera.fov*Math.PI/360), hh = vh*camera.aspect;
    rad = Math.max((s.x/2+4)/hh, (s.y/2+4)/vh, 15)*1.1 + s.z/2; target.copy(c); th = .35; ph = 1.25; place();
  }
  function label(text, pos, cls="lbl"){       // a label at a fixed 3D point (not attached to a node)
    const d = document.createElement("div"); d.className = cls; d.textContent = text; el.appendChild(d);
    free.push({d, pos:pos.clone()}); return d;
  }

  return {setGraph, packet, burst, highlight, pulse, flashCapture, setHeat, fit, clear, ensureNode, ensureLink, relax, fitTo, label,
          add(obj){ root.add(obj); return obj; },
          onPick(cb){ pickCb = cb; }, nodePosition(id){ return nodes.get(id)?.g.position.clone(); }, has(id){ return nodes.has(id); },
          setAutoRotate(v){ auto = v; },
          dispose(){ alive = false; cancelAnimationFrame(raf); ro.disconnect(); renderer.dispose(); cv.remove(); labels.forEach(d=>d.remove()); lenses.forEach(L=>L.label.remove()); free.forEach(f=>f.d.remove()); }};
}
window.Neon = Neon;
window.NEON_STATUS = STATUS_COLOR;
})();
