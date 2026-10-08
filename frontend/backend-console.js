(function(){
  'use strict';
  const API='/api/v1';
  let clientId='authenticated-user';
  if(window.PGAuth?.user?.id) clientId=window.PGAuth.user.id;
  const $=s=>document.querySelector(s);
  const esc=v=>String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
  const fmt=v=>v?new Date(v).toLocaleString():'—';
  async function api(path,opts={}){const r=await fetch(API+path,{...opts,headers:{'Content-Type':'application/json',...(opts.headers||{})}});const d=await r.json().catch(()=>({error:'Invalid server response'}));if(!r.ok)throw new Error(d.error||`HTTP ${r.status}`);return d;}
  function toast(msg,type='info'){ if(typeof window.pgToast==='function') window.pgToast(msg,type); else alert(msg); }
  function addConsole(){
    const footer=document.querySelector('footer'); if(!footer||document.getElementById('pgBackendCenter'))return;
    const sec=document.createElement('section');sec.id='pgBackendCenter';sec.className='pg-backend-center';
    sec.innerHTML=`
      <div class="container">
        <div class="pg-backend-head">
          <div><span class="pg-backend-kicker">SERVER-SIDE SECURITY LAYER</span><h2>PhishGuard Backend Security Center</h2><p>Your original PhishGuard interface is now connected to a persistent Node.js + SQLite backend.</p></div>
          <div class="pg-live-pill" id="pgBackendStatus"><span></span> Checking backend...</div>
        </div>
        <div class="pg-backend-grid pg-metrics">
          <div class="pg-bcard"><small>Total backend scans</small><strong id="bTotal">0</strong><span>Stored in SQLite</span></div>
          <div class="pg-bcard"><small>Threats detected</small><strong id="bThreats">0</strong><span>Score ≥ 35</span></div>
          <div class="pg-bcard"><small>Critical</small><strong id="bCritical">0</strong><span>Immediate attention</span></div>
          <div class="pg-bcard"><small>Server uptime</small><strong id="bUptime">—</strong><span>Node.js process</span></div>
        </div>
        <div class="pg-backend-grid pg-tools">
          <div class="pg-bpanel pg-wide">
            <div class="pg-btitle"><div><b>Server-Side Analyzer</b><small>Run the analysis through the backend and save it permanently.</small></div><span class="pg-chip">REST API</span></div>
            <div class="pg-tabs"><button class="active" data-btab="message">Message</button><button data-btab="url">URL</button><button data-btab="intel">Live Intel</button></div>
            <div id="bTabMessage" class="btab"><textarea id="bMessage" placeholder="Paste a suspicious SMS, email, WhatsApp message or bank alert..."></textarea><div class="pg-actions"><button id="bAnalyzeMessage" class="pg-bprimary">Analyze with Backend</button><button id="bUseOriginal">Use Original Detector Text</button></div></div>
            <div id="bTabUrl" class="btab hidden"><input id="bUrl" placeholder="https://example.com/login"><div class="pg-actions"><button id="bAnalyzeUrl" class="pg-bprimary">Analyze URL on Server</button><button id="bUseOriginalUrl">Use Original URL</button></div></div>
            <div id="bTabIntel" class="btab hidden"><input id="bIntelUrl" placeholder="example.com"><div class="pg-actions"><button id="bIntel" class="pg-bprimary">Run DNS + RDAP Intelligence</button></div><div id="bIntelResult" class="pg-intel-result">No intelligence lookup yet.</div></div>
            <div id="bResult" class="pg-backend-result"><div class="pg-empty">Backend analysis results will appear here.</div></div>
          </div>
          <div class="pg-bpanel">
            <div class="pg-btitle"><div><b>Backend System Health</b><small>Live server diagnostics</small></div></div>
            <div id="bHealth" class="pg-health-list"></div>
            <div class="pg-endpoints"><b>API services</b><code>POST /analyze/message</code><code>POST /analyze/url</code><code>GET /dashboard</code><code>GET /scans</code><code>GET /threat-intel</code><code>POST /reports</code></div>
          </div>
        </div>
        <div class="pg-backend-grid">
          <div class="pg-bpanel pg-wide"><div class="pg-btitle"><div><b>Risk Analytics</b><small>Calculated from backend database records</small></div><button id="bRefresh" class="pg-smallbtn">↻ Refresh</button></div><div class="pg-bars" id="bBars"></div></div>
          <div class="pg-bpanel"><div class="pg-btitle"><div><b>Backend Actions</b><small>Data that survives page refresh</small></div></div><div class="pg-action-stack"><button id="bSync">⇅ Sync existing local scans</button><button id="bSaveQuiz">✓ Save latest quiz result</button><button id="bSaveChecklist">☑ Sync checklist</button><button id="bReport">▣ Create report from latest scan</button><button id="bExport">⇩ Export backend JSON</button></div><div id="bActionMsg" class="pg-action-msg"></div></div>
        </div>
        <div class="pg-bpanel"><div class="pg-btitle"><div><b>Persistent Scan History</b><small>Real records from SQLite, not LocalStorage</small></div><span id="bClient" class="pg-chip"></span></div><div class="pg-table-wrap"><table class="pg-btable"><thead><tr><th>Time</th><th>Type</th><th>Risk</th><th>Score</th><th>Confidence</th><th>Category</th><th>Action</th></tr></thead><tbody id="bHistory"><tr><td colspan="7">Loading...</td></tr></tbody></table></div></div>
        <div class="pg-bpanel"><div class="pg-btitle"><div><b>Saved Incident Reports</b><small>Generated by the backend report service</small></div></div><div id="bReports" class="pg-reports"></div></div>
      </div>`;
    footer.parentNode.insertBefore(sec,footer);
    bind(); refresh();
  }
  function renderResult(scan){
    const cls=scan.level.toLowerCase();
    $('#bResult').innerHTML=`<div class="pg-result-top"><div><span class="pg-risk ${cls}">${esc(scan.level)}</span><h3>${esc(scan.type==='url'?'URL':'Message')} analysis complete</h3></div><div class="pg-score"><strong>${scan.score}</strong><span>/100</span></div></div><div class="pg-result-meta"><span>Confidence: <b>${scan.confidence}%</b></span><span>Stored: <b>SQLite</b></span><span>ID: <b>${esc(scan.id)}</b></span></div><div class="pg-findings">${(scan.findings||[]).map(f=>`<div><b>${esc(f.title)}</b><span class="pg-mini ${String(f.severity||'LOW').toLowerCase()}">${esc(f.severity||'INFO')}</span><p>${esc(f.detail)}</p></div>`).join('')||'<div>No rule findings.</div>'}</div><div class="pg-recommend"><b>Recommended action</b><p>${esc(scan.recommendation)}</p></div>`;
  }
  function renderHistory(items){
    $('#bHistory').innerHTML=items.length?items.map(s=>`<tr><td>${esc(fmt(s.created_at))}</td><td>${esc(s.type.toUpperCase())}</td><td><span class="pg-mini ${s.level.toLowerCase()}">${esc(s.level)}</span></td><td><b>${s.score}</b></td><td>${s.confidence}%</td><td>${esc(s.category||'—')}</td><td><button class="pg-view" data-id="${esc(s.id)}">View</button></td></tr>`).join(''):'<tr><td colspan="7">No backend scans yet. Run the server-side analyzer above.</td></tr>';
    document.querySelectorAll('.pg-view').forEach(b=>b.onclick=async()=>{try{const d=await api('/scans/'+b.dataset.id);renderResult(d.scan);document.getElementById('pgBackendCenter').scrollIntoView({behavior:'smooth'});}catch(e){toast(e.message,'warning')}});
  }
  function renderBars(d){const vals=[['Safe',d.metrics.safe],['Medium',d.metrics.medium],['High',d.metrics.high],['Critical',d.metrics.critical]];const max=Math.max(1,...vals.map(x=>x[1]));$('#bBars').innerHTML=vals.map(([n,v])=>`<div class="pg-bar-row"><span>${n}</span><div><i style="width:${Math.round(v/max*100)}%"></i></div><b>${v}</b></div>`).join('');}
  async function refresh(){
    try{const h=await api('/health');$('#pgBackendStatus').innerHTML='<span></span> Backend ONLINE';$('#pgBackendStatus').classList.add('online');$('#bHealth').innerHTML=`<div><span>Service</span><b>${esc(h.service)}</b></div><div><span>Node</span><b>${esc(h.node)}</b></div><div><span>Database</span><b>SQLite / WAL</b></div><div><span>Database path</span><b>${esc(h.databasePath)}</b></div><div><span>Server time</span><b>${esc(fmt(h.time))}</b></div>`; }catch(e){$('#pgBackendStatus').innerHTML='<span></span> Backend OFFLINE';$('#bHealth').innerHTML='<div><span>Status</span><b>Backend unavailable</b></div>';return;}
    try{const d=await api('/dashboard?clientId='+encodeURIComponent(clientId));$('#bTotal').textContent=d.metrics.total;$('#bThreats').textContent=d.metrics.threats;$('#bCritical').textContent=d.metrics.critical;$('#bUptime').textContent=(d.server.uptime/3600).toFixed(1)+'h';renderBars(d);renderHistory(d.recent);}catch(e){toast(e.message,'warning')}
    try{const r=await api('/reports?clientId='+encodeURIComponent(clientId));$('#bReports').innerHTML=r.items.length?r.items.slice(0,10).map(x=>`<div class="pg-report-row"><div><b>${esc(x.title)}</b><span>${esc(x.severity)} · ${esc(fmt(x.created_at))}</span></div><button class="pg-view-report" data-json='${esc(JSON.stringify(x.report_json))}'>Open</button></div>`).join(''):'<div class="pg-empty">No backend reports yet.</div>';}catch(e){}
    $('#bClient').textContent='Session '+clientId.slice(-8);
  }
  function bind(){
    document.querySelectorAll('[data-btab]').forEach(btn=>btn.onclick=()=>{document.querySelectorAll('[data-btab]').forEach(x=>x.classList.remove('active'));btn.classList.add('active');document.querySelectorAll('.btab').forEach(x=>x.classList.add('hidden'));$('#bTab'+btn.dataset.btab[0].toUpperCase()+btn.dataset.btab.slice(1)).classList.remove('hidden');});
    $('#bAnalyzeMessage').onclick=async()=>{const text=$('#bMessage').value.trim();if(!text)return toast('Enter a message first.','warning');try{const d=await api('/analyze/message',{method:'POST',body:JSON.stringify({text,clientId})});renderResult(d.scan);refresh();toast('Backend scan saved to SQLite.','success')}catch(e){toast(e.message,'warning')}};
    $('#bAnalyzeUrl').onclick=async()=>{const url=$('#bUrl').value.trim();if(!url)return toast('Enter a URL first.','warning');try{const d=await api('/analyze/url',{method:'POST',body:JSON.stringify({url,clientId})});renderResult(d.scan);refresh();toast('URL analysis saved to SQLite.','success')}catch(e){toast(e.message,'warning')}};
    $('#bUseOriginal').onclick=()=>{$('#bMessage').value=$('#messageInput')?.value||''};
    $('#bUseOriginalUrl').onclick=()=>{$('#bUrl').value=$('#urlInput')?.value||''};
    $('#bIntel').onclick=async()=>{const url=$('#bIntelUrl').value.trim();if(!url)return toast('Enter a domain or URL.','warning');$('#bIntelResult').innerHTML='Running live DNS + RDAP lookups...';try{const d=await api('/threat-intel?url='+encodeURIComponent(url));$('#bIntelResult').innerHTML=`<div class="intel-grid"><div><b>Domain</b><span>${esc(d.domain)}</span></div><div><b>DNS A records</b><span>${esc((d.sources.dns?.answers||[]).join(', ')||'None')}</span></div><div><b>RDAP status</b><span>${esc((d.sources.rdap?.status||[]).join(', ')||'Unavailable')}</span></div><div><b>Name servers</b><span>${esc((d.sources.rdap?.nameServers||[]).join(', ')||'Unavailable')}</span></div><div><b>URLhaus</b><span>${esc(d.sources.urlhaus?.status||d.sources.urlhaus?.query_status||'Optional')}</span></div></div><p class="intel-note">${d.signals.length?esc(d.signals.join(' ')):'No direct external threat signal was returned by the configured sources.'}</p>`}catch(e){$('#bIntelResult').textContent=e.message}};
    $('#bRefresh').onclick=refresh;
    $('#bSync').onclick=async()=>{let scans=[];try{const raw=localStorage.getItem('pg_scans');if(raw){scans=JSON.parse(raw)||[]}}catch(e){} if(!scans.length && window.PG?.scans) scans=window.PG.scans; if(!scans.length){$('#bActionMsg').textContent='No local scans found.';return} let n=0;for(const s of scans.slice(0,100)){try{await api('/analyze/'+(s.source==='URL'?'url':'message'),{method:'POST',body:JSON.stringify({clientId,...(s.source==='URL'?{url:s.originalText||''}:{text:s.originalText||''})})});n++}catch(e){}} $('#bActionMsg').textContent=`Synced ${n} local scan(s) to the backend.`;refresh();};
    $('#bSaveQuiz').onclick=async()=>{const score=Number(localStorage.getItem('pg_quiz_score'));const total=Number(localStorage.getItem('pg_quiz_total')||10);if(!Number.isFinite(score)){toast('No saved quiz score found yet. Complete the quiz first.','warning');return}try{await api('/quiz/results',{method:'POST',body:JSON.stringify({clientId,score,total})});toast('Quiz result saved to backend.','success')}catch(e){toast(e.message,'warning')}};
    $('#bSaveChecklist').onclick=async()=>{const completed=[];for(let i=1;i<=8;i++){const x=$('#check'+i);if(x?.checked)completed.push(i)}try{await api('/checklist',{method:'POST',body:JSON.stringify({clientId,completed})});toast('Security checklist synced to SQLite.','success')}catch(e){toast(e.message,'warning')}};
    $('#bReport').onclick=async()=>{try{const d=await api('/scans?clientId='+encodeURIComponent(clientId)+'&limit=1');if(!d.items.length)return toast('Run a backend scan first.','warning');await api('/reports',{method:'POST',body:JSON.stringify({clientId,scanId:d.items[0].id})});toast('Incident report created by backend.','success');refresh()}catch(e){toast(e.message,'warning')}};
    $('#bExport').onclick=async()=>{try{const d=await api('/export');const blob=new Blob([JSON.stringify(d,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='phishguard-backend-export.json';a.click();URL.revokeObjectURL(a.href);toast('Backend data exported.','success')}catch(e){toast(e.message,'warning')}};
    document.addEventListener('click',e=>{if(e.target.classList.contains('pg-view-report')){try{const d=JSON.parse(e.target.dataset.json);if(typeof window.pgModal==='function')window.pgModal('Backend Incident Report','<pre style="white-space:pre-wrap;text-align:left">'+esc(JSON.stringify(d,null,2))+'</pre>')}catch(x){}}});
  }
  window.addEventListener('pg-auth-ready',()=>refresh());
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',addConsole);else addConsole();
})();
