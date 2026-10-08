(function(){
'use strict';
const API='/api/v1', $=id=>document.getElementById(id);
const esc=v=>String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
const dt=v=>v?new Date(v).toLocaleString():'—';
const secs=n=>{n=Math.max(0,Math.round(Number(n)||0));if(n<60)return n+'s';const m=Math.floor(n/60),h=Math.floor(m/60),d=Math.floor(h/24);if(d)return d+'d '+(h%24)+'h';if(h)return h+'h '+(m%60)+'m';return m+'m'};
const activeDuration=x=>secs(x.active_seconds||0);
async function api(path,opts={}){const r=await fetch(API+path,{credentials:'same-origin',headers:{'Content-Type':'application/json',...(opts.headers||{})},...opts});const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.error||'Request failed');return d}
function error(e){ $('message').textContent=e.message; $('message').classList.remove('hidden'); }
async function load(){
 try{
  const d=await api('/admin/overview');
  $('message').classList.add('hidden');
  $('totalUsers').textContent=d.metrics.totalUsers;
  $('activeUsers').textContent=d.metrics.activeUsers;
  $('totalSessions').textContent=d.metrics.totalSessions;
  $('avgDuration').textContent=secs(d.metrics.averageSessionSeconds);
  $('activeTable').innerHTML=d.active.length?d.active.map(x=>`<tr><td class="user">${esc(x.name)}</td><td class="email">${esc(x.email)}</td><td>${dt(x.created_at)}</td><td>${dt(x.last_active_at)}</td><td><b>${activeDuration(x)}</b></td><td>${esc(x.ip_address||'—')}</td><td title="${esc(x.user_agent||'')}">${esc((x.user_agent||'').slice(0,55))}</td></tr>`).join(''):'<tr><td colspan="7" class="empty">No users are currently active.</td></tr>';
  $('usersTable').innerHTML=d.users.map(x=>`<tr><td class="user">${esc(x.name)}</td><td class="email">${esc(x.email)}</td><td><span class="pill ${x.role==='admin'?'admin':''}">${esc(x.role)}</span></td><td>${dt(x.created_at)}</td><td>${x.total_sessions}</td><td>${dt(x.last_login)}</td><td>${secs(x.total_duration)}</td></tr>`).join('');
  $('historyTable').innerHTML=d.history.length?d.history.map(x=>`<tr><td class="user">${esc(x.name)}<br><span class="email">${esc(x.email)}</span></td><td>${dt(x.session_created_at)}</td><td>${dt(x.ended_at)}</td><td><b>${secs(x.duration_seconds)}</b></td><td>${esc(x.end_reason||'—')}</td><td>${esc(x.ip_address||'—')}</td><td title="${esc(x.user_agent||'')}">${esc((x.user_agent||'').slice(0,55))}</td></tr>`).join(''):'<tr><td colspan="7" class="empty">No completed sessions yet.</td></tr>';
 }catch(e){ if(e.message.includes('Administrator')) error(e); else if(e.message.includes('Authentication')) location.href='/'; else error(e); }
}
$('refresh').onclick=load;
$('logout').onclick=async()=>{try{await api('/auth/logout',{method:'POST'})}finally{location.href='/'}}; 
load(); setInterval(load,15000);
})();