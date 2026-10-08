
(function(){
  'use strict';
  const API='/api/v1';
  const $=id=>document.getElementById(id);
  const screen=$('pgAuthScreen'), loginForm=$('pgLoginForm'), registerForm=$('pgRegisterForm');
  window.PGAuth={user:null};
  function message(text,type=''){const el=$('pgAuthMessage');el.textContent=text||'';el.className='pg-auth-message '+type;}
  function setMode(mode){
    $('pgLoginTab').classList.toggle('active',mode==='login');
    $('pgRegisterTab').classList.toggle('active',mode==='register');
    loginForm.classList.toggle('hidden',mode!=='login');
    registerForm.classList.toggle('hidden',mode!=='register');
    message('');
  }
  async function api(path,opts={}){
    const r=await fetch(API+path,{credentials:'same-origin',...opts,headers:{'Content-Type':'application/json',...(opts.headers||{})}});
    const d=await r.json().catch(()=>({error:'Invalid server response'}));
    if(!r.ok)throw new Error(d.error||`HTTP ${r.status}`);
    return d;
  }
  function signedIn(user){
    window.PGAuth.user=user;
    startHeartbeat();
    screen.classList.add('hidden');
    $('pgUserBar').classList.remove('hidden');
    $('pgUserName').textContent=user.name||user.email;
    let adminLink=document.getElementById('pgAdminLink');
    if(user.role==='admin' && !adminLink){
      adminLink=document.createElement('a'); adminLink.id='pgAdminLink'; adminLink.href='/admin.html'; adminLink.textContent='Admin Dashboard';
      adminLink.style.cssText='margin-left:10px;color:#93c5fd;text-decoration:none;font-weight:700;';
      $('pgUserBar').insertBefore(adminLink,$('pgLogout'));
    }
    window.dispatchEvent(new CustomEvent('pg-auth-ready',{detail:user}));
  }
  let heartbeatTimer=null;
  function startHeartbeat(){
    if(heartbeatTimer) clearInterval(heartbeatTimer);
    const beat=()=>{ if(document.visibilityState==='visible') api('/auth/heartbeat',{method:'POST'}).catch(()=>{}); };
    beat();
    heartbeatTimer=setInterval(beat,30000);
    document.addEventListener('visibilitychange',beat);
  }
  function stopHeartbeat(){ if(heartbeatTimer) clearInterval(heartbeatTimer); heartbeatTimer=null; }
  async function check(){
    try{const d=await api('/auth/me');signedIn(d.user)}catch(e){screen.classList.remove('hidden');$('pgUserBar').classList.add('hidden');}
  }
  $('pgLoginTab').onclick=()=>setMode('login');
  $('pgRegisterTab').onclick=()=>setMode('register');
  loginForm.onsubmit=async e=>{
    e.preventDefault(); message('Signing in…','success');
    try{const d=await api('/auth/login',{method:'POST',body:JSON.stringify({email:$('pgLoginEmail').value,password:$('pgLoginPassword').value})});signedIn(d.user)}
    catch(err){message(err.message)}
  };
  registerForm.onsubmit=async e=>{
    e.preventDefault();
    if($('pgRegisterPassword').value!==$('pgRegisterConfirm').value)return message('Passwords do not match.');
    message('Creating your account…','success');
    try{const d=await api('/auth/register',{method:'POST',body:JSON.stringify({name:$('pgRegisterName').value,email:$('pgRegisterEmail').value,password:$('pgRegisterPassword').value})});signedIn(d.user)}
    catch(err){message(err.message)}
  };
  $('pgLogout').onclick=async()=>{try{stopHeartbeat();await api('/auth/logout',{method:'POST'});}finally{window.PGAuth.user=null;$('pgUserBar').classList.add('hidden');screen.classList.remove('hidden');setMode('login');}};
  check();
})();
