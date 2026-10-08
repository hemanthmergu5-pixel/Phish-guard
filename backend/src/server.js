const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const PORT = Number(process.env.PORT || 5000);
const HOST = process.env.HOST || '0.0.0.0';
const isProduction = process.env.NODE_ENV === 'production';
const root = path.resolve(__dirname, '..', '..');
const dbDir = path.join(root, 'backend', 'database');
fs.mkdirSync(dbDir, { recursive: true });
const dbPath = process.env.DB_PATH ? path.resolve(process.env.DB_PATH) : path.join(dbDir, 'phishguard.db');
fs.mkdirSync(path.dirname(dbPath), { recursive: true });
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 password_salt TEXT NOT NULL,
 created_at TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user'
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY,
 user_id TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 created_at TEXT NOT NULL,
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS scans (
 id TEXT PRIMARY KEY, client_id TEXT NOT NULL, type TEXT NOT NULL, input TEXT NOT NULL,
 score INTEGER NOT NULL, level TEXT NOT NULL, category TEXT, confidence INTEGER NOT NULL,
 findings TEXT NOT NULL, recommendation TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reports (
 id TEXT PRIMARY KEY, client_id TEXT NOT NULL, scan_id TEXT NOT NULL, title TEXT NOT NULL,
 severity TEXT NOT NULL, report_json TEXT NOT NULL, created_at TEXT NOT NULL,
 FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS quiz_results (
 id TEXT PRIMARY KEY, client_id TEXT NOT NULL, score INTEGER NOT NULL, total INTEGER NOT NULL,
 percentage REAL NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS checklist (
 client_id TEXT PRIMARY KEY, completed_json TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_client_created ON scans(client_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
`);

// Backward-compatible migrations for databases created by earlier PhishGuard versions.
try { db.exec(`ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'`); } catch (e) {}
try { db.exec(`ALTER TABLE sessions ADD COLUMN last_active_at TEXT`); } catch (e) {}
try { db.exec(`ALTER TABLE sessions ADD COLUMN ip_address TEXT`); } catch (e) {}
try { db.exec(`ALTER TABLE sessions ADD COLUMN user_agent TEXT`); } catch (e) {}
try { db.exec(`ALTER TABLE sessions ADD COLUMN active_seconds INTEGER NOT NULL DEFAULT 0`); } catch (e) {}
db.exec(`
CREATE TABLE IF NOT EXISTS session_history (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL,
 session_created_at TEXT NOT NULL,
 last_active_at TEXT NOT NULL,
 ended_at TEXT,
 duration_seconds INTEGER NOT NULL DEFAULT 0,
 ip_address TEXT,
 user_agent TEXT,
 end_reason TEXT,
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_session_history_user ON session_history(user_id, session_created_at DESC);
CREATE INDEX IF NOT EXISTS idx_session_history_created ON session_history(session_created_at DESC);
`);
try { db.exec(`ALTER TABLE session_history ADD COLUMN active_seconds INTEGER NOT NULL DEFAULT 0`); } catch (e) {}

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.set('trust proxy', process.env.TRUST_PROXY === 'true' ? 1 : false);
app.use(cors());
app.use(express.json({ limit: '64kb' }));
app.use(rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false }));

const now = () => new Date().toISOString();
const id = prefix => `${prefix}_${crypto.randomBytes(7).toString('hex')}`;
const SESSION_DAYS = 7;
const hashPassword = (password, salt = crypto.randomBytes(16).toString('hex')) => ({
  salt,
  hash: crypto.scryptSync(password, salt, 64).toString('hex')
});
const verifyPassword = (password, salt, storedHash) => {
  const derived = crypto.scryptSync(password, salt, 64);
  const stored = Buffer.from(storedHash, 'hex');
  return stored.length === derived.length && crypto.timingSafeEqual(stored, derived);
};
const hashSessionToken = token => crypto.createHash('sha256').update(token).digest('hex');
const cookieValue = (req, name) => {
  const cookies = String(req.headers.cookie || '').split(';');
  for (const item of cookies) {
    const [k, ...rest] = item.trim().split('=');
    if (k === name) return decodeURIComponent(rest.join('='));
  }
  return null;
};
const createSession = (userId, req = null) => {
  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashSessionToken(token);
  const created = now();
  const expires = new Date(Date.now() + SESSION_DAYS * 86400000).toISOString();
  db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at,created_at,last_active_at,ip_address,user_agent) VALUES(?,?,?,?,?,?,?)')
    .run(tokenHash, userId, expires, created, created,
      req?.ip || null, String(req?.headers?.['user-agent'] || '').slice(0,500) || null);
  return { token, expires };
};
const setSessionCookie = (res, token, expires) => {
  const secure = isProduction ? '; Secure' : '';
  res.setHeader('Set-Cookie',
    `pg_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Expires=${new Date(expires).toUTCString()}${secure}`
  );
};
const clearSessionCookie = res => {
  const secure = isProduction ? '; Secure' : '';
  res.setHeader('Set-Cookie', `pg_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`);
};
function touchSession(tokenHash) {
  const current = now();
  const session = db.prepare('SELECT * FROM sessions WHERE token_hash=?').get(tokenHash);
  if (!session) return null;
  const previous = Date.parse(session.last_active_at || session.created_at);
  const elapsed = Math.max(0, Math.min(90, Math.round((Date.parse(current) - previous) / 1000)));
  db.prepare('UPDATE sessions SET last_active_at=?, active_seconds=COALESCE(active_seconds,0)+? WHERE token_hash=?').run(current, elapsed, tokenHash);
  return { ...session, last_active_at: current, active_seconds: Number(session.active_seconds || 0) + elapsed };
}
function authUser(req) {
  const token = cookieValue(req, 'pg_session');
  if (!token) return null;
  const tokenHash = hashSessionToken(token);
  const current = now();
  const row = db.prepare(`
    SELECT u.id,u.name,u.email,u.role,s.expires_at,s.created_at,s.last_active_at,s.active_seconds
    FROM sessions s JOIN users u ON u.id=s.user_id
    WHERE s.token_hash=? AND s.expires_at > ?
  `).get(tokenHash, current);
  if (row) {
    const touched = touchSession(tokenHash);
    if (touched) { row.last_active_at = touched.last_active_at; row.active_seconds = touched.active_seconds; }
  }
  return row || null;
}
function archiveSession(session, reason='expired') {
  if (!session) return false;
  const ended = now();
  const lastActive = session.last_active_at || session.created_at;
  const previous = Date.parse(lastActive);
  const elapsed = Math.max(0, Math.min(90, Math.round((Date.parse(ended)-previous)/1000)));
  const activeSeconds = Number(session.active_seconds || 0) + elapsed;
  db.prepare(`INSERT INTO session_history
    (id,user_id,session_created_at,last_active_at,ended_at,duration_seconds,ip_address,user_agent,active_seconds,end_reason)
    VALUES(?,?,?,?,?,?,?,?,?,?)`)
    .run(id('SES'),session.user_id,session.created_at,lastActive,ended,activeSeconds,session.ip_address,session.user_agent,activeSeconds,reason);
  db.prepare('DELETE FROM sessions WHERE token_hash=?').run(session.token_hash);
  return true;
}
function cleanupExpiredSessions() {
  const expired = db.prepare('SELECT * FROM sessions WHERE expires_at <= ?').all(now());
  for (const session of expired) archiveSession(session, 'expired');
}
function endSessionByToken(token, reason='logout') {
  if (!token) return false;
  const tokenHash = hashSessionToken(token);
  const session = db.prepare('SELECT * FROM sessions WHERE token_hash=?').get(tokenHash);
  if (!session) return false;
  return archiveSession(session, reason);
}
function requireAdmin(req,res,next) {
  if (!req.user || req.user.role !== 'admin') return res.status(403).json({ok:false,error:'Administrator access required.'});
  next();
}
function requireAuth(req,res,next) {
  const user = authUser(req);
  if (!user) return res.status(401).json({ok:false,error:'Authentication required. Please log in.'});
  req.user = user;
  next();
}

const cleanClient = value => String(value || 'anonymous').slice(0, 120).replace(/[^a-zA-Z0-9._:-]/g, '_');
const clamp = n => Math.max(0, Math.min(100, Math.round(n)));
const levelFor = score => score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 35 ? 'MEDIUM' : score >= 15 ? 'LOW' : 'SAFE';

const messageRules = [
 ['urgency','Urgency / pressure tactic','Creates immediate pressure to act before verifying the request.',16,/(urgent|immediately|act now|within \d+ hours?|today|last warning|final notice)/i],
 ['otp','OTP / verification code request','Requests a one-time password or verification code.',28,/(otp|one[- ]time password|verification code|security code|cvv|pin)/i],
 ['credentials','Credential or sensitive-data request','Requests passwords, login credentials or sensitive personal information.',25,/(password|passcode|login details|username|aadhaar|pan card|card number|account number)/i],
 ['payment','Payment / money request','Requests money, fees, transfers, UPI payments or gift cards.',22,/(send money|pay now|payment|upi|collect request|gift card|processing fee|transfer)/i],
 ['threat','Threat / account suspension','Uses fear of blocking, legal action or account suspension.',18,/(blocked|suspended|deactivated|legal action|police|fine|penalty|account will be closed)/i],
 ['reward','Prize / reward lure','Uses prizes, refunds, bonuses or guaranteed rewards to entice action.',14,/(winner|won|prize|reward|cashback|refund|bonus|lottery|free gift)/i],
 ['impersonation','Impersonation signal','Claims to represent a bank, government, delivery service or known brand.',12,/(bank|sbi|hdfc|icici|axis|income tax|police|courier|amazon|flipkart|paytm|phonepe|google pay|npci)/i]
];

function analyzeMessage(text) {
 let score = 0; const findings = []; const categories = [];
 for (const [key,title,detail,points,re] of messageRules) if (re.test(text)) { score += points; findings.push({title,detail,severity: points >= 25 ? 'HIGH' : points >= 16 ? 'MEDIUM' : 'LOW', points, key}); categories.push(title); }
 const urls = text.match(/https?:\/\/[^\s<>"']+|www\.[^\s<>"']+/gi) || [];
 if (urls.length) { score += 15; findings.push({title:'Link detected',detail:'The message contains a clickable-looking URL that should be independently verified.',severity:'HIGH',points:15,key:'url'}); categories.push('Suspicious link'); }
 if (/bit\.ly|tinyurl\.com|t\.co|cutt\.ly|shorturl/i.test(text)) { score += 15; findings.push({title:'URL shortener',detail:'A shortened URL hides the final destination.',severity:'HIGH',points:15,key:'shortener'}); categories.push('Shortened URL'); }
 score = clamp(score);
 const level = levelFor(score);
 const recommendation = score >= 80 ? 'Do not click links or share OTPs, passwords or financial information. Verify through an official channel.' : score >= 60 ? 'Treat this as highly suspicious. Do not respond or pay until independently verified.' : score >= 35 ? 'Be cautious. Verify the sender, website and request before taking action.' : 'No strong red flags were detected. Still verify unexpected requests independently.';
 const confidence = clamp(55 + findings.length * 8 + (urls.length ? 10 : 0));
 return { score, level, confidence, categories:[...new Set(categories)], findings, urls, recommendation };
}

function analyzeUrl(raw) {
 let input = String(raw || '').trim(); let score = 0; const findings = []; const categories=[];
 if (!input) return {score:0,level:'SAFE',confidence:0,categories:[],findings:[],recommendation:'Enter a URL.'};
 if (!/^https?:\/\//i.test(input)) input = 'https://' + input;
 let u; try { u = new URL(input); } catch { return {score:90,level:'CRITICAL',confidence:92,categories:['Malformed URL'],findings:[{title:'Malformed URL',detail:'The supplied address could not be parsed as a valid URL.',severity:'CRITICAL',points:90}],recommendation:'Do not open this address until it is verified.'}; }
 const host=u.hostname.toLowerCase(); const full=input.toLowerCase();
 if (u.protocol !== 'https:') { score+=15; findings.push({title:'No HTTPS',detail:'The URL does not use HTTPS.',severity:'MEDIUM',points:15}); categories.push('Transport security'); }
 if (full.includes('@')) { score+=25; findings.push({title:'@ symbol in URL',detail:'The @ syntax can obscure the actual destination.',severity:'HIGH',points:25}); categories.push('URL obfuscation'); }
 if (host.startsWith('xn--') || host.includes('.xn--')) { score+=30; findings.push({title:'Punycode domain',detail:'Internationalized domain encoding can be used in look-alike attacks.',severity:'HIGH',points:30}); categories.push('Look-alike domain'); }
 if ((host.match(/\./g)||[]).length >= 4) { score+=10; findings.push({title:'Deep subdomain structure',detail:'The hostname has many subdomain levels.',severity:'LOW',points:10}); categories.push('Domain complexity'); }
 if (host.length > 55) { score+=10; findings.push({title:'Long hostname',detail:'The hostname is unusually long.',severity:'LOW',points:10}); categories.push('Domain complexity'); }
 if (/login|verify|secure|account|update|wallet|bonus|winner|prize|payment|banking/i.test(full)) { score+=12; findings.push({title:'High-risk keyword',detail:'The URL contains wording frequently seen in phishing lures.',severity:'MEDIUM',points:12}); categories.push('Phishing keywords'); }
 if (/bit\.ly|tinyurl\.com|t\.co|cutt\.ly|shorturl/i.test(host)) { score+=20; findings.push({title:'Shortened URL',detail:'The final destination is hidden behind a URL shortener.',severity:'HIGH',points:20}); categories.push('URL shortener'); }
 if (/\.(exe|scr|apk|zip)(\?|$)/i.test(u.pathname)) { score+=25; findings.push({title:'Potentially risky file type',detail:'The URL path points to a potentially executable/archive file.',severity:'HIGH',points:25}); categories.push('Potential malware delivery'); }
 score=clamp(score); const level=levelFor(score); const confidence=clamp(62 + findings.length*6);
 return {score,level,confidence,categories:[...new Set(categories)],findings,recommendation:score>=80?'Do not open the URL. Verify the domain independently.':score>=60?'Treat the URL as highly suspicious and avoid entering information.':score>=35?'Verify the domain and destination before interacting.':'No strong structural red flags were detected; still verify the destination.'};
}

function saveScan(clientId,type,input,result){
 const scan={id:id('SCAN'),client_id:cleanClient(clientId),type,input:String(input).slice(0,10000),score:result.score,level:result.level,category:result.categories.join(', '),confidence:result.confidence,findings:JSON.stringify(result.findings),recommendation:result.recommendation,created_at:now()};
 db.prepare(`INSERT INTO scans VALUES (@id,@client_id,@type,@input,@score,@level,@category,@confidence,@findings,@recommendation,@created_at)`).run(scan); return scan;
}
function publicScan(r){ return {...r,findings:JSON.parse(r.findings||'[]'), categories:r.category?r.category.split(', ').filter(Boolean):[]}; }

async function threatIntel(rawUrl){
 let u; try { u = new URL(/^https?:\/\//i.test(rawUrl)?rawUrl:'https://'+rawUrl); } catch { return {ok:false,error:'Invalid URL'}; }
 const domain=u.hostname;
 const result={ok:true,domain,checkedAt:now(),sources:{},signals:[]};
 try { const dns=await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`,{headers:{accept:'application/dns-json'}}); const data=await dns.json(); result.sources.dns={status:data.Status,answers:(data.Answer||[]).map(x=>x.data).slice(0,10)}; if(!data.Answer?.length) result.signals.push('No A record returned by Cloudflare DNS.'); } catch(e){ result.sources.dns={error:e.message}; }
 try { const rdap=await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`,{headers:{accept:'application/rdap+json'}}); if(rdap.ok){ const data=await rdap.json(); result.sources.rdap={handle:data.handle||null,status:data.status||[],nameServers:(data.nameservers||[]).map(x=>x.ldhName).filter(Boolean).slice(0,8),events:(data.events||[]).map(x=>({action:x.eventAction,date:x.eventDate})).slice(0,8)}; } else result.sources.rdap={status:rdap.status}; } catch(e){ result.sources.rdap={error:e.message}; }
 if(process.env.URLHAUS_AUTH_KEY){ try { const form=new URLSearchParams({auth_key:process.env.URLHAUS_AUTH_KEY,url:u.href}); const r=await fetch('https://urlhaus-api.abuse.ch/v1/url/',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:form}); const d=await r.json(); result.sources.urlhaus={query_status:d.query_status,url_status:d.url_status,threat:d.threat||null,tags:d.tags||[]}; if(d.query_status==='ok' && d.url_status==='online') result.signals.push('URLhaus reports this URL as an online malware URL.'); } catch(e){ result.sources.urlhaus={error:e.message}; } } else result.sources.urlhaus={status:'not_configured',message:'Optional URLhaus Auth-Key not configured.'};
 return result;
}

app.get('/api/v1/health',(req,res)=>res.json({ok:true,status:'online',service:'PhishGuard Backend',version:'3.1.0',database:'sqlite',databasePath:dbPath,node:process.version,time:now()}));

app.post('/api/v1/auth/register',(req,res)=>{
  const name=String(req.body?.name||'').trim().slice(0,80);
  const email=String(req.body?.email||'').trim().toLowerCase();
  const password=String(req.body?.password||'');
  if(name.length<2) return res.status(400).json({error:'Name must be at least 2 characters.'});
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({error:'Enter a valid email address.'});
  if(password.length<8) return res.status(400).json({error:'Password must be at least 8 characters.'});
  if(password.length>128) return res.status(400).json({error:'Password is too long.'});
  if(db.prepare('SELECT id FROM users WHERE email=?').get(email)) return res.status(409).json({error:'An account with this email already exists.'});
  const userId=id('USR');
  const pw=hashPassword(password);
  db.prepare('INSERT INTO users(id,name,email,password_hash,password_salt,created_at,role) VALUES(?,?,?,?,?,?,?)')
    .run(userId,name,email,pw.hash,pw.salt,now(),'user');
  const session=createSession(userId,req);
  setSessionCookie(res,session.token,session.expires);
  res.status(201).json({ok:true,user:{id:userId,name,email,role:'user'}});
});
app.post('/api/v1/auth/login',(req,res)=>{
  const email=String(req.body?.email||'').trim().toLowerCase();
  const password=String(req.body?.password||'');
  const user=db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if(!user || !verifyPassword(password,user.password_salt,user.password_hash))
    return res.status(401).json({error:'Invalid email or password.'});
  // Keep previous sessions so the admin can see concurrent/multiple logins.
  cleanupExpiredSessions();
  const session=createSession(user.id,req);
  setSessionCookie(res,session.token,session.expires);
  res.json({ok:true,user:{id:user.id,name:user.name,email:user.email,role:user.role}});
});
app.get('/api/v1/auth/me',requireAuth,(req,res)=>res.json({ok:true,user:{id:req.user.id,name:req.user.name,email:req.user.email,role:req.user.role}}));
app.post('/api/v1/auth/logout',(req,res)=>{
  const token=cookieValue(req,'pg_session');
  if(token) endSessionByToken(token,'logout');
  clearSessionCookie(res);
  res.json({ok:true});
});


app.post('/api/v1/auth/heartbeat',requireAuth,(req,res)=>{
  const token=cookieValue(req,'pg_session');
  if(token) touchSession(hashSessionToken(token));
  res.json({ok:true,activeAt:now()});
});

// Admin session/activity dashboard.
// A session is considered "active" when its last heartbeat was received within the last 90 seconds.
app.get('/api/v1/admin/overview',requireAuth,requireAdmin,(req,res)=>{
  cleanupExpiredSessions();
  const cutoff=new Date(Date.now()-90*1000).toISOString();
  const users=db.prepare(`
    SELECT u.id,u.name,u.email,u.role,u.created_at,
      (SELECT COUNT(*) FROM session_history h WHERE h.user_id=u.id) + (SELECT COUNT(*) FROM sessions s2 WHERE s2.user_id=u.id AND s2.expires_at > ?) AS total_sessions,
      MAX((SELECT MAX(h.session_created_at) FROM session_history h WHERE h.user_id=u.id),(SELECT MAX(s2.created_at) FROM sessions s2 WHERE s2.user_id=u.id)) AS last_login,
      (SELECT MAX(h.ended_at) FROM session_history h WHERE h.user_id=u.id) AS last_logout,
      (SELECT COALESCE(SUM(h.duration_seconds),0) FROM session_history h WHERE h.user_id=u.id) + (SELECT COALESCE(SUM(s2.active_seconds),0) FROM sessions s2 WHERE s2.user_id=u.id) AS total_duration
    FROM users u ORDER BY u.created_at DESC
  `).all(now());

  const active=db.prepare(`
    SELECT s.token_hash,s.created_at,s.last_active_at,s.expires_at,s.active_seconds,s.ip_address,s.user_agent,
           u.id user_id,u.name,u.email,u.role
    FROM sessions s JOIN users u ON u.id=s.user_id
    WHERE s.expires_at > ? AND s.last_active_at >= ?
    ORDER BY s.last_active_at DESC
  `).all(now(),cutoff);

  const history=db.prepare(`
    SELECT h.*,u.name,u.email
    FROM session_history h JOIN users u ON u.id=h.user_id
    ORDER BY h.session_created_at DESC LIMIT 200
  `).all();

  const totalUsers=db.prepare('SELECT COUNT(*) c FROM users').get().c;
  const activeUsers=db.prepare(`SELECT COUNT(DISTINCT user_id) c FROM sessions WHERE expires_at > ? AND last_active_at >= ?`).get(now(),cutoff).c;
  const totalSessions=db.prepare('SELECT (SELECT COUNT(*) FROM session_history) + (SELECT COUNT(*) FROM sessions) c').get().c;
  const avgDuration=db.prepare('SELECT COALESCE(AVG(duration_seconds),0) v FROM session_history').get().v;

  res.json({ok:true,metrics:{totalUsers,activeUsers,totalSessions,averageSessionSeconds:Math.round(avgDuration)},
    active:active.map(x=>{const elapsed=Math.max(0,Math.min(90,Math.round((Date.now()-Date.parse(x.last_active_at||x.created_at))/1000)));return {...x,token_hash:undefined,active_seconds:Number(x.active_seconds||0)+elapsed}}),users,history});
});

app.post('/api/v1/admin/end-session',requireAuth,requireAdmin,(req,res)=>{
  const tokenHash=String(req.body?.tokenHash||'');
  if(!tokenHash)return res.status(400).json({error:'tokenHash is required'});
  const session=db.prepare('SELECT * FROM sessions WHERE token_hash=?').get(tokenHash);
  if(!session)return res.status(404).json({error:'Session not found or already ended.'});
  archiveSession(session,'admin_terminated');
  res.json({ok:true});
});

app.post('/api/v1/analyze/message',requireAuth,(req,res)=>{ const text=String(req.body?.text||'').trim(); if(text.length<2||text.length>10000) return res.status(400).json({error:'Message must be between 2 and 10000 characters.'}); const result=analyzeMessage(text); const scan=saveScan(req.user.id,'message',text,result); res.json({ok:true,scan:publicScan(scan)}); });
app.post('/api/v1/analyze/url',requireAuth,(req,res)=>{ const url=String(req.body?.url||'').trim(); if(url.length<3||url.length>3000) return res.status(400).json({error:'URL must be between 3 and 3000 characters.'}); const result=analyzeUrl(url); const scan=saveScan(req.user.id,'url',url,result); res.json({ok:true,scan:publicScan(scan)}); });
app.get('/api/v1/scans',requireAuth,(req,res)=>{ const client=req.user.id; const limit=Math.min(Number(req.query.limit||50),200); const rows=client?db.prepare('SELECT * FROM scans WHERE client_id=? ORDER BY created_at DESC LIMIT ?').all(cleanClient(client),limit):db.prepare('SELECT * FROM scans ORDER BY created_at DESC LIMIT ?').all(limit); res.json({ok:true,items:rows.map(publicScan)}); });
app.get('/api/v1/scans/:id',requireAuth,(req,res)=>{ const r=db.prepare('SELECT * FROM scans WHERE id=? AND client_id=?').get(req.params.id,req.user.id); if(!r)return res.status(404).json({error:'Scan not found'}); res.json({ok:true,scan:publicScan(r)}); });
app.get('/api/v1/dashboard',requireAuth,(req,res)=>{ const client=req.user.id; const where=client?' WHERE client_id=?':''; const args=client?[cleanClient(client)]:[]; const total=db.prepare(`SELECT COUNT(*) c FROM scans${where}`).get(...args).c; const threats=db.prepare(`SELECT COUNT(*) c FROM scans${where}${where?' AND':' WHERE'} score>=35`).get(...args).c; const critical=db.prepare(`SELECT COUNT(*) c FROM scans${where}${where?' AND':' WHERE'} level='CRITICAL'`).get(...args).c; const high=db.prepare(`SELECT COUNT(*) c FROM scans${where}${where?' AND':' WHERE'} level='HIGH'`).get(...args).c; const medium=db.prepare(`SELECT COUNT(*) c FROM scans${where}${where?' AND':' WHERE'} level='MEDIUM'`).get(...args).c; const safe=db.prepare(`SELECT COUNT(*) c FROM scans${where}${where?' AND':' WHERE'} level='SAFE'`).get(...args).c; const types=db.prepare(`SELECT type,COUNT(*) c FROM scans${where} GROUP BY type ORDER BY c DESC`).all(...args); const categories=db.prepare(`SELECT category,COUNT(*) c FROM scans${where} GROUP BY category ORDER BY c DESC LIMIT 8`).all(...args); const recent=db.prepare(`SELECT * FROM scans${where} ORDER BY created_at DESC LIMIT 8`).all(...args).map(publicScan); res.json({ok:true,metrics:{total,threats,critical,high,medium,safe},types,categories,recent,server:{uptime:process.uptime(),memory:process.memoryUsage().rss,version:process.version}}); });
app.get('/api/v1/threat-intel',requireAuth,async(req,res)=>{ const url=String(req.query.url||'').trim(); if(!url)return res.status(400).json({error:'url is required'}); try{res.json(await threatIntel(url));}catch(e){res.status(502).json({error:'Threat intelligence lookup failed',detail:e.message});} });
app.post('/api/v1/reports',requireAuth,(req,res)=>{ const scan=db.prepare('SELECT * FROM scans WHERE id=? AND client_id=?').get(req.body?.scanId,req.user.id); if(!scan)return res.status(404).json({error:'Scan not found'}); const report={id:id('RPT'),client_id:req.user.id,scan_id:scan.id,title:req.body?.title||'PhishGuard Security Incident Report',severity:scan.level,report_json:JSON.stringify({scan:publicScan(scan),generatedAt:now()}),created_at:now()}; db.prepare(`INSERT INTO reports VALUES (@id,@client_id,@scan_id,@title,@severity,@report_json,@created_at)`).run(report); res.json({ok:true,report:{...report,report_json:JSON.parse(report.report_json)}}); });
app.get('/api/v1/reports',requireAuth,(req,res)=>{const client=req.user.id; const rows=client?db.prepare('SELECT * FROM reports WHERE client_id=? ORDER BY created_at DESC LIMIT 100').all(cleanClient(client)):db.prepare('SELECT * FROM reports ORDER BY created_at DESC LIMIT 100').all(); res.json({ok:true,items:rows.map(r=>({...r,report_json:JSON.parse(r.report_json)}))});});
app.post('/api/v1/quiz/results',requireAuth,(req,res)=>{const score=Number(req.body?.score||0),total=Number(req.body?.total||0);if(!Number.isFinite(score)||!Number.isFinite(total)||total<=0)return res.status(400).json({error:'Invalid quiz result'});const r={id:id('QUIZ'),client_id:req.user.id,score,total,percentage:Math.round(score/total*1000)/10,created_at:now()};db.prepare('INSERT INTO quiz_results VALUES (@id,@client_id,@score,@total,@percentage,@created_at)').run(r);res.json({ok:true,result:r});});
app.get('/api/v1/quiz/results',requireAuth,(req,res)=>{const rows=db.prepare('SELECT * FROM quiz_results WHERE client_id=? ORDER BY created_at DESC LIMIT 50').all(cleanClient(req.user.id));res.json({ok:true,items:rows});});
app.post('/api/v1/checklist',requireAuth,(req,res)=>{const completed=Array.isArray(req.body?.completed)?req.body.completed.slice(0,100):[];const r={client_id:req.user.id,completed_json:JSON.stringify(completed),updated_at:now()};db.prepare('INSERT INTO checklist(client_id,completed_json,updated_at) VALUES(?,?,?) ON CONFLICT(client_id) DO UPDATE SET completed_json=excluded.completed_json,updated_at=excluded.updated_at').run(r.client_id,r.completed_json,r.updated_at);res.json({ok:true,completed,updatedAt:r.updated_at});});
app.get('/api/v1/checklist',requireAuth,(req,res)=>{const r=db.prepare('SELECT * FROM checklist WHERE client_id=?').get(cleanClient(req.user.id));res.json({ok:true,completed:r?JSON.parse(r.completed_json):[],updatedAt:r?.updated_at||null});});
app.get('/api/v1/export',requireAuth,(req,res)=>{const scans=db.prepare('SELECT * FROM scans WHERE client_id=? ORDER BY created_at DESC').all(req.user.id).map(publicScan);const reports=db.prepare('SELECT * FROM reports WHERE client_id=? ORDER BY created_at DESC').all(req.user.id).map(r=>({...r,report_json:JSON.parse(r.report_json)}));const quizzes=db.prepare('SELECT * FROM quiz_results WHERE client_id=? ORDER BY created_at DESC').all(req.user.id);res.json({exportedAt:now(),scans,reports,quizzes});});


function ensureAdminAccount() {
  const email=String(process.env.ADMIN_EMAIL||'admin@phishguard.local').trim().toLowerCase();
  const password=String(process.env.ADMIN_PASSWORD||'Admin@12345');
  const name=String(process.env.ADMIN_NAME||'PhishGuard Administrator').trim();
  const existing=db.prepare('SELECT id FROM users WHERE email=?').get(email);
  if(existing){
    db.prepare("UPDATE users SET role='admin' WHERE email=?").run(email);
    return;
  }
  if(password.length<8) return;
  const pw=hashPassword(password);
  db.prepare('INSERT INTO users(id,name,email,password_hash,password_salt,created_at,role) VALUES(?,?,?,?,?,?,?)')
    .run(id('USR'),name,email,pw.hash,pw.salt,now(),'admin');
}
ensureAdminAccount();

app.use(express.static(path.join(root,'frontend')));
app.get('/api/v1', (req,res)=>res.json({ok:true,service:'PhishGuard API',version:'3.1.0',endpoints:['GET /api/v1/health','POST /api/v1/analyze/message','POST /api/v1/analyze/url','GET /api/v1/scans','GET /api/v1/dashboard','GET /api/v1/threat-intel','POST /api/v1/reports','GET /api/v1/reports','POST /api/v1/quiz/results','GET /api/v1/quiz/results','POST /api/v1/checklist','GET /api/v1/checklist','GET /api/v1/export']}));
app.use('/api', (req,res,next)=>{ if (req.path.startsWith('/v1/')) return res.status(404).json({ok:false,error:'API endpoint not found',path:req.originalUrl,available:'GET /api/v1'}); next(); });
app.get('*',(req,res)=>res.sendFile(path.join(root,'frontend','index.html')));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'Internal server error'});});
app.listen(PORT,HOST,()=>console.log(`PhishGuard 3.0 backend running at http://${HOST}:${PORT}`));
