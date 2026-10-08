# PhishGuard 3.1 — Original Frontend + Advanced Backend

This build preserves the original PhishGuard HTML interface and adds a visible **Backend Security Center** powered by Node.js, Express and SQLite.

### Authentication
The app now includes a database-backed login/register system. Passwords are hashed with Node.js `crypto.scrypt`, and authenticated users receive a secure HttpOnly session cookie. Scan history, reports, quiz results and checklist data are scoped to the logged-in account.

## Run

```powershell
npm.cmd install
npm.cmd run dev
```

Open http://localhost:5000

## Backend features visible in the website

- Live backend health and database status
- Persistent SQLite scan history
- Server-side message and URL risk engine
- Risk score, severity, confidence and explainable findings
- Dashboard analytics and recent activity
- Live DNS + RDAP domain intelligence (no API key required for the public endpoints)
- Optional URLhaus known-malware intelligence with a free Auth-Key
- Incident report creation and report history
- Quiz-result persistence
- Security-checklist persistence
- Database-backed user registration and login
- Password hashing with Node.js scrypt
- HttpOnly, SameSite session cookies and logout
- Per-user scan, report, quiz and checklist data
- REST API endpoint monitor
- Rate limiting, Helmet security headers, validation and centralized errors
- JSON export of backend scan history

## API

GET  /api/v1/health
POST /api/v1/analyze/message
POST /api/v1/analyze/url
GET  /api/v1/scans
GET  /api/v1/scans/:id
GET  /api/v1/dashboard
GET  /api/v1/threat-intel?url=...
POST /api/v1/reports
GET  /api/v1/reports
POST /api/v1/quiz/results
GET  /api/v1/quiz/results
POST /api/v1/checklist
GET  /api/v1/checklist

The application is an educational project and does not replace professional incident response or security tooling.


### Admin dashboard
The project now includes an administrator activity dashboard at:

`http://localhost:5000/admin.html`

The admin dashboard shows:
- Users currently active (heartbeat-based)
- Login time and current session duration
- Last activity time
- Registered users and total login count
- Total completed session time
- Session history with logout time and duration
- IP address and browser/user-agent information

Default demo administrator:
- Email: `admin@phishguard.local`
- Password: `Admin@12345`

For a real deployment, set `ADMIN_EMAIL`, `ADMIN_PASSWORD`, and `ADMIN_NAME` in the environment before starting the server.


## Admin + user accounts

- Normal users can register and log in from the main page.
- Administrators use the same login form; an account with `role=admin` gets an **Admin Dashboard** link.
- Admin dashboard: `/admin.html`.
- Admin metrics include registered users, active users, login count, average active session time, current active sessions, per-user total active time, and session history.
- Activity time is heartbeat-based: the browser sends a heartbeat every 30 seconds and only recorded active periods contribute to active time.
- Passwords are stored as salted `scrypt` hashes; session tokens are stored hashed and the browser cookie is HttpOnly. Production cookies also use `Secure`.

## Permanent public website deployment

The included `render.yaml` is configured for a Render Web Service with a 1 GB persistent disk for SQLite. A normal ephemeral filesystem would lose the user database after restarts/deploys.

1. Push this project to a GitHub repository.
2. In Render, create a Web Service from that repository and use the included `render.yaml` blueprint.
3. Set `ADMIN_EMAIL`, `ADMIN_PASSWORD`, and `ADMIN_NAME` in the Render environment. Use a strong unique admin password.
4. Deploy. Render gives the service a stable `onrender.com` URL. You can later attach your own domain.
5. Keep the persistent disk mounted at the configured database path.

A public URL cannot be created from this chat alone because the deployment must belong to your hosting account. Do not use a temporary tunnel if you need the database and login system to remain available.


## Multi-device / multi-user notes — v3.2

- The same HTTPS URL can be opened on desktop browsers, iPhone/iPad Safari, and Android Chrome/Firefox.
- The interface has an additional responsive layer for phones, tablets, and desktop screens.
- User accounts and sessions are stored server-side; multiple users can be signed in at the same time.
- Each login creates its own server-side session, so concurrent logins are visible to administrators.
- The administrator dashboard records registration time, login/session time, recent activity, active time, browser/user-agent, IP, and completed session history.
- The admin dashboard is protected by the `admin` role; normal users cannot access it.
- For production, use HTTPS and set `ADMIN_EMAIL`, `ADMIN_PASSWORD`, and `ADMIN_NAME` as environment variables.

### Important scaling limitation

“Unlimited users” cannot be guaranteed by a single web server or SQLite database. This build supports concurrent users, but for a large public service you should move the database from SQLite to a managed PostgreSQL database and run multiple application instances behind a load balancer. Keep sessions in a shared database or Redis when horizontally scaling.
