# PhishGuard deployment

This version includes `render.yaml` for a persistent Render deployment.

## Local

```powershell
npm.cmd install
npm.cmd start
```

Open `http://localhost:5000`.

## Render

1. Push the project to GitHub.
2. Create a Render Web Service from the repository and apply `render.yaml`.
3. Set `ADMIN_EMAIL`, `ADMIN_PASSWORD`, and `ADMIN_NAME`.
4. Deploy and use the generated `https://<service-name>.onrender.com` URL.

The SQLite database is stored under the persistent disk mount. Do not remove that disk or change `DB_PATH` unless you intentionally migrate the database.
