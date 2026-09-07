# Deployment

The whole application is one container: it serves the JSON API and the browser
client from a single port.

## The one hard requirement: HTTPS

The browser only exposes the Web Crypto API in a **secure context** — HTTPS, or
`localhost`. Over plain HTTP to any other hostname, `crypto.subtle` is
`undefined` and nothing in this application can work. The client detects this
and refuses with an explanation rather than failing halfway through an
operation.

Every platform below terminates TLS for you, so this is handled. It only bites
if you serve the container directly from a VM's IP address.

---

## Option A — Render (simplest; no CLI)

1. Push this repository to GitHub.
2. Go to [dashboard.render.com](https://dashboard.render.com) → **New** →
   **Blueprint**, and point it at your repository. Render reads `render.yaml`.
3. It will prompt for the two values marked `sync: false`:
   - `SFE_ADMIN_EMAIL` — your administrator login
   - `SFE_ADMIN_PASSWORD` — a real password, not the documented default
   `SFE_SECRET_KEY` is generated automatically and kept across deploys.
4. Deploy. You get `https://secure-file-encryption.onrender.com`.

**Two things to know about the free plan.**

*Storage is ephemeral.* Free services have no disk, so `/data` — the database
and every stored container — is wiped on restart. Accounts and uploads vanish.
Fine for a demonstration; not for anything you want to keep. Uncomment the
`disk:` block in `render.yaml` and move off `plan: free` to fix it.

*It sleeps.* After 15 minutes of inactivity the service spins down, and the next
visit waits roughly 50 seconds for a cold start. If you are demonstrating live,
open the link a minute beforehand.

## Option B — Fly.io (persistent storage on the free allowance)

```bash
curl -L https://fly.io/install.sh | sh
fly auth login
fly launch --no-deploy          # reads fly.toml; pick a unique app name
fly volumes create sfe_data --size 1
fly secrets set \
  SFE_SECRET_KEY="$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')" \
  SFE_ADMIN_EMAIL="you@example.com" \
  SFE_ADMIN_PASSWORD="a-real-password"
fly deploy
```

You get `https://<your-app>.fly.dev`, and the volume keeps accounts and uploads
across restarts. This is the better option if the link needs to keep working
over days rather than minutes.

## Option C — any Docker host

```bash
docker build -t sfe .
docker run -d -p 8000:8000 \
  -e SFE_ENV=production \
  -e SFE_SECRET_KEY="$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')" \
  -e SFE_ADMIN_EMAIL="you@example.com" \
  -e SFE_ADMIN_PASSWORD="a-real-password" \
  -v sfe-data:/data \
  sfe
```

Put nginx, Caddy, or Cloudflare Tunnel in front for TLS. Caddy is the least
work — two lines and it obtains a certificate itself:

```
encryption.example.com {
    reverse_proxy localhost:8000
}
```

## Local production-mode run

```bash
export SFE_SECRET_KEY=$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')
export SFE_ADMIN_PASSWORD='ComposeAdmin123'
docker compose up --build
```

Reachable at `http://localhost:8000`, which works because localhost counts as a
secure context.

---

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `SFE_ENV` | `development` | `production` enables the start-up checks below |
| `SFE_SECRET_KEY` | random per start | **Required in production.** Signs session tokens |
| `SFE_ADMIN_EMAIL` | `admin@example.com` | Bootstrap administrator |
| `SFE_ADMIN_PASSWORD` | `Admin@12345` | **Required in production** |
| `PORT` | `8000` | Injected by the platform; takes precedence over `SFE_PORT` |
| `SFE_DATA_DIR` | `./data` (`/data` in the image) | Database and containers |
| `SFE_MAX_UPLOAD_BYTES` | `52428800` | 50 MB |
| `SFE_RETENTION_DAYS` | `7` | Before a container becomes purgeable |
| `SFE_RATE_LIMIT_REQUESTS` | `120` | Per account, per minute |
| `SFE_LOGIN_RATE_LIMIT` | `10` | Per IP, per minute |
| `SFE_ENABLE_DOCS` | off in production | Set `1` to expose `/docs` |
| `SFE_ARGON2_MEMORY_KIB` | `65536` | Lower it if phones struggle |

### The start-up checks

With `SFE_ENV=production` the service **refuses to start** if `SFE_SECRET_KEY`
is unset or short, or if `SFE_ADMIN_PASSWORD` is still the documented default:

```
ConfigurationError: Refusing to start in production:
  - SFE_SECRET_KEY is not set...
  - SFE_ADMIN_PASSWORD is still the documented default...
```

Failing to boot is deliberate. A service that comes up with a publicly
documented admin password is worse than one that does not come up.

---

## What was verified

Built and run locally in production mode:

- image builds; container reports `healthy`
- register → upload → download returns **byte-identical** bytes
- an ordinary user gets **403** from `/api/admin/stats`
- `/docs` and `/openapi.json` return **404** in production
- `Strict-Transport-Security` present
- production with defaults still in place **refuses to start**
- `docker compose up` serves a healthy instance

## After deploying — check these

1. Open the link. If you see the red "not running in a secure context" banner,
   TLS is not terminating properly.
2. Sign in as your administrator, confirm the admin tab appears.
3. Register a second, ordinary account and confirm it does **not**.
4. Encrypt a small file, download it, decrypt it, confirm it opens.
5. Open DevTools → Network during an encryption and confirm no request body
   contains the passphrase. This is the demonstration worth showing.

## Known limits at this scale

- **SQLite, single process.** Correct for one container; move `SFE_DATABASE_URL`
  to PostgreSQL before running several.
- **The rate limiter is in-process.** Two workers means two independent
  counters. Run one worker, or move the limiter to Redis.
- **No migrations.** The schema is created with `create_all()`; changing a model
  after you have real data needs manual SQL or Alembic.
- **No token revocation.** Sign-out is client-side; a token stays valid until it
  expires (12 hours by default). Suspension *is* immediate.
