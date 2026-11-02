# SecureAudit

Website security check-ups for small businesses. This repo has two parts:

- **Free website scanner.** A visitor enters their site and gets a graded report (A–F) with plain-language fixes.
- **Services site.** Pricing, process, and a contact form that stores leads.

| Part | Stack | Hosted on |
|---|---|---|
| `backend/` | Python, FastAPI | Render (free web service) |
| `frontend/` | Plain HTML, CSS, JS | Vercel (static) |

## What the scanner checks

All checks are passive. The scanner only loads the homepage, opens a TLS connection and reads public DNS, the same things a browser does. It never probes paths, submits forms or scans ports.

| Area | Checks |
|---|---|
| Encryption | Valid certificate, days to expiry, TLS version, HTTP → HTTPS redirect |
| Headers | HSTS (and max-age), Content-Security-Policy, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, clickjacking protection |
| Information leaks | Server version, X-Powered-By |
| Cookies | Secure, HttpOnly and SameSite flags |
| Email spoofing | SPF record, DMARC policy |

Each check has a weight. A pass earns full points, a warning earns half, and the score maps to a grade (A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40).

### Abuse protection

- **SSRF guard.** Every hostname, including every redirect hop, is resolved and rejected if it points at a private, loopback, link-local or reserved address (e.g. `169.254.169.254` cloud metadata). Only ports 80 and 443 are allowed.
- **Rate limits.** 5 scans per minute per IP (`SCANS_PER_MINUTE`) and 3 contact submissions per minute.
- **Spam.** The contact form uses a honeypot field to drop bots silently.

## Run locally

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt pytest
uvicorn app.main:app --reload
```

Open http://localhost:8000. The API also serves the frontend, so one command runs everything.

Run the tests with `pytest -q` (inside `backend/`).

Docker (build from the repo root):

```bash
docker build -f backend/Dockerfile -t secureaudit .
docker run -p 8000:8000 secureaudit
```

## Deploy

### 1. Backend on Render

1. On Render, choose **New → Blueprint** and pick this repo. It reads `render.yaml`.
2. Wait for the first deploy, then check `https://<your-service>.onrender.com/api/health` returns `{"status":"ok"}`.
3. Copy the generated `ADMIN_TOKEN` from the service's **Environment** tab. You'll need it to read leads.

The Render URL works on its own too, because it serves the frontend as well.

### 2. Frontend on Vercel

1. If your Render URL isn't `https://secureaudit-api.onrender.com`, update the `destination` in `frontend/vercel.json` to your URL.
2. On Vercel, choose **Add New → Project**, import this repo and set **Root Directory** to `frontend`. Leave the framework preset as "Other".
3. Deploy. Vercel proxies `/api/*` to Render, so there's no CORS setup and no URL in the JavaScript.

`vercel.json` also sets strict security headers. Scan your own deployed site and it should get an A.

## Reading leads

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" https://<your-service>.onrender.com/api/leads
```

> **Note:** Render's free plan has no persistent disk. The SQLite file is wiped on every redeploy or restart. Before relying on the form for real clients, point leads at a hosted database (Supabase's free Postgres works) or an email/Slack webhook.

## API

| Method | Path | Body / auth | Returns |
|---|---|---|---|
| GET | `/api/health` | none | `{"status":"ok"}` |
| POST | `/api/scan` | `{"url": "example.com"}` | Report with `score`, `grade`, `summary`, `checks[]` |
| POST | `/api/contact` | `{name, email, business?, website?, message?}` | `201 {"ok": true}` |
| GET | `/api/leads` | `Authorization: Bearer <ADMIN_TOKEN>` | Latest 200 leads |

## Ethics

Only run active security testing on systems where the owner has given written permission. The scanner is passive by design. Anything deeper is part of the paid check-up and starts with a signed scope.
