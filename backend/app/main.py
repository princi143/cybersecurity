import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from contextlib import closing
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .scanner import ScanError, scan

ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",") if o.strip()]
DB_PATH = os.getenv("DB_PATH", str(Path(__file__).resolve().parent.parent / "leads.db"))
SCANS_PER_MINUTE = int(os.getenv("SCANS_PER_MINUTE", "5"))

app = FastAPI(title="SecureAudit API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS,
                   allow_methods=["GET", "POST"], allow_headers=["Content-Type"])


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return resp


# ------------------------------------------------------------ rate limiting
_hits: dict[str, deque] = defaultdict(deque)


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown")


def rate_limit(request: Request, limit: int, window: int = 60) -> None:
    key = f"{request.url.path}:{_client_ip(request)}"
    now = time.monotonic()
    q = _hits[key]
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(429, "Too many requests. Please wait a minute and try again.")
    q.append(now)


# ------------------------------------------------------------ database
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS leads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, email TEXT NOT NULL, business TEXT,
        website TEXT, message TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
    return conn


# ------------------------------------------------------------ routes
class ScanRequest(BaseModel):
    url: str = Field(..., max_length=253)


class ContactRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=80)
    email: str = Field(..., max_length=120)
    business: str = Field("", max_length=120)
    website: str = Field("", max_length=200)
    message: str = Field("", max_length=2000)
    company_fax: str = Field("", max_length=50)  # honeypot: humans never fill this


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/scan")
async def run_scan(body: ScanRequest, request: Request):
    rate_limit(request, SCANS_PER_MINUTE)
    try:
        result = await scan(body.url)
    except ScanError as e:
        raise HTTPException(400, str(e))
    return result.to_dict()


@app.post("/api/contact", status_code=201)
def contact(body: ContactRequest, request: Request):
    rate_limit(request, 3)
    if body.company_fax:
        return {"ok": True}  # silently drop bots
    if not EMAIL_RE.match(body.email):
        raise HTTPException(422, "Please enter a valid email address.")
    with closing(db()) as conn, conn:
        conn.execute("INSERT INTO leads (name, email, business, website, message) VALUES (?,?,?,?,?)",
                     (body.name.strip(), body.email.strip(), body.business.strip(),
                      body.website.strip(), body.message.strip()))
    return {"ok": True}


@app.get("/api/leads")
def list_leads(request: Request):
    """Read contact-form submissions. Requires header: Authorization: Bearer <ADMIN_TOKEN>."""
    token = os.getenv("ADMIN_TOKEN")
    if not token or not secrets.compare_digest(request.headers.get("authorization", ""), f"Bearer {token}"):
        raise HTTPException(401, "Unauthorized")
    with closing(db()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM leads ORDER BY id DESC LIMIT 200").fetchall()
    return [dict(r) for r in rows]


# Serve the frontend too when running locally / as a single service.
_frontend = Path(__file__).resolve().parents[2] / "frontend"
if _frontend.is_dir():
    app.mount("/", StaticFiles(directory=_frontend, html=True), name="frontend")
