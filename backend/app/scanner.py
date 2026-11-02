"""Passive website security scanner.

Only performs the requests a normal browser would make (GET the homepage over
HTTP and HTTPS, open a TLS connection, look up public DNS records). It never
probes paths, fuzzes input, or scans ports, so it is safe to run against any
public site.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

import dns.asyncresolver
import dns.exception
import httpx

USER_AGENT = "SecureAuditBot/1.0 (+passive security check)"
TIMEOUT = 8.0
MAX_REDIRECTS = 5


class ScanError(ValueError):
    """Raised for input the scanner refuses to handle."""


@dataclass
class Check:
    id: str
    category: str
    title: str
    status: str  # pass | warn | fail | info
    detail: str
    fix: str = ""
    weight: int = 0  # points available


@dataclass
class ScanResult:
    target: str
    host: str
    scanned_at: str
    score: int = 0
    grade: str = "F"
    checks: list[Check] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["summary"] = {
            s: sum(1 for c in self.checks if c.status == s)
            for s in ("pass", "warn", "fail", "info")
        }
        return d


# ---------------------------------------------------------------- input safety

def normalise_target(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise ScanError("Enter a website address.")
    if "://" not in raw:
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https"):
        raise ScanError("Only http and https websites can be scanned.")
    if not p.hostname or "." not in p.hostname:
        raise ScanError("That doesn't look like a public website address.")
    if p.port not in (None, 80, 443):
        raise ScanError("Only standard ports (80/443) can be scanned.")
    if p.username or p.password:
        raise ScanError("URLs with credentials are not allowed.")
    return p.hostname.lower().rstrip(".")


def _is_public(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return addr.is_global and not addr.is_multicast


async def assert_public_host(host: str) -> list[str]:
    """Resolve host and refuse anything that isn't a public internet address
    (blocks SSRF against localhost, cloud metadata, private networks)."""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ScanError(f"Could not resolve {host}.")
    ips = sorted({i[4][0] for i in infos})
    if not ips or not all(_is_public(ip) for ip in ips):
        raise ScanError("That address points to a private or reserved network.")
    return ips


async def _safe_get(client: httpx.AsyncClient, url: str) -> tuple[httpx.Response, list[str]]:
    """GET with manual redirects so every hop passes the public-host check."""
    chain = [url]
    for _ in range(MAX_REDIRECTS + 1):
        host = urlparse(url).hostname or ""
        await assert_public_host(host)
        resp = await client.get(url)
        if resp.is_redirect and "location" in resp.headers:
            url = urljoin(url, resp.headers["location"])
            if urlparse(url).scheme not in ("http", "https"):
                break
            chain.append(url)
            continue
        return resp, chain
    raise ScanError("Too many redirects.")


# ---------------------------------------------------------------- checks

def _tls_info(host: str) -> dict:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            return {"cert": cert, "version": tls.version()}


async def check_tls(host: str) -> list[Check]:
    out: list[Check] = []
    try:
        info = await asyncio.to_thread(_tls_info, host)
    except ssl.SSLCertVerificationError as e:
        return [Check("tls_valid", "Encryption", "Valid SSL certificate", "fail",
                      f"Certificate could not be verified: {e.verify_message}.",
                      "Install a valid certificate (free via Let's Encrypt) that matches the domain.", 25)]
    except (OSError, ssl.SSLError):
        return [Check("tls_valid", "Encryption", "HTTPS available", "fail",
                      "The site does not accept HTTPS connections.",
                      "Enable HTTPS. Most hosts offer free Let's Encrypt certificates.", 25)]

    cert = info["cert"]
    expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days = (expires - datetime.now(timezone.utc)).days
    issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "unknown issuer")
    out.append(Check("tls_valid", "Encryption", "Valid SSL certificate", "pass",
                     f"Trusted certificate issued by {issuer}.", weight=15))
    if days < 0:
        st, fix = "fail", "Renew the certificate immediately."
    elif days < 14:
        st, fix = "fail", "Renew now and enable auto-renewal."
    elif days < 30:
        st, fix = "warn", "Make sure auto-renewal is configured."
    else:
        st, fix = "pass", ""
    out.append(Check("tls_expiry", "Encryption", "Certificate expiry", st,
                     f"Expires {expires:%d %b %Y} ({days} days left).", fix, 10))

    ver = info["version"] or ""
    out.append(Check("tls_version", "Encryption", "Modern TLS version",
                     "pass" if ver in ("TLSv1.3", "TLSv1.2") else "fail",
                     f"Negotiated {ver or 'unknown'}.",
                     "" if ver in ("TLSv1.3", "TLSv1.2") else "Disable TLS 1.0/1.1 on the server.", 5))
    return out


async def check_http_redirect(client: httpx.AsyncClient, host: str) -> Check:
    try:
        resp, chain = await _safe_get(client, f"http://{host}/")
        final = str(resp.url)
    except (httpx.HTTPError, ScanError):
        return Check("https_redirect", "Encryption", "HTTP redirects to HTTPS", "info",
                     "Plain HTTP is not reachable, so there is nothing to redirect.", weight=0)
    if final.startswith("https://"):
        return Check("https_redirect", "Encryption", "HTTP redirects to HTTPS", "pass",
                     "Visitors on http:// are sent to the secure version.", weight=10)
    return Check("https_redirect", "Encryption", "HTTP redirects to HTTPS", "fail",
                 "The site still serves pages over unencrypted HTTP.",
                 "Add a permanent (301) redirect from http:// to https://.", 10)


HEADER_RULES = [
    ("strict-transport-security", "HSTS", 8,
     "Tells browsers to always use HTTPS, preventing downgrade attacks.",
     "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    ("content-security-policy", "Content-Security-Policy", 8,
     "Restricts which scripts can run, the main defence against XSS.",
     "Start with: Content-Security-Policy: default-src 'self' and loosen as needed."),
    ("x-content-type-options", "X-Content-Type-Options", 4,
     "Stops browsers guessing file types (MIME sniffing).",
     "Add: X-Content-Type-Options: nosniff"),
    ("referrer-policy", "Referrer-Policy", 3,
     "Controls how much of your URLs leak to other sites.",
     "Add: Referrer-Policy: strict-origin-when-cross-origin"),
    ("permissions-policy", "Permissions-Policy", 2,
     "Limits access to camera, microphone, location, etc.",
     "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"),
]


def check_headers(resp: httpx.Response) -> list[Check]:
    h = resp.headers
    out = []
    for name, title, weight, why, fix in HEADER_RULES:
        val = h.get(name)
        if name == "strict-transport-security" and val:
            try:
                max_age = int(val.lower().split("max-age=")[1].split(";")[0].strip())
            except (IndexError, ValueError):
                max_age = 0
            if max_age < 15552000:
                out.append(Check("hdr_hsts", "Headers", title, "warn",
                                 f"Present but max-age is short ({max_age}s).", fix, weight))
                continue
        out.append(Check(f"hdr_{name}", "Headers", title, "pass" if val else "fail",
                         f"Set: {val[:120]}" if val else f"Missing. {why}", "" if val else fix, weight))

    csp = h.get("content-security-policy", "")
    xfo = h.get("x-frame-options")
    framed = bool(xfo) or "frame-ancestors" in csp
    out.append(Check("hdr_clickjacking", "Headers", "Clickjacking protection",
                     "pass" if framed else "fail",
                     "Site cannot be embedded in other pages." if framed
                     else "Other sites can embed this page in an iframe to trick users.",
                     "" if framed else "Add: X-Frame-Options: DENY (or CSP frame-ancestors 'self')", 5))
    return out


def check_disclosure(resp: httpx.Response) -> list[Check]:
    out = []
    server = resp.headers.get("server", "")
    if any(c.isdigit() for c in server):
        out.append(Check("disc_server", "Information leaks", "Server version hidden", "warn",
                         f"Server header reveals version: {server}.",
                         "Hide version numbers (e.g. server_tokens off in nginx).", 3))
    else:
        out.append(Check("disc_server", "Information leaks", "Server version hidden", "pass",
                         "No version number exposed.", weight=3))
    powered = resp.headers.get("x-powered-by")
    out.append(Check("disc_powered", "Information leaks", "Tech stack hidden",
                     "warn" if powered else "pass",
                     f"X-Powered-By reveals: {powered}." if powered else "No X-Powered-By header.",
                     "Remove the X-Powered-By header." if powered else "", 2))
    return out


def check_cookies(resp: httpx.Response) -> Check:
    raw = resp.headers.get_list("set-cookie")
    if not raw:
        return Check("cookies", "Cookies", "Cookie security flags", "info",
                     "No cookies set on the homepage.", weight=0)
    weak = []
    for c in raw:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        missing = [f for f, k in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite"))
                   if k not in low]
        if missing:
            weak.append(f"{name} (missing {', '.join(missing)})")
    if not weak:
        return Check("cookies", "Cookies", "Cookie security flags", "pass",
                     f"All {len(raw)} cookie(s) use Secure, HttpOnly and SameSite.", weight=5)
    return Check("cookies", "Cookies", "Cookie security flags", "warn",
                 "Weak cookies: " + "; ".join(weak[:5]),
                 "Set Secure; HttpOnly; SameSite=Lax on session cookies.", 5)


async def _txt(name: str) -> list[str]:
    try:
        ans = await dns.asyncresolver.resolve(name, "TXT", lifetime=TIMEOUT)
        return [b"".join(r.strings).decode(errors="ignore") for r in ans]
    except (dns.exception.DNSException, OSError):
        return []


def _apex(host: str) -> str:
    parts = host.split(".")
    if len(parts) > 2 and parts[-2] in ("co", "com", "org", "net", "ac", "gov", "edu") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


async def check_email(host: str) -> list[Check]:
    apex = _apex(host)
    spf_records, dmarc_records = await asyncio.gather(_txt(apex), _txt(f"_dmarc.{apex}"))
    spf = next((r for r in spf_records if r.lower().startswith("v=spf1")), None)
    dmarc = next((r for r in dmarc_records if r.lower().startswith("v=dmarc1")), None)
    out = [Check("email_spf", "Email spoofing", "SPF record", "pass" if spf else "fail",
                 f"Found: {spf[:120]}" if spf else f"No SPF record on {apex}; anyone can send mail as you.",
                 "" if spf else "Add a TXT record like: v=spf1 include:_spf.google.com ~all", 6)]
    if dmarc:
        policy = "none"
        for part in dmarc.split(";"):
            k, _, v = part.strip().partition("=")
            if k.lower() == "p":
                policy = v.lower()
        st = "pass" if policy in ("quarantine", "reject") else "warn"
        out.append(Check("email_dmarc", "Email spoofing", "DMARC policy", st,
                         f"Policy is p={policy}.",
                         "" if st == "pass" else "Move to p=quarantine once reports look clean.", 6))
    else:
        out.append(Check("email_dmarc", "Email spoofing", "DMARC policy", "fail",
                         "No DMARC record; spoofed emails won't be blocked.",
                         f"Add TXT at _dmarc.{apex}: v=DMARC1; p=quarantine; rua=mailto:dmarc@{apex}", 6))
    return out


# ---------------------------------------------------------------- orchestration

def grade_for(score: int) -> str:
    for g, cutoff in (("A", 90), ("B", 75), ("C", 60), ("D", 40)):
        if score >= cutoff:
            return g
    return "F"


def score_checks(checks: list[Check]) -> int:
    possible = sum(c.weight for c in checks if c.status != "info")
    earned = sum(c.weight * {"pass": 1, "warn": 0.5}.get(c.status, 0) for c in checks if c.status != "info")
    return round(100 * earned / possible) if possible else 0


async def scan(raw_target: str) -> ScanResult:
    host = normalise_target(raw_target)
    await assert_public_host(host)
    result = ScanResult(target=raw_target, host=host,
                        scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))

    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False,
                                 headers={"User-Agent": USER_AGENT}) as client:
        tls_task = asyncio.create_task(check_tls(host))
        email_task = asyncio.create_task(check_email(host))
        redirect_check = await check_http_redirect(client, host)

        page = None
        for scheme in ("https", "http"):
            try:
                page, _ = await _safe_get(client, f"{scheme}://{host}/")
                break
            except (httpx.HTTPError, ScanError):
                continue

        result.checks += await tls_task
        result.checks.append(redirect_check)
        if page is not None:
            result.checks += check_headers(page)
            result.checks += check_disclosure(page)
            result.checks.append(check_cookies(page))
        else:
            result.checks.append(Check("reachable", "Availability", "Website reachable", "fail",
                                       "The homepage could not be loaded.", weight=0))
        result.checks += await email_task

    result.score = score_checks(result.checks)
    result.grade = grade_for(result.score)
    return result
