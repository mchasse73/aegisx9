"""Direct probes for the files and panels a web server must never serve.

This is the check that would have caught a public site serving its ``.git`` directory:
a port scan says "443 open, as approved" and a generic template run may skip the path,
but ``GET /.git/HEAD`` answering ``ref: refs/heads/...`` is unambiguous. A probe is a
finding only when the status is 200 *and* the body looks like the real thing, so a
catch-all "200 with the home page" server does not raise false alarms.

Probes run over both HTTP and HTTPS: a correctly protected HTTPS virtual host says
nothing about the plain-HTTP one on port 80. Connections go to the validated address;
the hostname is used for SNI and the ``Host`` header only. Redirects are not followed.
"""

from __future__ import annotations

import http.client
import re
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from aegisx9_scanner.log import error_name

USER_AGENT = "aegisx9-scanner"
MAX_BODY = 64 * 1024
DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    error: str = ""


Fetcher = Callable[[str, int, str], HttpResponse]
"""``fetcher(url, timeout_seconds, address)``: ``address`` pins the TCP connection."""


@dataclass(frozen=True)
class Probe:
    path: str
    category: str  # vcs | env | backup | metadata | admin | listing
    severity: str
    matcher: Callable[[HttpResponse], bool]
    description: str


@dataclass(frozen=True)
class ExposureFinding:
    host: str
    url: str
    category: str
    severity: str
    description: str
    status: int


def _text(resp: HttpResponse) -> str:
    return resp.body[:MAX_BODY].decode("utf-8", errors="replace")


def _content_type(resp: HttpResponse) -> str:
    return resp.headers.get("content-type", "").lower()


def _looks_like_git_head(resp: HttpResponse) -> bool:
    text = _text(resp).strip()
    return bool(re.match(r"^(ref: refs/|[0-9a-f]{40}$)", text))


def _looks_like_git_config(resp: HttpResponse) -> bool:
    text = _text(resp)
    return "[core]" in text and ("repositoryformatversion" in text or "[remote" in text)


def _looks_like_dotenv(resp: HttpResponse) -> bool:
    if "text/html" in _content_type(resp):
        return False
    lines = [ln.strip() for ln in _text(resp).splitlines() if ln.strip() and not ln.startswith("#")]
    assignments = [ln for ln in lines if re.match(r"^(export\s+)?[A-Za-z_][A-Za-z0-9_]*=", ln)]
    return len(lines) > 0 and len(assignments) >= max(1, len(lines) // 2)


def _looks_like_ds_store(resp: HttpResponse) -> bool:
    return resp.body.startswith(b"\x00\x00\x00\x01Bud1")


def _looks_like_archive_or_dump(resp: HttpResponse) -> bool:
    if "text/html" in _content_type(resp):
        return False
    body = resp.body
    magic = (b"PK\x03\x04", b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00", b"7z\xbc\xaf\x27\x1c", b"Rar!")
    if any(body.startswith(m) for m in magic) or (len(body) > 262 and body[257:262] == b"ustar"):
        return True
    text = _text(resp)
    return bool(
        re.search(r"^(--\s*(MySQL|PostgreSQL) dump|CREATE TABLE|INSERT INTO)", text, re.M | re.I)
    )


def _looks_like_admin_panel(resp: HttpResponse) -> bool:
    text = _text(resp).lower()
    markers = (
        "phpmyadmin",
        "adminer",
        "wp-login",
        'name="log"',
        "login_form",
        "<title>login",
        "sign in",
    )
    return any(m in text for m in markers)


def _looks_like_listing(resp: HttpResponse) -> bool:
    text = _text(resp)
    return bool(re.search(r"<title>Index of /|<h1>Index of /|Directory listing for /", text, re.I))


PROBES: tuple[Probe, ...] = (
    Probe(
        "/.git/HEAD", "vcs", "critical", _looks_like_git_head, "git repository served (.git/HEAD)"
    ),
    Probe(
        "/.git/config",
        "vcs",
        "critical",
        _looks_like_git_config,
        "git repository served (.git/config)",
    ),
    Probe("/.env", "env", "critical", _looks_like_dotenv, "environment file served (.env)"),
    Probe("/.env.bak", "env", "critical", _looks_like_dotenv, "environment file served (.env.bak)"),
    Probe(
        "/.env.local", "env", "critical", _looks_like_dotenv, "environment file served (.env.local)"
    ),
    Probe(
        "/.DS_Store",
        "metadata",
        "medium",
        _looks_like_ds_store,
        "Finder metadata served (.DS_Store)",
    ),
    Probe(
        "/backup.zip", "backup", "critical", _looks_like_archive_or_dump, "backup archive served"
    ),
    Probe(
        "/backup.tar.gz", "backup", "critical", _looks_like_archive_or_dump, "backup archive served"
    ),
    Probe("/backup.sql", "backup", "critical", _looks_like_archive_or_dump, "database dump served"),
    Probe("/dump.sql", "backup", "critical", _looks_like_archive_or_dump, "database dump served"),
    Probe("/db.sql", "backup", "critical", _looks_like_archive_or_dump, "database dump served"),
    Probe("/site.zip", "backup", "critical", _looks_like_archive_or_dump, "site archive served"),
    Probe("/www.zip", "backup", "critical", _looks_like_archive_or_dump, "site archive served"),
    Probe(
        "/wp-config.php.bak",
        "backup",
        "critical",
        lambda r: "DB_NAME" in _text(r),
        "config backup served",
    ),
    Probe(
        "/config.php.bak",
        "backup",
        "critical",
        lambda r: "<?php" in _text(r),
        "config backup served",
    ),
    Probe(
        "/phpmyadmin/", "admin", "high", _looks_like_admin_panel, "database admin panel reachable"
    ),
    Probe(
        "/adminer.php", "admin", "high", _looks_like_admin_panel, "database admin panel reachable"
    ),
    Probe("/wp-login.php", "admin", "high", _looks_like_admin_panel, "CMS login reachable"),
    Probe("/admin/", "admin", "high", _looks_like_admin_panel, "admin panel reachable"),
    Probe("/", "listing", "medium", _looks_like_listing, "directory listing at /"),
    Probe("/static/", "listing", "medium", _looks_like_listing, "directory listing at /static/"),
    Probe("/uploads/", "listing", "medium", _looks_like_listing, "directory listing at /uploads/"),
    Probe("/backup/", "listing", "high", _looks_like_listing, "directory listing at /backup/"),
    Probe("/backups/", "listing", "high", _looks_like_listing, "directory listing at /backups/"),
)


def _probe_context() -> ssl.SSLContext:
    """Content probes look at what is served, not at trust: a self-signed host that
    serves its .git directory is still a finding. The TLS check covers trust."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def open_connection(
    scheme: str, host: str, port: int, timeout: int, address: str
) -> http.client.HTTPConnection:
    """A connected client whose TCP peer is ``address`` and whose Host/SNI is ``host``."""
    from aegisx9_scanner.checks.tls import open_tls

    if scheme == "https":
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(host, port, timeout=timeout)
        conn.sock = open_tls(host, port, timeout, address, _probe_context())
        return conn
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    if address:
        import socket

        conn.sock = socket.create_connection((address, port), timeout=timeout)
    return conn


def fetch(url: str, timeout: int, address: str = "") -> HttpResponse:
    """GET without following redirects; the body is capped. The URL comes from the
    configured target list and the fixed probe table (http/https only)."""
    parts = urlsplit(url)
    if parts.scheme not in DEFAULT_PORTS or not parts.hostname:
        return HttpResponse(status=0, headers={}, body=b"", error="ValueError")
    host = parts.hostname
    port = parts.port or DEFAULT_PORTS[parts.scheme]
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    try:
        conn = open_connection(parts.scheme, host, port, timeout, address)
    except (OSError, ssl.SSLError, ValueError) as exc:
        return HttpResponse(status=0, headers={}, body=b"", error=error_name(exc))
    try:
        conn.request("GET", path, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
        resp = conn.getresponse()
        return HttpResponse(
            status=resp.status,
            headers={k.lower(): v for k, v in resp.getheaders()},
            body=resp.read(MAX_BODY),
        )
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
        return HttpResponse(status=0, headers={}, body=b"", error=error_name(exc))
    finally:
        conn.close()


def base_url(scheme: str, host: str, port: int | None = None) -> str:
    netloc = f"[{host}]" if ":" in host else host
    if port and port != DEFAULT_PORTS.get(scheme):
        netloc = f"{netloc}:{port}"
    return f"{scheme}://{netloc}"


def probe_host(
    host: str,
    *,
    scheme: str = "https",
    port: int | None = None,
    address: str = "",
    timeout: int = 10,
    fetcher: Fetcher | None = None,
    probes: tuple[Probe, ...] = PROBES,
) -> list[ExposureFinding]:
    fetcher = fetcher or fetch
    base = base_url(scheme, host, port)
    findings: list[ExposureFinding] = []
    for probe in probes:
        url = base + probe.path
        resp = fetcher(url, timeout, address)
        if resp.status == 200 and probe.matcher(resp):
            findings.append(
                ExposureFinding(
                    host=host,
                    url=url,
                    category=probe.category,
                    severity=probe.severity,
                    description=probe.description,
                    status=resp.status,
                )
            )
    return findings
