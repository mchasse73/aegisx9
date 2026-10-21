"""Direct probes for the files and panels a web server must never serve.

This is the check that would have caught a public site serving its ``.git`` directory:
a port scan says "443 open, as approved" and a generic template run may skip the path,
but ``GET /.git/HEAD`` answering ``ref: refs/heads/...`` is unambiguous. A probe is a
finding only when the status is 200 *and* the body looks like the real thing, so a
catch-all "200 with the home page" server does not raise false alarms.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

from aegisx9_scanner.log import error_name

USER_AGENT = "aegisx9-scanner"
MAX_BODY = 64 * 1024

Fetcher = Callable[[str, int], "HttpResponse"]


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    error: str = ""


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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def fetch(url: str, timeout: int) -> HttpResponse:
    """GET without following redirects; the body is capped. The URL comes from the
    configured target list and the fixed probe table (http/https only)."""
    if not url.startswith(("http://", "https://")):
        return HttpResponse(status=0, headers={}, body=b"", error="ValueError")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})  # noqa: S310
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            return HttpResponse(
                status=resp.status,
                headers={k.lower(): v for k, v in resp.getheaders()},
                body=resp.read(MAX_BODY),
            )
    except urllib.error.HTTPError as exc:
        return HttpResponse(
            status=exc.code, headers={k.lower(): v for k, v in exc.headers.items()}, body=b""
        )
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return HttpResponse(status=0, headers={}, body=b"", error=error_name(exc))


def probe_host(
    host: str,
    *,
    scheme: str = "https",
    timeout: int = 10,
    fetcher: Fetcher | None = None,
    probes: tuple[Probe, ...] = PROBES,
) -> list[ExposureFinding]:
    base = f"{scheme}://{host}"
    fetcher = fetcher or fetch
    findings: list[ExposureFinding] = []
    for probe in probes:
        url = base + probe.path
        resp = fetcher(url, timeout)
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
