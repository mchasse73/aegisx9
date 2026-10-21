"""TLS and HTTP security-header checks, standard library only.

* certificate expiry and chain validity against the system trust store;
* which protocol versions the server still accepts (TLS 1.0/1.1 are findings);
* HSTS and the common security headers on the HTTPS front page.
"""

from __future__ import annotations

import http.client
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from aegisx9_scanner.log import error_name

LEGACY_VERSIONS: tuple[ssl.TLSVersion, ...] = (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1)
SECURITY_HEADERS: tuple[str, ...] = (
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "content-security-policy",
    "referrer-policy",
)
CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"

PeerCertFetcher = Callable[[str, int, int], dict[str, Any]]
VersionProbe = Callable[[str, int, ssl.TLSVersion, int], bool]
HeaderFetcher = Callable[[str, int, int], dict[str, str]]


@dataclass
class TlsResult:
    host: str
    port: int = 443
    not_after: datetime | None = None
    days_left: int | None = None
    chain_ok: bool = False
    error: str = ""  # exception type name only
    legacy_versions: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    headers_fetched: bool = False

    @property
    def hsts(self) -> bool:
        return "strict-transport-security" in self.headers

    @property
    def missing_headers(self) -> list[str]:
        if not self.headers_fetched:
            return []
        return [h for h in SECURITY_HEADERS if h not in self.headers]


def fetch_peer_cert(host: str, port: int, timeout: int) -> dict[str, Any]:
    """The verified leaf certificate as ``getpeercert()`` returns it.

    Raises ``ssl.SSLCertVerificationError`` on an invalid chain, name mismatch or an
    expired certificate; the caller turns that into ``CERT_INVALID``.
    """
    ctx = ssl.create_default_context()
    with (
        socket.create_connection((host, port), timeout=timeout) as raw,
        ctx.wrap_socket(raw, server_hostname=host) as tls,
    ):
        return tls.getpeercert() or {}


def probe_version(host: str, port: int, version: ssl.TLSVersion, timeout: int) -> bool:
    """True when the server completes a handshake pinned to ``version``."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ssl.SSLError, ValueError):
        return False  # the local OpenSSL refuses to even offer this version
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as raw,
            ctx.wrap_socket(raw, server_hostname=host),
        ):
            return True
    except (OSError, ssl.SSLError):
        return False


def fetch_headers(host: str, port: int, timeout: int) -> dict[str, str]:
    conn = http.client.HTTPSConnection(
        host, port, timeout=timeout, context=ssl.create_default_context()
    )
    try:
        conn.request("GET", "/", headers={"User-Agent": "aegisx9-scanner", "Accept": "*/*"})
        resp = conn.getresponse()
        resp.read(0)
        return {k.lower(): v for k, v in resp.getheaders()}
    finally:
        conn.close()


def parse_not_after(cert: dict[str, Any]) -> datetime | None:
    raw = cert.get("notAfter")
    if not raw:
        return None
    try:
        return datetime.strptime(str(raw), CERT_DATE_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        return None


def check_tls(
    host: str,
    port: int = 443,
    *,
    timeout: int = 10,
    now: datetime | None = None,
    peer_cert: PeerCertFetcher = fetch_peer_cert,
    version_probe: VersionProbe = probe_version,
    headers: HeaderFetcher = fetch_headers,
) -> TlsResult:
    now = now or datetime.now(UTC)
    result = TlsResult(host=host, port=port)
    try:
        cert = peer_cert(host, port, timeout)
    except ssl.SSLCertVerificationError as exc:
        result.error = error_name(exc)
    except (OSError, ssl.SSLError) as exc:
        result.error = error_name(exc)
        return result  # nothing is listening or TLS is not spoken; no further probes
    else:
        result.chain_ok = True
        result.not_after = parse_not_after(cert)
        if result.not_after is not None:
            result.days_left = (result.not_after - now).days

    for version in LEGACY_VERSIONS:
        if version_probe(host, port, version, timeout):
            result.legacy_versions.append(version.name)

    if result.chain_ok:
        try:
            result.headers = headers(host, port, timeout)
            result.headers_fetched = True
        except (OSError, http.client.HTTPException, ssl.SSLError):
            result.headers_fetched = False
    return result
