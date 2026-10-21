from __future__ import annotations

import socket
import ssl
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegisx9_scanner.checks import (
    CommandResult,
    http_exposure,
    nuclei,
    ports,
    run_command,
    tls,
    uptime,
)
from aegisx9_scanner.checks import dns as dns_check
from aegisx9_scanner.targets import DnsExpectation, UptimeTarget

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
<host><status state="up"/>
<address addr="203.0.113.10" addrtype="ipv4"/>
<hostnames><hostname name="www.example.com" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
<port protocol="tcp" portid="80"><state state="filtered"/></port>
</ports></host>
<host><status state="up"/>
<address addr="2001:db8::1" addrtype="ipv6"/>
<ports><port protocol="udp" portid="53"><state state="open"/></port></ports></host>
<host><status state="up"/><address addr="aa:bb" addrtype="mac"/></host>
</nmaprun>
"""


# --- ports ---------------------------------------------------------------------------


def test_nmap_argv_variants() -> None:
    argv = ports.nmap_argv(
        "/usr/bin/nmap", ["a", "b"], proto="tcp", top_ports=1000, privileged=True, exclude=["x", ""]
    )
    assert argv[1] == "-sS" and argv[-2:] == ["a", "b"] and "--exclude" in argv and "x" in argv
    assert ports.nmap_argv("n", ["a"], proto="tcp", top_ports=10, privileged=False)[1] == "-sT"
    assert ports.nmap_argv("n", ["a"], proto="udp", top_ports=100, privileged=True)[1] == "-sU"


def test_parse_nmap_xml() -> None:
    found = ports.parse_nmap_xml(NMAP_XML)
    assert [(p.ip, p.port, p.proto, p.service, p.hostname) for p in found] == [
        ("2001:db8::1", 53, "udp", "", ""),
        ("203.0.113.10", 22, "tcp", "ssh", "www.example.com"),
        ("203.0.113.10", 443, "tcp", "https", "www.example.com"),
    ]
    assert found[1].key == ("203.0.113.10", 22, "tcp")
    assert ports.parse_nmap_xml("  ") == []


def test_scan_ports_privileged_runs_tcp_and_udp() -> None:
    calls: list[list[str]] = []

    def runner(argv: list[str], timeout: int) -> CommandResult:
        calls.append(argv)
        return CommandResult(0, NMAP_XML if argv[1] == "-sS" else "<nmaprun></nmaprun>")

    res = ports.scan_ports(
        ["203.0.113.0/27"], exclude=["192.0.2.0/24"], privileged=True, runner=runner, nmap="/x/nmap"
    )
    assert res.tcp_ran and res.udp_ran and len(res.open_ports) == 3
    assert [c[1] for c in calls] == ["-sS", "-sU"]
    assert all("192.0.2.0/24" in c for c in calls)


def test_scan_ports_unprivileged_skips_udp_and_reports_failures() -> None:
    res = ports.scan_ports(
        ["a"], privileged=False, runner=lambda a, t: CommandResult(1, ""), nmap="/x/nmap"
    )
    assert not res.tcp_ran and not res.udp_ran
    assert any("exited 1" in n for n in res.notes) and any(
        "UDP scan skipped" in n for n in res.notes
    )
    res = ports.scan_ports(
        ["a"], privileged=True, runner=lambda a, t: CommandResult(0, "<broken"), nmap="/x/nmap"
    )
    assert not res.tcp_ran and any("unparseable" in n for n in res.notes)
    assert "no targets" in ports.scan_ports([], privileged=False, nmap="/x/nmap").notes[0]
    assert (
        "not installed"
        in ports.scan_ports(
            ["a"], privileged=False, nmap=None, runner=lambda a, t: CommandResult(0, "")
        ).notes[0]
    )


def test_is_privileged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ports.os, "geteuid", lambda: 0, raising=False)
    assert ports.is_privileged()
    monkeypatch.setattr(ports.os, "geteuid", lambda: 1000, raising=False)
    assert not ports.is_privileged()


def test_run_command_real_and_failing(tmp_path: Path) -> None:
    res = run_command(["/bin/sh", "-c", "cat; echo out"], 10, stdin="in-")
    assert res.returncode == 0 and res.stdout == "in-out\n"
    res = run_command([str(tmp_path / "missing-tool")], 10)
    assert res.returncode == 127 and res.stderr == "FileNotFoundError"


def test_run_command_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise subprocess.TimeoutExpired("x", 1)

    monkeypatch.setattr(subprocess, "run", boom)
    assert run_command(["x"], 1).stderr == "TimeoutExpired"


# --- tls -----------------------------------------------------------------------------


def _cert(days: int, now: datetime) -> dict[str, object]:
    from datetime import timedelta

    when = now + timedelta(days=days)
    return {"notAfter": when.strftime("%b %d %H:%M:%S %Y GMT")}


def test_check_tls_healthy_and_expiring() -> None:
    now = datetime(2026, 10, 21, 12, tzinfo=UTC)
    res = tls.check_tls(
        "www.example.com",
        now=now,
        peer_cert=lambda h, p, t: _cert(40, now),
        version_probe=lambda h, p, v, t: False,
        headers=lambda h, p, t: {
            "strict-transport-security": "max-age=1",
            "x-frame-options": "DENY",
        },
    )
    assert res.chain_ok and res.days_left == 40 and res.hsts and not res.legacy_versions
    assert res.missing_headers == [
        "x-content-type-options",
        "content-security-policy",
        "referrer-policy",
    ]
    res = tls.check_tls(
        "www.example.com",
        now=now,
        peer_cert=lambda h, p, t: _cert(5, now),
        version_probe=lambda h, p, v, t: v == ssl.TLSVersion.TLSv1,
        headers=lambda h, p, t: (_ for _ in ()).throw(OSError()),
    )
    assert res.days_left == 5 and res.legacy_versions == ["TLSv1"] and not res.headers_fetched
    assert res.missing_headers == []


def test_check_tls_invalid_and_unreachable() -> None:
    def bad_chain(h: str, p: int, t: int) -> dict[str, object]:
        raise ssl.SSLCertVerificationError("x")

    res = tls.check_tls(
        "a", peer_cert=bad_chain, version_probe=lambda h, p, v, t: True, headers=lambda h, p, t: {}
    )
    assert (
        res.error == "SSLCertVerificationError"
        and not res.chain_ok
        and len(res.legacy_versions) == 2
    )

    def down(h: str, p: int, t: int) -> dict[str, object]:
        raise ConnectionRefusedError()

    res = tls.check_tls(
        "a", peer_cert=down, version_probe=lambda h, p, v, t: True, headers=lambda h, p, t: {}
    )
    assert res.error == "ConnectionRefusedError" and res.legacy_versions == []
    assert tls.parse_not_after({"notAfter": "garbage"}) is None
    assert tls.parse_not_after({}) is None
    res = tls.check_tls(
        "a",
        peer_cert=lambda h, p, t: {},
        version_probe=lambda h, p, v, t: False,
        headers=lambda h, p, t: {},
    )
    assert res.chain_ok and res.days_left is None


def test_tls_io_helpers_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_a: object, **_k: object) -> None:
        raise ConnectionRefusedError()

    monkeypatch.setattr(socket, "create_connection", refuse)
    assert tls.probe_version("a", 443, ssl.TLSVersion.TLSv1_2, 1) is False
    with pytest.raises(ConnectionRefusedError):
        tls.fetch_peer_cert("a", 443, 1)

    class Conn:
        def __init__(self, *_a: object, **_k: object) -> None:
            pass

        def request(self, *_a: object, **_k: object) -> None:
            pass

        def getresponse(self) -> object:
            class R:
                def read(self, _n: int) -> bytes:
                    return b""

                def getheaders(self) -> list[tuple[str, str]]:
                    return [("Strict-Transport-Security", "max-age=1")]

            return R()

        def close(self) -> None:
            pass

    monkeypatch.setattr(tls.http.client, "HTTPSConnection", Conn)
    assert tls.fetch_headers("a", 443, 1) == {"strict-transport-security": "max-age=1"}


# --- http exposure -------------------------------------------------------------------


def _responder(table: dict[str, tuple[int, bytes, str]]):  # type: ignore[no-untyped-def]
    def fetch(url: str, timeout: int) -> http_exposure.HttpResponse:
        path = url.split("example.com", 1)[1]
        status, body, ctype = table.get(path, (404, b"", "text/html"))
        return http_exposure.HttpResponse(status=status, headers={"content-type": ctype}, body=body)

    return fetch


def test_probe_host_detects_real_exposures_only() -> None:
    table = {
        "/.git/HEAD": (200, b"ref: refs/heads/main\n", "text/plain"),
        "/.git/config": (200, b"[core]\n\trepositoryformatversion = 0\n", "text/plain"),
        "/.env": (200, b"# comment\nAPP_ENV=prod\nDB_HOST=db\n", "text/plain"),
        "/.env.bak": (200, b"<html>catch-all</html>", "text/html"),
        "/.DS_Store": (200, b"\x00\x00\x00\x01Bud1\x00", "application/octet-stream"),
        "/backup.zip": (200, b"PK\x03\x04junk", "application/zip"),
        "/dump.sql": (200, b"-- MySQL dump 10.13\nCREATE TABLE t (id int);", "text/plain"),
        "/backup.tar.gz": (200, b"\x1f\x8bxx", "application/gzip"),
        "/site.zip": (200, b"<html>home</html>", "text/html"),
        "/wp-config.php.bak": (200, b"<?php define('DB_NAME', 'x');", "text/plain"),
        "/config.php.bak": (200, b"<?php return [];", "text/plain"),
        "/phpmyadmin/": (200, b"<title>phpMyAdmin</title>", "text/html"),
        "/admin/": (200, b"<html>welcome</html>", "text/html"),
        "/uploads/": (200, b"<title>Index of /uploads</title>", "text/html"),
        "/": (200, b"<html>home</html>", "text/html"),
    }
    findings = http_exposure.probe_host("www.example.com", fetcher=_responder(table))
    urls = {f.url.replace("https://www.example.com", "") for f in findings}
    assert urls == {
        "/.git/HEAD", "/.git/config", "/.env", "/.DS_Store", "/backup.zip", "/dump.sql",
        "/backup.tar.gz", "/wp-config.php.bak", "/config.php.bak", "/phpmyadmin/", "/uploads/",
    }  # fmt: skip
    git = next(f for f in findings if f.url.endswith("/.git/HEAD"))
    assert git.category == "vcs" and git.severity == "critical" and git.status == 200
    assert http_exposure.probe_host("www.example.com", fetcher=_responder({})) == []


def test_matchers_edge_cases() -> None:
    r = http_exposure.HttpResponse(
        200, {"content-type": "text/plain"}, b"a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0"
    )
    assert http_exposure._looks_like_git_head(r)
    assert not http_exposure._looks_like_dotenv(http_exposure.HttpResponse(200, {}, b"\n\n"))
    assert http_exposure._looks_like_archive_or_dump(
        http_exposure.HttpResponse(200, {}, b"x" * 257 + b"ustar" + b"y" * 10)
    )
    assert not http_exposure._looks_like_archive_or_dump(
        http_exposure.HttpResponse(200, {}, b"hello")
    )


def test_fetch_uses_urllib_without_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.error

    assert http_exposure.fetch("ftp://x", 1).error == "ValueError"

    class Resp:
        status = 200

        def __enter__(self) -> Resp:
            return self

        def __exit__(self, *a: object) -> None:
            pass

        def getheaders(self) -> list[tuple[str, str]]:
            return [("Content-Type", "text/plain")]

        def read(self, _n: int) -> bytes:
            return b"ref: refs/heads/main"

    monkeypatch.setattr(http_exposure._OPENER, "open", lambda req, timeout: Resp())
    r = http_exposure.fetch("https://www.example.com/.git/HEAD", 1)
    assert r.status == 200 and r.headers == {"content-type": "text/plain"}

    def http_error(req: object, timeout: int) -> None:
        raise urllib.error.HTTPError("https://x", 302, "Found", {"Location": "/"}, None)  # type: ignore[arg-type]

    monkeypatch.setattr(http_exposure._OPENER, "open", http_error)
    assert http_exposure.fetch("https://www.example.com/", 1).status == 302

    def url_error(req: object, timeout: int) -> None:
        raise urllib.error.URLError("x")

    monkeypatch.setattr(http_exposure._OPENER, "open", url_error)
    assert http_exposure.fetch("https://www.example.com/", 1).error == "URLError"
    assert http_exposure._NoRedirect().redirect_request() is None


# --- nuclei --------------------------------------------------------------------------


def test_nuclei_parse_and_run(tmp_path: Path) -> None:
    rows = (
        '{"template-id":"git-config","info":{"name":"Git Config","severity":"HIGH"},'
        '"host":"https://www.example.com","matched-at":"https://www.example.com/.git/config"}\n'
        "not json\n[1]\n"
    )
    found = nuclei.parse_jsonl(rows)
    assert len(found) == 1 and found[0].severity == "high" and found[0].template_id == "git-config"

    def runner(argv: list[str], timeout: int) -> CommandResult:
        out = Path(argv[argv.index("-output") + 1])
        out.write_text(rows)
        assert Path(argv[argv.index("-list") + 1]).read_text() == "https://www.example.com\n"
        return CommandResult(0, "")

    res = nuclei.run_nuclei(["www.example.com"], tmp_path / "w", runner=runner, nuclei="/x/nuclei")
    assert res.ran and len(res.findings) == 1
    res = nuclei.run_nuclei(
        ["a"], tmp_path / "w", runner=lambda a, t: CommandResult(0, ""), nuclei="/x/nuclei"
    )
    assert res.ran and res.findings == []
    res = nuclei.run_nuclei(
        ["a"], tmp_path / "w", runner=lambda a, t: CommandResult(2, ""), nuclei="/x/nuclei"
    )
    assert not res.ran and "exited 2" in res.notes[0]
    assert (
        "not installed"
        in nuclei.run_nuclei(
            ["a"], tmp_path, nuclei=None, runner=lambda a, t: CommandResult(0, "")
        ).notes[0]
    )
    assert "no hosts" in nuclei.run_nuclei([], tmp_path, nuclei="/x").notes[0]


# --- dns -----------------------------------------------------------------------------


def test_check_dns_drift_and_errors() -> None:
    def lookup(name: str, rtype: str) -> list[str]:
        if name == "www.example.com":
            return ["203.0.113.10"]
        if name == "mx.example.com":
            return ["10  mail.example.com."]
        if name == "gone.example.com":
            raise socket.gaierror()
        if name == "txt.example.com":
            raise LookupError("dig not installed")
        raise OSError()

    results = dns_check.check_dns(
        [
            DnsExpectation("www.example.com", "A", ("203.0.113.10",)),
            DnsExpectation("mx.example.com", "MX", ("10 mail.example.com",)),
            DnsExpectation("gone.example.com", "A", ("203.0.113.9",)),
            DnsExpectation("txt.example.com", "TXT", ("v=spf1 -all",)),
            DnsExpectation("err.example.com", "A", ("203.0.113.9",)),
        ],
        lookup=lookup,
    )
    assert [r.drifted for r in results] == [False, False, True, False, False]
    assert not results[3].supported and results[4].error == "OSError"


def test_system_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("203.0.113.10", 0))])
    assert dns_check.system_lookup("www.example.com", "A") == ["203.0.113.10"]
    monkeypatch.setattr(dns_check, "find_tool", lambda n: None)
    with pytest.raises(LookupError):
        dns_check.system_lookup("www.example.com", "MX")
    monkeypatch.setattr(dns_check, "find_tool", lambda n: "/usr/bin/dig")
    with pytest.raises(ValueError, match="unsafe"):
        dns_check.system_lookup("bad name", "MX")
    out = dns_check.system_lookup(
        "example.com", "MX", runner=lambda a, t: CommandResult(0, "10 mail.example.com.\n\n")
    )
    assert out == ["10 mail.example.com."]
    with pytest.raises(LookupError):
        dns_check.system_lookup("example.com", "MX", runner=lambda a, t: CommandResult(9, ""))


# --- uptime --------------------------------------------------------------------------


def test_check_uptime() -> None:
    ticks = iter([0.0, 0.5, 1.0, 5.0, 6.0, 6.1])

    def fetch(url: str, timeout: int) -> http_exposure.HttpResponse:
        if "down" in url:
            return http_exposure.HttpResponse(0, {}, b"", error="URLError")
        return http_exposure.HttpResponse(200, {}, b"ok")

    results = uptime.check_uptime(
        [
            UptimeTarget("https://www.example.com/", 200, 1000),
            UptimeTarget("https://slow.example.com/", 200, 1000),
            UptimeTarget("https://down.example.com/", 200, 1000),
        ],
        fetcher=fetch,
        clock=lambda: next(ticks),
    )
    assert [r.up for r in results] == [True, True, False]
    assert [r.slow for r in results] == [False, True, False]
    assert results[0].latency_ms == 500 and results[2].error == "URLError"
