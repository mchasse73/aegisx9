from __future__ import annotations

import socket
import ssl
import subprocess
from datetime import UTC, datetime, timedelta
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
        "/usr/bin/nmap",
        ["a", "b"],
        proto="tcp",
        top_ports=1000,
        privileged=True,
        exclude=["192.0.2.0/24", "", "2001:db8::/32"],
    )
    assert argv[1] == "-sS" and argv[-2:] == ["a", "b"]
    assert "--privileged" in argv and "-6" not in argv
    assert argv[argv.index("--exclude") + 1] == "192.0.2.0/24"  # only the IPv4 exclusion
    v6 = ports.nmap_argv(
        "n", ["2001:db8::1"], proto="udp", top_ports=100, privileged=True, family="6",
        exclude=["192.0.2.0/24", "2001:db8::/32"],
    )  # fmt: skip
    assert v6[1] == "-sU" and "-6" in v6 and v6[v6.index("--exclude") + 1] == "2001:db8::/32"
    plain = ports.nmap_argv("n", ["a"], proto="tcp", top_ports=10, privileged=False)
    assert plain[1] == "-sT" and "--privileged" not in plain and "--exclude" not in plain


def test_family_split() -> None:
    assert ports.split_by_family(["203.0.113.0/27", "2001:db8::1", "2001:db8::/64", "x"]) == (
        ["203.0.113.0/27", "x"],
        ["2001:db8::1", "2001:db8::/64"],
    )


def test_parse_nmap_xml() -> None:
    found = ports.parse_nmap_xml(NMAP_XML)
    assert [(p.ip, p.port, p.proto, p.service, p.hostname) for p in found] == [
        ("2001:db8::1", 53, "udp", "", ""),
        ("203.0.113.10", 22, "tcp", "ssh", "www.example.com"),
        ("203.0.113.10", 443, "tcp", "https", "www.example.com"),
    ]
    assert found[1].key == ("203.0.113.10", 22, "tcp")
    assert ports.parse_nmap_xml("  ") == []


def test_scan_ports_privileged_runs_both_families() -> None:
    calls: list[list[str]] = []

    def runner(argv: list[str], timeout: int) -> CommandResult:
        calls.append(argv)
        return CommandResult(0, NMAP_XML if argv[1] == "-sS" else "<nmaprun></nmaprun>")

    res = ports.scan_ports(
        ["203.0.113.0/27", "2001:db8::/64"],
        exclude=["192.0.2.0/24"],
        privileged=True,
        runner=runner,
        nmap="/x/nmap",
    )
    assert res.tcp_ran and res.udp_ran and len(res.open_ports) == 6
    assert [(c[1], "-6" in c) for c in calls] == [
        ("-sS", False),
        ("-sU", False),
        ("-sS", True),
        ("-sU", True),
    ]
    assert all("--privileged" in c for c in calls)
    assert "192.0.2.0/24" in calls[0] and "192.0.2.0/24" not in calls[2]


def test_scan_ports_unprivileged_skips_udp_and_reports_failures() -> None:
    res = ports.scan_ports(
        ["a"], privileged=False, runner=lambda a, t: CommandResult(1, ""), nmap="/x/nmap"
    )
    assert not res.tcp_ran and not res.udp_ran
    assert any("exited 1" in n for n in res.notes)
    assert any("UDP scan skipped" in n for n in res.notes)
    res = ports.scan_ports(
        ["a"], privileged=True, runner=lambda a, t: CommandResult(0, "<broken"), nmap="/x/nmap"
    )
    assert not res.tcp_ran and any("unparseable" in n for n in res.notes)
    # One family failing marks the whole TCP pass incomplete.
    res = ports.scan_ports(
        ["203.0.113.1", "2001:db8::1"],
        privileged=False,
        runner=lambda a, t: CommandResult(0 if "-6" in a else 1, "<nmaprun></nmaprun>"),
        nmap="/x/nmap",
    )
    assert not res.tcp_ran
    assert "no targets" in ports.scan_ports([], privileged=False, nmap="/x/nmap").notes[0]
    res = ports.scan_ports(
        ["a"], privileged=False, nmap=None, runner=lambda a, t: CommandResult(0, "")
    )
    assert "not installed" in res.notes[0]


def test_is_privileged_from_euid_or_capabilities(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    status = tmp_path / "status"
    monkeypatch.setattr(ports.os, "geteuid", lambda: 0, raising=False)
    assert ports.is_privileged(status)
    monkeypatch.setattr(ports.os, "geteuid", lambda: 1000, raising=False)
    assert not ports.is_privileged(status)  # no status file at all
    status.write_text("Name:\tnmap\nCapInh:\t0000000000000000\nCapEff:\t0000000000002000\n")
    assert ports.is_privileged(status)  # CAP_NET_RAW only, as the daily unit grants it
    status.write_text("CapEff:\t0000000000000000\n")
    assert not ports.is_privileged(status)
    status.write_text("CapEff:\tnot-hex\n")
    assert not ports.is_privileged(status)
    assert not ports.has_cap_net_raw("")


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
    when = now + timedelta(days=days)
    return {"notAfter": when.strftime("%b %d %H:%M:%S %Y GMT")}


def test_check_tls_healthy_and_expiring() -> None:
    now = datetime(2026, 10, 21, 12, tzinfo=UTC)
    seen: list[str] = []

    def cert(h: str, p: int, t: int, a: str) -> dict[str, object]:
        seen.append(a)
        return _cert(40, now)

    res = tls.check_tls(
        "www.example.com",
        address="203.0.113.10",
        now=now,
        peer_cert=cert,
        version_probe=lambda h, p, v, t, a: False,
        headers=lambda h, p, t, a: {
            "strict-transport-security": "max-age=1",
            "x-frame-options": "DENY",
        },
    )
    assert seen == ["203.0.113.10"] and res.address == "203.0.113.10"
    assert res.chain_ok and res.days_left == 40 and res.hsts and not res.legacy_versions
    assert res.missing_headers == [
        "x-content-type-options",
        "content-security-policy",
        "referrer-policy",
    ]
    res = tls.check_tls(
        "www.example.com",
        now=now,
        peer_cert=lambda h, p, t, a: _cert(5, now),
        version_probe=lambda h, p, v, t, a: v == ssl.TLSVersion.TLSv1,
        headers=lambda h, p, t, a: (_ for _ in ()).throw(OSError()),
    )
    assert res.days_left == 5 and res.legacy_versions == ["TLSv1"] and not res.headers_fetched
    assert res.missing_headers == []


def test_check_tls_invalid_and_unreachable() -> None:
    def bad_chain(h: str, p: int, t: int, a: str) -> dict[str, object]:
        raise ssl.SSLCertVerificationError("x")

    res = tls.check_tls(
        "a",
        peer_cert=bad_chain,
        version_probe=lambda h, p, v, t, a: True,
        headers=lambda h, p, t, a: {},
    )
    assert res.error == "SSLCertVerificationError" and not res.chain_ok
    assert len(res.legacy_versions) == 2

    def down(h: str, p: int, t: int, a: str) -> dict[str, object]:
        raise ConnectionRefusedError()

    res = tls.check_tls(
        "a", peer_cert=down, version_probe=lambda h, p, v, t, a: True, headers=lambda h, p, t, a: {}
    )
    assert res.error == "ConnectionRefusedError" and res.legacy_versions == []
    assert tls.parse_not_after({"notAfter": "garbage"}) is None
    assert tls.parse_not_after({}) is None
    res = tls.check_tls(
        "a",
        peer_cert=lambda h, p, t, a: {},
        version_probe=lambda h, p, v, t, a: False,
        headers=lambda h, p, t, a: {},
    )
    assert res.chain_ok and res.days_left is None


def test_tls_contexts_and_io_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    assert tls.verifying_context("www.example.com").check_hostname
    assert not tls.verifying_context("203.0.113.10").check_hostname  # chain still verified
    assert tls.verifying_context("203.0.113.10").verify_mode == ssl.CERT_REQUIRED

    peers: list[tuple[str, int]] = []

    def refuse(addr: tuple[str, int], timeout: int) -> None:
        peers.append(addr)
        raise ConnectionRefusedError()

    monkeypatch.setattr(socket, "create_connection", refuse)
    assert (
        tls.probe_version("www.example.com", 443, ssl.TLSVersion.TLSv1_2, 1, "203.0.113.10")
        is False
    )
    with pytest.raises(ConnectionRefusedError):
        tls.fetch_peer_cert("www.example.com", 443, 1, "203.0.113.10")
    with pytest.raises(ConnectionRefusedError):
        tls.fetch_peer_cert("www.example.com", 443, 1)  # no address: the name itself
    assert peers == [("203.0.113.10", 443), ("203.0.113.10", 443), ("www.example.com", 443)]

    class Sock:
        closed = False

        def close(self) -> None:
            self.closed = True

    class Raw(Sock):
        pass

    raw = Raw()
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout: raw)

    class Ctx:
        def wrap_socket(self, sock: object, server_hostname: str) -> None:
            raise ssl.SSLError("handshake")

    with pytest.raises(ssl.SSLError):
        tls.open_tls("www.example.com", 443, 1, "203.0.113.10", Ctx())  # type: ignore[arg-type]
    assert raw.closed  # the raw socket is not leaked when the handshake fails

    class Conn:
        sock: object = None

        def __init__(self, *_a: object, **_k: object) -> None:
            pass

        def request(self, *_a: object, **_k: object) -> None:
            assert self.sock is not None  # the pinned socket is used, never a new connect

        def getresponse(self) -> object:
            class R:
                def read(self, _n: int) -> bytes:
                    return b""

                def getheaders(self) -> list[tuple[str, str]]:
                    return [("Strict-Transport-Security", "max-age=1")]

            return R()

        def close(self) -> None:
            pass

    monkeypatch.setattr(tls, "open_tls", lambda h, p, t, a, ctx: Sock())
    monkeypatch.setattr(tls.http.client, "HTTPSConnection", Conn)
    assert tls.fetch_headers("www.example.com", 443, 1, "203.0.113.10") == {
        "strict-transport-security": "max-age=1"
    }


# --- http exposure -------------------------------------------------------------------


def _responder(table: dict[str, tuple[int, bytes, str]]):  # type: ignore[no-untyped-def]
    def fetch(url: str, timeout: int, address: str) -> http_exposure.HttpResponse:
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


def test_probe_host_schemes_ports_and_pinned_address() -> None:
    seen: list[tuple[str, str]] = []

    def fetch(url: str, timeout: int, address: str) -> http_exposure.HttpResponse:
        seen.append((url, address))
        return http_exposure.HttpResponse(404, {}, b"")

    http_exposure.probe_host(
        "www.example.com", scheme="http", port=8080, address="203.0.113.10", fetcher=fetch
    )
    assert seen[0] == ("http://www.example.com:8080/.git/HEAD", "203.0.113.10")
    assert http_exposure.base_url("https", "www.example.com", 443) == "https://www.example.com"
    assert http_exposure.base_url("http", "2001:db8::1", 8000) == "http://[2001:db8::1]:8000"


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


def test_fetch_pins_the_connection_and_never_follows_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert http_exposure.fetch("ftp://x", 1).error == "ValueError"
    opened: list[tuple[str, str, int, str]] = []

    class Resp:
        status = 302

        def getheaders(self) -> list[tuple[str, str]]:
            return [("Location", "/elsewhere"), ("Content-Type", "text/html")]

        def read(self, _n: int) -> bytes:
            return b"moved"

    class Conn:
        def __init__(self, scheme: str, host: str, port: int, address: str) -> None:
            opened.append((scheme, host, port, address))

        def request(self, method: str, path: str, headers: dict[str, str]) -> None:
            assert method == "GET" and path == "/.git/HEAD?x=1"

        def getresponse(self) -> Resp:
            return Resp()

        def close(self) -> None:
            pass

    monkeypatch.setattr(http_exposure, "open_connection", lambda s, h, p, t, a: Conn(s, h, p, a))
    r = http_exposure.fetch("https://www.example.com/.git/HEAD?x=1", 1, "203.0.113.10")
    assert r.status == 302 and r.headers["location"] == "/elsewhere" and r.body == b"moved"
    assert opened == [("https", "www.example.com", 443, "203.0.113.10")]

    def refuse(*_a: object) -> None:
        raise ConnectionRefusedError()

    monkeypatch.setattr(http_exposure, "open_connection", refuse)
    assert http_exposure.fetch("http://www.example.com/", 1).error == "ConnectionRefusedError"

    class Broken(Conn):
        def request(self, *_a: object, **_k: object) -> None:
            pass

        def getresponse(self) -> Resp:
            raise http_exposure.http.client.RemoteDisconnected("gone")

    monkeypatch.setattr(http_exposure, "open_connection", lambda s, h, p, t, a: Broken(s, h, p, a))
    assert http_exposure.fetch("http://www.example.com/", 1).error == "RemoteDisconnected"


def test_open_connection_uses_address(monkeypatch: pytest.MonkeyPatch) -> None:
    peers: list[tuple[str, int]] = []

    class Sock:
        def close(self) -> None:
            pass

    def connect(addr: tuple[str, int], timeout: int) -> Sock:
        peers.append(addr)
        return Sock()

    monkeypatch.setattr(socket, "create_connection", connect)
    conn = http_exposure.open_connection("http", "www.example.com", 80, 1, "203.0.113.10")
    assert (
        conn.sock is not None and peers == [("203.0.113.10", 80)] and conn.host == "www.example.com"
    )
    conn = http_exposure.open_connection("http", "www.example.com", 80, 1, "")
    assert conn.sock is None  # no pin requested: http.client connects by name later
    monkeypatch.setattr(tls, "open_tls", lambda h, p, t, a, ctx: Sock())
    conn = http_exposure.open_connection("https", "www.example.com", 443, 1, "203.0.113.10")
    assert conn.sock is not None


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
        listed = Path(argv[argv.index("-list") + 1]).read_text()
        assert listed == "https://www.example.com\nhttp://203.0.113.10:8080\n"
        return CommandResult(0, "")

    urls = ["https://www.example.com", "http://203.0.113.10:8080"]
    res = nuclei.run_nuclei(urls, tmp_path / "w", runner=runner, nuclei="/x/nuclei")
    assert res.ran and len(res.findings) == 1
    res = nuclei.run_nuclei(
        ["a"], tmp_path / "w", runner=lambda a, t: CommandResult(0, ""), nuclei="/x/nuclei"
    )
    assert res.ran and res.findings == []  # the previous output file was removed first

    def partial(argv: list[str], timeout: int) -> CommandResult:
        Path(argv[argv.index("-output") + 1]).write_text(rows)
        return CommandResult(2, "")

    res = nuclei.run_nuclei(["a"], tmp_path / "w", runner=partial, nuclei="/x/nuclei")
    assert not res.ran and len(res.findings) == 1 and "partial findings kept" in res.notes[0]
    res = nuclei.run_nuclei(
        ["a"], tmp_path / "w", runner=lambda a, t: CommandResult(2, ""), nuclei="/x/nuclei"
    )
    assert not res.ran and res.notes == ["nuclei exited 2"]
    res = nuclei.run_nuclei(["a"], tmp_path, nuclei=None, runner=lambda a, t: CommandResult(0, ""))
    assert "not installed" in res.notes[0]
    assert "no urls" in nuclei.run_nuclei([], tmp_path, nuclei="/x").notes[0]


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


def test_check_uptime_pins_to_validated_address() -> None:
    ticks = iter([0.0, 0.5, 1.0, 5.0, 6.0, 6.1])
    pinned: list[str] = []

    def fetch(url: str, timeout: int, address: str) -> http_exposure.HttpResponse:
        pinned.append(address)
        if "down" in url:
            return http_exposure.HttpResponse(0, {}, b"", error="URLError")
        return http_exposure.HttpResponse(200, {}, b"ok")

    results = uptime.check_uptime(
        [
            UptimeTarget("https://www.example.com/", 200, 1000, addresses=("203.0.113.10",)),
            UptimeTarget("https://slow.example.com/", 200, 1000, addresses=("203.0.113.11", "x")),
            UptimeTarget("https://down.example.com/", 200, 1000),
        ],
        fetcher=fetch,
        clock=lambda: next(ticks),
    )
    assert [r.up for r in results] == [True, True, False]
    assert [r.slow for r in results] == [False, True, False]
    assert results[0].latency_ms == 500 and results[2].error == "URLError"
    assert pinned == ["203.0.113.10", "203.0.113.11", ""]
    assert results[0].address == "203.0.113.10"
