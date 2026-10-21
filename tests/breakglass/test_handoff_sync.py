"""Tests for workspace/breakglass/bin/handoff-sync and aegisx9-event.

Nothing here touches the network: the EDA helper is mocked, Vault and gitleaks are fake
executables on PATH, and the "central workspace" is a local directory (``--to dir:``).
Credential-shaped values are generated at runtime.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import secrets
import shutil
import stat
import sys
import tarfile
import time
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "workspace" / "breakglass" / "bin"


def _load(name: str) -> ModuleType:
    loader = importlib.machinery.SourceFileLoader(name.replace("-", "_"), str(BIN / name))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = mod  # dataclasses resolve annotations through sys.modules
    loader.exec_module(mod)
    return mod


sync = _load("handoff-sync")
events = _load("aegisx9-event")

needs_rsync = pytest.mark.skipif(shutil.which("rsync") is None, reason="rsync not installed")

SESSIONS = (".claude/projects/p1/s1.jsonl", ".claude/projects/p1/s2.jsonl")
NOTES = (".aegisx9/handoff/notes.md", ".aegisx9/memory/m.json")


def _write(root: Path, rel: str, text: str, mtime: float | None = None) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    if mtime is not None:
        os.utime(path, (mtime, mtime))
    return path


def _script(directory: Path, name: str, body: str) -> Path:
    path = directory / name
    path.write_text(body)
    path.chmod(0o755)
    return path


@pytest.fixture
def home(tmp_path: Path) -> Path:
    h = tmp_path / "home"
    for rel in SESSIONS + NOTES:
        _write(h, rel, f"local {rel}\n")
    _write(h, ".ssh/config", "Host central\n")  # outside the sources: never bundled
    (h / ".aegisx9/handoff/link").symlink_to(h / ".ssh/config")  # symlinks are skipped
    return h


@pytest.fixture
def fake_bin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    b = tmp_path / "bin"
    b.mkdir()
    monkeypatch.setenv("PATH", f"{b}{os.pathsep}{os.environ['PATH']}")
    return b


def fake_gitleaks(fake_bin: Path, findings: list[dict[str, Any]]) -> None:
    """A gitleaks stand-in: writes the report for --report-path, exits 1 on findings."""
    (fake_bin / "findings.json").write_text(json.dumps(findings))
    _script(
        fake_bin,
        "gitleaks",
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "argv = sys.argv[1:]\n"
        "assert argv[:2] == ['detect', '--no-git'] and '--redact' in argv\n"
        "source = argv[argv.index('--source') + 1]\n"
        "report = argv[argv.index('--report-path') + 1]\n"
        "here = os.path.dirname(os.path.abspath(__file__))\n"
        "findings = json.load(open(os.path.join(here, 'findings.json')))\n"
        "for f in findings:\n"
        "    f['File'] = os.path.join(source, f['File'])\n"
        "json.dump(findings, open(report, 'w'))\n"
        "sys.exit(1 if findings else 0)\n",
    )


def fake_vault(fake_bin: Path) -> Path:
    log = fake_bin / "vault.log"
    _script(
        fake_bin,
        "vault",
        f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\n",
    )
    return log


@pytest.fixture
def captured_events(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    seen: list[dict[str, Any]] = []

    def emit(payload: dict[str, Any], state_dir: Path) -> bool:
        seen.append(dict(payload))
        return True

    monkeypatch.setattr(sync, "emit_event", emit)
    return seen


def _args(home: Path, remote: Path, tmp: Path, *extra: str) -> list[str]:
    return ["--to", f"dir:{remote}", "--home", str(home), "--tmp-dir", str(tmp), *extra]


# --- bundle -------------------------------------------------------------------------------------


def test_collect_and_stage_bundle_contents(home: Path, tmp_path: Path) -> None:
    rels = sync.collect(home)
    assert [r.as_posix() for r in rels] == list(SESSIONS + NOTES)  # source order, sorted within
    assert [sync.is_session(r) for r in rels] == [True, True, False, False]

    workdir = Path(sync.tempfile.mkdtemp(prefix="handoff-", dir=tmp_path))
    assert stat.S_IMODE(workdir.stat().st_mode) == 0o700
    staged, bundle = sync.stage(home, rels, workdir)
    with tarfile.open(bundle) as tar:
        assert sorted(tar.getnames()) == sorted(SESSIONS + NOTES)
    assert stat.S_IMODE(bundle.stat().st_mode) == 0o600
    local = json.loads((workdir / "manifest.json").read_text())
    assert set(local) == set(SESSIONS + NOTES)
    assert local[SESSIONS[0]]["size"] == len(f"local {SESSIONS[0]}\n")
    assert local == sync.manifest(staged, rels)


def test_target_parse() -> None:
    assert sync.Target.parse("coder:my-ws").host == "coder.my-ws"
    assert sync.Target.parse("ssh:central").rsync_dest == "central:"
    assert sync.Target.parse("dir:/tmp/x").host is None
    for bad in ("", "my-ws", "coder:", "ftp:x", "coder:bad name"):
        with pytest.raises(sync.SyncError):
            sync.Target.parse(bad)


# --- gitleaks refusal -------------------------------------------------------------------------


@needs_rsync
def test_refuses_upload_on_gitleaks_findings(
    home: Path,
    fake_bin: Path,
    tmp_path: Path,
    captured_events: list[dict[str, Any]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    planted = secrets.token_urlsafe(24)
    fake_gitleaks(
        fake_bin,
        [
            {"File": NOTES[0], "RuleID": "generic", "Secret": planted},
            {"File": NOTES[0], "RuleID": "generic", "Secret": planted},
            {"File": SESSIONS[1], "RuleID": "generic", "Secret": planted},
        ],
    )
    vault_log = fake_vault(fake_bin)
    remote = tmp_path / "remote"
    remote.mkdir()

    rc = sync.main(_args(home, remote, tmp_path))

    assert rc == 3
    err = capsys.readouterr().err
    assert f"{NOTES[0]}: 2" in err and f"{SESSIONS[1]}: 1" in err
    assert planted not in err
    assert list(remote.iterdir()) == []  # nothing uploaded
    assert all((home / rel).exists() for rel in SESSIONS + NOTES)  # nothing wiped
    assert not vault_log.exists()  # token kept
    assert captured_events[-1]["result"] == "refused_leaks"
    assert captured_events[-1]["findings"] == 3
    assert not list(tmp_path.glob("handoff-*"))  # work directory wiped


def test_scan_requires_gitleaks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sync.shutil, "which", lambda name: None)
    with pytest.raises(sync.SyncError):
        sync.scan(tmp_path, tmp_path)


# --- union merge against a fake remote ----------------------------------------------------


@needs_rsync
def test_union_merge_wipe_and_revoke(
    home: Path, fake_bin: Path, tmp_path: Path, captured_events: list[dict[str, Any]]
) -> None:
    fake_gitleaks(fake_bin, [])
    vault_log = fake_vault(fake_bin)
    remote = tmp_path / "remote"
    now = time.time()
    # s1 exists centrally with different content: append-only union keeps the central copy.
    _write(remote, SESSIONS[0], "central s1\n", mtime=now - 3600)
    # notes.md is newer centrally: --update keeps it. m.json is older: --update replaces it.
    _write(remote, NOTES[0], "central notes\n", mtime=now + 3600)
    _write(remote, NOTES[1], "central memory\n", mtime=now - 3600)

    rc = sync.main(_args(home, remote, tmp_path))

    assert rc == 0
    assert (remote / SESSIONS[0]).read_text() == "central s1\n"
    assert (remote / SESSIONS[1]).read_text() == f"local {SESSIONS[1]}\n"
    assert (remote / NOTES[0]).read_text() == "central notes\n"
    assert (remote / NOTES[1]).read_text() == f"local {NOTES[1]}\n"
    assert stat.S_IMODE((remote / SESSIONS[1]).stat().st_mode) == 0o600
    # Local session files are shredded; notes stay (they were merged, not moved).
    assert not any((home / rel).exists() for rel in SESSIONS)
    assert all((home / rel).exists() for rel in NOTES)
    assert vault_log.read_text().strip() == "token revoke -self"
    event = captured_events[-1]
    assert event["event"] == "breakglass_sync"
    assert event["result"] == "ok" and event["revoked"] is True
    assert event["files"] == 4
    assert not list(tmp_path.glob("handoff-*"))


@needs_rsync
def test_dry_run_changes_nothing(
    home: Path, fake_bin: Path, tmp_path: Path, captured_events: list[dict[str, Any]]
) -> None:
    fake_gitleaks(fake_bin, [])
    vault_log = fake_vault(fake_bin)
    remote = tmp_path / "remote"
    remote.mkdir()

    rc = sync.main(_args(home, remote, tmp_path, "--dry-run"))

    assert rc == 0
    assert list(remote.iterdir()) == []
    assert all((home / rel).exists() for rel in SESSIONS + NOTES)
    assert not vault_log.exists()
    assert captured_events[-1]["result"] == "dry_run"


@needs_rsync
def test_keep_local_still_revokes(
    home: Path, fake_bin: Path, tmp_path: Path, captured_events: list[dict[str, Any]]
) -> None:
    fake_gitleaks(fake_bin, [])
    vault_log = fake_vault(fake_bin)
    remote = tmp_path / "remote"

    rc = sync.main(_args(home, remote, tmp_path, "--keep-local"))

    assert rc == 0
    assert all((home / rel).exists() for rel in SESSIONS + NOTES)
    assert all((remote / rel).exists() for rel in SESSIONS + NOTES)
    assert vault_log.read_text().strip() == "token revoke -self"
    assert captured_events[-1]["keep_local"] is True


@needs_rsync
def test_verification_failure_keeps_local(
    home: Path,
    fake_bin: Path,
    tmp_path: Path,
    captured_events: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_gitleaks(fake_bin, [])
    vault_log = fake_vault(fake_bin)
    remote = tmp_path / "remote"
    real = sync.remote_manifest
    calls = {"n": 0}

    def flaky(target: Any, rels: list[Path]) -> dict[str, Any]:
        calls["n"] += 1
        found = real(target, rels)
        if calls["n"] == 2:  # the "after" manifest: pretend one file never arrived
            found.pop(SESSIONS[1])
        return found

    monkeypatch.setattr(sync, "remote_manifest", flaky)
    rc = sync.main(_args(home, remote, tmp_path))

    assert rc == 4
    assert all((home / rel).exists() for rel in SESSIONS + NOTES)
    assert not vault_log.exists()
    assert captured_events[-1]["result"] == "verify_failed"
    assert captured_events[-1]["problems"] == 1


@needs_rsync
def test_unrecorded_event_is_an_error_after_sync(
    home: Path, fake_bin: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_gitleaks(fake_bin, [])
    fake_vault(fake_bin)
    monkeypatch.setattr(sync, "emit_event", lambda payload, state_dir: False)
    rc = sync.main(_args(home, tmp_path / "remote", tmp_path, "--keep-local"))
    assert rc == 5
    assert all((tmp_path / "remote" / rel).exists() for rel in SESSIONS + NOTES)


def test_verify_semantics() -> None:
    a = {"size": 1, "sha256": "a"}
    b = {"size": 2, "sha256": "b"}
    c = {"size": 3, "sha256": "c"}
    local = {"x": a, "y": a, "z": a}
    before = {"y": b, "z": b}
    after = {"x": a, "y": b, "z": c}
    problems = sync.verify(local, before, after)
    assert problems == ["z: remote content matches neither local nor previous"]
    assert sync.verify({"x": a}, {}, {}) == ["x: missing after upload"]


def test_nothing_to_sync(tmp_path: Path, captured_events: list[dict[str, Any]]) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    assert sync.main(_args(empty, tmp_path / "remote", tmp_path)) == 0
    assert captured_events == []


def test_main_reports_only_exception_type(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    marker = secrets.token_hex(8)

    def boom(home: Path) -> list[Path]:
        raise RuntimeError(f"contains {marker}")

    monkeypatch.setattr(sync, "collect", boom)
    assert sync.main(_args(tmp_path, tmp_path / "r", tmp_path)) == 1
    err = capsys.readouterr().err
    assert "RuntimeError" in err and marker not in err
    assert sync.main(["--to", "nope", "--home", str(tmp_path)]) == 2


# --- shred ---------------------------------------------------------------------------------------


def test_shred_fallback_overwrites_and_unlinks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    victim = tmp_path / "s.jsonl"
    victim.write_bytes(b"x" * 5000)
    monkeypatch.setattr(sync.shutil, "which", lambda name: None)
    sync.shred_file(victim)
    assert not victim.exists()
    sync.shred_file(victim)  # already gone: no error


@pytest.mark.skipif(shutil.which("shred") is None, reason="shred not installed")
def test_shred_uses_coreutils_when_present(tmp_path: Path) -> None:
    victim = tmp_path / "s.jsonl"
    victim.write_bytes(b"y" * 100)
    sync.shred_file(victim)
    assert not victim.exists()


def test_wipe_tree_removes_everything(tmp_path: Path) -> None:
    root = tmp_path / "w"
    _write(root, "a/b.txt", "1")
    _write(root, "c.tar", "2")
    sync.wipe_tree(root)
    assert not root.exists()


# --- aegisx9-event -------------------------------------------------------------------------------


class _Response:
    def __init__(self, status: int) -> None:
        self.status = status

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


@pytest.fixture
def hmac_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[bytes, Path]:
    key = secrets.token_urlsafe(48).encode()
    key_file = tmp_path / "event.hmac"
    key_file.write_bytes(key + b"\n")
    key_file.chmod(0o600)
    monkeypatch.setenv("AEGISX9_EVENT_URL", "https://events.example/aegisx9")
    monkeypatch.setenv("AEGISX9_EVENT_HMAC_FILE", str(key_file))
    return key, key_file


def test_event_signature_and_headers(
    hmac_env: tuple[bytes, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    key, _ = hmac_env
    seen: list[Any] = []

    def fake_urlopen(req: Any, timeout: float = 0) -> _Response:
        seen.append(req)
        return _Response(202)

    monkeypatch.setattr(events.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(
        events.sys, "stdin", _Stdin(json.dumps({"event": "breakglass_sync", "k": 1}))
    )

    assert events.main([]) == 0
    req = seen[0]
    body = req.data
    sent = json.loads(body)
    assert sent["event"] == "breakglass_sync" and sent["event_id"] and sent["sent_at"]
    assert body == events.canonical(sent)
    assert req.get_header("X-aegisx9-signature") == events.sign(body, key)
    assert req.get_header("X-aegisx9-event") == "breakglass_sync"
    assert key.decode() not in capsys.readouterr().err


class _Stdin:
    def __init__(self, text: str) -> None:
        self._text = text

    def read(self) -> str:
        return self._text


def test_event_spool_and_flush(
    hmac_env: tuple[bytes, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spool = tmp_path / "outbox"
    attempts: list[str] = []

    def down(req: Any, timeout: float = 0) -> _Response:
        attempts.append(json.loads(req.data)["event"])
        raise OSError("unreachable")

    monkeypatch.setattr(events.urllib.request, "urlopen", down)
    monkeypatch.setattr(events.sys, "stdin", _Stdin(json.dumps({"event": "breakglass_activation"})))
    assert events.main(["--spool", str(spool)]) == 0
    queued = list(spool.glob("*.json"))
    assert len(queued) == 1
    assert stat.S_IMODE(queued[0].stat().st_mode) == 0o600
    assert stat.S_IMODE(spool.stat().st_mode) == 0o700

    # Without a spool, failure is an error.
    monkeypatch.setattr(events.sys, "stdin", _Stdin(json.dumps({"event": "breakglass_sync"})))
    assert events.main([]) == 1

    delivered: list[str] = []

    def up(req: Any, timeout: float = 0) -> _Response:
        delivered.append(json.loads(req.data)["event"])
        return _Response(200)

    monkeypatch.setattr(events.urllib.request, "urlopen", up)
    assert events.main(["--spool", str(spool), "--flush"]) == 0
    assert delivered == ["breakglass_activation"]
    assert list(spool.glob("*.json")) == []


def test_event_rejects_bad_config_and_input(
    hmac_env: tuple[bytes, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    key, key_file = hmac_env
    with pytest.raises(events.EventError):
        events.post("http://events.example/x", {"event": "e"}, key)
    for bad in ({"event": "Bad Name"}, ["not", "an", "object"], {"nothing": 1}):
        with pytest.raises(events.EventError):
            events.validate(bad)

    key_file.chmod(0o644)
    with pytest.raises(events.EventError):
        events.load_key(key_file)
    assert events.main([]) == 2
    key_file.chmod(0o600)

    monkeypatch.setattr(events.sys, "stdin", _Stdin("not json"))
    assert events.main([]) == 2
    monkeypatch.delenv("AEGISX9_EVENT_URL")
    assert events.main([]) == 2


def test_event_http_error_status(
    hmac_env: tuple[bytes, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(events.urllib.request, "urlopen", lambda req, timeout=0: _Response(500))
    monkeypatch.setattr(events.sys, "stdin", _Stdin(json.dumps({"event": "breakglass_sync"})))
    assert events.main([]) == 1
