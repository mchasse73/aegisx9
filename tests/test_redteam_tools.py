import base64
import datetime as dt
import http.client
import importlib.util
import json
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from types import ModuleType

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _load(rel: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(rel.replace("/", "_"), ROOT / rel)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gate = _load("redteam/garak/gate.py")
rollout = _load("redteam/wait_for_rollout.py")
get_token = _load("redteam/get_token.py")
freshness = _load("redteam/freshness.py")


def test_gate_pass_rates_and_thresholds(tmp_path: Path) -> None:
    rows = [
        {"entry_type": "start_run setup"},
        {"entry_type": "eval", "probe": "dan.Dan_11_0", "passed": 9, "total": 10},
        {"entry_type": "eval", "probe": "dan.AutoDANCached", "passed": 10, "total": 10},
        {"entry_type": "eval", "probe": "encoding.InjectBase64", "passed": 5, "total": 10},
    ]
    report = tmp_path / "r.report.jsonl"
    report.write_text("\n".join(json.dumps(r) for r in rows) + "\n\n")
    rates = gate.pass_rates(report)
    assert rates == {"dan": 0.95, "encoding": 0.5}
    thresholds = json.loads((ROOT / "redteam/garak/thresholds.json").read_text())
    assert gate.evaluate(rates, thresholds) == ["encoding"]


def _run_gate(
    tmp_path: Path, rows: list[dict], thresholds: dict, monkeypatch: pytest.MonkeyPatch
) -> int:  # type: ignore[type-arg]
    report, th = tmp_path / "r.report.jsonl", tmp_path / "t.json"
    report.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    th.write_text(json.dumps(thresholds))
    monkeypatch.setattr(sys, "argv", ["gate", "--report", str(report), "--thresholds", str(th)])
    return int(gate.main())


def test_gate_fails_when_a_configured_family_did_not_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [{"entry_type": "eval", "probe": "dan.Dan_11_0", "passed": 10, "total": 10}]
    th = {"default": 0.9, "probes": {"dan": 0.9, "web_injection": 0.95}}
    assert _run_gate(tmp_path, rows, th, monkeypatch) == 1
    th["probes"].pop("web_injection")
    assert _run_gate(tmp_path, rows, th, monkeypatch) == 0


def test_gate_zero_attempts_is_not_a_pass(tmp_path: Path) -> None:
    report = tmp_path / "r.report.jsonl"
    report.write_text(json.dumps({"entry_type": "eval", "probe": "dan.X", "passed": 0, "total": 0}))
    assert gate.pass_rates(report) == {"dan": 0.0}


def test_garak_probe_spec_matches_thresholds() -> None:
    cfg = yaml.safe_load((ROOT / "redteam/garak/aegisx9.yaml").read_text())
    spec = next(v for v in _walk(cfg) if isinstance(v, dict) and "probe_spec" in v)["probe_spec"]
    families = {p.strip().split(".")[0] for p in spec.split(",") if p.strip()}
    thresholds = json.loads((ROOT / "redteam/garak/thresholds.json").read_text())
    assert families == set(thresholds["probes"])


def _walk(node: object) -> list[object]:
    out = [node]
    if isinstance(node, dict):
        for v in node.values():
            out += _walk(v)
    elif isinstance(node, list):
        for v in node:
            out += _walk(v)
    return out


def test_rollout_complete() -> None:
    digest = "sha256:" + "a" * 64
    deploy = {
        "metadata": {"generation": 2},
        "spec": {
            "replicas": 2,
            "template": {"spec": {"containers": [{"image": f"img@{digest}"}]}},
        },
        "status": {"observedGeneration": 2, "updatedReplicas": 2, "availableReplicas": 2},
    }
    assert rollout.rollout_complete(deploy, digest)
    deploy["status"]["availableReplicas"] = 1
    assert not rollout.rollout_complete(deploy, digest)
    assert rollout.DIGEST_RE.match(digest)


# --- wait_for_rollout: digest source and API polling --------------------------------


def _deploy(digest: str, ready: bool = True) -> dict:  # type: ignore[type-arg]
    n = 1 if ready else 0
    return {
        "metadata": {"generation": 1},
        "spec": {"replicas": 1, "template": {"spec": {"containers": [{"image": f"i@{digest}"}]}}},
        "status": {"observedGeneration": 1, "updatedReplicas": n, "availableReplicas": n},
    }


def test_digest_from_staging_overlay_is_the_pin() -> None:
    overlay = ROOT / "deploy/overlays/staging/kustomization.yaml"
    digest = rollout.digest_from_overlay(overlay)
    assert rollout.DIGEST_RE.match(digest)
    assert digest in overlay.read_text()


def test_digest_from_overlay_needs_exactly_one_pin(tmp_path: Path) -> None:
    f = tmp_path / "k.yaml"
    f.write_text("images:\n  - name: x\n")
    with pytest.raises(rollout.RolloutError):
        rollout.digest_from_overlay(f)
    pin = "sha256:" + "b" * 64
    f.write_text(f"    digest: {pin}\n    digest: {pin}\n")
    with pytest.raises(rollout.RolloutError):
        rollout.digest_from_overlay(f)


def test_digest_from_file_rejects_garbage(tmp_path: Path) -> None:
    f = tmp_path / "d.txt"
    f.write_text("latest\n")
    with pytest.raises(rollout.RolloutError):
        rollout.digest_from_file(f)


def test_deployments_path_only_aegisx9_namespaces() -> None:
    assert rollout.deployments_path("aegisx9-staging").startswith(
        "/apis/apps/v1/namespaces/aegisx9-staging/deployments?labelSelector="
    )
    with pytest.raises(rollout.RolloutError):
        rollout.deployments_path("kube-system")


def test_wait_polls_until_rolled_out() -> None:
    digest = "sha256:" + "c" * 64
    answers = [
        {"items": []},
        {"items": [_deploy(digest, ready=False)]},
        {"items": [_deploy(digest)]},
    ]
    seen: list[str] = []

    def fetch(path: str) -> dict:  # type: ignore[type-arg]
        seen.append(path)
        return answers.pop(0)

    assert rollout.wait(fetch, "aegisx9-staging", digest, 60, sleep=lambda _s: None)
    assert len(seen) == 3


def test_wait_retries_transient_errors() -> None:
    digest = "sha256:" + "2" * 64
    answers: list[object] = [
        rollout.RolloutError("API answered 503", 503),
        TimeoutError(),
        ValueError("bad json"),
        http.client.IncompleteRead(b"{", 10),
        {"items": [_deploy(digest)]},
    ]

    def fetch(_path: str) -> dict:  # type: ignore[type-arg]
        a = answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a  # type: ignore[return-value]

    assert rollout.wait(fetch, "aegisx9-staging", digest, 60, sleep=lambda _s: None)


def test_wait_stops_at_once_on_forbidden() -> None:
    calls = [0]

    def fetch(_path: str) -> dict:  # type: ignore[type-arg]
        calls[0] += 1
        raise rollout.RolloutError("API answered 403", 403)

    with pytest.raises(rollout.RolloutError):
        rollout.wait(fetch, "aegisx9-staging", "sha256:" + "3" * 64, 60, sleep=lambda _s: None)
    assert calls[0] == 1


def test_wait_times_out_on_other_digest() -> None:
    digest, other = "sha256:" + "d" * 64, "sha256:" + "e" * 64
    t = [0.0]

    def clock() -> float:
        t[0] += 10
        return t[0]

    assert not rollout.wait(
        lambda _p: {"items": [_deploy(other)]},
        "aegisx9-staging",
        digest,
        30,
        sleep=lambda _s: None,
        clock=clock,
    )


def test_rollout_main_reports_refusal_without_body(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    f = tmp_path / "d.txt"
    f.write_text("sha256:" + "f" * 64)

    def refused(_path: str) -> dict:  # type: ignore[type-arg]
        raise rollout.RolloutError("API answered 403", 403)

    rc = rollout.main(["--namespace", "aegisx9-staging", "--digest-file", str(f)], fetch=refused)
    assert rc == 2
    assert "403" in capsys.readouterr().err


def test_rollout_main_succeeds_from_overlay(tmp_path: Path) -> None:
    pin = "sha256:" + "1" * 64
    k = tmp_path / "kustomization.yaml"
    k.write_text(f"images:\n  - name: x\n    digest: {pin}\n")
    rc = rollout.main(
        ["--namespace", "aegisx9-staging", "--overlay", str(k), "--timeout", "1"],
        fetch=lambda _p: {"items": [_deploy(pin)]},
    )
    assert rc == 0


def test_in_cluster_fetch_needs_cluster_env(tmp_path: Path) -> None:
    with pytest.raises(rollout.RolloutError):
        rollout.in_cluster_fetch(tmp_path, env={})


# --- get_token: machine identity, never a stored gateway key -----------------------

TOKEN_ENV = {
    "AEGIS_RT_TOKEN_URL": "https://idp.example.com/application/o/token/",
    "AEGIS_RT_CLIENT_ID": "redteam-client",
    "AEGIS_RT_ASSERTION_AUDIENCE": "redteam-client",
    "ACTIONS_ID_TOKEN_REQUEST_URL": "https://gh.example.com/oidc?api-version=2.0",
}


def _token_env(**extra: str) -> dict[str, str]:
    env = dict(TOKEN_ENV, ACTIONS_ID_TOKEN_REQUEST_TOKEN=secrets.token_urlsafe(16))
    env.update(extra)
    return env


def test_federated_flow_sends_the_github_token_as_assertion() -> None:
    gh_jwt, access = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    calls: list[urllib.request.Request] = []

    def fetch(req: urllib.request.Request) -> dict:  # type: ignore[type-arg]
        calls.append(req)
        if len(calls) == 1:
            return {"value": gh_jwt}
        return {"access_token": access, "token_type": "Bearer", "expires_in": 900}

    token, lifetime = get_token.request_token(_token_env(), fetch)
    assert (token, lifetime) == (access, 900)
    gh_q = urllib.parse.parse_qs(urllib.parse.urlsplit(calls[0].full_url).query)
    assert gh_q["audience"] == ["redteam-client"]
    form = urllib.parse.parse_qs((calls[1].data or b"").decode())
    assert form["grant_type"] == ["client_credentials"]
    assert form["client_assertion"] == [gh_jwt]
    assert form["client_assertion_type"] == [get_token.ASSERTION_TYPE]
    assert "client_secret" not in form


def test_client_secret_fallback_skips_github_oidc() -> None:
    fallback = secrets.token_urlsafe(24)
    calls: list[urllib.request.Request] = []

    def fetch(req: urllib.request.Request) -> dict:  # type: ignore[type-arg]
        calls.append(req)
        return {
            "access_token": secrets.token_urlsafe(8),
            "token_type": "bearer",
            "expires_in": "800",
        }

    _, lifetime = get_token.request_token(_token_env(AEGIS_RT_CLIENT_SECRET=fallback), fetch)
    assert lifetime == 800
    assert len(calls) == 1
    form = urllib.parse.parse_qs((calls[0].data or b"").decode())
    assert form["client_secret"] == [fallback]
    assert "client_assertion" not in form


@pytest.mark.parametrize(
    "answer",
    [
        {"access_token": "x", "token_type": "Bearer", "expires_in": 3600},
        {"access_token": "x", "token_type": "Bearer", "expires_in": 300},
        {"access_token": "x", "token_type": "Bearer"},
        {"access_token": "x", "token_type": "mac", "expires_in": 900},
        {"token_type": "Bearer", "expires_in": 900},
    ],
    ids=["too-long", "too-short", "no-lifetime", "not-bearer", "no-token"],
)
def test_token_answers_refused(answer: dict) -> None:  # type: ignore[type-arg]
    env = _token_env(AEGIS_RT_CLIENT_SECRET=secrets.token_urlsafe(8))
    with pytest.raises(get_token.TokenError):
        get_token.request_token(env, lambda _r: answer)


def test_unconfigured_credential_is_a_clear_error() -> None:
    with pytest.raises(get_token.TokenError, match="no red-team credential"):
        get_token.request_token({}, lambda _r: {})
    env = {k: v for k, v in TOKEN_ENV.items() if k != "AEGIS_RT_ASSERTION_AUDIENCE"}
    with pytest.raises(get_token.TokenError, match="AEGIS_RT_ASSERTION_AUDIENCE"):
        get_token.request_token(env, lambda _r: {})
    with pytest.raises(get_token.TokenError, match="id-token"):
        get_token.request_token(dict(TOKEN_ENV), lambda _r: {})


def test_fetch_refuses_plain_http() -> None:
    with pytest.raises(get_token.TokenError):
        get_token._fetch_json(urllib.request.Request("http://idp.example.com/token"))


def test_hand_over_masks_before_export(tmp_path: Path) -> None:
    token = secrets.token_urlsafe(24)
    target = tmp_path / "github_env"
    lines: list[str] = []
    get_token.hand_over(token, target, out=lines.append)
    assert lines == ["::add-mask::" + token]
    assert target.read_text() == f"{get_token.OUTPUT_VAR}={token}\n"
    with pytest.raises(get_token.TokenError):
        get_token.hand_over("a\nb", target, out=lines.append)


def test_get_token_main_never_prints_the_token(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    access = secrets.token_urlsafe(32)
    target = tmp_path / "github_env"
    env = _token_env(AEGIS_RT_CLIENT_SECRET=secrets.token_urlsafe(8), GITHUB_ENV=str(target))
    rc = get_token.main(
        env, lambda _r: {"access_token": access, "token_type": "Bearer", "expires_in": 900}
    )
    assert rc == 0
    err = capsys.readouterr().err
    assert access not in err
    assert "valid 900 s" in err
    assert access in target.read_text()


def test_get_token_main_reports_type_only(capsys: pytest.CaptureFixture[str]) -> None:
    def boom(_r: urllib.request.Request) -> dict:  # type: ignore[type-arg]
        raise RuntimeError("https://idp.example.com/?code=leak")

    env = _token_env(AEGIS_RT_CLIENT_SECRET=secrets.token_urlsafe(8), GITHUB_ENV="/nonexistent/env")
    assert get_token.main(env, boom) == 1
    err = capsys.readouterr().err
    assert "RuntimeError" in err
    assert "leak" not in err


# --- freshness ------------------------------------------------------------------------

NOW = dt.datetime(2026, 11, 3, 12, 0, tzinfo=dt.UTC)
FRESH_ENV = {"GITHUB_REPOSITORY": "o/r"}
FRESH_ARGS = ["--workflow", "redteam-staging.yml", "--max-age-hours", "48"]


def _runs(*started: str, conclusion: str = "success", branch: str = "main") -> dict:  # type: ignore[type-arg]
    return {
        "workflow_runs": [
            {
                "run_started_at": t,
                "created_at": t,
                "updated_at": "2026-11-03T11:00:00Z",
                "conclusion": conclusion,
                "head_branch": branch,
            }
            for t in started
        ]
    }


def test_freshness_fresh_stale_never() -> None:
    assert freshness.main(FRESH_ARGS, FRESH_ENV, lambda _u: _runs("2026-11-02T12:00:00Z"), NOW) == 0
    assert freshness.main(FRESH_ARGS, FRESH_ENV, lambda _u: _runs("2026-10-30T12:00:00Z"), NOW) == 1
    assert freshness.main(FRESH_ARGS, FRESH_ENV, lambda _u: _runs(), NOW) == 1


def test_freshness_ignores_updated_at_and_non_success() -> None:
    # An old run touched recently (updated_at today) must not look fresh.
    assert freshness.main(FRESH_ARGS, FRESH_ENV, lambda _u: _runs("2026-10-20T06:17:00Z"), NOW) == 1
    stale_other = _runs("2026-11-03T06:17:00Z", conclusion="failure")
    assert freshness.main(FRESH_ARGS, FRESH_ENV, lambda _u: stale_other, NOW) == 1
    other_branch = _runs("2026-11-03T06:17:00Z", branch="feature")
    assert freshness.main(FRESH_ARGS, FRESH_ENV, lambda _u: other_branch, NOW) == 1


def test_freshness_fetch_only_github_api() -> None:
    with pytest.raises(ValueError):
        freshness._fetch("https://example.com/x", "t")


def test_freshness_queries_main_successes_only() -> None:
    seen: list[str] = []

    def fetch(url: str) -> dict:  # type: ignore[type-arg]
        seen.append(url)
        return _runs()

    freshness.main(FRESH_ARGS, FRESH_ENV, fetch, NOW)
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(seen[0]).query)
    assert q["branch"] == ["main"] and q["status"] == ["success"]
    assert "/actions/workflows/redteam-staging.yml/runs" in seen[0]


def test_freshness_unreadable_history() -> None:
    def broken(_u: str) -> dict:  # type: ignore[type-arg]
        raise urllib.error.URLError("down")

    assert freshness.main(FRESH_ARGS, FRESH_ENV, broken, NOW) == 2
    assert freshness.main(FRESH_ARGS, {}, None, NOW) == 2


@pytest.mark.parametrize(
    ("body", "code"),
    [
        (b'{"error": "invalid_grant", "error_description": "details"}', "invalid_grant"),
        (b'{"error": "Not A Code!"}', None),
        (b'{"error": 5}', None),
        (b"<html>bad gateway</html>", None),
        (b"[]", None),
    ],
)
def test_oauth_error_code_only_standard_shape(body: bytes, code: str | None) -> None:
    assert get_token.oauth_error_code(body) == code


def test_token_request_error_names_the_step() -> None:
    def fetch(req: urllib.request.Request) -> dict:  # type: ignore[type-arg]
        if "audience=" in req.full_url:
            return {"value": secrets.token_urlsafe(16)}
        raise get_token.TokenError("endpoint answered 400 (invalid_grant)")

    with pytest.raises(
        get_token.TokenError, match=r"^identity provider token request: .*invalid_grant"
    ):
        get_token.request_token(_token_env(), fetch)


def test_github_oidc_error_names_the_step() -> None:
    def fetch(_req: urllib.request.Request) -> dict:  # type: ignore[type-arg]
        raise get_token.TokenError("endpoint answered 403")

    with pytest.raises(get_token.TokenError, match=r"^GitHub OIDC token: endpoint answered 403"):
        get_token.request_token(_token_env(), fetch)


def _jwt(claims: dict) -> str:  # type: ignore[type-arg]
    def enc(d: dict) -> str:  # type: ignore[type-arg]
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")

    return f"{enc({'alg': 'none'})}.{enc(claims)}.{secrets.token_urlsafe(8)}"


def test_describe_assertion_prints_shape_not_values() -> None:
    env = {"GITHUB_REPOSITORY": "o/r", "GITHUB_REF": "refs/heads/main"}
    out = get_token.describe_assertion(_jwt({"sub": "repo:o/r:environment:other"}), env)
    assert out.startswith("assertion sub shape repo=:environment!=")
    assert "o/r" not in out and "other" not in out
    ref = get_token.describe_assertion(_jwt({"sub": "repo:o/r:ref:refs/heads/main"}), env)
    assert "repo=:ref=" in ref
    assert get_token.describe_assertion("not-a-jwt", env) == "assertion is not a readable JWT"


def test_refused_assertion_reports_its_shape() -> None:
    env = _token_env(GITHUB_REPOSITORY="o/r")

    def fetch(req: urllib.request.Request) -> dict:  # type: ignore[type-arg]
        if "audience=" in req.full_url:
            return {"value": _jwt({"sub": "repo:o/r:environment:redteam"})}
        raise get_token.TokenError("endpoint answered 400 (invalid_grant)")

    with pytest.raises(get_token.TokenError, match=r"sub shape repo=:environment="):
        get_token.request_token(env, fetch)


@pytest.mark.parametrize(
    ("fail_on", "prefix"),
    [("audience=", "GitHub OIDC token"), ("token/", "identity provider token request")],
)
def test_transport_errors_name_the_step(fail_on: str, prefix: str) -> None:
    def fetch(req: urllib.request.Request) -> dict:  # type: ignore[type-arg]
        if fail_on in req.full_url:
            raise ConnectionResetError("details that must not be printed")
        return {"value": secrets.token_urlsafe(16)}

    with pytest.raises(get_token.TokenError) as err:
        get_token.request_token(_token_env(), fetch)
    assert str(err.value) == f"{prefix}: failed (ConnectionResetError)"


def test_broken_error_body_keeps_the_status(monkeypatch: pytest.MonkeyPatch) -> None:
    import http.client
    import io

    class Broken(io.BytesIO):
        def read(self, *_a: object) -> bytes:
            raise http.client.IncompleteRead(b"")

    def urlopen(*_a: object, **_k: object) -> None:
        raise urllib.error.HTTPError("https://idp.example.com/t", 400, "Bad", {}, Broken())  # type: ignore[arg-type]

    monkeypatch.setattr(get_token.urllib.request, "urlopen", urlopen)
    req = urllib.request.Request("https://idp.example.com/t")
    with pytest.raises(get_token.TokenError, match=r"^endpoint answered 400$"):
        get_token._fetch_json(req)


def test_promptfoo_file_references_resolve_from_the_config_dir() -> None:
    # promptfoo resolves every file:// path from the config's directory, including those
    # inside attack files; a path written relative to attacks/ breaks the suite (#147).
    base = Path(__file__).resolve().parents[1] / "redteam" / "promptfoo"
    refs = []
    for f in [base / "promptfooconfig.yaml", *sorted((base / "attacks").glob("*.yaml"))]:
        refs += re.findall(r"file://([^\s:'\"]+)", f.read_text(encoding="utf-8"))
    assert refs
    missing = [r for r in refs if not (base / r).is_file()]
    assert not missing, missing


def test_describe_access_token_reports_names_and_membership_only() -> None:
    claims = {"sub": "svc-x", "groups": ["g-other", "g-redteam"]}
    out = get_token.describe_access_token(_jwt(claims), {})
    assert out == "access token claims [groups, sub]; 2 groups"
    assert "svc-x" not in out and "g-other" not in out
    found = get_token.describe_access_token(_jwt(claims), {"AEGIS_RT_EXPECTED_GROUP": "g-redteam"})
    assert found.endswith("2 groups, expected group present")
    absent = get_token.describe_access_token(
        _jwt({"groups": "g-other"}), {"AEGIS_RT_EXPECTED_GROUP": "g"}
    )
    assert absent.endswith("1 groups, expected group ABSENT")
    missing = get_token.describe_access_token(_jwt({"sub": "svc-x"}), {})
    assert missing.endswith("groups claim missing")
    assert get_token.describe_access_token("opaque", {}) == "access token is not a readable JWT"
    as_list = "e30." + base64.urlsafe_b64encode(b"[1]").decode().rstrip("=") + ".x"
    assert get_token.describe_access_token(as_list, {}) == "access token is not a readable JWT"
