from __future__ import annotations

import json
import logging
import secrets
import threading
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from aegisx9 import gateway_ops as ops


def _plan_dict() -> dict[str, Any]:
    return {
        "proxyMaxBudgetUsd": 180,
        "consumers": [
            {
                "teamId": "public-chat",
                "maxBudgetUsd": 20,
                "budgetDuration": "30d",
                "models": ["claude-haiku-5-5"],
                "defaultModel": "claude-haiku-5-5",
            },
            {
                "teamId": "developers",
                "alias": "Developers",
                "maxBudgetUsd": 50,
                "memberBudgetUsd": 25,
                "models": ["claude-sonnet-5-5", "claude-opus-5-5", "claude-haiku-5-5"],
                "defaultModel": "claude-sonnet-5-5",
            },
        ],
    }


def _write_plan(tmp_path: Path, data: Mapping[str, Any] | None = None) -> str:
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(data or _plan_dict()), encoding="utf-8")
    return str(path)


@dataclass
class FakeApi:
    teams: dict[str, dict[str, Any]] = field(default_factory=dict)
    calls: list[tuple[str, str, dict[str, str], Any]] = field(default_factory=list)
    global_spend: float = 90.0
    deny: bool = False
    fail_writes: bool = False
    jwks: dict[str, Any] = field(default_factory=dict)

    def __call__(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes | None
    ) -> tuple[int, Any]:
        payload = json.loads(body) if body else None
        self.calls.append((method, url, dict(headers), payload))
        if self.deny:
            return 401, None
        if url.endswith("/identity/oidc/.well-known/keys"):
            return 200, self.jwks
        if url.endswith("/global/spend"):
            return 200, {"spend": self.global_spend, "max_budget": 180.0}
        if "/team/info?team_id=" in url:
            team_id = url.split("team_id=", 1)[1]
            if team_id in self.teams:
                return 200, {"team_id": team_id, "team_info": self.teams[team_id]}
            return 404, None
        if self.fail_writes:
            return 500, None
        if url.endswith("/team/new") or url.endswith("/team/update"):
            assert payload is not None
            self.teams.setdefault(payload["team_id"], {"spend": 0.0}).update(payload)
            return 200, {"team_id": payload["team_id"]}
        return 404, None


def _client(api: FakeApi, key: str) -> ops.AdminClient:
    return ops.AdminClient(base_url="http://gateway:4000/", master_key=key, request=api)


def test_plan_loads_and_validates(tmp_path: Path) -> None:
    plan = ops.BudgetPlan.load(_write_plan(tmp_path))
    assert plan.proxy_max_budget_usd == 180
    dev = plan.consumers[1]
    assert dev.member_budget_usd == 25
    payload = dev.team_payload()
    assert payload["model_aliases"] == {"default": "claude-sonnet-5-5"}
    assert payload["team_member_budget"] == 25
    assert payload["team_member_budget_duration"] == "30d"
    assert "team_member_budget" not in plan.consumers[0].team_payload()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["consumers"][0].update(defaultModel="claude-opus-5-5"),
        lambda d: d["consumers"][0].update(maxBudgetUsd=0),
        lambda d: d["consumers"][0].pop("models"),
        lambda d: d["consumers"].append(dict(d["consumers"][0])),
        lambda d: d.update(proxyMaxBudgetUsd=60),
    ],
)
def test_plan_rejects_bad_definitions(tmp_path: Path, mutate: Any) -> None:
    data = _plan_dict()
    mutate(data)
    with pytest.raises(ops.OpsError):
        ops.BudgetPlan.load(_write_plan(tmp_path, data))


def test_plan_unreadable(tmp_path: Path) -> None:
    with pytest.raises(ops.OpsError):
        ops.BudgetPlan.load(str(tmp_path / "missing.json"))


def test_bootstrap_creates_then_updates(tmp_path: Path) -> None:
    api, key = FakeApi(), secrets.token_urlsafe(24)
    plan = ops.BudgetPlan.load(_write_plan(tmp_path))
    assert ops.bootstrap_teams(_client(api, key), plan) == 0
    writes = [c for c in api.calls if c[0] == "POST"]
    assert [c[1].rsplit("/", 1)[1] for c in writes] == ["new", "new"]
    assert all(c[2]["authorization"] == f"Bearer {key}" for c in api.calls)
    assert api.teams["public-chat"]["models"] == ["claude-haiku-5-5"]
    assert api.teams["public-chat"]["max_budget"] == 20
    api.calls.clear()
    ops.bootstrap_teams(_client(api, key), plan)
    writes = [c for c in api.calls if c[0] == "POST"]
    assert [c[1].rsplit("/", 1)[1] for c in writes] == ["update", "update"]


def test_repeated_bootstrap_does_not_postpone_budget_reset(tmp_path: Path) -> None:
    api, key = FakeApi(), secrets.token_urlsafe(24)
    plan = ops.BudgetPlan.load(_write_plan(tmp_path))
    ops.bootstrap_teams(_client(api, key), plan)
    created = [c[3] for c in api.calls if c[1].endswith("/team/new")]
    assert all(p["budget_duration"] == "30d" for p in created)
    for _ in range(2):
        api.calls.clear()
        ops.bootstrap_teams(_client(api, key), plan)
        updates = [c[3] for c in api.calls if c[1].endswith("/team/update")]
        assert len(updates) == 2
        assert all("budget_duration" not in p for p in updates)
        assert all(p["max_budget"] > 0 for p in updates)
    # A changed window is still sent.
    api.teams["public-chat"]["budget_duration"] = "7d"
    api.calls.clear()
    ops.bootstrap_teams(_client(api, key), plan)
    sent = {c[3]["team_id"]: c[3] for c in api.calls if c[1].endswith("/team/update")}
    assert sent["public-chat"]["budget_duration"] == "30d"
    assert "budget_duration" not in sent["developers"]


@pytest.mark.parametrize(
    "answer", [(500, None), (429, None), (200, None), (200, {"team_info": []})]
)
def test_team_lookup_failure_is_not_missing(tmp_path: Path, answer: tuple[int, Any]) -> None:
    class Flaky(FakeApi):
        def __call__(
            self, method: str, url: str, headers: Mapping[str, str], body: bytes | None
        ) -> tuple[int, Any]:
            if "/team/info" in url:
                self.calls.append((method, url, dict(headers), None))
                return answer
            return super().__call__(method, url, headers, body)

    api = Flaky()
    plan = ops.BudgetPlan.load(_write_plan(tmp_path))
    with pytest.raises(ops.OpsError):
        ops.bootstrap_teams(_client(api, secrets.token_urlsafe(8)), plan)
    assert not any(c[1].endswith("/team/new") for c in api.calls)
    with pytest.raises(ops.OpsError):
        ops.check_spend(_client(api, secrets.token_urlsafe(8)), plan)


def test_check_spend_lookup_failure_emits_failure_event(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    class Down(FakeApi):
        def __call__(
            self, method: str, url: str, headers: Mapping[str, str], body: bytes | None
        ) -> tuple[int, Any]:
            if "/team/info" in url:
                return 502, None
            return super().__call__(method, url, headers, body)

    env = {
        "LITELLM_MASTER_KEY": secrets.token_urlsafe(16),
        "AEGISX9_GATEWAY_URL": "http://gateway:4000",
        "AEGISX9_BUDGET_PLAN": _write_plan(tmp_path),
    }
    with caplog.at_level(logging.INFO):
        assert ops.run(["check-spend"], env, Down()) == 1
    events = [getattr(r, "fields", {}) for r in caplog.records]
    assert any(e.get("event") == "aegisx9_ops_error" for e in events)
    assert not any(e.get("event") == "aegisx9_team_missing" for e in events)


def test_bootstrap_with_no_consumers_is_a_no_op(tmp_path: Path) -> None:
    api = FakeApi()
    plan = ops.BudgetPlan.load(_write_plan(tmp_path, {"proxyMaxBudgetUsd": 20, "consumers": []}))
    assert ops.bootstrap_teams(_client(api, secrets.token_urlsafe(8)), plan) == 0
    assert api.calls == []
    assert ops.check_spend(_client(api, secrets.token_urlsafe(8)), plan) == 0


def test_bootstrap_write_failure(tmp_path: Path) -> None:
    api = FakeApi(fail_writes=True)
    with pytest.raises(ops.OpsError):
        ops.bootstrap_teams(
            _client(api, secrets.token_urlsafe(8)), ops.BudgetPlan.load(_write_plan(tmp_path))
        )


def test_admin_refusal_is_reported_without_key(tmp_path: Path) -> None:
    key = secrets.token_urlsafe(24)
    with pytest.raises(ops.OpsError) as exc:
        _client(FakeApi(deny=True), key).call("GET", "/global/spend")
    assert key not in str(exc.value)
    assert key not in repr(_client(FakeApi(), key))


def test_check_spend_logs_percentages(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    api = FakeApi(global_spend=144.0)
    api.teams["public-chat"] = {"spend": 10.0, "max_budget": 20.0}
    plan = ops.BudgetPlan.load(_write_plan(tmp_path))
    with caplog.at_level(logging.INFO, logger="aegisx9.gateway_ops"):
        assert ops.check_spend(_client(api, secrets.token_urlsafe(8)), plan) == 0
    fields = [getattr(r, "fields", {}) for r in caplog.records]
    spend = [f for f in fields if f.get("event") == "aegisx9_spend"]
    assert spend[0] == {
        "event": "aegisx9_spend",
        "scope": "proxy",
        "name": "proxy",
        "spend_usd": 144.0,
        "budget_usd": 180.0,
        "pct": 80.0,
    }
    assert spend[1]["name"] == "public-chat" and spend[1]["pct"] == 50.0
    assert any(f.get("event") == "aegisx9_team_missing" for f in fields)


def test_check_spend_errors(tmp_path: Path) -> None:
    class Broken(FakeApi):
        def __call__(self, *a: Any) -> tuple[int, Any]:
            return 500, None

    with pytest.raises(ops.OpsError):
        ops.check_spend(
            _client(Broken(), secrets.token_urlsafe(8)), ops.BudgetPlan.load(_write_plan(tmp_path))
        )


def _jwks(n: int = 2) -> dict[str, Any]:
    return {
        "keys": [
            {"kty": "RSA", "kid": secrets.token_hex(4), "n": secrets.token_hex(16), "e": "AQAB"}
            for _ in range(n)
        ]
    }


def test_jwks_digest_is_order_independent() -> None:
    doc = _jwks()
    reordered = {"keys": list(reversed(doc["keys"]))}
    assert ops.jwks_digest(doc) == ops.jwks_digest(reordered)
    assert ops.jwks_digest(doc) != ops.jwks_digest(_jwks())
    with pytest.raises(ops.OpsError):
        ops.jwks_digest({"keys": []})


@pytest.mark.parametrize(
    "expected,changed,missing",
    [("match", False, False), ("other", True, False), ("", False, True)],
)
def test_check_jwks(
    caplog: pytest.LogCaptureFixture, expected: str, changed: bool, missing: bool
) -> None:
    api = FakeApi(jwks=_jwks())
    digest = ops.jwks_digest(api.jwks)
    baseline = {"match": [digest.upper(), "x"], "other": ["0" * 64], "": [""]}[expected]
    with caplog.at_level(logging.INFO, logger="aegisx9.gateway_ops"):
        assert ops.check_jwks(api, "https://vault.example.invalid/", baseline) == 0
    (line,) = [getattr(r, "fields", {}) for r in caplog.records]
    assert line["changed"] is changed
    assert line["baseline_missing"] is missing
    assert line["sha256"] == digest
    method, url, headers, _ = api.calls[0]
    assert (method, url) == (
        "GET",
        "https://vault.example.invalid/v1/identity/oidc/.well-known/keys",
    )
    assert headers == {}  # unauthenticated endpoint: no token is sent


def test_check_jwks_fetch_failure() -> None:
    with pytest.raises(ops.OpsError):
        ops.check_jwks(FakeApi(deny=True), "https://vault.example.invalid", [])


# -- entry point -------------------------------------------------------------------------------


def test_run_usage() -> None:
    assert ops.run([], {}) == 2
    assert ops.run(["drop-tables"], {}) == 2


def test_run_bootstrap_and_spend(tmp_path: Path) -> None:
    api = FakeApi()
    env = {
        "LITELLM_MASTER_KEY": secrets.token_urlsafe(16),
        "AEGISX9_GATEWAY_URL": "http://gateway:4000",
        "AEGISX9_BUDGET_PLAN": _write_plan(tmp_path),
    }
    assert ops.run(["bootstrap-teams"], env, api) == 0
    assert ops.run(["check-spend"], env, api) == 0


def test_run_reports_errors_without_values(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    key = secrets.token_urlsafe(16)
    env = {
        "LITELLM_MASTER_KEY": key,
        "AEGISX9_GATEWAY_URL": "http://gateway:4000",
        "AEGISX9_BUDGET_PLAN": _write_plan(tmp_path),
    }
    with caplog.at_level(logging.INFO):
        assert ops.run(["check-spend"], env, FakeApi(deny=True)) == 1
        assert ops.run(["check-spend"], {"AEGISX9_BUDGET_PLAN": env["AEGISX9_BUDGET_PLAN"]}) == 1
        assert ops.run(["check-jwks"], {"VAULT_ADDR": "http://vault.example.invalid"}) == 1

        def unreachable(*_a: Any) -> tuple[int, Any]:
            raise ConnectionRefusedError

        assert (
            ops.run(["check-jwks"], {"VAULT_ADDR": "https://vault.example.invalid"}, unreachable)
            == 1
        )
    assert key not in caplog.text
    errors = [getattr(r, "fields", {}) for r in caplog.records if r.levelno == logging.ERROR]
    assert {e["detail"] for e in errors} >= {
        "admin API refused the request (401)",
        "VAULT_ADDR must be an https URL",
        "ConnectionRefusedError",
    }


def test_run_check_jwks(tmp_path: Path) -> None:
    api = FakeApi(jwks=_jwks())
    env = {
        "VAULT_ADDR": "https://vault.example.invalid",
        "AEGISX9_JWKS_EXPECTED_SHA256": ops.jwks_digest(api.jwks),
    }
    assert ops.run(["check-jwks"], env, api) == 0


def test_run_check_jwks_builds_tls_client(monkeypatch: pytest.MonkeyPatch) -> None:
    built: list[object] = []

    def fake_urllib_request(context: object = None, timeout: float = 30.0) -> Any:
        built.append(context)
        return FakeApi(jwks=_jwks())

    monkeypatch.setattr(ops, "urllib_request", fake_urllib_request)
    assert ops.run(["check-jwks"], {"VAULT_ADDR": "https://vault.example.invalid"}) == 0
    assert built and built[0] is not None


@pytest.mark.parametrize("content", ["[1, 2]", '{"consumers": []}', '{"proxyMaxBudgetUsd": "x"}'])
def test_plan_structure_errors(tmp_path: Path, content: str) -> None:
    path = tmp_path / "plan.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ops.OpsError):
        ops.BudgetPlan.load(str(path))


# -- real HTTP -----------------------------------------------------------------------------------


@pytest.fixture
def http_server() -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            pass

        def do_GET(self) -> None:
            if self.path == "/ok":
                body = b'{"spend": 1}'
                self.send_response(200)
            elif self.path == "/text":
                body = b"plain"
                self.send_response(200)
            else:
                body = b'{"error": "nope"}'
                self.send_response(404)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_urllib_request(http_server: str) -> None:
    request = ops.urllib_request(timeout=5)
    assert request("GET", http_server + "/ok", {}, None) == (200, {"spend": 1})
    assert request("GET", http_server + "/text", {}, None) == (200, None)
    assert request("GET", http_server + "/missing", {}, None) == (404, None)
    with pytest.raises(ops.OpsError):
        request("GET", "file:///etc/hostname", {}, None)


def test_main_uses_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.argv", ["gateway_ops"])
    assert ops.main() == 2
    logging.getLogger("aegisx9").handlers[:] = []
    logging.getLogger("aegisx9").propagate = True
