"""Day-2 jobs for the gateway: consumer budgets, spend checks and the federation JWKS check.

Run as ``python -m aegisx9.gateway_ops <command>`` from Kubernetes Jobs/CronJobs in the
gateway's namespace:

``bootstrap-teams``
    Idempotently creates or updates one LiteLLM team per consumer (budget, budget window,
    model allowlist, per-member budget, default-model alias) through the proxy's admin API.
``check-spend``
    Logs one ``aegisx9_spend`` JSON line for the proxy-wide budget and one per consumer,
    with the percentage used. Loki rules alert at 50/80/100 %.
``check-jwks``
    Fetches the secrets store's published OIDC identity keys (``identity/oidc/.well-known/keys``)
    and checks that every key id uploaded to the Anthropic federation issuer
    (``AEGISX9_WIF_UPLOADED_KIDS``) is still published. That endpoint lists every identity
    key, including ones that rotate on their own schedule, so the check never compares the
    whole set; an uploaded key that disappears means the store rotated it and every token
    exchange will fail until the new public key is uploaded.

The admin key is read from ``LITELLM_MASTER_KEY`` (a Secret reference) and is never logged.
Errors are logged by exception type name only. Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final
from urllib.parse import quote, urlsplit

from aegisx9 import __version__
from aegisx9.wif_broker import configure_logging

logger = logging.getLogger("aegisx9.gateway_ops")

VAULT_KEYS_PATH: Final = "/v1/identity/oidc/.well-known/keys"


class OpsError(Exception):
    """A day-2 job could not complete. The message never contains secret values."""


@dataclass(frozen=True)
class Consumer:
    team_id: str
    max_budget_usd: float
    budget_duration: str
    models: tuple[str, ...]
    default_model: str
    alias: str = ""
    member_budget_usd: float | None = None

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any], default_duration: str = "30d") -> Consumer:
        try:
            models = tuple(str(m) for m in data["models"])
            consumer = cls(
                team_id=str(data["teamId"]),
                alias=str(data.get("alias", data["teamId"])),
                max_budget_usd=float(data["maxBudgetUsd"]),
                budget_duration=str(data.get("budgetDuration", default_duration)),
                models=models,
                default_model=str(data["defaultModel"]),
                member_budget_usd=(
                    float(data["memberBudgetUsd"])
                    if data.get("memberBudgetUsd") is not None
                    else None
                ),
            )
        except (KeyError, TypeError, ValueError) as e:
            raise OpsError(f"invalid consumer definition ({type(e).__name__})") from e
        if consumer.default_model not in consumer.models:
            raise OpsError(f"consumer {consumer.team_id}: default model is not allowlisted")
        if consumer.max_budget_usd <= 0:
            raise OpsError(f"consumer {consumer.team_id}: budget must be positive")
        return consumer

    def team_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "team_id": self.team_id,
            "team_alias": self.alias,
            "max_budget": self.max_budget_usd,
            "budget_duration": self.budget_duration,
            "models": list(self.models),
            # Clients that ask for "default" get the consumer's default model.
            "model_aliases": {"default": self.default_model},
        }
        if self.member_budget_usd is not None:
            payload["team_member_budget"] = self.member_budget_usd
            payload["team_member_budget_duration"] = self.budget_duration
        return payload


@dataclass(frozen=True)
class BudgetPlan:
    proxy_max_budget_usd: float
    consumers: tuple[Consumer, ...]

    @classmethod
    def load(cls, path: str) -> BudgetPlan:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise OpsError(f"budget plan unreadable ({type(e).__name__})") from e
        if not isinstance(data, dict):
            raise OpsError("budget plan is not an object")
        duration = str(data.get("budgetDuration", "30d"))
        consumers = tuple(Consumer.from_mapping(c, duration) for c in data.get("consumers", []))
        try:
            proxy_budget = float(data["proxyMaxBudgetUsd"])
        except (KeyError, TypeError, ValueError) as e:
            raise OpsError(f"proxyMaxBudgetUsd invalid ({type(e).__name__})") from e
        plan = cls(proxy_max_budget_usd=proxy_budget, consumers=consumers)
        plan.validate()
        return plan

    def validate(self) -> None:
        ids = [c.team_id for c in self.consumers]
        if len(ids) != len(set(ids)):
            raise OpsError("duplicate consumer team ids")
        allocated = sum(c.max_budget_usd for c in self.consumers)
        if allocated > self.proxy_max_budget_usd:
            raise OpsError("consumer budgets exceed the proxy-wide budget")


# -- HTTP ----------------------------------------------------------------------------------

Request = Callable[[str, str, Mapping[str, str], bytes | None], tuple[int, Any]]


def _refused_before_sending(exc: BaseException) -> bool:
    """True only for failures that happen before any byte of the request is sent."""
    reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    return isinstance(reason, ConnectionRefusedError)


def urllib_request(
    context: ssl.SSLContext | None = None,
    timeout: float = 30.0,
    connect_retry_seconds: float = 60.0,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> Request:
    """HTTP helper for the day-2 jobs.

    A short-lived pod can be refused for its first seconds while the network policy
    controller adds its address. Only a refused connection is retried: nothing was sent, so
    no write can be replayed. Timeouts and other failures after sending propagate. Retries
    stop at a monotonic deadline ``connect_retry_seconds`` after the first attempt, and each
    attempt's timeout is capped to the time left.
    """

    def _request(
        method: str, url: str, headers: Mapping[str, str], body: bytes | None
    ) -> tuple[int, Any]:
        if urlsplit(url).scheme not in {"http", "https"}:
            raise OpsError("unsupported URL scheme")
        req = urllib.request.Request(url, data=body, method=method, headers=dict(headers))  # noqa: S310 - scheme checked above
        deadline = clock() + connect_retry_seconds
        delay = 2.0
        while True:
            remaining = deadline - clock()
            attempt_timeout = max(1.0, min(timeout, remaining)) if remaining > 0 else timeout
            try:
                with urllib.request.urlopen(req, timeout=attempt_timeout, context=context) as resp:  # noqa: S310 - scheme checked above
                    raw = resp.read(4 * 1024 * 1024)
                    status = resp.status
                break
            except urllib.error.HTTPError as e:
                status, raw = e.code, b""
                e.close()
                break
            except (urllib.error.URLError, ConnectionError) as e:
                remaining = deadline - clock()
                if not _refused_before_sending(e) or remaining <= 0:
                    raise
                sleep(min(delay, remaining))
                delay = min(delay * 2, 10.0)
        try:
            return status, json.loads(raw) if raw else None
        except ValueError:
            return status, None

    return _request


@dataclass
class AdminClient:
    base_url: str
    master_key: str = field(repr=False)
    request: Request

    def _headers(self) -> dict[str, str]:
        return {
            "authorization": f"Bearer {self.master_key}",
            "content-type": "application/json",
            "accept": "application/json",
        }

    def call(
        self, method: str, path: str, payload: Mapping[str, Any] | None = None
    ) -> tuple[int, Any]:
        body = json.dumps(payload).encode() if payload is not None else None
        status, data = self.request(method, self.base_url.rstrip("/") + path, self._headers(), body)
        if status in (401, 403):
            raise OpsError(f"admin API refused the request ({status})")
        return status, data

    def team_info(self, team_id: str) -> Mapping[str, Any] | None:
        """The team's record, or None when it does not exist (HTTP 404 only). Any other
        failure or a malformed answer raises, so a broken lookup is never read as absent."""
        status, data = self.call("GET", "/team/info?team_id=" + quote(team_id, safe=""))
        if status == 404:
            return None
        if status != 200 or not isinstance(data, dict):
            raise OpsError(f"team {team_id}: /team/info returned {status}")
        info = data.get("team_info", data)
        if not isinstance(info, dict):
            raise OpsError(f"team {team_id}: /team/info answer is malformed")
        return info


# -- commands --------------------------------------------------------------------------------


def bootstrap_teams(client: AdminClient, plan: BudgetPlan) -> int:
    for consumer in plan.consumers:
        info = client.team_info(consumer.team_id)
        exists = info is not None
        path = "/team/update" if exists else "/team/new"
        payload = consumer.team_payload()
        if info is not None and info.get("budget_duration") == consumer.budget_duration:
            # LiteLLM recomputes budget_reset_at whenever budget_duration is sent; resending
            # an unchanged value on every sync would keep postponing the budget reset.
            payload.pop("budget_duration")
        status, _ = client.call("POST", path, payload)
        if status != 200:
            raise OpsError(f"team {consumer.team_id}: {path} returned {status}")
        logger.info(
            "team configured",
            extra={
                "fields": {
                    "event": "aegisx9_team_configured",
                    "team": consumer.team_id,
                    "action": "updated" if exists else "created",
                    "max_budget_usd": consumer.max_budget_usd,
                    "models": list(consumer.models),
                }
            },
        )
    return 0


def _spend_line(scope: str, name: str, spend: float, budget: float) -> dict[str, Any]:
    pct = round(100.0 * spend / budget, 1) if budget > 0 else 0.0
    return {
        "event": "aegisx9_spend",
        "scope": scope,
        "name": name,
        "spend_usd": round(spend, 4),
        "budget_usd": budget,
        "pct": pct,
    }


def _number(value: object) -> float:
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else 0.0


def check_spend(client: AdminClient, plan: BudgetPlan) -> int:
    status, data = client.call("GET", "/global/spend")
    if status != 200 or not isinstance(data, dict):
        raise OpsError(f"/global/spend returned {status}")
    budget = _number(data.get("max_budget")) or plan.proxy_max_budget_usd
    lines = [_spend_line("proxy", "proxy", _number(data.get("spend")), budget)]
    for consumer in plan.consumers:
        info = client.team_info(consumer.team_id)
        if info is None:
            logger.warning(
                "team missing",
                extra={"fields": {"event": "aegisx9_team_missing", "team": consumer.team_id}},
            )
            continue
        team_budget = _number(info.get("max_budget")) or consumer.max_budget_usd
        lines.append(_spend_line("team", consumer.team_id, _number(info.get("spend")), team_budget))
    for line in lines:
        logger.info("spend", extra={"fields": line})
    return 0


def jwks_digest(document: Mapping[str, Any]) -> str:
    """Order-independent digest of the public keys in a JWKS document."""
    keys = document.get("keys")
    if not isinstance(keys, list) or not keys:
        raise OpsError("JWKS document has no keys")
    canonical = sorted(json.dumps(k, sort_keys=True, separators=(",", ":")) for k in keys)
    return hashlib.sha256("\n".join(canonical).encode()).hexdigest()


def parse_kids(value: str) -> list[str]:
    """Comma-separated key ids, blanks dropped, order kept, duplicates removed."""
    return list(dict.fromkeys(k.strip() for k in value.split(",") if k.strip()))


def check_jwks(request: Request, vault_addr: str, uploaded_kids: Sequence[str]) -> int:
    """The keys endpoint is unauthenticated: no Vault token is needed or sent.

    Logs one ``aegisx9_jwks`` line. Key ids are public identifiers; the digest of the
    published set is informational only (the set changes whenever any key rotates).
    """
    status, data = request("GET", vault_addr.rstrip("/") + VAULT_KEYS_PATH, {}, None)
    if status != 200 or not isinstance(data, dict):
        raise OpsError(f"JWKS fetch returned {status}")
    digest = jwks_digest(data)
    published = {k.get("kid") for k in data["keys"] if isinstance(k, dict)}
    uploaded = [k for k in uploaded_kids if k.strip()]
    missing = [k for k in uploaded if k not in published]
    logger.info(
        "jwks check",
        extra={
            "fields": {
                "event": "aegisx9_jwks",
                "missing_uploaded_kids": missing,
                "missing_count": len(missing),
                "uploaded_count": len(uploaded),
                "published_count": len(data["keys"]),
                "sha256": digest,
            }
        },
    )
    return 0


# -- entry point -----------------------------------------------------------------------------


def _admin_client(env: Mapping[str, str], request: Request) -> AdminClient:
    master_key = env.get("LITELLM_MASTER_KEY", "")
    base_url = env.get("AEGISX9_GATEWAY_URL", "")
    if not master_key or not base_url:
        raise OpsError("LITELLM_MASTER_KEY and AEGISX9_GATEWAY_URL are required")
    return AdminClient(base_url=base_url, master_key=master_key, request=request)


def run(argv: Sequence[str], env: Mapping[str, str], request: Request | None = None) -> int:
    if len(argv) != 1 or argv[0] not in {"bootstrap-teams", "check-spend", "check-jwks"}:
        logger.error("usage: python -m aegisx9.gateway_ops bootstrap-teams|check-spend|check-jwks")
        return 2
    command = argv[0]
    logger.info("starting", extra={"fields": {"version": __version__, "command": command}})
    try:
        if command == "check-jwks":
            vault_addr = env.get("VAULT_ADDR", "")
            if urlsplit(vault_addr).scheme != "https":
                raise OpsError("VAULT_ADDR must be an https URL")
            if request is None:
                context = ssl.create_default_context(cafile=env.get("VAULT_CACERT") or None)
                request = urllib_request(context)
            uploaded = parse_kids(env.get("AEGISX9_WIF_UPLOADED_KIDS", ""))
            return check_jwks(request, vault_addr, uploaded)
        plan = BudgetPlan.load(env.get("AEGISX9_BUDGET_PLAN", "/etc/aegisx9-budgets/plan.json"))
        client = _admin_client(env, request or urllib_request())
        if command == "bootstrap-teams":
            return bootstrap_teams(client, plan)
        return check_spend(client, plan)
    except (OpsError, OSError) as e:
        detail = e.args[0] if isinstance(e, OpsError) and e.args else type(e).__name__
        logger.error(
            "job failed",
            extra={"fields": {"event": "aegisx9_ops_error", "command": command, "detail": detail}},
        )
        return 1


def main() -> int:
    configure_logging()
    return run(sys.argv[1:], os.environ)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
