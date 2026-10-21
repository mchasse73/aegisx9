"""HTTP reachability and latency for the public endpoints (the ``uptime`` subcommand,
run every five minutes by a systemd timer)."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from aegisx9_scanner.checks.http_exposure import Fetcher, fetch
from aegisx9_scanner.targets import UptimeTarget

Clock = Callable[[], float]


@dataclass(frozen=True)
class UptimeResult:
    url: str
    status: int
    latency_ms: int
    expect_status: int
    max_latency_ms: int
    error: str = ""

    @property
    def up(self) -> bool:
        return not self.error and self.status == self.expect_status

    @property
    def slow(self) -> bool:
        return self.up and self.latency_ms > self.max_latency_ms


def check_uptime(
    targets: list[UptimeTarget],
    *,
    timeout: int = 10,
    fetcher: Fetcher | None = None,
    clock: Clock = time.monotonic,
) -> list[UptimeResult]:
    fetcher = fetcher or fetch
    results: list[UptimeResult] = []
    for target in targets:
        started = clock()
        resp = fetcher(target.url, timeout)
        latency_ms = int((clock() - started) * 1000)
        results.append(
            UptimeResult(
                url=target.url,
                status=resp.status,
                latency_ms=latency_ms,
                expect_status=target.expect_status,
                max_latency_ms=target.max_latency_ms,
                error=resp.error,
            )
        )
    return results
