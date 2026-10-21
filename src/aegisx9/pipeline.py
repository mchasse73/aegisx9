"""Guard pipeline: run guards in order, short-circuit on BLOCK, emit one audit event."""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from aegisx9.audit import AuditEvent
from aegisx9.guards.base import Finding, Guard, GuardContext, Verdict

AuditSink = Callable[[AuditEvent], None]


@dataclass(frozen=True)
class PipelineResult:
    verdict: Verdict
    text: str
    findings: tuple[Finding, ...]
    blocked_by: str | None = None

    @property
    def blocked(self) -> bool:
        return self.verdict is Verdict.BLOCK


class GuardPipeline:
    def __init__(self, guards: Sequence[Guard], audit_sink: AuditSink | None = None) -> None:
        self._guards = tuple(guards)
        self._sink = audit_sink

    @property
    def guards(self) -> tuple[Guard, ...]:
        return self._guards

    def run(self, text: str, ctx: GuardContext) -> PipelineResult:
        started = time.perf_counter()
        original = text
        verdict = Verdict.ALLOW
        findings: list[Finding] = []
        blocked_by: str | None = None

        for guard in self._guards:
            if ctx.direction not in guard.directions:
                continue
            result = guard.check(text, ctx)
            findings.extend(result.findings)
            if result.verdict.severity > verdict.severity:
                verdict = result.verdict
            if result.verdict is Verdict.BLOCK:
                blocked_by = guard.name
                break
            text = result.text

        outcome = PipelineResult(verdict, text, tuple(findings), blocked_by)
        if self._sink is not None:
            self._sink(
                AuditEvent.for_content(
                    content=original,
                    request_id=ctx.request_id,
                    direction=ctx.direction,
                    verdict=verdict,
                    model=ctx.model,
                    principal=ctx.principal,
                    latency_ms=(time.perf_counter() - started) * 1000,
                    findings=outcome.findings,
                )
            )
        return outcome


def default_pipeline(audit_sink: AuditSink | None = None) -> GuardPipeline:
    from aegisx9.guards import PIIRedactionGuard, PromptInjectionGuard, SecretRedactionGuard

    return GuardPipeline(
        [PromptInjectionGuard(), SecretRedactionGuard(), PIIRedactionGuard()],
        audit_sink=audit_sink,
    )
