"""Core guard types.

A guard inspects one piece of text (a prompt on the way in, a completion on the way
out) and returns a verdict. Guards never return or log the sensitive values they find:
a :class:`Finding` carries only a category and a count.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable


class Direction(StrEnum):
    INPUT = "input"
    OUTPUT = "output"


class Verdict(StrEnum):
    """Ordered from least to most severe."""

    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"

    @property
    def severity(self) -> int:
        return _SEVERITY[self]


_SEVERITY = {Verdict.ALLOW: 0, Verdict.REDACT: 1, Verdict.BLOCK: 2}


@dataclass(frozen=True)
class Finding:
    """Something a guard detected. Never holds the matched value itself."""

    guard: str
    category: str
    count: int = 1


@dataclass(frozen=True)
class GuardContext:
    request_id: str
    direction: Direction
    model: str = ""
    principal: str = ""


@dataclass(frozen=True)
class GuardResult:
    verdict: Verdict
    text: str
    findings: tuple[Finding, ...] = field(default_factory=tuple)

    @classmethod
    def allow(cls, text: str) -> GuardResult:
        return cls(Verdict.ALLOW, text)


@runtime_checkable
class Guard(Protocol):
    """Interface every guard implements."""

    name: str
    directions: frozenset[Direction]

    def check(self, text: str, ctx: GuardContext) -> GuardResult: ...
