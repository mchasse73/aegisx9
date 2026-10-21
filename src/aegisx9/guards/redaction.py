"""Secret and PII redaction.

Matches are replaced with ``[REDACTED:<category>]``. The original value is never kept,
returned, or logged; only per-category counts leave this module.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from aegisx9.guards.base import Direction, Finding, GuardContext, GuardResult, Verdict

Validator = Callable[[str], bool]

SECRET_PATTERNS: Mapping[str, re.Pattern[str]] = {
    "aws_access_key_id": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "private_key": re.compile(
        r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z]+ )?PRIVATE KEY-----",
        re.DOTALL,
    ),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    "bearer_token": re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{20,}=*"),
    "generic_api_key": re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9._~+/-]{16,}"
    ),
}

PII_PATTERNS: Mapping[str, re.Pattern[str]] = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "us_ssn": re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    "phone": re.compile(r"(?<!\w)(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}\b"),
    "payment_card": re.compile(r"\b(?:\d[ -]?){12,18}\d\b"),
}


def luhn_valid(candidate: str) -> bool:
    digits = [int(c) for c in candidate if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


PII_VALIDATORS: Mapping[str, Validator] = {"payment_card": luhn_valid}


def _redact(
    text: str,
    patterns: Mapping[str, re.Pattern[str]],
    validators: Mapping[str, Validator],
) -> tuple[str, dict[str, int]]:
    counts: dict[str, int] = {}
    for category, pattern in patterns.items():
        validator = validators.get(category)

        def _sub(
            m: re.Match[str], category: str = category, validator: Validator | None = validator
        ) -> str:
            if validator is not None and not validator(m.group(0)):
                return m.group(0)
            counts[category] = counts.get(category, 0) + 1
            return f"[REDACTED:{category}]"

        text = pattern.sub(_sub, text)
    return text, counts


@dataclass
class _RedactionGuard:
    name: str
    patterns: Mapping[str, re.Pattern[str]]
    validators: Mapping[str, Validator] = field(default_factory=dict)
    directions: frozenset[Direction] = field(
        default_factory=lambda: frozenset({Direction.INPUT, Direction.OUTPUT})
    )

    def check(self, text: str, ctx: GuardContext) -> GuardResult:
        redacted, counts = _redact(text, self.patterns, self.validators)
        if not counts:
            return GuardResult.allow(text)
        findings = tuple(Finding(self.name, c, n) for c, n in sorted(counts.items()))
        return GuardResult(Verdict.REDACT, redacted, findings)


def SecretRedactionGuard() -> _RedactionGuard:
    return _RedactionGuard(name="secret_redaction", patterns=SECRET_PATTERNS)


def PIIRedactionGuard() -> _RedactionGuard:
    return _RedactionGuard(name="pii_redaction", patterns=PII_PATTERNS, validators=PII_VALIDATORS)


def contains_secret(text: str) -> bool:
    """True if ``text`` matches any secret pattern. Used to self-check audit records."""
    return any(p.search(text) for p in SECRET_PATTERNS.values())
