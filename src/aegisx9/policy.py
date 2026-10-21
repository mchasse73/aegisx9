"""Model allowlist, per-principal budgets and rate limits.

LiteLLM enforces budgets and rate limits natively in production; this module is the
policy-as-code source those settings are generated from, and the in-process check used
in tests and by the guard callback.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field


class PolicyViolationError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ModelPolicy:
    allowed_models: frozenset[str]
    max_output_tokens: int = 2048
    monthly_budget_usd: float = 0.0

    def check_model(self, model: str) -> None:
        if model not in self.allowed_models:
            raise PolicyViolationError("model_not_allowed", f"model {model!r} is not allowlisted")

    def check_max_tokens(self, requested: int | None) -> int:
        if requested is None:
            return self.max_output_tokens
        if requested < 1:
            raise PolicyViolationError("invalid_max_tokens", "max_tokens must be positive")
        return min(requested, self.max_output_tokens)


@dataclass
class TokenBucket:
    """Simple per-key token bucket (requests per minute)."""

    rate_per_minute: int
    clock: Callable[[], float] = time.monotonic
    _state: dict[str, tuple[float, float]] = field(default_factory=dict)

    def allow(self, key: str) -> bool:
        now = self.clock()
        capacity = float(self.rate_per_minute)
        tokens, last = self._state.get(key, (capacity, now))
        tokens = min(capacity, tokens + (now - last) * capacity / 60.0)
        if tokens < 1.0:
            self._state[key] = (tokens, now)
            return False
        self._state[key] = (tokens - 1.0, now)
        return True


@dataclass
class BudgetLedger:
    """Tracks spend per principal against a fixed budget."""

    budget_usd: float
    _spent: dict[str, float] = field(default_factory=dict)

    def remaining(self, principal: str) -> float:
        return self.budget_usd - self._spent.get(principal, 0.0)

    def charge(self, principal: str, cost_usd: float) -> None:
        if cost_usd < 0:
            raise ValueError("cost must be non-negative")
        if self.remaining(principal) - cost_usd < 0:
            raise PolicyViolationError("budget_exceeded", "budget exceeded")
        self._spent[principal] = self._spent.get(principal, 0.0) + cost_usd
