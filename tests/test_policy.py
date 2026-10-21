import pytest

from aegisx9.policy import BudgetLedger, ModelPolicy, PolicyViolationError, TokenBucket


def test_model_allowlist() -> None:
    policy = ModelPolicy(allowed_models=frozenset({"small"}), max_output_tokens=100)
    policy.check_model("small")
    with pytest.raises(PolicyViolationError) as exc:
        policy.check_model("huge")
    assert exc.value.code == "model_not_allowed"


def test_max_tokens_clamped() -> None:
    policy = ModelPolicy(allowed_models=frozenset(), max_output_tokens=100)
    assert policy.check_max_tokens(None) == 100
    assert policy.check_max_tokens(5000) == 100
    assert policy.check_max_tokens(10) == 10
    with pytest.raises(PolicyViolationError):
        policy.check_max_tokens(0)


def test_token_bucket_refills() -> None:
    now = [0.0]
    bucket = TokenBucket(rate_per_minute=2, clock=lambda: now[0])
    assert bucket.allow("k") and bucket.allow("k")
    assert not bucket.allow("k")
    now[0] += 30.0
    assert bucket.allow("k")
    assert bucket.allow("other")


def test_budget_ledger() -> None:
    ledger = BudgetLedger(budget_usd=1.0)
    ledger.charge("p", 0.6)
    assert ledger.remaining("p") == pytest.approx(0.4)
    with pytest.raises(PolicyViolationError):
        ledger.charge("p", 0.5)
    with pytest.raises(ValueError):
        ledger.charge("p", -1)
