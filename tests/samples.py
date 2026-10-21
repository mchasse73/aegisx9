"""Credential-shaped test samples, assembled at runtime.

No credential-shaped literal appears in this repository: secret scanners flag even fake
ones. Each sample is built from harmless fragments when a test asks for it.
"""

from __future__ import annotations

import random
import string

_rng = random.Random(1337)  # noqa: S311 - deterministic test data, not crypto


def _chars(alphabet: str, n: int) -> str:
    return "".join(_rng.choice(alphabet) for _ in range(n))


def aws_access_key_id() -> str:
    return "".join(["AK", "IA"]) + _chars(string.ascii_uppercase + string.digits, 16)


def github_token() -> str:
    return "gh" + "p_" + _chars(string.ascii_letters + string.digits, 36)


def private_key_block() -> str:
    label = " ".join(["RSA", "PRIVATE", "KEY"])
    body = _chars(string.ascii_letters + string.digits, 64)
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----"


def jwt() -> str:
    seg = string.ascii_letters + string.digits
    return ".".join(["ey" + "J" + _chars(seg, 20), "ey" + "J" + _chars(seg, 30), _chars(seg, 24)])


def labelled_api_key() -> str:
    return "api" + "_key=" + _chars(string.ascii_letters + string.digits, 24)


def payment_card() -> str:
    # A Luhn-valid test number generated from a random prefix.
    digits = [4] + [_rng.randint(0, 9) for _ in range(14)]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    digits.append((10 - total % 10) % 10)
    return "".join(map(str, digits))


def email() -> str:
    return "jane.doe" + "@" + "example" + ".org"


def ssn() -> str:
    return "-".join(["123", "45", "6789"])


def phone() -> str:
    return "(555) 010-" + "4477"
