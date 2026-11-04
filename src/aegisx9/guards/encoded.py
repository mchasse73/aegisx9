"""Detection of text smuggled in base64, base32 or hex (OWASP LLM01 obfuscation).

An attacker wraps an instruction or a forbidden payload in an encoding the keyword guard
can't read, then asks the model to decode it. This guard finds encoded spans, decodes each
one, and blocks when the decoded bytes carry text:

* ``encoded_<category>``: the decoded text matches a prompt-injection pattern. This check
  runs on every decode, however much binary junk surrounds the text;
* ``encoded_text``: the decoded bytes are readable prose, markup or code. Binary data
  (hashes, keys, images, git SHAs) doesn't count, nor does a JSON object whose string values
  are all single tokens (WebAuthn client data, API ids): prose needs spaces.

The pipeline runs this guard after secret and PII redaction, so credentials that happen to be
base64 (JWTs, ``Authorization: Basic``, ``password: <value>``) are redacted, not blocked.

The ``encoded_text`` rule is a policy: a gateway that lets prompts carry opaque text can't
apply any other guard to it. Turn it off with ``block_encoded_text=False`` to keep only the
injection check on decoded spans.

Work is linear in the text length: each decoder's spans don't overlap, and a span longer than
``_MAX_SPAN_CHARS`` is decoded up to that prefix rather than skipped.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from aegisx9.guards.base import Direction, Finding, GuardContext, GuardResult, Verdict
from aegisx9.guards.injection import injection_categories

# Candidate spans. The decoded-text test does the real filtering, so these only need to keep
# ordinary words out of the decoders. '=' may precede a span (key=value), so it isn't in the
# base64 lookbehind.
_BASE64 = re.compile(
    r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{6,}"
    r"(?:={1,2}(?![A-Za-z0-9+/=])|(?![A-Za-z0-9+/_=-]))"
)
_BASE32 = re.compile(r"(?<![A-Za-z0-9=])[A-Z2-7]{16,}={0,6}(?![A-Za-z0-9=])")
_HEX = re.compile(r"(?<![0-9A-Za-z])(?:0[xX])?((?:[0-9A-Fa-f]{2}){3,})(?![0-9A-Za-z])")
# Hex written byte by byte: "49 67 6e", "49:67:6e", "\x49\x67\x6e", "%49%67%6e".
_HEX_BYTES = re.compile(
    r"(?<![0-9A-Za-z])((?:[0-9A-Fa-f]{2}[ :,-]){3,}[0-9A-Fa-f]{2})(?![0-9A-Za-z])"
    r"|((?:\\x[0-9A-Fa-f]{2}){4,})"
    r"|((?:%[0-9A-Fa-f]{2}){4,})"
)

_MAX_SPAN_CHARS = 64 * 1024  # longer spans are decoded up to this prefix
_MIN_DECODED_CHARS = 3
_MIN_TEXTY_RATIO = 0.6  # letters, digits and whitespace / all characters
_MAX_JUNK_RATIO = 0.1  # undecodable or control characters a readable decode may hold
_MIN_LETTERS = 3
# A short decode is believed only when it is nearly all letters: random words decode to
# short printable junk often enough to matter.
_SHORT_DECODE_CHARS = 8
_MIN_SHORT_LETTER_RATIO = 0.75
# A base64 candidate with no padding, digit or symbol looks like an ordinary word, and a
# candidate of digits only looks like an order number, so both must be long to be decoded.
_PLAIN_BASE64_MIN_CHARS = 20
_DIGITS_ONLY_MIN_CHARS = 16


def _truncate(span: str, block: int) -> str:
    if len(span) <= _MAX_SPAN_CHARS:
        return span
    return span[: _MAX_SPAN_CHARS - _MAX_SPAN_CHARS % block]


def _b64_once(body: str) -> bytes | None:
    if len(body) % 4 == 1:
        body = body[:-1]
    padded = body + "=" * (-len(body) % 4)
    urlsafe = "-" in body or "_" in body
    if urlsafe and ("+" in body or "/" in body):
        return None
    try:
        return base64.b64decode(padded, altchars=b"-_" if urlsafe else b"+/", validate=True)
    except (binascii.Error, ValueError):
        return None


def _b64(span: str) -> list[bytes]:
    if len(span) < 8 and not span.endswith("="):
        return []
    if span.isalpha() and len(span) < _PLAIN_BASE64_MIN_CHARS:
        return []
    if span.isdigit() and len(span) < _DIGITS_ONLY_MIN_CHARS:
        return []
    body = _truncate(span.rstrip("="), 4)
    # A '-' or '_' next to the span may be punctuation rather than base64url: try without it.
    bodies = dict.fromkeys([body, body.strip("-_")])
    return [raw for b in bodies if b and (raw := _b64_once(b)) is not None]


def _b32(span: str) -> list[bytes]:
    body = _truncate(span.rstrip("="), 8)
    body = body[: len(body) - len(body) % 8] if len(body) % 8 in (1, 3, 6) else body
    try:
        return [base64.b32decode(body + "=" * (-len(body) % 8))]
    except (binascii.Error, ValueError):
        return []


def _hex(span: str) -> list[bytes]:
    if span.isdigit() and len(span) < _DIGITS_ONLY_MIN_CHARS:
        return []
    try:
        return [bytes.fromhex(_truncate(span, 2))]
    except ValueError:
        return []


def _hex_bytes(span: str) -> list[bytes]:
    digits = re.sub(r"[^0-9A-Fa-f]", "", span.replace("\\x", ""))
    try:
        return [bytes.fromhex(_truncate(digits, 2))]
    except ValueError:
        return []


_Decoder = tuple[str, re.Pattern[str], Callable[[str], list[bytes]]]
_DECODERS: tuple[_Decoder, ...] = (
    ("base64", _BASE64, _b64),
    ("base32", _BASE32, _b32),
    ("hex", _HEX, _hex),
    ("hex", _HEX_BYTES, _hex_bytes),
)


@dataclass(frozen=True)
class Decoded:
    encoding: str
    text: str
    junk: int  # undecodable or control characters in ``text``


def _junk(ch: str) -> bool:
    return ch == "�" or not (ch.isprintable() or ch in "\t\r\n")


def decoded_spans(text: str) -> Iterator[Decoded]:
    """Every encoded span in ``text`` that decodes to at least a few characters."""
    for encoding, pattern, decode in _DECODERS:
        for match in pattern.finditer(text):
            span = next((g for g in match.groups() if g), match.group(0))
            for raw in decode(span):
                decoded = raw.decode("utf-8", errors="replace")
                if len(decoded) >= _MIN_DECODED_CHARS:
                    yield Decoded(encoding, decoded, sum(_junk(ch) for ch in decoded))


def is_readable(span: Decoded) -> bool:
    text = span.text
    if span.junk / len(text) > _MAX_JUNK_RATIO:
        return False
    clean = "".join(ch for ch in text if not _junk(ch))
    letters = sum(ch.isalpha() for ch in clean)
    if letters < _MIN_LETTERS:
        return False
    if len(clean) < _SHORT_DECODE_CHARS:
        ascii_letters = sum(ch.isascii() and ch.isalpha() for ch in clean)
        return span.junk == 0 and ascii_letters / len(clean) >= _MIN_SHORT_LETTER_RATIO
    texty = sum(ch.isalnum() or ch.isspace() for ch in clean)
    return texty / len(clean) >= _MIN_TEXTY_RATIO


def _tokens_only(value: object) -> bool:
    if isinstance(value, str):
        return not any(ch.isspace() for ch in value)
    if isinstance(value, dict):
        return all(_tokens_only(k) and _tokens_only(v) for k, v in value.items())
    if isinstance(value, list):
        return all(_tokens_only(v) for v in value)
    return True


def is_structured_data(text: str) -> bool:
    """A JSON object holding only identifiers, numbers and flags, no prose."""
    stripped = text.strip()
    if not stripped.startswith("{"):
        return False
    try:
        value = json.loads(stripped)
    except ValueError:
        return False
    return isinstance(value, dict) and _tokens_only(value)


@dataclass
class EncodedPayloadGuard:
    name: str = "encoded_payload"
    directions: frozenset[Direction] = field(default_factory=lambda: frozenset({Direction.INPUT}))
    block_encoded_text: bool = True

    def check(self, text: str, ctx: GuardContext) -> GuardResult:
        counts: Counter[str] = Counter()
        for span in decoded_spans(text):
            hits = injection_categories(span.text)
            counts.update(f"encoded_{category}" for category in hits)
            if (
                not hits
                and self.block_encoded_text
                and is_readable(span)
                and not is_structured_data(span.text)
            ):
                counts["encoded_text"] += 1
        if counts:
            findings = tuple(Finding(self.name, c, n) for c, n in sorted(counts.items()))
            return GuardResult(Verdict.BLOCK, text, findings)
        return GuardResult.allow(text)
