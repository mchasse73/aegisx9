"""Instructions planted in pasted data, and completions that obey them (OWASP LLM01, indirect).

A user pastes a document, a web page, a chat log or a tool result and asks for a summary.
The attacker's text sits inside that data and tells the model to drop the user's task and
print something else: a phishing link, a slogan, a fake verdict. These attacks are phrased
so they don't need the keyword guard's "ignore all previous instructions".

Signals (only the category names reach the audit log, never the matched text):

* strong, blocked inside the data region (see :func:`data_region`):

  * ``context_override``: "ignore the rest of this data and print", "disregard all info
    except the following", "ignore them and instead focus exclusively on", "nevermind,
    ignore … instructions";
  * ``session_marker``: ``<end of session>``, ``<|endoftext|>`` and similar fake
    end-of-conversation tokens;

* weak, also counted only in the data region:

  * ``fake_role_turn``: a line that starts a ``System:``/``Assistant:``/``User:`` turn;
  * ``separator_payload``: separator lines stacked on top of each other (an escape trick);
  * ``output_forcing_literal``: a forcing phrase ("just print", "reply with only",
    "provide it to the user") followed by a quoted or bracketed literal to emit. "Reply with
    only the summary" has no literal, so it isn't forcing.

:class:`EmbeddedInstructionGuard` (input) scans user and tool messages only. It blocks a
strong signal, or a forcing literal planted on a fake role turn or straight after stacked
separators. Other weak signals are allowed, and their findings still reach the audit log.

:class:`InstructionEchoGuard` (output) blocks a completion that repeats, as whole words, a
literal the current turn's data tried to force. The proxy hook computes those literals once
per request (:func:`request_literals`) into :attr:`GuardContext.prompt_literals`; a caller
with only text can pass :attr:`GuardContext.prompt_text`. Neither is ever logged.

Line endings are normalised first (CRLF and lone CR become LF, trailing blanks are dropped),
so a Windows-style paste reads like any other.

Every function is pure and linear in the text length. Patterns are compiled once, start
with a literal word (so the regex engine can skip ahead) and have bounded quantifiers; each
literal search looks at a fixed-size window.
"""

from __future__ import annotations

import bisect
import re
import urllib.parse
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

from aegisx9.guards.base import Direction, Finding, GuardContext, GuardResult, Verdict

# Roles whose whole message is data (tool results).
DATA_ROLES = frozenset({"tool", "function"})
# Roles the input guard scans. System and assistant turns are the operator's own text, often
# few-shot examples full of role lines and quoted answers. "" is a caller that sets no role.
SCANNED_ROLES = frozenset({"user", "", *DATA_ROLES})

_VERBS = r"(?:print|say|output|write|type|repeat|return|respond|reply|answer|state|tell)"
_DOC = r"(?:data|text|document|article|message|email|content|input|snippets?|page|report)"

# Every pattern runs on the lower-cased text and starts with a literal. A phrase must also
# start at a word boundary (checked in _word_matches); a session marker needn't, since
# "text<|endoftext|>" is as much a marker as " <|endoftext|>". No two adjacent quantifiers
# can match the same characters, so no pattern backtracks quadratically (a test times each).
_STRONG: dict[str, tuple[re.Pattern[str], ...]] = {
    "context_override": tuple(
        re.compile(p)
        for p in (
            # "Ignore the rest of this data and print ..."
            *(
                rf"{verb}\s+the\s+rest\s+of\s+(?:this|the|these)\s+{_DOC}"
                rf"(?:\s*,)?\s+and\s+(?:instead\s+)?(?:just\s+|only\s+|simply\s+)?{_VERBS}\b"
                for verb in ("ignore", "disregard", "skip")
            ),
            # "Disregard all info except for the following information ..."
            r"disregard\s+(?:all|any)\s+(?:other\s+)?(?:info(?:rmation)?|content|text|data|context)"
            r"\s+(?:except|but|other\s+than)\s+(?:for\s+)?(?:the\s+following|what\s+is|this|these)\b",
            # "... ignore them and instead focus exclusively on ..."
            r"ignore\s+(?:them|those|these|it|everything(?:\s+else)?)(?:\s*,)?\s+and\s+instead\s+"
            r"focus\s+(?:exclusively|only|solely)\b",
            # "... Nevermind. Ignore any previous ... instructions"
            r"never\s?mind\b[\s.,!;:-]{0,10}(?:ignore|disregard|forget)\b[^\n]{0,40}?\binstructions?\b",
        )
    ),
    "session_marker": tuple(
        re.compile(p)
        for p in (
            r"<\s*(?:/\s*)?(?:end|stop)\s+of\s+(?:session|conversation|context|chat|prompt|turn)\s*>",
            r"\[\s*(?:end|stop)\s+of\s+(?:session|conversation|context|chat|prompt|turn)\s*\]",
            r"<\|(?:endoftext|im_end|eot_id|end_of_turn)\|>",
        )
    ),
}
STRONG_SIGNALS = frozenset(_STRONG)

# Line-based patterns run on "\n" + text, so every line, the first included, starts with "\n".
# Pasted data starts at a separator line, a code fence or a quoted line ...
_REGION_LINE = re.compile(r"\n[ \t]*(?:[-=*_~#]{4,}[ \t]*(?=\n|$)|`{3,}|~{3,}|>)")
# ... or after a line that introduces "the following:" block.
_REGION_INTRO = re.compile(r"the\s+following\b[^\n:]{0,60}:[ \t]*(?=\n|$)")
_ROLE_LINE = re.compile(r"\n[ \t>*_]{0,8}(?:system|assistant|user|human|ai|bot)[ \t]*:")
_SEPARATOR = re.compile(r"[-=*_~#]{4,}")
_MAX_STACK_GAP = 3  # blank lines allowed between two stacked separators

_FORCING: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p)
    for p in (
        rf"just\s+{_VERBS}\b(?:\s+with)?",
        rf"only\s+{_VERBS}\b(?:\s+with)?",
        rf"simply\s+{_VERBS}\b(?:\s+with)?",
        r"reply\s+(?:with\s+)?only\b",
        r"respond\s+(?:with\s+)?only\b",
        r"answer\s+(?:with\s+)?only\b",
        r"provide\s+it\s+to\s+the\s+user\b",
        r"focus\s+(?:only|exclusively|solely)\s+on\b",
        r"translate\s+(?:this|it)\s+(?:\w+\s+)?as\b",
    )
)
# A bare verb forces only straight after one of these words and right before a literal.
_BARE_VERBS = tuple(
    re.compile(rf"{v}\b(?=\s*[:\"“'<])") for v in ("print", "say", "output", "repeat", "write")
)
_BARE_LEADS = frozenset({"and", "then", "now", "please"})

_TOKEN_SPLIT = re.compile(r"[\s\"'<>()\[\]{}`*,;|]+")
_HOST = re.compile(r"(?:[a-z0-9-]{1,63}\.){1,8}([a-z]{2,24})")
# A dotted name ending in one of these is a file name, not a link, unless it has a scheme
# or starts with www.
# fmt: off
_FILE_EXTENSIONS = frozenset({
    "py", "md", "js", "ts", "jsx", "tsx", "json", "yaml", "yml", "toml", "txt", "sh", "go", "rs",
    "java", "rb", "php", "html", "htm", "css", "lock", "cfg", "ini", "xml", "csv", "log", "conf",
    "env", "sql", "c", "h", "cpp", "hpp", "cs", "kt", "swift", "pl", "lua", "r", "ipynb", "pdf",
    "png", "jpg", "gif", "svg", "zip", "gz", "tar", "whl",
})
# fmt: on
_OPEN = re.compile(r"[\"“'<]")
_NEWLINE = re.compile(r"\n")
_SENTENCE_END = re.compile(r"[.!?](?:\s|$)")

_WINDOW = 200  # a forcing phrase's literal must start this close
_SHORT_GAP = 60  # ... and this close unless an introducing colon precedes it
_MAX_LINE = 512  # a literal ends on its own line, within this many characters
_MAX_TRIES = 4  # delimiter candidates tried per forcing phrase
_MIN_ECHO_CHARS = 4
_ECHO_PREFIX = 64  # a literal is echoed when its first 64 characters are
_FEW_LITERALS = 64  # above this many, echo matching switches to a sliding window


def _normalise(text: str) -> str:
    """LF line endings and no trailing blanks, so every line-based check sees one form."""
    if "\r" in text:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
    if " \n" in text or "\t\n" in text or text.endswith((" ", "\t")):
        text = "\n".join(line.rstrip(" \t") for line in text.split("\n"))
    return text


def _lower(text: str) -> str:
    # str.lower() keeps the length for every character except U+0130, which it expands.
    return text.replace("İ", "i").lower()


def _word_matches(pattern: re.Pattern[str], low: str) -> Iterator[re.Match[str]]:
    for match in pattern.finditer(low):
        start = match.start()
        if start == 0 or not low[start - 1].isalnum():
            yield match


def _strong_counts(low: str) -> Counter[str]:
    counts: Counter[str] = Counter()
    for category, patterns in _STRONG.items():
        if category == "session_marker":
            n = sum(1 for p in patterns for _ in p.finditer(low))
        else:
            n = sum(1 for p in patterns for _ in _word_matches(p, low))
        if n:
            counts[category] = n
    return counts


def strong_signals(text: str) -> tuple[str, ...]:
    """The strong categories anywhere in ``text`` (the encoded guard's decoded spans)."""
    return tuple(sorted(_strong_counts(_lower(_normalise(text)))))


def _region_start(low: str) -> int:
    starts = []
    if (line := _REGION_LINE.search("\n" + low)) is not None:
        starts.append(line.start())  # the "\n" prefix makes this the line's own offset
    if (intro := _REGION_INTRO.search(low)) is not None:
        starts.append(intro.end())
    return min(starts, default=-1)


def data_region(text: str, role: str = "") -> str:
    """The part of ``text`` that is pasted data: all of a tool message, else from the first
    separator, fence or quoted line, or after "the following:". Empty when there is none.
    The result has normalised line endings."""
    text = _normalise(text)
    if role in DATA_ROLES:
        return text
    start = _region_start(_lower(text))
    return text[start:] if start >= 0 else ""


def _quoted(text: str, i: int, line_end: int) -> list[str]:
    opener = text[i]
    if opener == "<":
        if text.startswith("<<", i):
            end = text.find(">>", i + 2, line_end)
            return [text[i + 2 : end]] if end != -1 else []
        first = text.find(">", i + 1, line_end)
        if first == -1:
            return []
        last = text.rfind(">", i + 1, line_end)
        return [text[i + 1 : first], text[i + 1 : last]] if last > first else [text[i + 1 : first]]
    if opener == "'":
        if i > 0 and text[i - 1].isalnum():
            return []  # an apostrophe, not a quote
        end = i
        while (end := text.find("'", end + 1, line_end)) != -1:
            if end + 1 >= len(text) or not text[end + 1].isalnum():
                return [text[i + 1 : end]]
        return []
    ends = [p for c in '"”' if (p := text.find(c, i + 1, line_end)) != -1]
    if not ends:
        return []
    first = min(ends)
    last = max(text.rfind(c, i + 1, line_end) for c in '"”')
    return [text[i + 1 : first], text[i + 1 : last]] if last > first else [text[i + 1 : first]]


_TWO_ALNUM = re.compile(r"[^\W_].*?[^\W_]", re.DOTALL)


def _has_text(literal: str) -> bool:
    return _TWO_ALNUM.search(literal) is not None


def _literal_after(text: str, end: int) -> list[str]:
    """The literal a forcing phrase ending at ``end`` points at, or ``[]``."""
    for tries, opener in enumerate(_OPEN.finditer(text, end, end + _WINDOW), start=1):
        i = opener.start()
        gap = text[end:i]
        if "\n\n" in gap:
            return []
        near = len(gap.strip()) <= _SHORT_GAP and not _SENTENCE_END.search(gap)
        if near or gap.rstrip().endswith(":"):
            line_end = text.find("\n", i, i + _MAX_LINE)
            line_end = line_end if line_end != -1 else min(len(text), i + _MAX_LINE)
            # The nearest closing delimiter decides; the farthest one on the line is a second
            # reading for nested quotes or markup.
            found = [s.strip().strip("\"'“”").strip() for s in _quoted(text, i, line_end)]
            if found and _has_text(found[0]):
                return [s for s in found if _has_text(s)]
        if tries >= _MAX_TRIES:
            break
    return []


def _forcing_phrases(low: str) -> Iterator[re.Match[str]]:
    for pattern in _FORCING:
        yield from _word_matches(pattern, low)
    for pattern in _BARE_VERBS:
        for match in _word_matches(pattern, low):
            lead = low[max(0, match.start() - 12) : match.start()].split()
            if lead and lead[-1] in _BARE_LEADS:
                yield match


def _forcing(region: str, low: str) -> Iterator[tuple[int, list[str]]]:
    for match in _forcing_phrases(low):
        literals = _literal_after(region, match.end())
        if literals:
            yield match.start(), literals


def _hostname(token: str) -> tuple[str, bool]:
    """The host a token names, and whether it had an http(s) scheme ("" if it names none)."""
    low = token.lower()
    if low.startswith(("http://", "https://")):
        try:
            return urllib.parse.urlsplit(low).hostname or "", True
        except ValueError:
            return "", True
    host = re.split(r"[/?#]", low, maxsplit=1)[0]
    return host.rsplit("@", 1)[-1].split(":", 1)[0], False


def is_link(token: str) -> bool:
    """A URL or a domain name; a dotted file name (``main.py``) is neither."""
    host, scheme = _hostname(token)
    match = _HOST.fullmatch(host)
    if match is None:
        return False
    return scheme or host.startswith("www.") or match.group(1) not in _FILE_EXTENSIONS


def _expand(literals: list[str]) -> Iterator[tuple[str, bool]]:
    """Each literal, then the URLs and domains inside it (flagged True)."""
    for literal in literals:
        yield literal, False
        if "." in literal:
            for token in _TOKEN_SPLIT.split(literal):
                token = token.rstrip(".:!?")
                if "." in token and len(token) <= 300 and is_link(token):
                    yield token, True
                    host, _ = _hostname(token)
                    if host and host != token.lower():
                        yield host, True


def _forced(region: str) -> dict[str, bool]:
    out: dict[str, bool] = {}
    for _, literals in _forcing(region, _lower(region)):
        for candidate, is_link in _expand(literals):
            candidate = candidate.strip()
            if len(candidate) >= _MIN_ECHO_CHARS and _has_text(candidate):
                out[candidate] = out.get(candidate, False) or is_link
    return out


def forced_literals(text: str, *, whole: bool = False) -> tuple[str, ...]:
    """Literals that the data region of ``text`` tells the model to emit, with the URLs and
    domains inside them. ``whole=True`` treats all of ``text`` as data."""
    return tuple(_forced(_normalise(text) if whole else data_region(text)))


@dataclass(frozen=True)
class ForcedLiteral:
    """A literal one message's data tried to force, for the echo guard. Never logged."""

    text: str = field(repr=False)
    link: bool = False  # a URL or domain inside a forced literal
    corroborated: bool = False  # the same message carries another signal


def request_literals(messages: Iterable[tuple[str, str]]) -> tuple[ForcedLiteral, ...]:
    """The forced literals of ``(role, text)`` messages, each corroborated only by its own
    message's signals. Computed once per request; the result lives in its GuardContext."""
    out: dict[tuple[str, bool], bool] = {}
    for role, text in messages:
        region = data_region(text, role)
        if not region:
            continue
        forced = _forced(region)
        if not forced:
            continue
        counts, _ = _scan(region, "tool")
        corroborated = bool(set(counts) - {"output_forcing_literal"})
        for literal, link in forced.items():
            out[(literal, link)] = out.get((literal, link), False) or corroborated
    return tuple(ForcedLiteral(t, link, c) for (t, link), c in out.items())


def _end_of_previous_line(text: str, line_start: int) -> int:
    """Where the text before ``line_start`` ends once blank lines are skipped (bounded)."""
    i, floor = line_start, max(0, line_start - _WINDOW)
    while i > floor and text[i - 1].isspace():
        i -= 1
    return i


def _stacked_separator_ends(region: str) -> set[int]:
    """The end offset of every separator line that sits on top of another one (at most
    _MAX_STACK_GAP blank lines apart), so the last line of a stack of any height counts."""
    ends: set[int] = set()
    offset = 0
    blanks = _MAX_STACK_GAP + 1  # blank lines since the last separator line
    for line in region.split("\n"):
        body = line.lstrip(" \t")
        if _SEPARATOR.fullmatch(body):
            if blanks <= _MAX_STACK_GAP:
                ends.add(offset + len(line))
            blanks = 0
        elif body:
            blanks = _MAX_STACK_GAP + 1
        else:
            blanks += 1
        offset += len(line) + 1
    return ends


def _scan(text: str, role: str) -> tuple[Counter[str], bool]:
    """Signal counts, and whether a forcing literal was planted on a turn or separator."""
    text = _normalise(text)
    low = _lower(text)
    start = 0 if role in DATA_ROLES else _region_start(low)
    if start < 0:
        return Counter(), False
    region, region_low = text[start:], low[start:]
    counts = _strong_counts(region_low)
    lines = "\n" + region_low  # offsets in ``lines`` are region offsets + 1
    role_lines = {m.start() for m in _ROLE_LINE.finditer(lines)}  # each one a line's "\n"
    stacked_ends = _stacked_separator_ends(region)
    if role_lines:
        counts["fake_role_turn"] = len(role_lines)
    if stacked_ends:
        counts["separator_payload"] = len(stacked_ends)
    planted = False
    newlines: list[int] | None = None
    for pos, _ in _forcing(region, region_low):
        counts["output_forcing_literal"] += 1
        if newlines is None:  # once per text, so finding a line start stays linear
            newlines = [m.start() for m in _NEWLINE.finditer(region)]
        k = bisect.bisect_left(newlines, pos)
        line_start = newlines[k - 1] + 1 if k else 0
        if line_start in role_lines or _end_of_previous_line(region, line_start) in stacked_ends:
            planted = True
    return counts, planted


def embedded_signals(text: str, role: str = "") -> tuple[str, ...]:
    """Every signal category ``text`` carries, strong and weak, sorted."""
    return tuple(sorted(_scan(text, role)[0]))


@dataclass
class EmbeddedInstructionGuard:
    name: str = "embedded_instruction"
    directions: frozenset[Direction] = field(default_factory=lambda: frozenset({Direction.INPUT}))
    # Policy: block a forcing literal planted on a fake role turn or after stacked separators.
    # Strong signals are always blocked.
    block_weak_combinations: bool = True

    def check(self, text: str, ctx: GuardContext) -> GuardResult:
        if ctx.role not in SCANNED_ROLES:
            return GuardResult.allow(text)
        counts, planted = _scan(text, ctx.role)
        if not counts:
            return GuardResult.allow(text)
        findings = tuple(Finding(self.name, c, n) for c, n in sorted(counts.items()))
        strong = any(c in STRONG_SIGNALS for c in counts)
        verdict = Verdict.BLOCK if strong or (planted and self.block_weak_combinations) else None
        return GuardResult(verdict or Verdict.ALLOW, text, findings)


def _is_word(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def _echoes(completion: str, literals: Iterable[str]) -> int:
    """How many literals the completion contains as whole words, case-insensitively."""
    low = _lower(_normalise(completion))
    # prefix -> whether its end must be a word boundary (not when the literal was cut short)
    wanted: dict[str, bool] = {}
    for lit in literals:
        lit_low = _lower(_normalise(lit))
        prefix = lit_low[:_ECHO_PREFIX]
        wanted[prefix] = wanted.get(prefix, True) and len(lit_low) <= _ECHO_PREFIX

    def bounded(i: int, prefix: str) -> bool:
        if _is_word(prefix[0]) and i > 0 and _is_word(low[i - 1]):
            return False
        j = i + len(prefix)
        return not (wanted[prefix] and _is_word(prefix[-1]) and j < len(low) and _is_word(low[j]))

    found: set[str] = set()
    if len(wanted) <= _FEW_LITERALS:
        for prefix in wanted:
            i = low.find(prefix)
            while i != -1 and not bounded(i, prefix):
                i = low.find(prefix, i + 1)
            if i != -1:
                found.add(prefix)
        return len(found)
    # Many literals: one pass per distinct length (at most _ECHO_PREFIX of them), so the
    # work stays linear in the completion however many literals the prompt plants.
    by_length: defaultdict[int, set[str]] = defaultdict(set)
    for prefix in wanted:
        by_length[len(prefix)].add(prefix)
    for length, group in by_length.items():
        for i in range(len(low) - length + 1):
            if (sub := low[i : i + length]) in group and sub not in found and bounded(i, sub):
                found.add(sub)
    return len(found)


@dataclass
class InstructionEchoGuard:
    name: str = "instruction_echo"
    directions: frozenset[Direction] = field(default_factory=lambda: frozenset({Direction.OUTPUT}))
    enabled: bool = True
    # Policy: a forced literal counts only when its own message carries another signal
    # (a strong one, a fake role turn or stacked separators). URLs and domains inside a
    # forced literal always count. False checks every forced literal, which also blocks an
    # answer that obeys the user's own 'reply with only "positive"' after a separator.
    corroborated_only: bool = True

    def check(self, text: str, ctx: GuardContext) -> GuardResult:
        if not self.enabled:
            return GuardResult.allow(text)
        forced = ctx.prompt_literals
        if forced is None:
            forced = request_literals([("tool", ctx.prompt_text)]) if ctx.prompt_text else ()
        literals = [
            f.text for f in forced if f.link or f.corroborated or not self.corroborated_only
        ]
        hits = _echoes(text, literals) if literals else 0
        if hits:
            finding = Finding(self.name, "echoed_embedded_literal", hits)
            return GuardResult(Verdict.BLOCK, text, (finding,))
        return GuardResult.allow(text)
