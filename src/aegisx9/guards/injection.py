"""Heuristic prompt-injection / jailbreak detection.

This is a fast first line of defence. Phase 1 adds a model-based classifier behind the
same :class:`~aegisx9.guards.base.Guard` interface; the heuristics stay as a cheap
pre-filter and as a fallback when the classifier is unavailable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from aegisx9.guards.base import Direction, Finding, GuardContext, GuardResult, Verdict

_PATTERNS: dict[str, re.Pattern[str]] = {
    "instruction_override": re.compile(
        r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|earlier|all)\b"
        r".{0,40}\b(instructions?|rules|prompts?|directions)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "system_prompt_exfiltration": re.compile(
        r"\b(reveal|print|show|repeat|output|leak)\b.{0,40}"
        r"\b(system|hidden|initial|developer)\s+(prompt|instructions|message)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "role_hijack": re.compile(
        r"\b(you are now|act as|pretend to be|from now on you are)\b.{0,60}"
        r"\b(DAN|unrestricted|jailbroken|developer mode|no (rules|restrictions|filters))\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "delimiter_injection": re.compile(
        r"(<\|im_start\|>|<\|system\|>|\[/?INST\]|###\s*system\s*:)", re.IGNORECASE
    ),
}


@dataclass
class PromptInjectionGuard:
    name: str = "prompt_injection"
    directions: frozenset[Direction] = field(default_factory=lambda: frozenset({Direction.INPUT}))

    def check(self, text: str, ctx: GuardContext) -> GuardResult:
        findings = tuple(
            Finding(self.name, category)
            for category, pattern in _PATTERNS.items()
            if pattern.search(text)
        )
        if findings:
            return GuardResult(Verdict.BLOCK, text, findings)
        return GuardResult.allow(text)
