"""Definitions shared by build_sets and score: the sets, the families and small helpers."""

from __future__ import annotations

import hashlib
import importlib.metadata
from collections.abc import Iterable
from dataclasses import dataclass

TARGET, HOLDOUT, FP = "target", "holdout", "fp"
SET_ORDER = (TARGET, HOLDOUT, FP)
SEED = 7731
GARAK_VERSION = "0.17.1"


@dataclass(frozen=True)
class AttackFamily:
    """One attack family: where its prompts come from and how many ADR 0024 measured."""

    name: str
    set: str
    expected: int
    probes: tuple[str, ...] = ()  # garak plugin names under probes.
    builder: str = ""  # a named builder for families that aren't one probe class


ATTACK_FAMILIES: tuple[AttackFamily, ...] = (
    # Target: the gate's two probes, which the heuristics were tuned on.
    AttackFamily(
        "promptinject_hijack",
        TARGET,
        525,
        probes=(
            "promptinject.HijackHateHumansFull",
            "promptinject.HijackKillHumansFull",
            "promptinject.HijackLongPromptFull",
        ),
    ),
    AttackFamily(
        "LatentInjectionReportFull",
        TARGET,
        648,
        probes=("latentinjection.LatentInjectionReportFull",),
    ),
    # Hold-out: never tuned against; 7,168 prompts in all.
    AttackFamily(
        "FactSnippetEiffel",
        HOLDOUT,
        2400,
        probes=("latentinjection.LatentInjectionFactSnippetEiffelFull",),
    ),
    AttackFamily(
        "FactSnippetLegal",
        HOLDOUT,
        1080,
        probes=("latentinjection.LatentInjectionFactSnippetLegalFull",),
    ),
    AttackFamily(
        "TranslationEnFr",
        HOLDOUT,
        270,
        probes=("latentinjection.LatentInjectionTranslationEnFrFull",),
    ),
    AttackFamily(
        "TranslationEnZh",
        HOLDOUT,
        270,
        probes=("latentinjection.LatentInjectionTranslationEnZhFull",),
    ),
    AttackFamily("Whois", HOLDOUT, 168, probes=("latentinjection.LatentWhois",)),
    AttackFamily("WhoisSnippet", HOLDOUT, 400, probes=("latentinjection.LatentWhoisSnippetFull",)),
    AttackFamily("Resume", HOLDOUT, 2400, probes=("latentinjection.LatentInjectionResumeFull",)),
    AttackFamily("promptinject_prompt_leaking", HOLDOUT, 175, builder="prompt_leaking"),
    AttackFamily("promptfoo_injection", HOLDOUT, 5, builder="promptfoo_injection"),
)

FP_CORPORA: tuple[str, ...] = (
    "dictionary_words",
    "random_sentences",
    "order_numbers",
    "developer_data",
    "chat_transcripts",
    "markdown_front_matter",
    "code_printing_literals",
    "prompt_engineering_requests",
    "emails_asking_reply",
    "promptfoo_benign",
)


def package_version(dist: str) -> str | None:
    try:
        return importlib.metadata.version(dist)
    except importlib.metadata.PackageNotFoundError:
        return None


def texts_sha256(texts: Iterable[str]) -> str:
    h = hashlib.sha256()
    for t in texts:
        h.update(t.encode("utf-8"))
        h.update(b"\0")
    return h.hexdigest()
