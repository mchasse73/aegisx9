"""Adapter that plugs the guard pipeline into the LiteLLM proxy.

Referenced from the LiteLLM config as ``aegisx9.litellm_hooks.aegis_guard``. It depends
only on the shape of LiteLLM's request/response dicts, so it is importable and testable
without LiteLLM installed.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import uuid
from collections.abc import Callable
from typing import Any

from aegisx9.audit import AuditEvent, pseudonymise
from aegisx9.guards.base import Direction, GuardContext
from aegisx9.guards.embedded import ForcedLiteral, request_literals
from aegisx9.pipeline import GuardPipeline, default_pipeline
from aegisx9.policy import ModelPolicy, PolicyViolationError
from aegisx9.signing import AuditSigner, sign_event

# LiteLLM only loads a callback that is a CustomLogger instance or a callable. Subclass it
# when LiteLLM is installed (the gateway image); fall back to object so the package stays
# importable and testable without LiteLLM.
try:
    from litellm.integrations.custom_logger import (  # type: ignore[import-not-found,unused-ignore]
        CustomLogger as _HookBase,
    )
except ImportError:  # pragma: no cover - exercised in the image smoke test
    _HookBase = object  # type: ignore[assignment,misc,unused-ignore]

audit_logger = logging.getLogger("aegisx9.audit")


class GuardBlockedError(Exception):
    """Raised to make the proxy reject a request. The message never echoes content.

    A block is the caller's request being refused, not a server fault: LiteLLM's proxy
    answers with the exception's ``status_code`` and ``type`` (OpenAI error shape), so it is
    a 400 ``invalid_request_error``. As a plain exception it was a 500, which clients and
    SDKs retry with backoff (#171). The message keeps its ``request blocked by`` prefix;
    the red-team suites and clients key off it.
    """

    status_code = 400
    type = "invalid_request_error"

    def __init__(self, guard: str, direction: Direction) -> None:
        self.message = f"request blocked by {guard} ({direction.value} guard)"
        super().__init__(self.message)
        self.guard = guard
        self.direction = direction


# Messages whose content the request's caller supplied as input or data.
_PROMPT_ROLES = frozenset({"user", "tool", "function"})


def _text_parts(content: Any) -> list[dict[str, Any]]:
    """The text parts of an OpenAI content-parts list; images and other parts are skipped."""
    if not isinstance(content, list):
        return []
    return [
        part
        for part in content
        if isinstance(part, dict)
        and part.get("type") == "text"
        and isinstance(part.get("text"), str)
    ]


def message_text(content: Any) -> str | None:
    """A message's text: a string, or its text parts joined by newlines; None if it has none."""
    if isinstance(content, str):
        return content
    parts = _text_parts(content)
    return "\n".join(part["text"] for part in parts) if parts else None


def current_turn(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The messages after the last assistant message: this turn's input."""
    for i in range(len(messages) - 1, -1, -1):
        if messages[i].get("role") == "assistant":
            return messages[i + 1 :]
    return messages


def prompt_literals(data: dict[str, Any]) -> tuple[ForcedLiteral, ...]:
    """The literals this turn's user and tool messages tried to force, for the echo guard.

    Computed once per request. pre_call has already redacted every message. The result goes
    only into :attr:`GuardContext.prompt_literals`; it is never logged or audited.
    """
    pairs = []
    for message in current_turn(list(data.get("messages", []) or [])):
        role = str(message.get("role", ""))
        text = message_text(message.get("content"))
        if role in _PROMPT_ROLES and text:
            pairs.append((role, text))
    return request_literals(pairs)


def _log_audit(event: AuditEvent) -> None:
    audit_logger.info(event.to_json(), extra={"otel_attributes": event.to_otel_attributes()})


def signed_audit_sink(signer: AuditSigner) -> Callable[[AuditEvent], None]:
    """Audit sink that writes transit-signed envelopes (production default)."""

    def _sink(event: AuditEvent) -> None:
        envelope = sign_event(event, signer)
        audit_logger.info(
            json.dumps(envelope, sort_keys=True, separators=(",", ":")),
            extra={"otel_attributes": event.to_otel_attributes()},
        )

    return _sink


class AegisGuard(_HookBase):  # type: ignore[misc,valid-type,unused-ignore]
    def __init__(
        self,
        pipeline: GuardPipeline | None = None,
        policy: ModelPolicy | None = None,
        principal_salt: str = "",
    ) -> None:
        super().__init__()
        self.pipeline = pipeline or default_pipeline(audit_sink=_log_audit)
        self.policy = policy
        self._salt = principal_salt

    def _ctx(self, data: dict[str, Any], direction: Direction, subject: str) -> GuardContext:
        metadata = data.setdefault("metadata", {})
        request_id = metadata.setdefault("aegis_request_id", uuid.uuid4().hex)
        return GuardContext(
            request_id=str(request_id),
            direction=direction,
            model=str(data.get("model", "")),
            principal=pseudonymise(subject, self._salt) if subject else "",
        )

    def pre_call(self, data: dict[str, Any], subject: str = "") -> dict[str, Any]:
        if self.policy is not None:
            self.policy.check_model(str(data.get("model", "")))
            data["max_tokens"] = self.policy.check_max_tokens(data.get("max_tokens"))
        ctx = self._ctx(data, Direction.INPUT, subject)
        for message in data.get("messages", []):
            content = message.get("content")
            msg_ctx = dataclasses.replace(ctx, role=str(message.get("role", "")))
            if isinstance(content, str):
                message["content"] = self._run_input(content, msg_ctx)
                continue
            # Content-parts list: every guard sees each text part (and redacts it in place),
            # and with several parts also the joined text, so a marker in one part and an
            # attack in the next are read together.
            parts = _text_parts(content)
            for part in parts:
                part["text"] = self._run_input(part["text"], msg_ctx)
            if len(parts) > 1:
                self._run_input("\n".join(part["text"] for part in parts), msg_ctx)
        return data

    def _run_input(self, text: str, ctx: GuardContext) -> str:
        result = self.pipeline.run(text, ctx)
        if result.blocked:
            raise GuardBlockedError(result.blocked_by or "unknown", Direction.INPUT)
        return result.text

    def post_call(
        self,
        data: dict[str, Any],
        completion: str,
        subject: str = "",
        literals: tuple[ForcedLiteral, ...] | None = None,
    ) -> str:
        """Guard one completion. ``literals`` is the request's :func:`prompt_literals`,
        computed once per request when several choices are checked."""
        if literals is None:
            literals = prompt_literals(data)
        ctx = dataclasses.replace(
            self._ctx(data, Direction.OUTPUT, subject), prompt_literals=literals
        )
        result = self.pipeline.run(completion, ctx)
        if result.blocked:
            raise GuardBlockedError(result.blocked_by or "unknown", Direction.OUTPUT)
        return result.text

    # LiteLLM proxy hook signatures -------------------------------------------------
    async def async_pre_call_hook(
        self, user_api_key_dict: Any, cache: Any, data: dict[str, Any], call_type: str
    ) -> dict[str, Any]:
        subject = str(getattr(user_api_key_dict, "user_id", "") or "")
        try:
            return self.pre_call(data, subject)
        except PolicyViolationError as exc:
            raise GuardBlockedError(f"policy:{exc.code}", Direction.INPUT) from exc

    async def async_post_call_success_hook(
        self, data: dict[str, Any], user_api_key_dict: Any, response: Any
    ) -> Any:
        subject = str(getattr(user_api_key_dict, "user_id", "") or "")
        literals: tuple[ForcedLiteral, ...] | None = None
        for choice in getattr(response, "choices", []) or []:
            message = getattr(choice, "message", None)
            content = getattr(message, "content", None)
            if message is not None and isinstance(content, str):
                if literals is None:
                    literals = prompt_literals(data)  # once per request, for every choice
                message.content = self.post_call(data, content, subject, literals)
        return response


aegis_guard = AegisGuard()
