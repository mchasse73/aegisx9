"""Adapter that plugs the guard pipeline into the LiteLLM proxy.

Referenced from the LiteLLM config as ``aegisx9.litellm_hooks.aegis_guard``. It depends
only on the shape of LiteLLM's request/response dicts, so it is importable and testable
without LiteLLM installed.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Callable
from typing import Any

from aegisx9.audit import AuditEvent, pseudonymise
from aegisx9.guards.base import Direction, GuardContext
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
    """Raised to make the proxy reject a request. The message never echoes content."""

    def __init__(self, guard: str, direction: Direction) -> None:
        super().__init__(f"request blocked by {guard} ({direction.value} guard)")
        self.guard = guard
        self.direction = direction


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
            if not isinstance(content, str):
                continue
            result = self.pipeline.run(content, ctx)
            if result.blocked:
                raise GuardBlockedError(result.blocked_by or "unknown", Direction.INPUT)
            message["content"] = result.text
        return data

    def post_call(self, data: dict[str, Any], completion: str, subject: str = "") -> str:
        ctx = self._ctx(data, Direction.OUTPUT, subject)
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
        for choice in getattr(response, "choices", []) or []:
            message = getattr(choice, "message", None)
            content = getattr(message, "content", None)
            if message is not None and isinstance(content, str):
                message.content = self.post_call(data, content, subject)
        return response


aegis_guard = AegisGuard()
