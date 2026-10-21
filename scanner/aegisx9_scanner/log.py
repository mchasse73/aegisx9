"""Structured JSON logging for the scanner.

Rule: an error is logged by its exception *type* only. ``str(e)`` can carry URLs with
query-string tokens, file contents or response bodies, so it never reaches a log line.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

LOGGER_NAME = "aegisx9_scanner"


class JsonFormatter(logging.Formatter):
    """One JSON object per line; extra fields come from ``record.fields``."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(timespec="seconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update(fields)
        return json.dumps(payload, sort_keys=True, default=str)


def get_logger() -> logging.Logger:
    return logging.getLogger(LOGGER_NAME)


def configure(level: int = logging.INFO, stream: Any = None) -> logging.Logger:
    """Install the JSON handler once; later calls only adjust the level."""
    logger = get_logger()
    if not any(isinstance(h.formatter, JsonFormatter) for h in logger.handlers):
        handler = logging.StreamHandler(stream or sys.stderr)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger


def event(msg: str, level: int = logging.INFO, **fields: Any) -> None:
    get_logger().log(level, msg, extra={"fields": fields})


def error_name(exc: BaseException) -> str:
    """The only representation of an exception that may be logged or reported."""
    return type(exc).__name__


def log_error(msg: str, exc: BaseException, **fields: Any) -> None:
    event(msg, level=logging.ERROR, error=error_name(exc), **fields)
