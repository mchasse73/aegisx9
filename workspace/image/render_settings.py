#!/usr/bin/env python3
"""Render the managed Claude Code settings from the baseline template.

Managed settings are static JSON, and the workspace container runs as the unprivileged
``dev`` user, so nothing can rewrite ``/etc/claude-code`` once the container starts.
The site-specific values (gateway URL, OTLP endpoint, Vault address, model list) are
therefore rendered **at image build time**: the signed image digest attests the whole
baseline, configuration included. Changing a value means building and signing a new
image, which is intended.

Usage::

    render_settings.py --template managed-settings.json --env workspace.env \
        --output /etc/claude-code/managed-settings.json

Every ``KEY=VALUE`` in the env file may be overridden by a process environment variable
of the same name (Docker build args). Placeholders in the template:

* ``"${NAME}"`` inside a string is substituted with the value of ``NAME``;
* a string that is exactly ``"${NAME_LIST}"`` becomes a JSON list built by splitting the
  value of ``NAME`` on commas (empty value: empty list).

Only the standard library is used so the script runs unchanged in the build stage.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_PLACEHOLDER = re.compile(r"\$\{([A-Z0-9_]+)\}")
_LIST_ONLY = re.compile(r"^\$\{([A-Z0-9_]+)_LIST\}$")
URL_KEYS = ("AEGISX9_GATEWAY_URL", "AEGISX9_OTLP_ENDPOINT", "AEGISX9_VAULT_ADDR")
FORBIDDEN_ENV_NAMES = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")


class RenderError(ValueError):
    """The template or the values are not usable."""


def load_env_file(path: Path) -> dict[str, str]:
    """Parse a ``KEY=VALUE`` file; blank lines and ``#`` comments are ignored."""
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise RenderError(f"bad line in {path.name}")
        values[key] = value.strip()
    return values


def resolve_values(defaults: dict[str, str], environ: dict[str, str]) -> dict[str, str]:
    """Apply environment overrides and validate the result."""
    # An empty override (a declared but unset Docker build arg) keeps the default.
    values = {k: environ.get(k) or v for k, v in defaults.items()}
    for key in URL_KEYS:
        url = values.get(key, "")
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname or "<" in url or ">" in url:
            raise RenderError(f"{key} must be an https URL without placeholders")
    values["AEGISX9_IMAGE_VERSION"] = environ.get("AEGISX9_IMAGE_VERSION", "0.0.0")
    return values


def sandbox_domains(values: dict[str, str]) -> list[str]:
    """The explicit sandbox allowlist plus the hosts of the three service URLs."""
    domains = [d.strip() for d in values.get("AEGISX9_SANDBOX_DOMAINS", "").split(",")]
    for key in URL_KEYS:
        host = urlsplit(values[key]).hostname
        if host:
            domains.append(host)
    unique: dict[str, None] = {d: None for d in domains if d}
    return list(unique)


def _substitute(node: Any, values: dict[str, str]) -> Any:
    if isinstance(node, dict):
        return {k: _substitute(v, values) for k, v in node.items()}
    if isinstance(node, list):
        return [_substitute(v, values) for v in node]
    if isinstance(node, str):
        m = _LIST_ONLY.match(node)
        if m:
            name = m.group(1)
            if name == "AEGISX9_SANDBOX_DOMAINS":
                return sandbox_domains(values)
            raw = values.get(name)
            if raw is None:
                raise RenderError(f"missing value for {name}")
            return [item.strip() for item in raw.split(",") if item.strip()]

        def repl(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in values:
                raise RenderError(f"missing value for {name}")
            return values[name]

        return _PLACEHOLDER.sub(repl, node)
    return node


def render(template: dict[str, Any], values: dict[str, str]) -> dict[str, Any]:
    """Render the template and refuse an output that still carries a credential slot."""
    rendered: dict[str, Any] = _substitute(template, values)
    env_block = rendered.get("env", {})
    for name in FORBIDDEN_ENV_NAMES:
        if name in env_block:
            raise RenderError(f"{name} must never be set by managed settings")
    if not rendered.get("apiKeyHelper"):
        raise RenderError("apiKeyHelper must be set")
    return rendered


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render the managed Claude Code settings.")
    parser.add_argument("--template", required=True, type=Path)
    parser.add_argument("--env", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--env-output",
        type=Path,
        default=None,
        help="also write the resolved KEY=VALUE pairs (for /etc/aegisx9/workspace.env)",
    )
    args = parser.parse_args(argv)
    try:
        template = json.loads(args.template.read_text(encoding="utf-8"))
        values = resolve_values(load_env_file(args.env), dict(os.environ))
        rendered = render(template, values)
        args.output.write_text(json.dumps(rendered, indent=2) + "\n", encoding="utf-8")
        if args.env_output is not None:
            lines = [f"{k}={v}" for k, v in sorted(values.items())]
            args.env_output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except (OSError, ValueError) as e:
        print(f"render_settings: {type(e).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
