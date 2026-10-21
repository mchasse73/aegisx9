"""The locked Claude Code baseline: every control present, no credential slot anywhere."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from ws_helpers import EXAMPLE_VALUES, IMAGE_DIR, load_script

render_settings = load_script("render_settings.py")


@pytest.fixture(scope="module")
def settings() -> dict[str, Any]:
    template = json.loads((IMAGE_DIR / "managed-settings.json").read_text())
    defaults = render_settings.load_env_file(IMAGE_DIR / "workspace.env")
    values = render_settings.resolve_values(
        defaults, {**EXAMPLE_VALUES, "AEGISX9_IMAGE_VERSION": "1.2.3"}
    )
    result: dict[str, Any] = render_settings.render(template, values)
    return result


def _walk(node: Any) -> Iterator[Any]:
    if isinstance(node, dict):
        for k, v in node.items():
            yield k
            yield from _walk(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk(v)
    else:
        yield node


def test_permissions_baseline(settings: dict[str, Any]) -> None:
    perms = settings["permissions"]
    assert perms["defaultMode"] == "default"
    assert perms["disableBypassPermissionsMode"] == "disable"
    assert perms["disableAutoMode"] == "disable"
    assert perms["blockReadsOutsideWorkingDirectories"] is True
    for rule in (
        "Read(./.env)",
        "Read(./.env.*)",
        "Read(./secrets/**)",
        "Read(*.pem)",
        "Read(*.key)",
        "Read(//home/dev/.aws/**)",
        "WebFetch",
        "WebSearch",
        "Bash(curl *)",
    ):
        assert rule in perms["deny"]
    assert settings["allowManagedPermissionRulesOnly"] is True
    assert settings["allowManagedHooksOnly"] is True
    assert settings["allowManagedMcpServersOnly"] is True


def test_gateway_only_routing(settings: dict[str, Any]) -> None:
    assert settings["allowedProviders"] == ["customEndpoint"]
    assert settings["forceLoginMethod"] == "gateway"
    assert settings["apiKeyHelper"] == "/opt/aegisx9/bin/gateway-token"
    assert settings["availableModels"] == ["claude-sonnet-4-5", "claude-haiku-4-5"]
    assert settings["deniedModels"] == []
    assert settings["enforceAvailableModels"] is True
    env = settings["env"]
    assert env["ANTHROPIC_BASE_URL"] == EXAMPLE_VALUES["AEGISX9_GATEWAY_URL"]
    assert env["VAULT_ADDR"] == EXAMPLE_VALUES["AEGISX9_VAULT_ADDR"]
    assert env["CLAUDE_CODE_API_KEY_HELPER_TTL_MS"] == "3300000"


def test_no_static_credential_anywhere(settings: dict[str, Any]) -> None:
    dump = json.dumps(settings)
    for name in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        assert name not in dump
    for leaf in _walk(settings):
        assert not isinstance(leaf, str) or "${" not in leaf, "unrendered placeholder"


def test_sandbox(settings: dict[str, Any]) -> None:
    sandbox = settings["sandbox"]
    assert sandbox["enabled"] is True
    assert sandbox["allowUnsandboxedCommands"] is False
    assert sandbox["failIfUnavailable"] is True
    domains = sandbox["network"]["allowedDomains"]
    assert domains == [
        "github.com",
        "gateway.example.test",
        "otlp.example.test",
        "vault.example.test",
    ]
    assert "~/.aws" in sandbox["filesystem"]["denyRead"]
    assert "~/.claude/.credentials.json" in sandbox["filesystem"]["denyRead"]


def test_hooks_fail_closed(settings: dict[str, Any]) -> None:
    hooks = settings["hooks"]
    assert set(hooks) == {"UserPromptSubmit", "PreToolUse", "SessionEnd"}
    commands = []
    for groups in hooks.values():
        for group in groups:
            for hook in group["hooks"]:
                assert hook["type"] == "command"
                assert hook["onFailure"] == "block"
                assert hook["timeout"] > 0
                commands.append(hook["command"])
    assert commands == [
        "/opt/aegisx9/hooks/prompt-credential-check.sh",
        "/opt/aegisx9/hooks/pretooluse-guard.sh",
        "/opt/aegisx9/hooks/session-end-handoff.sh",
    ]
    assert hooks["PreToolUse"][0]["matcher"] == "Bash"
    for cmd in commands:
        assert (IMAGE_DIR / "hooks" / Path(cmd).name).exists()


def test_telemetry_without_prompts(settings: dict[str, Any]) -> None:
    env = settings["env"]
    assert env["CLAUDE_CODE_ENABLE_TELEMETRY"] == "1"
    assert env["OTEL_METRICS_EXPORTER"] == "otlp"
    assert env["OTEL_LOGS_EXPORTER"] == "otlp"
    assert env["OTEL_EXPORTER_OTLP_ENDPOINT"] == EXAMPLE_VALUES["AEGISX9_OTLP_ENDPOINT"]
    assert env["OTEL_EXPORTER_OTLP_PROTOCOL"] == "http/protobuf"
    assert "aegisx9.workspace_image=1.2.3" in env["OTEL_RESOURCE_ATTRIBUTES"]
    assert "OTEL_LOG_USER_PROMPTS" not in env
    assert env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] == "1"
    assert env["DISABLE_FEEDBACK_COMMAND"] == "1"


def test_misc_controls(settings: dict[str, Any]) -> None:
    assert settings["cleanupPeriodDays"] == 7
    assert settings["disableClaudeAiConnectors"] is True
    assert settings["remoteControlAtStartup"] is False
    assert settings["autoUpdatesChannel"] == "stable"
    assert settings["skipWebFetchPreflight"] is True
    rules = settings["claudeMd"]
    for phrase in (
        "Never print a secret",
        "never on a command line",
        "type(e).__name__",
        "handoff",
    ):
        assert phrase in rules


def test_managed_mcp_is_exclusive_and_empty() -> None:
    mcp = json.loads((IMAGE_DIR / "managed-mcp.json").read_text())
    assert mcp == {"mcpServers": {}}


def test_render_refuses_placeholders_and_credential_slots() -> None:
    template = json.loads((IMAGE_DIR / "managed-settings.json").read_text())
    defaults = render_settings.load_env_file(IMAGE_DIR / "workspace.env")
    with pytest.raises(render_settings.RenderError):
        render_settings.resolve_values(defaults, {})
    values = render_settings.resolve_values(defaults, EXAMPLE_VALUES)
    poisoned = json.loads(json.dumps(template))
    poisoned["env"]["ANTHROPIC_" + "API_KEY"] = "x"
    with pytest.raises(render_settings.RenderError):
        render_settings.render(poisoned, values)
    poisoned = json.loads(json.dumps(template))
    poisoned["apiKeyHelper"] = ""
    with pytest.raises(render_settings.RenderError):
        render_settings.render(poisoned, values)
    with pytest.raises(render_settings.RenderError):
        render_settings.render({"x": "${AEGISX9_NOPE}"}, values)
    with pytest.raises(render_settings.RenderError):
        render_settings.render({"x": "${AEGISX9_NOPE_LIST}"}, values)
    assert (
        render_settings.resolve_values(defaults, {**EXAMPLE_VALUES, "AEGISX9_MODELS": ""})[
            "AEGISX9_MODELS"
        ]
        == defaults["AEGISX9_MODELS"]
    )


def test_env_file_parser_rejects_garbage(tmp_path: Path) -> None:
    bad = tmp_path / "bad.env"
    bad.write_text("lower=1\n")
    with pytest.raises(render_settings.RenderError):
        render_settings.load_env_file(bad)
    good = tmp_path / "good.env"
    good.write_text("# comment\n\nA_B=1\n")
    assert render_settings.load_env_file(good) == {"A_B": "1"}


def test_render_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = tmp_path / "settings.json"
    env_out = tmp_path / "workspace.env"
    argv = [
        "--template",
        str(IMAGE_DIR / "managed-settings.json"),
        "--env",
        str(IMAGE_DIR / "workspace.env"),
        "--output",
        str(out),
        "--env-output",
        str(env_out),
    ]
    assert render_settings.main(argv) == 1  # placeholders left in place
    for k, v in EXAMPLE_VALUES.items():
        monkeypatch.setenv(k, v)
    assert render_settings.main(argv) == 0
    rendered = json.loads(out.read_text())
    assert rendered["env"]["ANTHROPIC_BASE_URL"] == EXAMPLE_VALUES["AEGISX9_GATEWAY_URL"]
    assert "AEGISX9_GATEWAY_URL=" + EXAMPLE_VALUES["AEGISX9_GATEWAY_URL"] in env_out.read_text()


def test_dockerfile_hardening() -> None:
    text = (IMAGE_DIR / "Dockerfile").read_text()
    froms = re.findall(r"^FROM (\S+)", text, flags=re.M)
    assert froms and all(re.search(r"@sha256:[0-9a-f]{64}$", f) for f in froms)
    assert re.search(r"^USER dev$", text, flags=re.M)
    assert re.search(r"^HEALTHCHECK ", text, flags=re.M)
    assert not re.search(r"^EXPOSE", text, flags=re.M)
    assert not re.search(r"\bsudo\b", re.sub(r"#.*", "", text))
    assert "ANTHROPIC_API_KEY=" not in text and "ANTHROPIC_AUTH_TOKEN=" not in text
    for label in ("title", "description", "source", "licenses", "version"):
        assert f"org.opencontainers.image.{label}=" in text
    for path in ("/etc/claude-code/managed-settings.json", "/etc/claude-code/managed-mcp.json"):
        assert path in text
