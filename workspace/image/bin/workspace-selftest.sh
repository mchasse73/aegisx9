#!/usr/bin/env bash
# AegisX9 workspace self-test. Run as `dev` inside the container (CI does, and the
# HEALTHCHECK runs it with --quick). Exit 0 when the locked baseline is intact.
set -euo pipefail

quick=0
[ "${1:-}" = "--quick" ] && quick=1
failures=0
check() {
  if "$@" >/dev/null 2>&1; then return 0; fi
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}
owned_by_root_0644() { [ "$(stat -c '%u:%g %a' "$1")" = "0:0 644" ]; }
owned_by_root_0755() { [ "$(stat -c '%u:%g %a' "$1")" = "0:0 755" ]; }
no_sudo() { ! command -v sudo && [ ! -e /etc/sudoers ] && ! id -nG | grep -qw sudo; }
unset_env() { [ -z "${ANTHROPIC_API_KEY:-}" ] && [ -z "${ANTHROPIC_AUTH_TOKEN:-}" ]; }
settings_sane() {
  python3 - <<'PY'
import json, sys
s = json.load(open("/etc/claude-code/managed-settings.json"))
ok = (
    s["apiKeyHelper"] == "/opt/aegisx9/bin/gateway-token"
    and s["permissions"]["disableBypassPermissionsMode"] == "disable"
    and s["sandbox"]["enabled"] is True
    and not any(k in s.get("env", {}) for k in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"))
)
sys.exit(0 if ok else 1)
PY
}

check owned_by_root_0644 /etc/claude-code/managed-settings.json
check owned_by_root_0644 /etc/claude-code/managed-mcp.json
check owned_by_root_0644 /etc/aegisx9/workspace.env
check test ! -w /etc/claude-code/managed-settings.json
check settings_sane
check unset_env
check test "$(id -u)" = 1000
check no_sudo
for f in /opt/aegisx9/hooks/*.sh /opt/aegisx9/bin/*; do
  check owned_by_root_0755 "$f"
done
if [ "$quick" -eq 0 ]; then
  check claude --version
  # No package manager in the workspace (#99): npm, npx and corepack are build-time only.
  check test ! -e /opt/node/bin/npm
  check test ! -e /opt/node/bin/npx
  check test ! -e /opt/node/lib/node_modules/npm
  check vault version
  check python3 --version
  check rsync --version
  check pgrep --version
  check test -x /usr/sbin/sshd
fi
[ "$failures" -eq 0 ] || { echo "workspace-selftest: $failures failure(s)" >&2; exit 1; }
echo "workspace-selftest: ok"
