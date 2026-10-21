#!/usr/bin/env bash
# AegisX9 workspace hook: PreToolUse (matcher: Bash).
# Blocks shell commands that read known credential stores, dump the environment, or use
# an interpreter one-liner to do either. Other tools are allowed through untouched.
#
# Input : the Claude Code hook JSON on stdin ({"tool_name": "Bash", "tool_input": {...}}).
# Output: exit 0 to allow; exit 2 with a one-line reason on stderr to block.
# The command text is never echoed. Any internal error blocks the call (fail closed).
set -euo pipefail
umask 077

block() {
  printf 'pretooluse-guard: %s\n' "$1" >&2
  exit 2
}
trap 'block "internal error; tool call blocked (fail closed)"' ERR

here=$(cd "$(dirname "$0")" && pwd)
patterns="${AEGISX9_BASH_DENY_PATTERNS:-$here/bash-deny-patterns.txt}"
[ -r "$patterns" ] || block "pattern file unavailable; tool call blocked (fail closed)"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cmd_file="$tmp/command.txt"

# Writes the command to a 0600 file and prints only the tool name. The hook JSON stays
# on stdin; the extractor itself is passed as code, not through stdin.
extract=$(cat <<'PY'
import json
import sys

data = json.load(sys.stdin)
tool = str(data.get("tool_name", ""))
command = data.get("tool_input", {}).get("command", "") if tool == "Bash" else ""
if not isinstance(command, str):
    command = json.dumps(command)
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    fh.write(command)
print(tool)
PY
)
tool=$(python3 -c "$extract" "$cmd_file")

[ "$tool" = "Bash" ] || exit 0

if grep -E -q -f "$patterns" "$cmd_file"; then
  block "command touches a credential store, dumps the environment or escalates privileges; it is not allowed in this workspace"
fi
exit 0
