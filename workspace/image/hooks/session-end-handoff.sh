#!/usr/bin/env bash
# AegisX9 workspace hook: SessionEnd.
# Makes sure a handoff note exists for today. If the session did not write one, a stub
# with the session id and a reminder is created through the `handoff` CLI, so the note
# format has a single source of truth.
#
# Input : the Claude Code hook JSON on stdin ({"session_id": "...", "reason": "..."}).
# Output: exit 0 when the note exists (or was just created); exit 2 on failure.
set -euo pipefail
umask 077

fail() {
  printf 'session-end-handoff: %s\n' "$1" >&2
  exit 2
}
trap 'fail "internal error; no handoff note written"' ERR

# Always the managed CLI: no environment variable can substitute another program.
cli=/opt/aegisx9/bin/handoff
[ -r "$cli" ] || fail "handoff CLI unavailable"

# Only the session id and the end reason are read; both are sanitised to a safe charset.
extract=$(cat <<'PY'
import json
import re
import sys

try:
    data = json.load(sys.stdin)
except ValueError:
    data = {}


def clean(value):
    return re.sub(r"[^A-Za-z0-9_.-]", "", str(value))[:64] or "unknown"


print(clean(data.get("session_id", "")), clean(data.get("reason", "")))
PY
)
read -r session reason < <(python3 -c "$extract")

python3 "$cli" stub --session "$session" --reason "$reason"
