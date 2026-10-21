#!/usr/bin/env bash
# AegisX9 workspace hook: UserPromptSubmit.
# Blocks a prompt that carries credential-shaped text before it leaves the workspace.
#
# Input : the Claude Code hook JSON on stdin ({"prompt": "...", ...}).
# Output: exit 0 to allow; exit 2 with a one-line reason on stderr to block.
# The matched text is never echoed. Any internal error blocks the prompt (fail closed);
# the managed settings also set "onFailure": "block" for a crash or a timeout.
set -euo pipefail
umask 077

block() {
  printf 'prompt-credential-check: %s\n' "$1" >&2
  exit 2
}
trap 'block "internal error; prompt blocked (fail closed)"' ERR

here=$(cd "$(dirname "$0")" && pwd)
patterns="${AEGISX9_CREDENTIAL_PATTERNS:-$here/credential-patterns.txt}"
[ -r "$patterns" ] || block "pattern file unavailable; prompt blocked (fail closed)"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
prompt_file="$tmp/prompt.txt"

# Extract the prompt text into a 0600 file (umask 077) without printing it. The hook
# JSON stays on stdin; the extractor itself is passed as code, not through stdin.
extract=$(cat <<'PY'
import json
import sys

data = json.load(sys.stdin)
text = data.get("prompt", "")
if not isinstance(text, str):
    text = json.dumps(text)
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    fh.write(text)
PY
)
python3 -c "$extract" "$prompt_file"

# 1. Fast local check: common token shapes.
if grep -E -q -f "$patterns" "$prompt_file"; then
  block "credential-shaped text in the prompt; remove the secret and rephrase"
fi

# 2. gitleaks' full rule set on the same text. A missing or failing scanner blocks too.
command -v gitleaks >/dev/null 2>&1 || block "secret scanner unavailable; prompt blocked (fail closed)"
rc=0
gitleaks dir "$tmp" --no-banner --redact --exit-code 2 >/dev/null 2>&1 || rc=$?
case "$rc" in
  0) exit 0 ;;
  2) block "gitleaks found a secret in the prompt; remove it and rephrase" ;;
  *) block "secret scanner failed; prompt blocked (fail closed)" ;;
esac
