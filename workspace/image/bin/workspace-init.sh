#!/usr/bin/env bash
# AegisX9 workspace: per-login initialisation, run as the `dev` user.
# Sourced by /etc/profile.d/aegisx9-workspace.sh and safe to run from a Coder startup
# script. It never writes outside $HOME and never prints a secret.
#
# 1. Static credentials can never reach Claude Code: ANTHROPIC_AUTH_TOKEN and
#    ANTHROPIC_API_KEY take precedence over apiKeyHelper, so both are removed from the
#    environment here (the PreToolUse hook also refuses commands that set them).
# 2. The home volume gets the directories the helpers expect, owner-only.
# 3. The managed handoff skill is linked into the user's skills directory.
unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN
umask 077
mkdir -p "$HOME/.aegisx9/handoff" "$HOME/.claude/skills"
chmod 700 "$HOME/.aegisx9" "$HOME/.aegisx9/handoff"
if [ ! -e "$HOME/.claude/skills/handoff" ] && [ -d /opt/aegisx9/claude/skills/handoff ]; then
  ln -s /opt/aegisx9/claude/skills/handoff "$HOME/.claude/skills/handoff"
fi
umask 022
