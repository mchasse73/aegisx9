# syntax=docker/dockerfile:1.7
# AegisX9 developer workspace image.
#
# One signed, digest-pinned image per developer pod (Coder on Kubernetes). It bakes in
# the LOCKED Claude Code policy baseline as root-owned files the `dev` user cannot change:
#   /etc/claude-code/managed-settings.json   rendered from image/managed-settings.json
#   /etc/claude-code/managed-mcp.json        exclusive MCP list (empty for now)
#   /etc/aegisx9/workspace.env               the resolved build-time values (no secrets)
#   /opt/aegisx9/hooks/*                     fail-closed hooks
#   /opt/aegisx9/bin/*                       apiKeyHelper, handoff CLI, init, self-test
# Build context: the `workspace/` directory (see workspace/README.md).
#
# Base image bump: `docker buildx imagetools inspect ubuntu:24.04` prints the manifest
# list digest; put it after `@` below (Dependabot proposes it too). Tool versions are
# build args; every download is verified against the publisher's checksum file.
# No gitleaks binary: upstream builds ship with an old Go toolchain and fail the Trivy
# gate; the prompt hook is regex-only and the gateway's input guard is authoritative.

FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac AS tools
ARG NODE_VERSION=24.22.1
ARG VAULT_VERSION=2.2.0
# hadolint ignore=DL3008
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates curl unzip xz-utils \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /dl
RUN set -eu; \
    node_tar="node-v${NODE_VERSION}-linux-x64.tar.xz"; \
    curl -fsSLO "https://nodejs.org/dist/v${NODE_VERSION}/${node_tar}"; \
    curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/SHASUMS256.txt" \
      | grep " ${node_tar}\$" | sha256sum -c -; \
    mkdir -p /opt/node; \
    tar -xJf "${node_tar}" -C /opt/node --strip-components=1; \
    rm -f /opt/node/CHANGELOG.md /opt/node/README.md
RUN set -eu; \
    zip="vault_${VAULT_VERSION}_linux_amd64.zip"; \
    base="https://releases.hashicorp.com/vault/${VAULT_VERSION}"; \
    curl -fsSLO "${base}/${zip}"; \
    curl -fsSL "${base}/vault_${VAULT_VERSION}_SHA256SUMS" | grep " ${zip}\$" | sha256sum -c -; \
    mkdir -p /opt/tools/bin; \
    unzip -q "${zip}" vault -d /opt/tools/bin

FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
ARG VERSION=0.0.0
ARG CLAUDE_CODE_VERSION=2.1.306
# Site values rendered into the managed settings (defaults in image/workspace.env).
ARG AEGISX9_ENVIRONMENT
ARG AEGISX9_GATEWAY_URL
ARG AEGISX9_OTLP_ENDPOINT
ARG AEGISX9_VAULT_ADDR
ARG AEGISX9_MODELS
ARG AEGISX9_DENIED_MODELS
ARG AEGISX9_SANDBOX_DOMAINS
ARG AEGISX9_API_KEY_HELPER_TTL_MS
LABEL org.opencontainers.image.title="aegisx9-workspace" \
      org.opencontainers.image.description="AegisX9 developer workspace: Claude Code with a locked, gateway-only policy baseline" \
      org.opencontainers.image.source="https://github.com/mchasse73/aegisx9" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.vendor="AegisX9"

# Runtime packages. No sudo: the package is absent and no sudoers file exists.
# bubblewrap + socat back the Claude Code Bash sandbox. openssh-server, rsync and procps
# (pgrep) are required by the Coder template: its agent starts sshd unprivileged on a
# loopback port with host keys from the home volume (never generated here), the sync
# tool connects as `dev`, and pod probes use pgrep. Nothing is started by the image.
# hadolint ignore=DL3008
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      bubblewrap ca-certificates curl git git-lfs jq less locales openssh-client \
      openssh-server procps python3 python3-venv ripgrep rsync socat tini unzip \
 && rm -rf /var/lib/apt/lists/* \
 && locale-gen en_US.UTF-8 \
 && userdel -r ubuntu \
 && groupadd --gid 1000 dev \
 && useradd --uid 1000 --gid dev --create-home --shell /bin/bash dev \
 && mkdir -p /run/sshd \
 && rm -f /etc/ssh/ssh_host_*

COPY --from=tools /opt/node /opt/node
COPY --from=tools --chmod=0755 /opt/tools/bin/vault /usr/local/bin/
ENV PATH=/opt/node/bin:/opt/aegisx9/bin:/usr/local/bin:/usr/bin:/bin \
    LANG=en_US.UTF-8 \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false
RUN npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
 && npm cache clean --force

# The locked baseline: root-owned, read-only for everyone else.
COPY --chmod=0755 image/hooks/prompt-credential-check.sh image/hooks/pretooluse-guard.sh \
     image/hooks/session-end-handoff.sh /opt/aegisx9/hooks/
COPY --chmod=0644 image/hooks/credential-patterns.txt image/hooks/bash-deny-patterns.txt /opt/aegisx9/hooks/
COPY --chmod=0755 image/bin/gateway_token.py /opt/aegisx9/bin/gateway-token
COPY --chmod=0755 image/bin/handoff.py /opt/aegisx9/bin/handoff
COPY --chmod=0755 image/bin/workspace-init.sh /opt/aegisx9/bin/workspace-init
COPY --chmod=0755 image/bin/workspace-selftest.sh /opt/aegisx9/bin/workspace-selftest
COPY --chmod=0644 image/managed-settings.json image/managed-mcp.json image/workspace.env \
     image/render_settings.py /opt/aegisx9/share/
COPY --chmod=0644 claude/skills/handoff/SKILL.md /opt/aegisx9/claude/skills/handoff/SKILL.md
COPY --chmod=0644 image/profile.d/aegisx9-workspace.sh /etc/profile.d/aegisx9-workspace.sh
COPY --chmod=0644 image/sshd/aegisx9.conf /etc/ssh/sshd_config.d/aegisx9.conf
RUN mkdir -p /etc/claude-code/managed-settings.d /etc/aegisx9 \
 && AEGISX9_IMAGE_VERSION="${VERSION}" python3 /opt/aegisx9/share/render_settings.py \
      --template /opt/aegisx9/share/managed-settings.json \
      --env /opt/aegisx9/share/workspace.env \
      --output /etc/claude-code/managed-settings.json \
      --env-output /etc/aegisx9/workspace.env \
 && install -m 0644 /opt/aegisx9/share/managed-mcp.json /etc/claude-code/managed-mcp.json \
 && chown -R root:root /etc/claude-code /etc/aegisx9 /opt/aegisx9 \
 && find /opt/aegisx9 /etc/claude-code /etc/aegisx9 -type d -exec chmod 0755 {} + \
 && chmod 0755 /etc/claude-code /etc/claude-code/managed-settings.d /etc/aegisx9 \
 && chmod 0644 /etc/claude-code/managed-settings.json /etc/aegisx9/workspace.env

USER dev
WORKDIR /home/dev
ENV HOME=/home/dev
# Home layout for the bare image (a mounted home volume hides it; workspace-init, sourced
# by /etc/profile.d at login or called by the platform's startup script, recreates it).
# Directories that COPY --chmod=0644 creates implicitly have no execute bit, which makes
# every path test under /opt/aegisx9 fail silently for a non-root user; the find/chmod
# above fixes that, and this check prints the tree if it ever regresses.
RUN { . /opt/aegisx9/bin/workspace-init && test -L /home/dev/.claude/skills/handoff; } \
 || { ls -laR /opt/aegisx9/claude /home/dev/.claude >&2; exit 1; }
# ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN are deliberately never set: apiKeyHelper is
# the only credential source. workspace-init also unsets them at every login.
HEALTHCHECK --interval=60s --timeout=15s --start-period=20s --retries=3 \
  CMD ["/opt/aegisx9/bin/workspace-selftest", "--quick"]
ENTRYPOINT ["/usr/bin/tini", "--"]
# Coder replaces the command with its agent start script; standalone the pod just idles.
CMD ["sleep", "infinity"]
