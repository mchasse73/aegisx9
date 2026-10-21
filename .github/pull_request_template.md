## What and why

<!-- One or two sentences. Link the issue. -->
Closes #

## Type

- [ ] feat
- [ ] fix
- [ ] security
- [ ] docs
- [ ] ci / build
- [ ] refactor / test / chore

## Checklist

- [ ] Title follows Conventional Commits
- [ ] Tests added or updated; coverage gate passes
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] No credential-shaped literals, hostnames, IPs or internal paths added
- [ ] Audit events still carry no prompt/completion text or secret values
- [ ] If a workflow changed: no self-hosted (`aegisx9-arc`) job can run on `pull_request`
- [ ] If `deploy/overlays/prod` changed: digest is signed by the main release workflow and has passed the staging red-team gate

## Risk and rollback

<!-- What could break, and how to revert. -->
