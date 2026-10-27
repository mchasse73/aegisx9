# External vantage scanner (`aegisx9-scan`)

The one place that looks at the organisation's public surface **from the real internet,
every day**, and refuses to say "clean" unless it has actually checked.

## The threat it exists to catch

A public web site served its `.git` directory for months. A daily TCP top-ports scan ran
the whole time and emailed "clean" every morning: port 443 was open, as approved, and
nothing else was. A port scan cannot see a file. Nobody looked from outside at what
the open port actually *served*, so a misconfiguration that any search engine could
find stayed invisible to the owner.

This scanner replaces that check with four questions, asked from a host that is outside
every allow-list:

1. **What is reachable?** nmap TCP top 1000 (`-sS` when it has `CAP_NET_RAW`, else
   `-sT`) and UDP top 100 across every hostname and address block in scope.
2. **Is it approved?** Every open `(host, ip, port, proto)` is compared with the
   approved-exposure registry and the previous run's snapshot.
3. **What does it serve?** Direct probes for `/.git/HEAD`, `/.git/config`, `/.env`,
   backup archives and dumps, `/.DS_Store`, admin panels and directory listings (a
   finding only when the body is the real thing, so catch-all 200s do not false-alarm);
   nuclei exposure/config/backup/misconfiguration templates; TLS expiry, chain,
   legacy protocol versions and security headers. Probes run over HTTP **and** HTTPS,
   against every configured name, every address target and every web listener the
   port scan discovered, and they connect to the validated address (the name is used
   for SNI and the `Host` header only).
4. **Does it still answer?** DNS expectations for named records, and HTTP
   reachability/latency every five minutes.

Everything feeds one report and one alert path. A run with no alerts still produces a
dated **clean** report, and the daily scan sends its result every day, `clean` included:
silence from it means the scanner is broken, never that the surface is fine. The
five-minute uptime probe and the weekly red-team run notify on a change of state only
(see "When a notification is sent").

## Approved-exposure registry

`approved_public.yml` is the single source of truth for what may be public. The real
file lives in **the platform operations repository** and is deployed to the host by the
automation role; this directory ships only `approved_public.example.yml` with
placeholder values. The format:

| Section | Meaning |
|---|---|
| `public:` | Reachable with no gate. Each entry: `domain` (or `domains`), `ip`, `service`, `purpose`, `authorized_by`, `authorized_date`, `reason`, `expiry` (`never` or a date); optional `ports` (default 80, 443) and `proto`. All authorization fields are required here. |
| any other `<name>:` list | A gated tier (public DNS, but a network or SSO gate in front). Same entry shape; optional `middleware`, `auth_gate`, `backend`, `caveat` are kept for the report. |
| `prohibited:` | Names or globs that must never answer on the internet. Any open port on one is `PROHIBITED_HOST`, critical. |
| `approved_aws_sg_exceptions:` | Security groups approved for `0.0.0.0/0` ingress on listed ports. |

`expiry` is honoured: an expired entry no longer approves anything and is reported as
`EXPIRED_APPROVAL` until it is renewed or removed. Approvals are the owner's decision;
the scanner never widens them.

## Never-target list (hard rule)

`never_target.yml` is loaded **before anything else**. Hostnames, CIDRs and glob
patterns in it are refused wherever they come from (`targets.yml`, the registry, a DNS or
uptime entry, or `--target-url`): they are not resolved, scanned, probed or red-teamed.
A hostname that resolves into a forbidden CIDR is refused too, and every refusal is
logged and reported as `REFUSED_TARGET` (severity `info`). A refusal is informational: the
registry can list a name that is also a never-target on purpose (a public live-trading
endpoint), so a refusal on its own never makes a run ALERT. `validate-config` still exits
`2` on any refusal, so a mistake is caught at deploy time. The list is
also passed to nmap as `--exclude`.

**Live-trading endpoints are never scanned or loaded.** They belong in this file.

## Alert classification

| Kind | Severity | Meaning |
|---|---|---|
| `NEW_OPEN_PORT` | high (medium if seen before) | Open port on a known host that no active approval covers |
| `UNAPPROVED_HOST` | high (medium if seen before) | Open port on an address the registry does not know at all |
| `PROHIBITED_HOST` | critical | A prohibited name answers on the internet |
| `EXPOSURE_FINDING` | per finding | `.git`/`.env`/backup served, admin panel, listing, nuclei match, legacy TLS, missing headers |
| `CERT_EXPIRING` | medium, high under 7 days | Certificate expires in fewer than `cert_warn_days` (14) |
| `CERT_INVALID` | high | Chain, name or validity failed verification |
| `DNS_DRIFT` | high | A named record does not answer exactly what is expected |
| `APPROVED_PORT_OPENED` / `PORT_CLOSED` | medium | An approved port that was not open last run, or a port that closed since: a change is reported even when it is approved, so "clean" means nothing moved |
| `DOWN` / `DEGRADED` | high / low | Endpoint unreachable or wrong status / slower than its budget |
| `EXPIRED_APPROVAL`, `CHECK_INCOMPLETE` | medium, low-medium | Registry hygiene, a check that could not complete |
| `REFUSED_TARGET` | info | A configured name is on the never-target list and was not touched (reported, not alerted unless `alert_min_severity` is `info`) |
| `REDTEAM_REGRESSION` | high | promptfoo attack succeeded or a garak family fell below its threshold |

`settings.alert_min_severity` (default `medium`; `AEGISX9_SCANNER_ALERT_MIN_SEVERITY`
overrides it) decides which findings alert. Lower ones stay in the report as
informational. Any alert makes the command exit `1`, so systemd marks the unit failed.

## Running locally

```bash
pip install -e '.[dev]'                       # or: pip install 'aegisx9[scanner]'
mkdir -p /tmp/aegisx9-scan/config /tmp/aegisx9-scan/state
cp scanner/approved_public.example.yml /tmp/aegisx9-scan/config/approved_public.yml
cp scanner/targets.example.yml        /tmp/aegisx9-scan/config/targets.yml
cp scanner/never_target.example.yml   /tmp/aegisx9-scan/config/never_target.yml

aegisx9-scan --config /tmp/aegisx9-scan/config --state /tmp/aegisx9-scan/state validate-config
aegisx9-scan --config /tmp/aegisx9-scan/config --state /tmp/aegisx9-scan/state --dry-run daily
aegisx9-scan --config ... --state ... --dry-run redteam --target-url https://gateway.example.com
```

`--dry-run` loads the configuration, applies the never-target list, prints the plan and
a report, and performs **no network activity and no notifications** (hostnames are not
even resolved). Without it, `daily` needs `nmap` on `PATH` (and `nuclei` for the
template pass; both are optional and their absence is reported as a note). Exit codes:
`0` clean, `1` alerts, `2` configuration error.

Reports land in `<state>/reports/<date>/<mode>-<time>-<run id>.{json,md}`; the latest is
copied to `<state>/last_report.json`; `<state>/snapshot.json` is what the next daily run
diffs against. Reports and the snapshot are created `0600`; `<state>/notify/<job>.json`
(the last notified state, no secrets) is `0660`. Every subdirectory the scanner creates
is `0770` whatever the umask, because the three units share the state directory through
the scanner group.

## How alerts flow

```
aegisx9-scan daily/uptime/redteam
   -> report (JSON + Markdown, dated, clean or not)
   -> webhook POST, HMAC-signed            -> Event-Driven Ansible rulebook
        X-AegisX9-Signature: sha256=<hex>      exposure_change | down | redteam_regression
   -> email through SES (optional)              -> job template "AegisX9 - Exposure change"
                                                   (incident record, notification)
                                                clean -> recorded
```

The webhook body is JSON (`event`, `source`, `version`, `run_id`, `mode`, `timestamp`,
`summary`, `alert_count`, `alerts[]`, `report_path`, `notify_reason`) and is signed with HMAC-SHA256 over
the exact bytes. The key is read from the `0600` file named by
`AEGISX9_SCANNER_WEBHOOK_SECRET_FILE` (or from `AEGISX9_SCANNER_WEBHOOK_SECRET`), never
from a command line. Email uses `boto3` when it is importable, otherwise the AWS CLI with
the request on stdin. Errors are logged by exception type only.

### When a notification is sent

Each job keeps the state it last notified in `<state>/notify/<job>.json`.

| Job | Notifies when | Subject |
|---|---|---|
| `daily` | every run (the heartbeat; `notify_reason` `summary`), or `recovered` after a notified failure | `CLEAN` / `ALERT` / `RECOVERED` |
| `uptime`, `redteam` | the set of alerting findings (kind, target, port) differs from the one last notified (`alert`, `changed`); the same failure is still there 24 hours after the last notice (`reminder`); clean again after a notified failure, once (`recovered`) | `ALERT` / `ALERT (still failing)` / `RECOVERED` |

A clean run after a clean run is silent for `uptime` and `redteam`; their reports are
still written. The state is recorded only after a channel accepted the notice, so a
failed delivery is retried on the next run. Details that change every run (latency, a
status text) do not count as a new state.

## Red-team from outside

`aegisx9-scan redteam --target-url <public gateway URL>` runs this repository's
`redteam/promptfoo` and `redteam/garak` suites against the *public* endpoint, after the
never-target check. The red-team API key comes from the `0600` file in
`AEGISX9_SCANNER_REDTEAM_KEY_FILE` and reaches the tools through their environment.
The suites are expected at `AEGISX9_SCANNER_REDTEAM_SUITE_DIR` (default
`/opt/aegisx9-scanner/redteam`, deployed by cloud-init and the automation role). A
missing tool, key or suite is `CHECK_INCOMPLETE`, not a pass. With no target configured
the weekly unit exits clean with a note.

## On the host

| Piece | Where |
|---|---|
| Package and venv | `/opt/aegisx9-scanner/venv/bin/aegisx9-scan`, installed from a pinned release tag or commit SHA as `aegisx9[scanner] @ git+https://github.com/mchasse73/aegisx9@<ref>`, with CPU-only torch for garak and no pip cache |
| Configuration | `/etc/aegisx9-scanner/{approved_public,targets,never_target}.yml` and the non-secret `env` file (0600) |
| Secrets | Fetched at boot from the cloud parameter store by `aegisx9-scanner-env.service` (AWS CLI v2 from the signature-verified official installer; the snap cannot run in its sandbox) into `0600` root files, handed to the units with systemd `LoadCredential=`; never in user-data, never on argv. The webhook URL and HMAC key are **required**, and so is the red-team key when a red-team target is set: if one cannot be read, the service fails with an error naming the parameter (never its value), no empty file is left and the scan units (`Requires=`) do not start. An absent optional parameter (the tunnel credential) is logged as info and leaves an empty file |
| Units | `systemd/`: `aegisx9-scan-daily` (08:00 America/New_York; static user with `CAP_NET_RAW CAP_NET_ADMIN` for raw scans), `aegisx9-scan-uptime` (every 5 min, `DynamicUser`), `aegisx9-scan-redteam` (weekly, `DynamicUser`); all `ProtectSystem=strict`, `PrivateTmp`, `NoNewPrivileges`, `ProtectProc=invisible`. `ProcSubset=pid` only on the uptime unit: nmap needs `/proc/net`, and Node.js and torch read `/proc/stat`, `/proc/cpuinfo` and `/proc/meminfo`. The daily unit sets `StateDirectoryMode=0770` and `LogsDirectoryMode=0770` to match the tmpfiles file; without them each start reset the directory to `0755` and the other units lost write access. `tests/scanner/test_scanner_units.py` and the CI job `scanner-sandbox` (nmap under the daily unit's parsed sandbox) guard both |
| Infrastructure | `infra/scanner/` (Terraform, applied by platform operations through Terraform Enterprise): t3.small, Ubuntu 24.04 from the public SSM parameter, IMDSv2, encrypted root, no inbound security-group rules (Session Manager only), least-privilege role, existing elastic IP by association |
| Deployment | `automation/playbooks/scanner_deploy.yml` (role `x9.aegisx9.scanner`, over the Session Manager connection) |
| Response | `extensions/eda/rulebooks/aegisx9_security_events.yml`, role `x9.aegisx9.exposure_change` |

The host authenticates to the cloud with its instance role only. Vault access, when the
platform team enables it, uses the cloud IAM auth method (no secret on the box); see the
`vault_aws_auth_enabled` variable.
