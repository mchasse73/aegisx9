"""Fail when a workflow has not succeeded on main within a maximum age.

Reads the repository's run history through the GitHub REST API with the job's own
``GITHUB_TOKEN`` (``actions: read``). Exits 0 when fresh, 1 when stale or never
succeeded, 2 when the history can't be read.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

API = "https://api.github.com"
MAX_RESPONSE_BYTES = 1 << 20

Fetch = Callable[[str], Mapping[str, Any]]


def _fetch(url: str, token: str) -> Mapping[str, Any]:
    req = urllib.request.Request(  # noqa: S310 - fixed https API base
        url,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    if not url.startswith(API + "/"):
        raise ValueError("only the GitHub API is queried")
    with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310
        body = resp.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise ValueError("answer too large")
    data = json.loads(body)
    if not isinstance(data, dict):
        raise ValueError("answer is not an object")
    return data


def _when(value: object) -> dt.datetime:
    return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def last_success(fetch: Fetch, repo: str, workflow: str) -> dt.datetime | None:
    """Start time of the newest successful run on main, or None.

    Uses ``run_started_at``, not ``updated_at``: later activity on an old run (a re-run
    attempt, a log deletion) moves ``updated_at`` and would make a stale gate look fresh.
    The conclusion is checked here too rather than trusting the query filter alone.
    """
    query = urllib.parse.urlencode({"branch": "main", "status": "success", "per_page": 20})
    path = f"/repos/{repo}/actions/workflows/{urllib.parse.quote(workflow)}/runs?{query}"
    runs = fetch(API + path).get("workflow_runs") or []
    started = [
        _when(r.get("run_started_at") or r["created_at"])
        for r in runs
        if r.get("conclusion") == "success" and r.get("head_branch") == "main"
    ]
    return max(started) if started else None


def main(
    argv: list[str] | None = None,
    env: Mapping[str, str] | None = None,
    fetch: Fetch | None = None,
    now: dt.datetime | None = None,
) -> int:
    env = os.environ if env is None else env
    ap = argparse.ArgumentParser()
    ap.add_argument("--workflow", required=True)
    ap.add_argument("--max-age-hours", type=float, required=True)
    args = ap.parse_args(argv)
    repo = env.get("GITHUB_REPOSITORY", "")
    token = env.get("GH_TOKEN", "")
    if not repo or (fetch is None and not token):
        print("freshness: GITHUB_REPOSITORY and GH_TOKEN are required", file=sys.stderr)
        return 2
    try:
        when = last_success(fetch or (lambda url: _fetch(url, token)), repo, args.workflow)
    except (urllib.error.URLError, OSError, ValueError, KeyError) as e:
        print(f"freshness: could not read run history ({type(e).__name__})", file=sys.stderr)
        return 2
    now = now or dt.datetime.now(dt.UTC)
    if when is None:
        print(f"freshness: {args.workflow} has never succeeded on main", file=sys.stderr)
        return 1
    age_h = (now - when).total_seconds() / 3600
    if age_h > args.max_age_hours:
        print(
            f"freshness: last success of {args.workflow} on main was {age_h:.0f} h ago "
            f"(limit {args.max_age_hours:.0f} h)",
            file=sys.stderr,
        )
        return 1
    print(f"freshness: {args.workflow} succeeded on main {age_h:.1f} h ago")
    return 0


if __name__ == "__main__":
    sys.exit(main())
