"""Write garak's OpenAICompatible generator options from environment variables (stdout)."""

from __future__ import annotations

import json
import os
import sys


def main() -> int:
    url = os.environ.get("AEGIS_STAGING_URL", "").rstrip("/")
    model = os.environ.get("AEGIS_REDTEAM_MODEL", "")
    if not url or not model:
        print("AEGIS_STAGING_URL and AEGIS_REDTEAM_MODEL must be set", file=sys.stderr)
        return 2
    options = {
        "openai": {
            "OpenAICompatible": {
                "uri": f"{url}/v1",
                "model": model,
                "max_tokens": 256,
                "suppressed_params": ["n", "frequency_penalty", "presence_penalty"],
            }
        }
    }
    json.dump(options, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
