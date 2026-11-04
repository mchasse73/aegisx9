"""Write garak's OpenAICompatible generator options from environment variables (stdout).

The model is not an option here: garak sends the target name (``--target_name``) as the
request's model and ignores a ``model`` key, so the workflow passes it on the command line.
"""

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
                "max_tokens": 1024,  # 256 cut 47 answers off before any text (#193)
                "suppressed_params": ["n", "frequency_penalty", "presence_penalty"],
            }
        }
    }
    json.dump(options, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
