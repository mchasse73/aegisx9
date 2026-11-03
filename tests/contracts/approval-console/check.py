"""Load the approval console <-> gate API contract fixture and check JSON values against its small schemas. Stdlib only.

Both test suites import this file (the gate drives its real app into every case; the console's fake gate answers from the
fixture), so there is ONE reading of the schema language. See README.md in this directory for the format.

Schema language (a strict subset of JSON Schema, enough for this API):
  type                  "object" | "array" | "string" | "integer" | "number" | "boolean" | "null", or a list of them
  required              [keys] that must be present (objects)
  properties            {key: schema} for keys that may be present
  additionalProperties  false = no other keys; a schema = every other key's value must match it (default: any)
  propertyNames         a schema every key must match (use with additionalProperties for maps such as job id -> hash)
  items                 schema of every array element; minItems / maxItems
  const, enum           exact value / one of these values
  pattern               a regex the string must match (re.search, so anchor it); minLength / maxLength
  minimum               lower bound for integers / numbers
"""
from __future__ import annotations

import json
import re
from pathlib import Path

DIR = Path(__file__).resolve().parent
AUTH = "auth"
_TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}


def _is(v, t):
    if t == "integer":
        return isinstance(v, int) and not isinstance(v, bool)
    if t == "number":
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    return isinstance(v, _TYPES[t])


def errors(value, schema, where="$") -> list[str]:
    """Every way `value` fails `schema` (empty list = it matches)."""
    if schema is None:
        return [] if value is None else [f"{where}: expected no body, got {type(value).__name__}"]
    out = []
    if "type" in schema:
        ts = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_is(value, t) for t in ts):
            return [f"{where}: expected {'|'.join(ts)}, got {type(value).__name__}"]
    if "const" in schema and value != schema["const"]:
        out.append(f"{where}: expected {schema['const']!r}, got {value!r}"[:300])
    if "enum" in schema and value not in schema["enum"]:
        out.append(f"{where}: {value!r} not in {schema['enum']}"[:300])
    if isinstance(value, str):
        if "pattern" in schema and not re.search(schema["pattern"], value):
            out.append(f"{where}: {value[:80]!r} does not match {schema['pattern']}")
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 1 << 30):
            out.append(f"{where}: length {len(value)} out of range")
    if isinstance(value, (int, float)) and not isinstance(value, bool) and "minimum" in schema and value < schema["minimum"]:
        out.append(f"{where}: {value} < {schema['minimum']}")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        for k in schema.get("required", []):
            if k not in value:
                out.append(f"{where}: missing required key {k!r}")
        extra = schema.get("additionalProperties", True)
        for k, v in value.items():
            if "propertyNames" in schema:
                out += errors(k, schema["propertyNames"], f"{where}.<key {k!r}>")
            if k in props:
                out += errors(v, props[k], f"{where}.{k}")
            elif extra is False:
                out.append(f"{where}: unexpected key {k!r}")
            elif isinstance(extra, dict):
                out += errors(v, extra, f"{where}.{k}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", 1 << 30):
            out.append(f"{where}: {len(value)} items out of range")
        if "items" in schema:
            for i, v in enumerate(value):
                out += errors(v, schema["items"], f"{where}[{i}]")
    return out


def matches(value, schema) -> bool:
    return not errors(value, schema)


def load(name: str) -> dict:
    """One fixture file by stem (e.g. "webauthn-register")."""
    return json.loads((DIR / f"{name}.json").read_text())


def endpoints() -> dict[str, dict]:
    """{stem: fixture} for every endpoint file (auth.json excluded)."""
    return {p.stem: json.loads(p.read_text()) for p in sorted(DIR.glob("*.json")) if p.stem != AUTH}


def response(fx: dict, name: str) -> dict:
    hit = [r for r in fx["responses"] if r["name"] == name]
    if len(hit) != 1:
        raise KeyError(f"{fx.get('endpoint', {}).get('path', AUTH)}: no single response named {name!r}")
    return hit[0]


def path_matches(template: str, path: str) -> bool:
    """'/jobs/approval-challenge/<nonce>' matches '/jobs/approval-challenge/0123...'."""
    return bool(re.fullmatch("[^/]+".join(map(re.escape, re.split(r"<[^>]+>", template))), path))


def route(method: str, path: str) -> tuple[str, dict] | None:
    """(stem, fixture) whose endpoint is this method + concrete path, or None."""
    for stem, fx in endpoints().items():
        ep = fx["endpoint"]
        if ep["method"] == method and path_matches(ep["path"], path):
            return stem, fx
    return None


def self_check() -> list[str]:
    """The fixture's own consistency: every example matches its schema; names unique; required fields of the format present."""
    out = []
    for stem, fx in [*endpoints().items(), (AUTH, load(AUTH))]:
        for k in ("roles", "responses"):
            if k not in fx:
                out.append(f"{stem}: missing {k!r}")
        if stem != AUTH:
            req = fx.get("request", {})
            if "body_schema" not in req or "example" not in req:
                out.append(f"{stem}: request needs body_schema and example")
            else:
                out += [f"{stem} request example: {e}" for e in errors(req["example"], req["body_schema"])]
        names = [r.get("name") for r in fx.get("responses", [])]
        if len(names) != len(set(names)):
            out.append(f"{stem}: duplicate response names")
        for r in fx.get("responses", []):
            for k in ("name", "status", "body_schema", "example", "when"):
                if k not in r:
                    out.append(f"{stem}/{r.get('name')}: missing {k!r}")
            out += [f"{stem}/{r.get('name')} example: {e}" for e in errors(r.get("example"), r.get("body_schema"))]
            if r.get("console_action") not in (None, "relay", "fresh_login", "refresh_retry_once", "bad_gateway"):
                out.append(f"{stem}/{r['name']}: unknown console_action {r['console_action']!r}")
    return out


if __name__ == "__main__":
    import sys
    problems = self_check()
    print("\n".join(problems) or "fixture OK")
    sys.exit(1 if problems else 0)
