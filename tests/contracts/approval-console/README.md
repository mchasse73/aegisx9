# Approval console ↔ gate API: contract fixture

The approval console (a web page where an approver reviews build jobs and signs them with a hardware security key over
WebAuthn) talks to one backend, the **gate**, which verifies every signature and decides. They are built and tested
separately. Each side used to test against its own fake of the other, and each fake matched its own side's assumptions, so
both suites stayed green while the two halves disagreed. Two real examples:

- The console sent the registration body as the browser's bare `PublicKeyCredential.toJSON()` object; the gate reads
  `{"credential": <toJSON>}`. Both suites passed.
- The gate refuses `register-options` as well as `register` with "sign in again" when the login isn't fresh. The console
  handled the refusal on `register` only.

This directory is the neutral copy of the contract that **both** suites assert against, so neither side can drift alone.

## The rule

**Change the contract here first, then both sides.** A new field, a new refusal code or a changed status starts as an edit to
the JSON file of that endpoint. The gate's contract test then fails until the gate produces it, and the console's contract test
fails until the console sends or handles it. Never fix a red contract test by editing a fake.

## Format

One JSON file per endpoint, plus `auth.json` for refusals any endpoint can give before its handler runs.

```json
{
  "endpoint": {"method": "POST", "path": "/jobs/webauthn/register"},
  "roles": ["approver"],
  "description": "...",
  "request": {"body_schema": {...}, "example": {...}},
  "responses": [
    {"name": "registered", "status": 201, "when": "...", "body_schema": {...}, "example": {...}, "console_action": "relay"}
  ]
}
```

- `roles`: who may call it. `approver` is the console (it forwards the signed-in user's identity-provider token as
  `Authorization: Bearer`); `operator`, `contain` and `project` are the gate's own service identities.
- `request.body_schema`: `null` for a request with no body (GET). `example` is a body the gate accepts.
- `responses`: **every** success shape and **every** refusal the gate can return today, each with a unique `name`. Refusals
  that carry a machine reason have `code` pinned with `const`; exact texts the console depends on (the fresh-login text) are
  pinned with `const` too.
- `console_action` (only on cases the console can receive) says what the console must do:
  - `relay`: return the gate's status and body unchanged to the browser.
  - `fresh_login`: answer 403 with `{"error", "fresh_login": "/login?fresh=1&next=..."}`, so the page forces a new sign-in and
    comes back (no redirect loop).
  - `refresh_retry_once`: on 401, refresh the user's token and retry once; a second 401 means "sign in again".
  - `bad_gateway`: a 5xx becomes 502 without the gate's body.
- Paths may hold placeholders (`/jobs/approval-challenge/<nonce>`).

Example values are generic: approver `approver@example.com`, console origin `https://console.example.com`, RP ID
`console.example.com`, base64url ids, 32-hex nonces, ISO-8601 UTC timestamps, sha256 hex. The statement header
(`x9-build-approval v2`) is the deployment's statement format (see the statement v2 spec next to this directory).

### Schema language

A strict subset of JSON Schema, read by `check.py` (stdlib only): `type` (or a list of types), `required`, `properties`,
`additionalProperties` (`false` or a schema), `propertyNames`, `items`, `minItems`/`maxItems`, `const`, `enum`, `pattern`
(anchored regex), `minLength`/`maxLength`, `minimum`. Success bodies use `additionalProperties: false`, so a new field is a
contract change, not a silent addition.

`python3 check.py` checks the fixture itself: every example matches its schema, names are unique, and every
`console_action` is known.

## How each suite uses it

**One checker, shared.** Both suites import `check.py` from this directory, so the schema language has exactly one reading.

**Gate suite** (the gate's `test_contract.py`): for every endpoint and every response case, it drives the **real** gate
application into that case, with real token verification against a fake identity provider and real WebAuthn crypto from a
fake authenticator, and asserts the status and that the body matches `body_schema`. Bodies that produced a success must match
`request.body_schema` (so the request examples are shapes the gate really accepts, including every optional field the console
adds). A case with no driver **fails**; it is never skipped. It also scans the gate's source for every refusal code it can
raise and fails if one is in no fixture case and not listed as unreachable.

**Console suite** (the console's `tests/test_contract.py` and its fake gate in `tests/conftest.py`): the fake gate answers
**from this fixture**: it routes by method and path, answers the endpoint's first success example by default, and a test picks
a named case with `respond(endpoint, name)`. It refuses (raises) any request body that breaks `request.body_schema`, and any
test-supplied override that matches no fixture case. The contract test then asserts that every body the console sends matches
the request schema (the check that would have caught the registration drift) and that for every case with a `console_action`
the console does exactly that action, on every console route.

## Findings recorded while building the fixture

These are today's real behaviour, recorded as is (the fixture describes what the gate does, not what it should do):

- **A token outside the approver group gets 401, not 403.** The gate treats it as an invalid token, so the console refreshes,
  retries, then asks the user to sign in again, which can't help. A clearer 403 would be a contract change.
- **`register` refuses a malformed body with 403 `code: malformed`, not 400.**
- **The registry's `unknown` code is never returned by `revoke`:** an unknown credential is a 404 without a code.
- **The `disabled` refusal code is unreachable on `approve-webauthn`:** the route answers 503 before the check that raises it.
- The console's audit summary of an approval answer listed keys the gate never sends; it now lists the gate's real keys.

## In AegisX9

This copy comes from customer zero's console and gate, which are live in the reference deployment (2026-11-03). Example
values and request ids are generic. In AegisX9 it is the **starting contract** for the approval console (#108) and the
approval gate (#109). Neither is built yet, so for now only `test_approval_console_contract.py` runs, checking the fixture
against itself.

Planned product differences, each to be made here first (see "The rule") when the gate is built:

- **Wrong group:** a token outside the approver group gets 403, not 401, so the console doesn't refresh and retry for
  nothing.
- **Malformed request bodies:** 400 with `code: malformed`, not 403.
- **Unknown credential on revoke:** 404 with a `code`.
- **Unreachable cases removed:** for example `disabled` on approve, where a 503 always comes first.
- **Enrolment (ADR 0012):** a new approver credential stays pending until an existing hardware-signed approval activates it.
  Customer zero activates a credential on a fresh login, which the product doesn't allow, so the register cases change.
- **Paths and statement header:** `/jobs/...` and the `x9-build-approval v2` header are customer zero's. The product's
  paths and statement format follow ADR 0012.
