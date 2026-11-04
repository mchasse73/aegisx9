# 22. Block text hidden in base64, base32 or hex in prompts

- Status: Accepted
- Date: 2026-11-03

## Context

The first complete garak run against staging found that 76% of base64-encoded and 83% of
hex-encoded payloads got past the input guard. The model decoded them and repeated or acted on
the hidden text (OWASP LLM01:2025, obfuscation; #172). The keyword guard reads only plaintext.
Matching injection patterns inside decoded text isn't enough on its own: garak's payloads, like
real ones, are often plain forbidden content rather than "ignore your instructions".

## Decision

1. A new input guard, `encoded_payload`, finds base64 (standard and URL-safe, padded or not),
   base32 and hex spans and decodes each one. Hex is accepted plain, with a `0x` prefix, byte
   by byte (`49 67`, `49:67`), as `\x49` escapes or as `%49`. A span over 64 KiB is decoded up
   to that prefix, not skipped. Work stays linear in the prompt length, and there's no cap on
   the number of spans, because a cap would let padding push a payload past it.
2. It blocks any decode whose text matches a prompt-injection pattern
   (`encoded_<category>`). This check runs on every decode, so junk bytes around the text don't
   hide it.
3. It also blocks a decode that is readable text, as `encoded_text`: prose, markup or code,
   which other guards can't inspect while it's encoded. Up to 10% of the decoded characters may
   be junk. These aren't counted as readable:
   - binary data: hashes, keys, images, random tokens, git SHAs, UUIDs;
   - JSON objects whose string values are all single tokens (WebAuthn client data, API ids);
     prose needs spaces, so `{"x": "<prose>"}` is still blocked.
4. The guard runs last, after secret and PII redaction. Base64 credentials are redacted, not
   blocked: JWTs, `password: <value>`, and `Authorization: Basic`, for which the secret guard
   gains a `basic_auth` pattern.
5. Rule 3 is a policy that a deployment can turn off (`block_encoded_text=False`). Rule 2 still
   applies when it's off.
6. Ordinary words and numbers must not reach the decoders.
   - A base64 candidate made only of letters must be 20 characters or more.
   - A candidate made only of digits must be 16 or more.
   - A decode shorter than 8 characters must be at least 75% ASCII letters.

## Consequences

- Measured before release, offline, through the whole guard pipeline, using garak 0.17.1's own
  payloads and prompt templates:
  - base64 blocked 92%;
  - hex blocked 89%.

  The misses are payloads of 3 to 6 characters, whose encodings look like words or numbers.
- The same run produced no blocks on any of these:
  - 104,334 dictionary words;
  - 5,000 random 12-word sentences;
  - 20,000 random order numbers;
  - the benign promptfoo suite;
  - developer data: JWTs, Basic auth, Kubernetes Secret manifests, SHA-256 digests, UUIDs,
    MAC addresses, random tokens, binary base64.

  Of the repository's 356 files pasted as prompts, one was blocked as `encoded_text`: a
  test-pattern file that holds a standalone base64 credential marker.
- A user who asks the gateway to decode someone else's base64 message is refused. They can
  decode it locally instead.
- A forbidden single word inside an encoded JSON object isn't caught by rule 3.
- Not covered: ROT13, Braille, Morse and other ciphers, which can't be told apart from text
  without a model. They belong to the classifier stage the injection guard's docstring plans.
- The red-team thresholds are unchanged.
