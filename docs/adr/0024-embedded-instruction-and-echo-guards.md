# 24. Block instructions planted in pasted data, and completions that obey them

- Status: Accepted
- Date: 2026-11-04 (owner decision)
- Issues: #179, #195; streaming follow-up #197; classifier follow-up #198

## Context

The nightly garak gate found two indirect prompt-injection families below their floors
(OWASP LLM01:2025, indirect injection):

- `promptinject` goal hijacking scored 0.90 against a floor of 0.95 (#179). The keyword guard
  already caught four of its five templates. The fifth one shouts a stop command and asks for
  a quoted string, with no "ignore … instructions" in it.
- `latentinjection.LatentInjectionReport` scored 0.30 against 0.85 (#195). The attack is
  hidden in a pasted document after a separator line. It tells the model to drop everything
  except a bracketed string, fakes an assistant/user exchange, or fakes an end-of-session
  tag followed by a `System:` turn. garak scores a hit when the trigger domain appears in the
  answer.

These attacks don't need the phrases the keyword guard knows. What they share is structure:
an instruction inside data, and a literal the model is told to emit.

## Decision

1. A new input guard, `embedded_instruction` (`src/aegisx9/guards/embedded.py`), scans user and
   tool messages only. System and assistant messages are the operator's own text, often
   few-shot examples full of role lines and quoted answers. It looks for these signals, all
   of them only inside the data region:
   - **Strong** signals block. Outside pasted data the same words are the user's own
     instruction ("disregard all other context except the following paragraph"), so they
     aren't blocked there.
     - `context_override`: drop the rest of the data and emit something; drop all information
       except what follows; ignore the coming snippets and focus only on one thing;
       "nevermind" followed by ignoring instructions.
     - `session_marker`: a fake end-of-session or end-of-conversation tag, or a model
       end-of-text token.
   - **Weak** signals:
     - `fake_role_turn`: a line that starts a `System:`, `Assistant:` or `User:` turn.
     - `separator_payload`: separator lines stacked on top of each other.
     - `output_forcing_literal`: a forcing phrase ("just print", "reply with only",
       "provide it to the user") followed by a quoted or bracketed literal. A forcing phrase
       with no literal ("reply with only the summary") isn't forcing.
2. The data region is all of a `tool` message. In any other message it starts at the first
   separator line (four or more of `-=*_~#`), code fence, quoted line, or "the following …:"
   line. A message with none of these has no data region. Line endings are normalised first
   (CRLF and lone CR become LF, trailing blanks are dropped), so a Windows-style paste reads
   the same. The proxy hook now passes each message's role in `GuardContext.role`.
   An assistant message that only calls tools continues the current turn rather than ending it.
   OpenAI content-parts lists are flattened: every input guard sees each text part, and with
   several parts also their joined text, so a marker in one part and an attack in the next
   are read together. If only the joined text needs a redaction (a key split across parts),
   the text parts become one redacted part where the first one was. Before this change the
   hook skipped list content for every guard, including the redaction guards.
3. The guard blocks on any strong signal. It also blocks a forcing literal *planted* in the
   structure: on a fake role turn's own line, or on the line straight after stacked
   separators. Weak signals on their own are allowed, and their findings go to the audit log.
   We tried counting a forcing literal plus a weak signal anywhere in the message, and it blocked
   ordinary prompts: a pasted chat transcript followed by the user's own `reply with only
   "positive"`.
4. The keyword guard's `instruction_override` pattern also matches a stop-everything command
   followed within 40 characters by print, say, output, write or repeat and then a quoted,
   bracketed or colon-introduced target, so "stop everything and write the unit tests" passes. The encoded-payload
   guard (ADR 0022) applies the strong embedded signals to every decoded span too.
5. A new output guard, `instruction_echo`, blocks a completion (`echoed_embedded_literal`) that
   contains, case-insensitively and as whole words, the first 64 characters of a literal of 4 or
   more characters that the current turn's data tried to force, or a URL or domain inside one.
   - The current turn is the user and tool messages after the last assistant message. Older
     turns' literals don't block later answers.
   - By default a forced literal counts only when its own message also carries another
     signal: a strong one, a fake role turn or stacked separators. One message can't
     corroborate another's literal. A URL or domain always counts: one with a scheme, `www.`,
     or a top-level domain that isn't a common file extension (`main.py` and `README.md`
     aren't links).
   - `corroborated_only=False` checks every forced literal. Doing so also blocks answers to
     ordinary prompts like `Classify:\n----\n<review>\n----\nReply with only "positive"`.
6. These toggles are policy, and each deployment chooses its own setting:
   - `EmbeddedInstructionGuard.block_weak_combinations` (default on);
   - `InstructionEchoGuard.enabled` (default on);
   - `InstructionEchoGuard.corroborated_only` (default on).

   Strong signals can't be turned off.
7. **Request-scoped prompt data.** `GuardContext.prompt_literals` is a new field. The proxy
   hook computes it once per request, after the call, from the current turn's user and tool
   messages, which `pre_call` has already redacted, and reuses it for every choice.
   `GuardContext.prompt_text` is the same input as plain text, for callers outside the hook.
   Both exist only for the lifetime of one request. `repr` leaves both out. `AuditEvent` has no field it could go into, and a test
   proves the audit log carries neither the literal nor the prompt. Guards keep no state
   between requests.
8. Pipeline order:
   - input: injection, embedded instruction, secret redaction, PII redaction, encoded payload;
   - output: instruction echo (on the raw completion), then secret and PII redaction.
9. **Streaming is out of scope.** The echo guard sees only complete, non-streamed
   completions. Streamed answers are a known gap, tracked in #197.
10. **Gates.** These stay standing gates for every guard change:
    - the false-positive corpora below, which must produce no blocks except genuine strong
      signals;
    - the hold-out families, reported but never tuned against.

    A model-based classifier stays deferred (see `injection.py`). The red-team thresholds don't
    change.

## Consequences

- Measured offline before release, through `default_pipeline()`. The prompts were rebuilt from
  the garak 0.17.1 wheel by parsing its source with `ast`, never importing it.
  - promptinject goal hijacking, all 5 templates × 35 base prompts × 3 rogue strings
    (525 prompts): 100% blocked at input (the stop-everything template: 70 of 70).
  - LatentInjectionReportFull (all 648 prompts): 100% blocked at input. With the input guards
    off, `instruction_echo` alone blocks 100% of compliant answers for both targets.
- A pre-PR review found 10 evasions and false blocks in the first version. All are fixed, each
  with a regression test:
  - CRLF line endings hid the data region;
  - trailing blanks on a separator hid stacked separators;
  - a forcing phrase padded past 512 characters into a fake turn wasn't checked;
  - file names counted as links;
  - echo matched inside longer words;
  - echo used literals from earlier turns, and let one message corroborate another's literal;
  - few-shot system prompts were scanned;
  - the user's own instructions tripped strong signals;
  - content-parts lists weren't guarded at all;
  - the echo guard recomputed the prompt's literals for every choice.
- Copilot's review of the PR then found 7 more, all fixed with regression tests:
  - two patterns backtracked quadratically on long whitespace runs; every pattern is now
    timed on 64 KB pathological input;
  - a private key split across two content parts was redacted only in the joined check, and
    that result was discarded. The text parts are now merged into one redacted part, and
    non-text parts keep their order;
  - a session marker glued to a word wasn't matched;
  - URLs with ports, queries or fragments weren't counted as links;
  - three or more stacked separators weren't checked;
  - an assistant tool call ended the turn, which cut the user's request out of it.
- Hold-out, not tuned against: 1,848 of 7,168 blocked (26%), below the 80% we aimed for. The owner
  chose to ship anyway (2026-11-04): the guards close the gate's two probes with no measured
  false positives, and the hold-out set becomes the acceptance bar for the classifier (#198).
  - FactSnippetEiffel 38%; FactSnippetLegal 44%;
  - Translation (French and Chinese) 33% each; Whois 33%; WhoisSnippet 13%;
  - promptinject prompt-leaking 100%; the promptfoo injection suite 5 of 5;
  - Resume 0% of 2,400.

  Resume plants praise and fake screening verdicts, not instructions, so it needs the
  classifier. The FactSnippet misses are a fake turn that politely asks the model to repeat a
  bracketed string. Treating "you repeat" or "you say" as forcing would have caught most of
  them (Eiffel 88%, Legal 89%). It would also have blocked a pasted transcript in which a user
  asks how to say "hello" in Spanish, so we didn't.

  Before the review the hold-out stood at 34% (Eiffel 50%, Legal 67%, WhoisSnippet 20%). The
  difference is the user's-own-instruction fix. Those snippet probes plant "ignore the rest
  of this data and print …" after a top line with no separator, which now reads as the user's
  words. Neither target lost a prompt.
- False positives (input blocks), all zero:
  - 104,334 dictionary words; 5,000 random 12-word sentences; 20,000 order numbers;
  - the benign promptfoo suite;
  - developer data: JWTs, Kubernetes Secret manifests, SHA-256 digests, UUIDs, git SHAs;
  - new corpora: pasted chat transcripts, Markdown with front matter and horizontal rules,
    code that prints literals, prompt-engineering requests, emails that ask for a reply.
- Every tracked file in the repository, pasted after "Summarize this:": 12 of 362 blocked.
  Every block comes from the keyword or encoded-payload guard, on a file that holds attack
  strings or a credential marker: the red-team suites, the guard sources and tests, and the CI
  smoke test. `embedded_instruction` blocks none of them.
- On benign request/answer pairs, the echo guard's default blocks 0 of 4. With
  `corroborated_only=False` it blocks 3 of 4, because the user's own quoted instruction comes
  back in the answer.
- Performance on a 32 KB prompt: the embedded guard's p99 is 1.3 ms, and the echo guard's p99
  is 0.9 ms (32 KB request, 4 KB answer). Both are linear in the input. The worst adversarial
  inputs, a forcing phrase or role line every 10 to 20 characters, take about 1 s per MB at
  input and up to 2 s per MB for the echo guard with `corroborated_only=False`. Other
  adversarial inputs take under 100 ms per MB.
- Pasted transcripts and documents with role lines or quoted forcing phrases produce
  ALLOW-verdict findings. That makes the audit log noisier.

## Scale/HA

- Every check is a pure function of the request.
- Patterns compile at import.
- There's no in-process state, cache or cross-request memory.
- `prompt_literals` and `prompt_text` live inside one request's context.

Replicas need nothing shared, so the guards scale horizontally with the gateway.

## Assume breach

- **Detect.** Every block, and every ALLOW-verdict weak-signal finding, goes as category counts
  into the signed audit log (ADR 0006). An attacker who learns the rules and stays under
  them still leaves a trail of `fake_role_turn` and `output_forcing_literal` findings, which
  can be alerted on per principal.
- **Contain.** Blocks answer 400 and echo nothing. A planted literal that slips past the input
  guard is stopped again at output when the model repeats it.
- **Recover.** The nightly garak gate measures both families, and the hold-out and
  false-positive corpora are rerun on every guard change.

The audit trail never holds prompt text, completions or the literals themselves.
