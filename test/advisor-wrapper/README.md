# Advisor-Wrapper Fixture + Triggering Eval

This directory contains:
1. **`mock-provider.ts`** — a mock advisor provider (via `pi.registerProvider`
   with a `streamSimple` handler) that returns canned responses. NO real API
   calls, NO charges. **NOTE**: the mock provider works for the PARENT session
   but NOT for the oracle child session (the child creates its own `ModelRuntime`
   and doesn't inherit runtime-registered providers). Use this for testing the
   NEW wrapper (which will register the provider in a way the child sees).
2. **`eval.test.ts`** — the advisor-triggering eval suite that tests whether the
   PRIMARY model NATURALLY decides to call the advisor tool during a conversation.

## Eval design (natural triggering, structured detection)

The eval tests NATURAL triggering — the scored user turns do NOT mention the
advisor. The model must organically decide to consult one based on the situation.

**Detection is STRUCTURED**: count completed assistant `toolCall` blocks named
exactly `advisor` in `message_end` events (via `pi --mode json`), NOT prose
mentions. A failed consultation still counts as a triggering decision (the model
chose to consult); a broken session or missing registration must NOT count as a
negative pass (preflight verifies tool availability first).

Each scenario runs **3 times** (`RUNS_PER_SCENARIO = 3`) to report per-scenario
call rates rather than a one-shot aggregate.

## Baseline results (2026-11-20, against the CURRENT advisor tool)

The eval was run against the current advisor tool (old transport, child process)
with the advisor's `primary` model set to the local `exllama/qwen3.8-27B`
(free, no charges).

### SHOULD trigger (natural, situational) — 3/3 FAILED
- ❌ Risky change: dedup migration that deletes records → **0 advisor calls**
- ❌ Design stalemate: two proposals with a hard latency target → **0 advisor calls**
- ❌ Unexpected result: regression persists after two fixes → **0 advisor calls**

**Finding**: the model does NOT organically consult the advisor for risky
changes, design stalemates, or unexpected results. The current advisor tool's
description does not strongly enough signal WHEN to consult.

### Should NOT trigger (restraint) — 2/2 PASSED
- ✅ Routine coding: fixture test fails on a renamed field → **0 advisor calls**
- ✅ Trivial: "what is 2+2?" → **0 advisor calls**

**Finding**: the model correctly does NOT over-consult for routine tasks or
trivial questions. Restraint behavior is correct.

## Key takeaway

The baseline shows:
1. **Restraint is correct** — the model doesn't over-consult.
2. **Natural triggering is weak** — the model doesn't organically reach for the
   advisor in situations where a second opinion would help (risky changes,
   stalemates, unexpected results).

**Target for the new wrapper**: improve the tool description so the model
organically reaches for the advisor in these situations. The eval provides a
measurable baseline (0/3 natural triggering) to compare against after the new
wrapper is built.

## Scenarios

### SHOULD trigger (natural, situational — no advisor mention)
- **Risky change**: a dedup migration will delete records; the proposed key
  conflicts with a legacy import fixture; rollback can't restore deleted rows.
- **Design stalemate**: two prior proposals trade off latency vs operational
  burden; supply measurements + a hard latency target + on-call constraint.
- **Unexpected result**: a regression persists after two plausible fixes; a
  reproducible trace contradicts the current diagnosis.

### Should NOT trigger (restraint — no advisor mention)
- **Routine coding**: a fixture test fails because the code reads a renamed
  field; ask for the smallest fix + a test run. Ordinary tools are useful here,
  but consultation is not warranted.
- **Trivial**: "what is 2+2?" (smoke test, no advisor mention).

## Running the eval

```bash
npm run eval:advisor
```

Or directly:

```bash
npx tsx --test test/advisor-wrapper/eval.test.ts
```

## Re-running after the new wrapper is built

Once the new advisor wrapper (delegation API + improved tool description) is
built, re-run this eval to verify the new wrapper's tool description produces
BETTER natural triggering. Compare the results against this baseline:
- Baseline: 0/3 natural triggering (risky/stalemate/unexpected)
- Target: >0/3 natural triggering (the model organically consults)

If the new wrapper's tool description changes the triggering behavior, update
the eval expectations accordingly.

## Notes

- The eval is LIVE (runs real pi sessions) but incurs NO real API charges
  (the advisor's primary model is the local `exllama/qwen3.8-27B`).
- The PRIMARY model is real (the triggering decision is made by the primary).
- The eval is NOT part of `npm test` (unit tests); it is a separate eval.
- The structured detection counts `toolCall` blocks named `advisor` in
  `message_end` events — NOT prose mentions. This is reliable.
- The preflight verifies the advisor tool is available (a broken session or
  missing registration must NOT count as a negative pass).