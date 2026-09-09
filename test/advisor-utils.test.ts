/**
 * Unit tests for the pure advisor helpers in extensions/lib/advisor-utils.ts.
 * Run with `npm test` (node --test via tsx).
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { Usage } from "@earendil-works/pi-ai";
import {
  ADVISOR_MAX_ADVICE_CHARS,
  ADVISOR_MAX_DIAGNOSTIC_CHARS,
  AdvisorEventAccumulator,
  addUsage,
  assembleRequestText,
  buildCandidates,
  capAdviceText,
  capDiagnosticText,
  capTranscriptEntries,
  createConcurrencyLimiter,
  keepEnd,
  keepStart,
  MAX_QUESTION_CHARS,
  MAX_TRANSCRIPT_ENTRY_CHARS,
  parseConfig,
  parseTarget,
  REASONING_EFFORTS,
  redactSensitiveText,
  remainingBudgetMs,
  requestCharBudget,
  resolveConsultTimeoutMs,
  splitEffortSuffix,
  TRANSCRIPT_ENTRY_CAP_MARKER,
  textFromContent,
  timeoutPrefix,
  withSlot,
} from "../extensions/lib/advisor-utils.js";

function mkUsage(input: number, output: number): Usage {
  return {
    input,
    output,
    cacheRead: 0,
    cacheWrite: 0,
    totalTokens: input + output,
    cost: { input, output, cacheRead: 0, cacheWrite: 0, total: input + output },
  };
}

const assistantMsg = (text: string, usage?: Usage) => ({
  role: "assistant",
  content: [{ type: "text", text }],
  ...(usage ? { usage } : {}),
});

const CONFIG_PATH = "/home/user/.pi/agent/advisor.json";

describe("textFromContent", () => {
  it("joins text parts and ignores non-text parts", () => {
    assert.equal(
      textFromContent([
        { type: "text", text: "a" },
        { type: "image" },
        { type: "text", text: "b" },
      ]),
      "a\nb",
    );
  });

  it("returns empty string for non-array content", () => {
    assert.equal(textFromContent("plain string"), "");
    assert.equal(textFromContent(null), "");
  });
});

describe("redactSensitiveText", () => {
  it("redacts PEM private key blocks", () => {
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----";
    assert.equal(redactSensitiveText(`before ${pem} after`), "before [REDACTED PRIVATE KEY] after");
    assert.doesNotMatch(redactSensitiveText(pem), /MIIEpAIB/);
  });

  it("redacts Authorization headers, with and without Bearer", () => {
    assert.equal(
      redactSensitiveText("Authorization: Bearer abc.def.ghi"),
      "Authorization: [REDACTED]",
    );
    assert.equal(redactSensitiveText("authorization=rawtoken123"), "authorization=[REDACTED]");
  });

  it("redacts quoted and bare key/value assignments", () => {
    assert.equal(redactSensitiveText('password: "s3cret value"'), "password: [REDACTED]");
    assert.equal(redactSensitiveText("api_key='sh h'"), "api_key=[REDACTED]");
    assert.equal(redactSensitiveText("client_secret = hunter2"), "client_secret = [REDACTED]");
    assert.equal(redactSensitiveText("pwd=abc123"), "pwd=[REDACTED]");
  });

  it("redacts well-known token prefixes", () => {
    assert.equal(redactSensitiveText("ghp_" + "A1b2C3d4E5f6G7h8I9j0"), "[REDACTED TOKEN]");
    assert.equal(redactSensitiveText("sk-" + "Abcdef1234567890XYZ"), "[REDACTED TOKEN]");
    assert.equal(redactSensitiveText("xoxb-" + "12345678901234567890"), "[REDACTED TOKEN]");
    assert.equal(redactSensitiveText("key: AKIAABCDEFGHIJKLMNOP"), "key: [REDACTED TOKEN]");
  });

  it("leaves ordinary key: value YAML and prose intact", () => {
    const yaml = ["database:", "  host: localhost", "  port: 5432", "reasoningEffort: high"].join(
      "\n",
    );
    assert.equal(redactSensitiveText(yaml), yaml);
  });

  it("does not treat identifiers like password_reset_url as secrets", () => {
    const line = "password_reset_url: https://example.com/reset";
    assert.equal(redactSensitiveText(line), line);
  });

  it("does not redact secret-key words in prose without an assignment", () => {
    assert.equal(
      redactSensitiveText("the password policy was updated"),
      "the password policy was updated",
    );
    assert.equal(redactSensitiveText("keep it secret"), "keep it secret");
  });
});

describe("keepEnd / keepStart", () => {
  const marker = "[…omitted…]";

  it("returns text unchanged when it fits", () => {
    assert.equal(keepEnd("abc", 10, marker), "abc");
    assert.equal(keepStart("abc", 10, marker), "abc");
  });

  it("keepEnd keeps the tail with the marker at the front", () => {
    // marker is 11 chars; keepEnd returns marker + (maxChars - marker.length) tail chars.
    const text = "abcdefghijklmnopqrst"; // 20 chars
    assert.equal(keepEnd(text, 15, marker), `${marker}qrst`);
    assert.equal(keepEnd(text, 15, marker).length, 15);
  });

  it("keepStart keeps the head with the marker at the end", () => {
    const text = "abcdefghijklmnopqrst"; // 20 chars
    assert.equal(keepStart(text, 15, marker), `abcd${marker}`);
    assert.equal(keepStart(text, 15, marker).length, 15);
  });

  it("degrades to a bare truncated marker when maxChars <= marker length", () => {
    assert.equal(keepEnd("abcdefgh", 3, marker), marker.slice(0, 3));
    assert.equal(keepStart("abcdefgh", 3, marker), marker.slice(0, 3));
    assert.equal(keepEnd("abcdefgh", 0, marker), "");
  });
});

describe("requestCharBudget", () => {
  it("falls back to MAX_QUESTION_CHARS when the context window is unusable", () => {
    assert.equal(requestCharBudget({ contextWindow: 0 }, 1000), MAX_QUESTION_CHARS);
    assert.equal(requestCharBudget({ contextWindow: Number.NaN }, 1000), MAX_QUESTION_CHARS);
    assert.equal(requestCharBudget({ contextWindow: -5 }, 1000), MAX_QUESTION_CHARS);
  });

  it("reserves room for the response and subtracts the prompt", () => {
    // contextWindow 128000, maxTokens 4096 → reserve 4096, input 123904 tokens.
    const budget = requestCharBudget({ contextWindow: 128_000, maxTokens: 4_096 }, 1_000);
    assert.equal(budget, Math.floor(123_904 * 3.5) - 1_000);
  });

  it("uses a proportional 20% reserve when maxTokens is absent", () => {
    // contextWindow 20000 → reserve max(1024, 4000) = 4000, input 16000 tokens.
    assert.equal(requestCharBudget({ contextWindow: 20_000 }, 500), 16_000 * 3.5 - 500);
  });

  it("never returns less than 512 chars", () => {
    assert.equal(requestCharBudget({ contextWindow: 1_000, maxTokens: 100 }, 50_000), 512);
  });
});

describe("capTranscriptEntries", () => {
  it("caps each entry individually before joining", () => {
    const big = "x".repeat(MAX_TRANSCRIPT_ENTRY_CHARS + 100);
    const out = capTranscriptEntries(["small", big, "y".repeat(MAX_TRANSCRIPT_ENTRY_CHARS + 1)]);
    assert.equal(out[0], "small");
    assert.equal(out[1].length, MAX_TRANSCRIPT_ENTRY_CHARS);
    assert.ok(out[1].startsWith("xxx"), "entry keeps its head");
    assert.ok(out[1].endsWith(TRANSCRIPT_ENTRY_CAP_MARKER));
    assert.equal(out[2].endsWith(TRANSCRIPT_ENTRY_CAP_MARKER), true);
  });

  it("leaves short entries untouched", () => {
    assert.deepEqual(capTranscriptEntries(["a", "b c"]) as string[], ["a", "b c"]);
  });
});

describe("redact-then-cap (sessionTranscript entry pipeline)", () => {
  it("redacts a PEM block whose closing delimiter would be severed by the cap", () => {
    // The PEM block starts near the head of a huge tool result: capping the
    // entry BEFORE redaction would cut the "-----END ...-----" line, and the
    // block-level redactor would then leave the key material exposed.
    const pem = `-----BEGIN RSA PRIVATE KEY-----\n${"A".repeat(2_000)}\n-----END RSA PRIVATE KEY-----`;
    const entry = `read result follows:\n${pem}\n${"x".repeat(MAX_TRANSCRIPT_ENTRY_CHARS * 3)}`;
    // The pipeline sessionTranscript uses: redact the complete entry, then cap.
    const redacted = redactSensitiveText(entry);
    assert.doesNotMatch(redacted, /A{100}/, "redaction must remove the key body");
    const [capped] = capTranscriptEntries([redacted]);
    assert.doesNotMatch(capped, /A{100}/, "capping after redaction must not expose key material");
    assert.doesNotMatch(capped, /BEGIN RSA/, "no raw PEM header survives");
  });

  it("shows why capping before redaction would leak", () => {
    // Counter-factual: cap first (the old, buggy order) severs the END line,
    // so the block-level redactor no longer matches the incomplete block.
    const pem = `-----BEGIN RSA PRIVATE KEY-----\n${"A".repeat(MAX_TRANSCRIPT_ENTRY_CHARS + 200)}\n-----END RSA PRIVATE KEY-----`;
    const entry = `\n${pem}`;
    const [cappedFirst] = capTranscriptEntries([entry]);
    const redactedLate = redactSensitiveText(cappedFirst);
    assert.match(redactedLate, /A{100}/, "capping before redaction exposes key material");
  });
});

describe("assembleRequestText", () => {
  const smallModel = { contextWindow: 4_000, maxTokens: 800 };
  const promptChars = 0;

  it("includes the question and transcript under the optional-context header when they fit", () => {
    const out = assembleRequestText(smallModel, "the question", "the transcript", promptChars);
    assert.ok(out.startsWith("## Question\nthe question"));
    assert.ok(
      out.includes(
        "## Optional context supplied by the caller (redacted, may be truncated; verify against the workspace)",
      ),
    );
    assert.ok(out.includes("the transcript"));
    assert.doesNotMatch(out, /Omitted/);
  });

  it("sends only the question when no transcript was supplied", () => {
    const out = assembleRequestText(smallModel, "the question", "", promptChars);
    assert.ok(out.startsWith("## Question\nthe question"));
    assert.doesNotMatch(out, /session history/);
    assert.doesNotMatch(out, /Optional context/);
    assert.doesNotMatch(out, /Omitted/);
  });

  it("drops the transcript entirely when it cannot coexist with the full question", () => {
    // Budget (~2.4k chars) < question (30k): the transcript must not survive,
    // and the question (not the transcript) absorbs the truncation.
    const question = "Q".repeat(30_000);
    const transcript = "t".repeat(12_000);
    const out = assembleRequestText(smallModel, question, transcript, promptChars);
    const budget = requestCharBudget(smallModel, promptChars);
    assert.ok(out.length <= budget);
    assert.doesNotMatch(out, /ttt/, "transcript dropped to make room for the question");
    assert.doesNotMatch(out, /Optional context/);
    assert.ok(out.includes("\nQQQ"), "question keeps its head");
    assert.ok(out.includes("[Omitted to fit the advisor model's context window.]"));
  });

  it("fits the budget when the question consumes it all and drops the transcript", () => {
    // A question larger than the whole budget leaves no room for ANY
    // transcript: it is dropped, and the question is truncated to fit.
    const tinyModel = { contextWindow: 200, maxTokens: 100 }; // budget = 1792 chars
    const out = assembleRequestText(tinyModel, "q".repeat(2_000), "t".repeat(5_000), 0);
    const budget = requestCharBudget(tinyModel, 0);
    assert.ok(out.length <= budget);
    assert.doesNotMatch(out, /ttt/, "no room for even a truncated transcript");
    assert.doesNotMatch(out, /Optional context/);
    assert.ok(out.includes("\nqqq"), "question keeps its head");
  });

  it("keeps a truncated transcript tail when it partially fits beside the question", () => {
    const question = "q".repeat(100);
    const transcript = "t".repeat(11_000);
    const out = assembleRequestText(smallModel, question, transcript, promptChars);
    const budget = requestCharBudget(smallModel, promptChars);
    assert.ok(out.length <= budget);
    assert.ok(out.includes(question), "full question survives");
    assert.ok(out.includes("[Earlier session context omitted.]"));
    assert.ok(out.includes("ttt"), "tail of the transcript is kept");
  });

  it("truncates the question alone when there is no transcript", () => {
    const question = "Q".repeat(30_000);
    const out = assembleRequestText(smallModel, question, "", promptChars);
    const budget = requestCharBudget(smallModel, promptChars);
    assert.ok(out.length <= budget);
    assert.ok(out.includes("\nQQQ"), "question keeps its head");
    assert.ok(out.includes("[Omitted to fit the advisor model's context window.]"));
  });
});

describe("splitEffortSuffix", () => {
  it("splits a valid @effort suffix", () => {
    assert.deepEqual(splitEffortSuffix("openai-codex/gpt-6-astra@max"), {
      base: "openai-codex/gpt-6-astra",
      effort: "max",
    });
    assert.deepEqual(splitEffortSuffix("anthropic/claude-4@low"), {
      base: "anthropic/claude-4",
      effort: "low",
    });
  });

  it("returns no effort for specs without a suffix", () => {
    assert.deepEqual(splitEffortSuffix("gpt-6"), { base: "gpt-6", effort: undefined });
    // "@" at position 0 is not a suffix.
    assert.deepEqual(splitEffortSuffix("@max"), { base: "@max", effort: undefined });
  });

  it("accepts every documented effort", () => {
    for (const effort of REASONING_EFFORTS) {
      assert.deepEqual(splitEffortSuffix(`m@${effort}`), { base: "m", effort });
    }
  });

  it("rejects invalid suffixes with an actionable message", () => {
    assert.throws(
      () => splitEffortSuffix("model@turbo"),
      /Invalid advisor effort "turbo" in "model@turbo". Expected one of: none, minimal, low, medium, high, xhigh, max or no suffix\./,
    );
    assert.throws(() => splitEffortSuffix("model@"), /Invalid advisor effort ""/);
  });
});

describe("buildCandidates", () => {
  it("treats an explicit provider/model selection as the whole chain", () => {
    const { candidates, explicit } = buildCandidates({
      provider: "openai-codex",
      modelId: "gpt-6",
      config: { primary: { model: "other" } },
      activeModel: { provider: "anthropic", id: "claude-4" },
    });
    assert.equal(explicit, true);
    assert.deepEqual(candidates, [
      { target: { provider: "openai-codex", model: "gpt-6" }, source: "explicit" },
    ]);
  });

  it("orders configured slots primary then fallback, plus the active model only when opted in", () => {
    const { candidates, explicit } = buildCandidates({
      provider: undefined,
      modelId: undefined,
      config: {
        primary: { provider: "a", model: "m1" },
        fallback: { model: "m2" },
        activeModelFallback: true,
      },
      activeModel: { provider: "b", id: "active" },
    });
    assert.equal(explicit, false);
    assert.deepEqual(
      candidates.map((c) => c.source),
      ["config primary", "config fallback", "active model fallback"],
    );
    assert.deepEqual(candidates[2].target, { provider: "b", model: "active" });
  });

  it("never appends the active model unless activeModelFallback is enabled", () => {
    const { candidates } = buildCandidates({
      provider: undefined,
      modelId: undefined,
      config: { primary: { model: "m1" } },
      activeModel: { provider: "b", id: "active" },
    });
    assert.deepEqual(
      candidates.map((c) => c.source),
      ["config primary"],
    );
  });

  it("returns an empty chain when nothing is configured (no implicit model)", () => {
    const { candidates, explicit } = buildCandidates({
      provider: undefined,
      modelId: undefined,
      config: {},
      activeModel: { provider: "b", id: "active" },
    });
    assert.equal(explicit, false);
    assert.deepEqual(candidates, []);
  });

  it("does not duplicate the active model when it is already in the chain", () => {
    const { candidates } = buildCandidates({
      provider: undefined,
      modelId: undefined,
      config: { primary: { provider: "a", model: "active" }, activeModelFallback: true },
      activeModel: { provider: "a", id: "active" },
    });
    assert.deepEqual(
      candidates.map((c) => c.source),
      ["config primary"],
    );
    // A config slot without a provider still dedupes by model id.
    const { candidates: noProvider } = buildCandidates({
      provider: undefined,
      modelId: undefined,
      config: { primary: { model: "active" }, activeModelFallback: true },
      activeModel: { provider: "a", id: "active" },
    });
    assert.deepEqual(
      noProvider.map((c) => c.source),
      ["config primary"],
    );
  });

  it("rejects an explicit provider without a model id", () => {
    assert.throws(
      () =>
        buildCandidates({
          provider: "openai-codex",
          modelId: undefined,
          config: {},
          activeModel: undefined,
        }),
      /An explicit advisor selection needs a model id/,
    );
  });
});

describe("parseTarget", () => {
  it("parses a valid target and trims whitespace", () => {
    assert.deepEqual(
      parseTarget({ provider: " p ", model: " m ", effort: "high" }, "primary", CONFIG_PATH),
      {
        provider: "p",
        model: "m",
        effort: "high",
      },
    );
  });

  it("returns undefined for an absent slot", () => {
    assert.equal(parseTarget(undefined, "primary", CONFIG_PATH), undefined);
  });

  it("rejects non-object values with an actionable message", () => {
    assert.throws(
      () => parseTarget("gpt-6", "primary", CONFIG_PATH),
      new RegExp(`${CONFIG_PATH}: primary must be an object.`),
    );
  });

  it("rejects a missing or empty model", () => {
    assert.throws(
      () => parseTarget({}, "fallback", CONFIG_PATH),
      new RegExp(`${CONFIG_PATH}: fallback.model must be a non-empty string.`),
    );
    assert.throws(
      () => parseTarget({ model: "  " }, "primary", CONFIG_PATH),
      new RegExp(`${CONFIG_PATH}: primary.model must be a non-empty string.`),
    );
  });

  it("rejects an empty or non-string provider", () => {
    assert.throws(
      () => parseTarget({ model: "m", provider: "" }, "primary", CONFIG_PATH),
      new RegExp(`${CONFIG_PATH}: primary.provider must be a non-empty string when provided.`),
    );
  });

  it("rejects an invalid effort by naming the allowed values", () => {
    assert.throws(
      () => parseTarget({ model: "m", effort: "turbo" }, "primary", CONFIG_PATH),
      new RegExp(
        `${CONFIG_PATH}: primary.effort must be one of: none, minimal, low, medium, high, xhigh, max.`,
      ),
    );
  });
});

describe("parseConfig", () => {
  it("rejects non-object top levels", () => {
    assert.throws(
      () => parseConfig(null, CONFIG_PATH),
      new RegExp(`${CONFIG_PATH}: top level must be an object.`),
    );
    assert.throws(
      () => parseConfig("a string", CONFIG_PATH),
      new RegExp(`${CONFIG_PATH}: top level must be an object.`),
    );
  });

  it("parses a fully valid config", () => {
    assert.deepEqual(
      parseConfig(
        {
          primary: { provider: "a", model: "m1", effort: "low" },
          fallback: { model: "m2" },
          reasoningEffort: "high",
          activeModelFallback: true,
          timeoutMs: 120_000,
        },
        CONFIG_PATH,
      ),
      {
        primary: { provider: "a", model: "m1", effort: "low" },
        // parseTarget returns explicit undefined keys for absent sub-fields.
        fallback: { provider: undefined, model: "m2", effort: undefined },
        reasoningEffort: "high",
        activeModelFallback: true,
        timeoutMs: 120_000,
      },
    );
  });

  it("parses an empty config (absent slots stay undefined)", () => {
    const config = parseConfig({}, CONFIG_PATH);
    assert.equal(config.primary, undefined);
    assert.equal(config.fallback, undefined);
    assert.equal(config.reasoningEffort, undefined);
    assert.equal(config.activeModelFallback, undefined);
  });

  it("rejects a non-boolean activeModelFallback", () => {
    assert.throws(
      () => parseConfig({ activeModelFallback: "yes" }, CONFIG_PATH),
      new RegExp(`${CONFIG_PATH}: activeModelFallback must be a boolean.`),
    );
  });

  it("rejects unknown top-level keys, naming them", () => {
    assert.throws(
      () => parseConfig({ fallBack: { model: "m" } }, CONFIG_PATH),
      new RegExp(`${CONFIG_PATH}: unknown key \\"fallBack\\" \\(allowed:`),
    );
    assert.throws(
      () => parseConfig({ reasoning_effort: "high", exploreBudgget: {} }, CONFIG_PATH),
      /unknown keys "reasoning_effort", "exploreBudgget"/,
    );
  });

  it("rejects unknown keys inside a model slot", () => {
    assert.throws(
      () => parseConfig({ primary: { model: "m", providerd: "a" } }, CONFIG_PATH),
      /primary has unknown key "providerd" \(allowed: provider, model, effort\)/,
    );
  });

  it("rejects the removed exploreBudget key as an unknown key", () => {
    assert.throws(
      () => parseConfig({ exploreBudget: { toolCalls: 5 } }, CONFIG_PATH),
      /unknown key "exploreBudget" \(allowed: primary, fallback, reasoningEffort, activeModelFallback, timeoutMs\)/,
    );
  });

  it("rejects primary === fallback (same model would just rerun)", () => {
    assert.throws(
      () =>
        parseConfig(
          {
            primary: { provider: "a", model: "m" },
            fallback: { provider: "a", model: "m" },
          },
          CONFIG_PATH,
        ),
      /primary and fallback are the same model \("a\/m"\)/,
    );
    // An absent provider still matches: same model id is the same model.
    assert.throws(
      () =>
        parseConfig(
          { primary: { model: "m" }, fallback: { provider: "a", model: "m" } },
          CONFIG_PATH,
        ),
      /primary and fallback are the same model/,
    );
    // Different providers for the same model id are different models — allowed.
    assert.doesNotThrow(() =>
      parseConfig(
        { primary: { provider: "a", model: "m" }, fallback: { provider: "b", model: "m" } },
        CONFIG_PATH,
      ),
    );
  });

  it("treats whitespace-padded model ids as the same model", () => {
    assert.throws(
      () =>
        parseConfig(
          { primary: { provider: "a", model: " m " }, fallback: { model: "m" } },
          CONFIG_PATH,
        ),
      /primary and fallback are the same model/,
    );
  });

  it("rejects an invalid timeoutMs", () => {
    for (const bad of ["fast", -1, 0, NaN, Infinity]) {
      assert.throws(
        () => parseConfig({ timeoutMs: bad }, CONFIG_PATH),
        new RegExp(`${CONFIG_PATH}: timeoutMs must be a positive number of milliseconds.`),
      );
    }
  });

  it("rejects an invalid global reasoningEffort", () => {
    assert.throws(
      () => parseConfig({ reasoningEffort: "turbo" }, CONFIG_PATH),
      new RegExp(
        `${CONFIG_PATH}: reasoningEffort must be one of: none, minimal, low, medium, high, xhigh, max.`,
      ),
    );
  });

  it("propagates slot validation errors", () => {
    assert.throws(
      () => parseConfig({ primary: "not-an-object" }, CONFIG_PATH),
      new RegExp(`${CONFIG_PATH}: primary must be an object.`),
    );
    assert.throws(
      () => parseConfig({ fallback: { model: "m", effort: "ultra" } }, CONFIG_PATH),
      new RegExp(`${CONFIG_PATH}: fallback.effort must be one of:`),
    );
  });
});

describe("capAdviceText / capDiagnosticText", () => {
  it("passes through text at or under the ceiling unchanged", () => {
    assert.equal(capAdviceText("short"), "short");
    assert.equal(
      capAdviceText("x".repeat(ADVISOR_MAX_ADVICE_CHARS)),
      "x".repeat(ADVISOR_MAX_ADVICE_CHARS),
    );
    assert.equal(capDiagnosticText("err"), "err");
    assert.equal(
      capDiagnosticText("e".repeat(ADVISOR_MAX_DIAGNOSTIC_CHARS)),
      "e".repeat(ADVISOR_MAX_DIAGNOSTIC_CHARS),
    );
  });

  it("truncates advice with a visible marker naming the omitted amount", () => {
    const text = "a".repeat(ADVISOR_MAX_ADVICE_CHARS + 1_500);
    const capped = capAdviceText(text);
    assert.ok(capped.startsWith("a".repeat(ADVISOR_MAX_ADVICE_CHARS)));
    assert.ok(capped.includes("[truncated: 1500 more characters omitted]"));
    assert.equal(
      capped.length,
      ADVISOR_MAX_ADVICE_CHARS + "\n\n[truncated: 1500 more characters omitted]".length,
    );
  });

  it("truncates diagnostics at the much tighter 4k ceiling", () => {
    const text = "e".repeat(ADVISOR_MAX_DIAGNOSTIC_CHARS + 10);
    const capped = capDiagnosticText(text);
    assert.ok(capped.includes("[truncated: 10 more characters omitted]"));
    assert.ok(capped.length < ADVISOR_MAX_ADVICE_CHARS);
  });
});

describe("resolveConsultTimeoutMs", () => {
  it("falls back to the mode default when nothing is set", () => {
    assert.equal(resolveConsultTimeoutMs({ mode: "review" }), 5 * 60_000);
    assert.equal(resolveConsultTimeoutMs({ mode: "explore" }), 10 * 60_000);
  });

  it("prefers per-call over config", () => {
    assert.equal(
      resolveConsultTimeoutMs({ perCall: 60_000, config: 300_000, mode: "review" }),
      60_000,
    );
    assert.equal(resolveConsultTimeoutMs({ config: 300_000, mode: "review" }), 300_000);
  });

  it("clamps to the documented 30 s..30 min range", () => {
    assert.equal(resolveConsultTimeoutMs({ perCall: 1, mode: "review" }), 30_000);
    assert.equal(resolveConsultTimeoutMs({ perCall: 10_000_000, mode: "review" }), 30 * 60_000);
    assert.equal(resolveConsultTimeoutMs({ config: 10, mode: "explore" }), 30_000);
  });
});

describe("remainingBudgetMs", () => {
  it("reports the time left on a deadline, floored at 0", () => {
    assert.equal(remainingBudgetMs(100, 40), 60);
    assert.equal(remainingBudgetMs(100, 100), 0);
    assert.equal(remainingBudgetMs(100, 150), 0);
  });
});

function abortedSignal(): AbortSignal {
  const controller = new AbortController();
  controller.abort();
  return controller.signal;
}

async function withTimeout(promise: Promise<void>): Promise<void> {
  await Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error("slot never freed")), 500)),
  ]);
}

describe("withSlot", () => {
  it("runs the work and releases the slot, even when the work throws", async () => {
    const limiter = createConcurrencyLimiter(1);
    await assert.rejects(
      withSlot(limiter, undefined, async () => {
        throw new Error("boom");
      }),
      /boom/,
    );
    // Slot must be free again: this acquire resolves immediately.
    await withTimeout(limiter.acquire());
    limiter.release();
  });

  it("refuses to start work when aborted while queued (the slot is released)", async () => {
    const limiter = createConcurrencyLimiter(1);
    await withTimeout(limiter.acquire()); // hold the only slot
    const controller = new AbortController();
    let started = false;
    const queued = withSlot(limiter, controller.signal, async () => {
      started = true;
      return "done";
    });
    controller.abort();
    limiter.release(); // let the queued waiter acquire
    await assert.rejects(queued, /aborted before the consultation started/);
    assert.equal(started, false);
    // Slot was released after the refusal: a fresh acquire resolves immediately.
    await withTimeout(limiter.acquire());
    limiter.release();
  });

  it("refuses immediately when the signal is already aborted, without consuming a slot", async () => {
    const limiter = createConcurrencyLimiter(1);
    let started = false;
    const rejected = withSlot(limiter, abortedSignal(), () => {
      started = true;
      return Promise.resolve("done");
    });
    // The slot was never taken: this acquire resolves immediately, in parallel.
    await withTimeout(limiter.acquire());
    await assert.rejects(rejected, /aborted before the consultation started/);
    assert.equal(started, false);
    limiter.release();
  });
});

describe("createConcurrencyLimiter", () => {
  it("allows up to max concurrent acquisitions", async () => {
    const limiter = createConcurrencyLimiter(2);
    await limiter.acquire();
    await limiter.acquire();
    // The third must wait; it resolves only after a release.
    let thirdResolved = false;
    const third = limiter.acquire().then(() => {
      thirdResolved = true;
    });
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(thirdResolved, false);
    limiter.release();
    await third;
    assert.equal(thirdResolved, true);
    limiter.release();
    limiter.release();
  });

  it("queues waiters in FIFO order and never rejects", async () => {
    const limiter = createConcurrencyLimiter(1);
    const order: string[] = [];
    await limiter.acquire();
    const a = limiter.acquire().then(() => {
      order.push("a");
    });
    const b = limiter.acquire().then(() => {
      order.push("b");
    });
    const c = limiter.acquire().then(() => {
      order.push("c");
    });
    limiter.release(); // hands the slot to a
    await a;
    limiter.release(); // hands the slot to b
    await b;
    limiter.release(); // hands the slot to c
    await c;
    assert.deepEqual(order, ["a", "b", "c"]);
  });

  it("a released slot is reusable even when the work threw (the withAdvisorSlot contract)", async () => {
    const limiter = createConcurrencyLimiter(1);
    const withSlot = async (work: () => Promise<void>) => {
      await limiter.acquire();
      try {
        await work();
      } finally {
        limiter.release();
      }
    };
    await withSlot(async () => {});
    await assert.rejects(
      withSlot(async () => {
        throw new Error("boom");
      }),
      /boom/,
    );
    // The failed work's finally still released the slot, so this completes.
    await withSlot(async () => {});
  });
});

describe("addUsage", () => {
  it("sums usages and preserves absent optional fields", () => {
    const sum = addUsage(mkUsage(1, 2), mkUsage(3, 4));
    assert.equal(sum.input, 4);
    assert.equal(sum.output, 6);
    assert.equal(sum.totalTokens, 10);
    assert.equal(sum.cost.total, 10);
    assert.equal(sum.reasoning, undefined);
    const withReasoning = addUsage({ ...mkUsage(1, 2), reasoning: 5 }, mkUsage(3, 4));
    assert.equal(withReasoning.reasoning, 5);
  });
});

describe("AdvisorEventAccumulator", () => {
  it("keeps earlier findings when the interrupted final assistant turn is empty", () => {
    const acc = new AdvisorEventAccumulator();
    acc.record({ type: "turn_start" });
    acc.record({ type: "message_end", message: assistantMsg("finding one", mkUsage(1, 1)) });
    acc.record({ type: "tool_execution_start", toolName: "grep" });
    acc.record({ type: "turn_start" });
    // The interrupted final turn: assistant message with no text (thinking/tools only).
    acc.record({ type: "message_end", message: { role: "assistant", content: [] } });
    assert.equal(acc.toolCalls, 1);
    assert.equal(acc.modelRequests, 2);
    assert.equal(acc.finalText(true), "finding one");
    // A completed run reports the final answer.
    assert.equal(acc.finalText(false), "");
  });

  it("survives a synthetic failure agent_end carrying only an empty message", () => {
    const acc = new AdvisorEventAccumulator();
    acc.record({ type: "turn_start" });
    acc.record({ type: "message_end", message: assistantMsg("early analysis", mkUsage(2, 3)) });
    // agent_end after an exception contains only the (empty) failure message —
    // it must not discard the collected text or usage.
    acc.record({
      type: "agent_end",
      messages: [{ role: "assistant", content: [] }],
    });
    assert.equal(acc.finalText(true), "early analysis");
    assert.equal(acc.usage?.output, 3);
  });

  it("aggregates usage per assistant message_end, never from agent_end", () => {
    const acc = new AdvisorEventAccumulator();
    acc.record({ type: "turn_start" });
    acc.record({ type: "message_end", message: assistantMsg("a", mkUsage(1, 1)) });
    acc.record({ type: "message_end", message: assistantMsg("b", mkUsage(2, 2)) });
    acc.record({
      type: "agent_end",
      messages: [assistantMsg("a", mkUsage(1, 1)), assistantMsg("b", mkUsage(2, 2))],
    });
    assert.equal(acc.usage?.input, 3);
    assert.equal(acc.usage?.output, 3);
  });

  it("completed runs report the last assistant text; duplicates are not repeated", () => {
    const acc = new AdvisorEventAccumulator();
    acc.record({ type: "message_end", message: assistantMsg("answer") });
    acc.record({ type: "message_end", message: assistantMsg("answer") });
    assert.equal(acc.finalText(false), "answer");
    assert.equal(acc.finalText(true), "answer");
  });
});

describe("timeoutPrefix", () => {
  it("marks explore and review timeouts incomplete, with or without partial output", () => {
    assert.equal(
      timeoutPrefix("explore", 60_000, ""),
      "advisor timed out after 60 seconds (incomplete)",
    );
    assert.equal(
      timeoutPrefix("review", 30_000, ""),
      "advisor request timed out after 30 seconds (incomplete)",
    );
    const withPartial = timeoutPrefix("explore", 90_000, "partial text");
    assert.ok(withPartial.includes("advisor timed out after 90 seconds (incomplete)"));
    assert.ok(
      withPartial.includes("Partial output before the timeout (incomplete, not a verdict):"),
    );
  });
});
