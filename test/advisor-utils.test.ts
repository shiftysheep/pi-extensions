/**
 * Unit tests for the pure advisor helpers in extensions/lib/advisor-utils.ts.
 * Run with `npm test` (node --test via tsx).
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  ADVISOR_MAX_ADVICE_CHARS,
  ADVISOR_MAX_DIAGNOSTIC_CHARS,
  ADVISOR_MAX_MODEL_REQUESTS,
  ADVISOR_MAX_TOOL_CALLS,
  assembleRequestText,
  buildCandidates,
  capAdviceText,
  capDiagnosticText,
  createConcurrencyLimiter,
  keepEnd,
  keepStart,
  MAX_QUESTION_CHARS,
  parseConfig,
  parseExploreBudget,
  parseTarget,
  REASONING_EFFORTS,
  redactSensitiveText,
  requestCharBudget,
  resolveConsultTimeoutMs,
  splitEffortSuffix,
  textFromContent,
} from "../extensions/lib/advisor-utils.js";

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

describe("assembleRequestText", () => {
  const smallModel = { contextWindow: 4_000, maxTokens: 800 };
  const promptChars = 0;

  it("includes the question and transcript verbatim when they fit", () => {
    const out = assembleRequestText(smallModel, "the question", "the transcript", promptChars);
    assert.ok(out.startsWith("## Question\nthe question"));
    assert.ok(out.includes("the transcript"));
    assert.doesNotMatch(out, /Omitted/);
  });

  it("shrinks the transcript before touching the question", () => {
    const question = "q".repeat(100);
    const transcript = "t".repeat(11_000);
    const out = assembleRequestText(smallModel, question, transcript, promptChars);
    const budget = requestCharBudget(smallModel, promptChars);
    assert.ok(out.length <= budget);
    assert.ok(out.includes(question), "question must survive transcript shrinking");
    assert.ok(out.includes("[Earlier session context omitted.]"));
    assert.ok(out.includes("ttt"), "tail of the transcript is kept");
  });

  it("truncates the question only when the transcript cannot absorb the overflow", () => {
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

describe("parseExploreBudget", () => {
  it("returns undefined when unset", () => {
    assert.equal(parseExploreBudget(undefined, CONFIG_PATH), undefined);
  });

  it("fills the missing field with the default", () => {
    assert.deepEqual(parseExploreBudget({ toolCalls: 10 }, CONFIG_PATH), {
      toolCalls: 10,
      modelRequests: ADVISOR_MAX_MODEL_REQUESTS,
    });
    assert.deepEqual(parseExploreBudget({ modelRequests: 3 }, CONFIG_PATH), {
      toolCalls: ADVISOR_MAX_TOOL_CALLS,
      modelRequests: 3,
    });
  });

  it("rejects non-object and empty budgets", () => {
    assert.throws(
      () => parseExploreBudget("x", CONFIG_PATH),
      new RegExp(`${CONFIG_PATH}: exploreBudget must be an object with toolCalls/modelRequests.`),
    );
    assert.throws(
      () => parseExploreBudget({}, CONFIG_PATH),
      new RegExp(`${CONFIG_PATH}: exploreBudget requires at least one of toolCalls/modelRequests.`),
    );
  });

  it("rejects values that are not positive integers", () => {
    assert.throws(
      () => parseExploreBudget({ toolCalls: 0 }, CONFIG_PATH),
      new RegExp(`${CONFIG_PATH}: exploreBudget.toolCalls must be a positive integer.`),
    );
    assert.throws(
      () => parseExploreBudget({ toolCalls: 2.5 }, CONFIG_PATH),
      new RegExp(`${CONFIG_PATH}: exploreBudget.toolCalls must be a positive integer.`),
    );
  });

  it("rejects values above the hard ceilings", () => {
    assert.throws(
      () => parseExploreBudget({ toolCalls: 101 }, CONFIG_PATH),
      new RegExp(`${CONFIG_PATH}: exploreBudget.toolCalls must be at most 100.`),
    );
    assert.throws(
      () => parseExploreBudget({ modelRequests: 41 }, CONFIG_PATH),
      new RegExp(`${CONFIG_PATH}: exploreBudget.modelRequests must be at most 40.`),
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
          exploreBudget: { toolCalls: 5 },
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
        exploreBudget: { toolCalls: 5, modelRequests: ADVISOR_MAX_MODEL_REQUESTS },
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
    assert.equal(config.exploreBudget, undefined);
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

  it("rejects unknown keys inside a model slot and exploreBudget", () => {
    assert.throws(
      () => parseConfig({ primary: { model: "m", providerd: "a" } }, CONFIG_PATH),
      /primary has unknown key "providerd" \(allowed: provider, model, effort\)/,
    );
    assert.throws(
      () => parseConfig({ exploreBudget: { toolCall: 5 } }, CONFIG_PATH),
      /exploreBudget has unknown key "toolCall" \(allowed: toolCalls, modelRequests\)/,
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
