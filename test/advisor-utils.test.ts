/**
 * Unit tests for the pure advisor helpers in extensions/lib/advisor-utils.ts.
 * Run with `npm test` (node --test via tsx).
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  ADVISOR_MAX_MODEL_REQUESTS,
  ADVISOR_MAX_TOOL_CALLS,
  assembleRequestText,
  buildCandidates,
  keepEnd,
  keepStart,
  MAX_QUESTION_CHARS,
  parseConfig,
  parseExploreBudget,
  parseTarget,
  REASONING_EFFORTS,
  redactSensitiveText,
  requestCharBudget,
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

  it("orders configured slots primary then fallback, then the active model", () => {
    const { candidates, explicit } = buildCandidates({
      provider: undefined,
      modelId: undefined,
      config: {
        primary: { provider: "a", model: "m1" },
        fallback: { model: "m2" },
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

  it("falls back to the built-in preference when nothing is configured", () => {
    const { candidates } = buildCandidates({
      provider: undefined,
      modelId: undefined,
      config: {},
      activeModel: undefined,
    });
    assert.equal(candidates.length, 1);
    assert.equal(candidates[0].source, "built-in preference");
    assert.equal(candidates[0].target.model, "gpt-5.6-sol");
  });

  it("does not duplicate the active model when it is already in the chain", () => {
    const { candidates } = buildCandidates({
      provider: undefined,
      modelId: undefined,
      config: { primary: { provider: "a", model: "active" } },
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
      config: { primary: { model: "active" } },
      activeModel: { provider: "a", id: "active" },
    });
    assert.deepEqual(
      noProvider.map((c) => c.source),
      ["config primary"],
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
        },
        CONFIG_PATH,
      ),
      {
        primary: { provider: "a", model: "m1", effort: "low" },
        // parseTarget returns explicit undefined keys for absent sub-fields.
        fallback: { provider: undefined, model: "m2", effort: undefined },
        reasoningEffort: "high",
        exploreBudget: { toolCalls: 5, modelRequests: ADVISOR_MAX_MODEL_REQUESTS },
      },
    );
  });

  it("parses an empty config (absent slots stay undefined)", () => {
    const config = parseConfig({}, CONFIG_PATH);
    assert.equal(config.primary, undefined);
    assert.equal(config.fallback, undefined);
    assert.equal(config.reasoningEffort, undefined);
    assert.equal(config.exploreBudget, undefined);
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
