/**
 * Executor-level tests for advisorExecute and attemptCandidate (execute.ts).
 *
 * These tests verify the fallback-chain orchestration, the disclosure flags
 * (fallbackFrom, independent=false), and the error paths (explicit lookup
 * failure vs consultation failure, transport-returned abort vs thrown
 * cancellation). They use the __test seam to inject fake implementations of
 * loadConfigSafe, findModel, preRefreshProviderAuth, and
 * consultWithChildProcess, so no live ExtensionContext or child process is
 * needed.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { Model, Usage } from "@earendil-works/pi-ai";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { advisorExecute } from "../extensions/advisor/execute.js";
import type { AdvisorConfig } from "../extensions/lib/advisor-utils.js";

/** Minimal fake Model that satisfies the type. */
function fakeModel(provider: string, id: string): Model<any> {
  return {
    provider,
    id,
    contextWindow: 128_000,
    maxTokens: 8_192,
    reasoning: false,
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
  } as unknown as Model<any>;
}

/** Minimal fake ExtensionContext that satisfies the type. */
function fakeCtx(activeModel?: { provider: string; id: string }): ExtensionContext {
  return {
    model: activeModel ? fakeModel(activeModel.provider, activeModel.id) : undefined,
    modelRegistry: {
      getAll: () => [],
      getAvailable: () => [],
      getProvider: () => undefined,
      getProviderAuth: async () => undefined,
    },
    cwd: "/tmp",
    sessionManager: {
      getBranch: () => [],
      getSessionDir: () => "/tmp",
      getEntries: () => [],
    },
    ui: {
      notify: () => {},
      confirm: async () => false,
      select: async () => undefined,
      theme: {
        fg: (color: string, text: string) => text,
        bold: (text: string) => text,
      },
    },
    hasUI: false,
    mode: "tui",
  } as unknown as ExtensionContext;
}

/** Fake usage with a known total. */
function fakeUsage(input: number, output: number): Usage {
  return {
    input,
    output,
    cacheRead: 0,
    cacheWrite: 0,
    totalTokens: input + output,
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
  };
}

describe("advisorExecute", () => {
  it("primary failure → fallback success, with usage and fallbackFrom disclosure", async () => {
    const primaryModel = fakeModel("openai", "gpt-4");
    const fallbackModel = fakeModel("anthropic", "claude-3");
    const fallbackUsage = fakeUsage(200, 100);

    const consultCalls: string[] = [];
    const consultImpl = async (opts: { modelLabel: string }) => {
      consultCalls.push(opts.modelLabel);
      if (opts.modelLabel === "openai/gpt-4") {
        throw new Error("primary failed");
      }
      return {
        text: "fallback advice",
        usage: fallbackUsage,
        toolCalls: 0,
        modelRequests: 1,
        status: "completed" as const,
      };
    };

    const findModelImpl = (ctx: ExtensionContext, target: { provider?: string; model: string }) => {
      if (target.model === "gpt-4") return primaryModel;
      if (target.model === "claude-3") return fallbackModel;
      throw new Error(`unknown model ${target.model}`);
    };

    const result = await advisorExecute(
      { question: "test question" },
      undefined,
      undefined,
      fakeCtx(),
      {
        loadConfigImpl: () => ({
          config: {
            primary: { provider: "openai", model: "gpt-4" },
            fallback: { provider: "anthropic", model: "claude-3" },
          } as AdvisorConfig,
          loadError: undefined,
        }),
        findModelImpl,
        preRefreshImpl: async () => {},
        consultImpl,
      },
    );

    assert.equal(consultCalls.length, 2);
    assert.equal(consultCalls[0], "openai/gpt-4");
    assert.equal(consultCalls[1], "anthropic/claude-3");
    assert.equal(result.details?.status, "completed");
    assert.equal(result.details?.model, "anthropic/claude-3");
    assert.equal(result.details?.source, "config fallback");
    // The footer should include fallbackFrom=openai/gpt-4
    const text = (result.content[0] as { type: "text"; text: string }).text;
    assert.ok(text.includes("fallbackFrom=openai/gpt-4"));
    // Usage should be the fallback's usage (the primary failed, so no usage from it)
    assert.equal(result.usage?.input, 200);
    assert.equal(result.usage?.output, 100);
  });

  it("explicit lookup failure → aggregate 'No usable advisor model' error", async () => {
    const findModelImpl = () => {
      throw new Error("model not found");
    };

    await assert.rejects(
      advisorExecute(
        { question: "test", provider: "openai", model: "gpt-4" },
        undefined,
        undefined,
        fakeCtx(),
        {
          loadConfigImpl: () => ({ config: {} as AdvisorConfig, loadError: undefined }),
          findModelImpl,
          preRefreshImpl: async () => {},
          consultImpl: async () => {
            throw new Error("should not be called");
          },
        },
      ),
      /No usable advisor model/,
    );
  });

  it("explicit consultation failure → immediate throw (not aggregate)", async () => {
    const model = fakeModel("openai", "gpt-4");
    const findModelImpl = () => model;
    const consultImpl = async () => {
      throw new Error("consultation failed");
    };

    await assert.rejects(
      advisorExecute(
        { question: "test", provider: "openai", model: "gpt-4" },
        undefined,
        undefined,
        fakeCtx(),
        {
          loadConfigImpl: () => ({ config: {} as AdvisorConfig, loadError: undefined }),
          findModelImpl,
          preRefreshImpl: async () => {},
          consultImpl,
        },
      ),
      /openai\/gpt-4: consultation failed/,
    );
  });

  it("transport-returned abort → 'cancelled' result", async () => {
    const model = fakeModel("openai", "gpt-4");
    const findModelImpl = () => model;
    const consultImpl = async () => ({
      text: "",
      toolCalls: 0,
      modelRequests: 0,
      status: "aborted" as const,
    });

    const result = await advisorExecute({ question: "test" }, undefined, undefined, fakeCtx(), {
      loadConfigImpl: () => ({
        config: { primary: { provider: "openai", model: "gpt-4" } } as AdvisorConfig,
        loadError: undefined,
      }),
      findModelImpl,
      preRefreshImpl: async () => {},
      consultImpl,
    });

    assert.equal(result.details?.status, "aborted");
    assert.equal(
      (result.content[0] as { type: "text"; text: string }).text,
      "Advisor consultation cancelled.",
    );
  });

  it("thrown cancellation (signal.aborted) → 'cancelled' result", async () => {
    const model = fakeModel("openai", "gpt-4");
    const findModelImpl = () => model;
    const abortController = new AbortController();
    const consultImpl = async () => {
      abortController.abort();
      throw new Error("aborted");
    };

    const result = await advisorExecute(
      { question: "test" },
      abortController.signal,
      undefined,
      fakeCtx(),
      {
        loadConfigImpl: () => ({
          config: { primary: { provider: "openai", model: "gpt-4" } } as AdvisorConfig,
          loadError: undefined,
        }),
        findModelImpl,
        preRefreshImpl: async () => {},
        consultImpl,
      },
    );

    // The thrown-cancellation path returns a minimal result: content is
    // "Advisor consultation cancelled." and details only include model/source
    // (no status, mode, or elapsedMs — unlike the transport-returned abort path).
    assert.equal(
      (result.content[0] as { type: "text"; text: string }).text,
      "Advisor consultation cancelled.",
    );
    assert.equal(result.details?.model, "openai/gpt-4");
    assert.equal(result.details?.source, "config primary");
    // status is NOT set in the details for the thrown-cancellation path.
    assert.equal(result.details?.status, undefined);
  });

  it("self-review disclosure (independent=false) when advisor model == active model", async () => {
    const activeModel = { provider: "openai", id: "gpt-4" };
    const model = fakeModel("openai", "gpt-4");
    const findModelImpl = () => model;
    const consultImpl = async () => ({
      text: "self-review advice",
      toolCalls: 0,
      modelRequests: 1,
      status: "completed" as const,
    });

    const result = await advisorExecute(
      { question: "test" },
      undefined,
      undefined,
      fakeCtx(activeModel),
      {
        loadConfigImpl: () => ({
          config: { primary: { provider: "openai", model: "gpt-4" } } as AdvisorConfig,
          loadError: undefined,
        }),
        findModelImpl,
        preRefreshImpl: async () => {},
        consultImpl,
      },
    );

    const text = (result.content[0] as { type: "text"; text: string }).text;
    assert.ok(text.includes("independent=false"));
    assert.ok(text.includes("self-review"));
  });
});
