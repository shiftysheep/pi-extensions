/**
 * Mock advisor provider for the advisor-wrapper fixture.
 *
 * Registers a mock provider via `pi.registerProvider` with a `streamSimple`
 * handler that returns canned advisor responses — NO real API calls, NO
 * charges. The advisor model is configured to use this mock provider, so the
 * wrapper's delegation calls hit the mock instead of a real model.
 *
 * The mock tracks `callCount` so the eval suite can verify HOW MANY times the
 * advisor was consulted (triggering behavior).
 *
 * Loaded via `pi -e ./test/advisor-wrapper/mock-provider.ts`.
 *
 * The provider is registered at the top level (during extension load).
 * `pi.registerProvider` is queued and applied once the runner binds its
 * context. The child session inherits parent providers via
 * `inheritParentProviders`.
 */

/** The mock provider id + model id the advisor will use. */
export const MOCK_PROVIDER_ID = "mock-advisor";
export const MOCK_MODEL_ID = "mock-advisor-model";

/**
 * Global state so the eval harness can inspect callCount and set responses.
 * Survives /reload (process-level), like the other advisor state.
 */
declare global {
  // eslint-disable-next-line no-var
  var __mockAdvisorProvider:
    | {
        callCount: number;
        responses: string[];
        lastQuestion: string;
      }
    | undefined;
}

/** The default canned advisor response. */
const DEFAULT_RESPONSE =
  "ADVISOR-MOCK-RESPONSE: I am the mock advisor. This is a canned response with no real model call.";

/** Mutable state for the mock provider. */
const state = {
  callCount: 0,
  responses: [DEFAULT_RESPONSE],
  lastQuestion: "",
};

export default function registerMockAdvisorProvider(pi: any) {
  // Register the mock provider at the top level (during extension load).
  pi.registerProvider(MOCK_PROVIDER_ID, {
    api: "mock",
    baseUrl: "http://localhost:0",
    models: [
      {
        id: MOCK_MODEL_ID,
        name: "Mock Advisor Model",
        reasoning: true,
        input: ["text"],
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
        contextWindow: 128000,
        maxTokens: 8192,
      },
    ],
    // Custom stream handler that returns canned responses.
    streamSimple: async (_model: any, context: any, _options: any) => {
      state.callCount++;
      // Capture the question (last user message) for inspection.
      const messages = context?.messages ?? [];
      const lastUser = [...messages].reverse().find((m: any) => m.role === "user");
      if (lastUser?.content) {
        state.lastQuestion =
          typeof lastUser.content === "string"
            ? lastUser.content
            : lastUser.content.map((c: any) => c.text ?? "").join("\n");
      }
      // Return the next canned response (cycle through the list).
      const response =
        state.responses[state.callCount % state.responses.length] ?? DEFAULT_RESPONSE;
      return {
        role: "assistant",
        content: [{ type: "text", text: response }],
        api: "mock",
        provider: MOCK_PROVIDER_ID,
        model: MOCK_MODEL_ID,
        usage: {
          input: 0,
          output: 0,
          cacheRead: 0,
          cacheWrite: 0,
          totalTokens: 0,
          cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
        },
        stopReason: "stop",
        timestamp: Date.now(),
      };
    },
  });

  // Expose state for the eval harness.
  globalThis.__mockAdvisorProvider = state;
}
