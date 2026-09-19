/**
 * Unit tests for the optional Jev danger classifier:
 *  - extensions/permission-gate/classifier.ts (pure decision logic)
 *  - extensions/permission-gate/jev-client.ts (fetch client, mocked network)
 * Run with `npm test` (node --test via tsx).
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  buildClassifierRequest,
  DEFAULT_CONFIRM_THRESHOLD,
  DEFAULT_DENY_THRESHOLD,
  decideClassifier,
  effectiveThresholds,
  parseClassifierProbs,
} from "../extensions/permission-gate/classifier.js";
import { callJev } from "../extensions/permission-gate/jev-client.js";

describe("buildClassifierRequest", () => {
  it("builds a System One request with shell-aware structured state and two nouls", () => {
    const req = buildClassifierRequest(
      "Clear-Disk -Number 1",
      "jev-latest",
      "powershell",
    ) as Record<string, unknown>;
    assert.deepEqual(req.state, { shell: "powershell", command: "Clear-Disk -Number 1" });
    assert.equal(req.model, "jev-latest");
    const questions = req.questions as Record<
      string,
      { type: string; instructions: string; criteria: { true: string; false: string } }
    >;
    assert.equal(questions.malicious.type, "noul");
    assert.equal(questions.dangerous.type, "noul");
    assert.ok(questions.malicious.instructions.length > 0);
    assert.ok(questions.dangerous.instructions.length > 0);
    assert.match(questions.dangerous.instructions, /autonomous agent/i);
    assert.match(questions.dangerous.criteria.true, /git push --force/i);
    assert.match(questions.dangerous.criteria.true, /git branch -D/i);
    assert.match(questions.dangerous.criteria.true, /Clear-Disk/i);
    assert.match(questions.malicious.criteria.true, /reverse shell/i);
    assert.match(questions.malicious.criteria.true, /encoded/i);
    assert.match(questions.malicious.criteria.true, /environment variables/i);
    assert.match(questions.malicious.criteria.true, /history/i);
    assert.match(questions.malicious.criteria.true, /conceal/i);
    assert.match(questions.malicious.criteria.true, /hidden code/i);
  });

  it("defaults direct callers to bash state", () => {
    const req = buildClassifierRequest("rm -rf /", "jev-latest") as Record<string, unknown>;
    assert.deepEqual(req.state, { shell: "bash", command: "rm -rf /" });
  });
});

describe("parseClassifierProbs", () => {
  it("extracts the two noul probabilities", () => {
    const body = {
      answers: { malicious: { type: "noul", noul: 0.8 }, dangerous: { type: "noul", noul: 0.3 } },
    };
    assert.deepEqual(parseClassifierProbs(body), { malicious: 0.8, dangerous: 0.3 });
  });
  it("accepts the [0,1] endpoints", () => {
    assert.deepEqual(
      parseClassifierProbs({ answers: { malicious: { noul: 0 }, dangerous: { noul: 1 } } }),
      { malicious: 0, dangerous: 1 },
    );
  });
  it("treats out-of-range or non-finite probabilities as malformed", () => {
    assert.equal(
      parseClassifierProbs({ answers: { malicious: { noul: 1.5 }, dangerous: { noul: 0.3 } } }),
      undefined,
    );
    assert.equal(
      parseClassifierProbs({ answers: { malicious: { noul: 0.3 }, dangerous: { noul: -0.2 } } }),
      undefined,
    );
    assert.equal(
      parseClassifierProbs({
        answers: { malicious: { noul: Infinity }, dangerous: { noul: 0.3 } },
      }),
      undefined,
    );
  });
  it("returns undefined for malformed shapes", () => {
    assert.equal(parseClassifierProbs(null), undefined);
    assert.equal(parseClassifierProbs("nope"), undefined);
    assert.equal(parseClassifierProbs({}), undefined);
    assert.equal(parseClassifierProbs({ answers: {} }), undefined);
    assert.equal(parseClassifierProbs({ answers: { malicious: { noul: "0.5" } } }), undefined);
    assert.equal(
      parseClassifierProbs({ answers: { malicious: { noul: NaN }, dangerous: { noul: 0.5 } } }),
      undefined,
    );
  });
});

describe("effectiveThresholds", () => {
  it("defaults to the named defaults", () => {
    assert.deepEqual(effectiveThresholds({}), {
      confirm: DEFAULT_CONFIRM_THRESHOLD,
      deny: DEFAULT_DENY_THRESHOLD,
    });
  });
  it("honors explicit values", () => {
    assert.deepEqual(
      effectiveThresholds({ classifierConfirmThreshold: 0.5, classifierDenyThreshold: 0.8 }),
      { confirm: 0.5, deny: 0.8 },
    );
  });
  it("clamps confirm to never exceed deny", () => {
    assert.deepEqual(
      effectiveThresholds({ classifierConfirmThreshold: 0.95, classifierDenyThreshold: 0.9 }),
      { confirm: 0.9, deny: 0.9 },
    );
  });
});

describe("decideClassifier", () => {
  const t = { confirm: 0.7, deny: 0.9 };
  it("proceeds when both are below confirm", () => {
    assert.equal(decideClassifier({ malicious: 0.2, dangerous: 0.3 }, t).action, "proceed");
  });
  it("confirms when a concern is in [confirm, deny)", () => {
    const v = decideClassifier({ malicious: 0.75, dangerous: 0.1 }, t);
    assert.equal(v.action, "confirm");
    assert.match(v.label, /malicious P=0\.75/);
    assert.doesNotMatch(v.label, /dangerous/);
  });
  it("denies when a concern reaches the deny threshold", () => {
    const v = decideClassifier({ malicious: 0.1, dangerous: 0.92 }, t);
    assert.equal(v.action, "deny");
    assert.match(v.label, /dangerous P=0\.92/);
  });
  it("uses the max of the two probabilities as the risk", () => {
    assert.equal(decideClassifier({ malicious: 0.0, dangerous: 0.95 }, t).action, "deny");
    assert.equal(decideClassifier({ malicious: 0.72, dangerous: 0.71 }, t).action, "confirm");
  });
  it("lists every concern at/above the confirm threshold", () => {
    const v = decideClassifier({ malicious: 0.8, dangerous: 0.75 }, t);
    assert.match(v.label, /malicious P=0\.80/);
    assert.match(v.label, /dangerous P=0\.75/);
  });
  it("treats both thresholds as inclusive", () => {
    assert.equal(decideClassifier({ malicious: 0.7, dangerous: 0 }, t).action, "confirm");
    assert.equal(decideClassifier({ malicious: 0.9, dangerous: 0 }, t).action, "deny");
  });
  it("collapses the confirm band when confirm equals deny", () => {
    const eq = { confirm: 0.8, deny: 0.8 };
    assert.equal(decideClassifier({ malicious: 0.79, dangerous: 0 }, eq).action, "proceed");
    assert.equal(decideClassifier({ malicious: 0.8, dangerous: 0 }, eq).action, "deny");
  });
});

describe("callJev", () => {
  const goodBody = {
    model: "jev-latest",
    answers: { malicious: { type: "noul", noul: 0.2 }, dangerous: { type: "noul", noul: 0.1 } },
  };
  function resp(status: number, body: unknown) {
    return { status, ok: status >= 200 && status < 300, json: async () => body };
  }
  it("posts to the endpoint with a bearer key and returns the body", async () => {
    let seenUrl = "";
    let seenAuth = "";
    const fetchImpl = (async (url: string, init: { headers: Record<string, string> }) => {
      seenUrl = url;
      seenAuth = init.headers.authorization;
      return resp(200, goodBody);
    }) as unknown as typeof fetch;
    const r = await callJev(
      { state: "x", model: "jev-latest", questions: {} },
      {
        apiKey: "k123",
        fetchImpl,
      },
    );
    assert.equal(r.ok, true);
    if (r.ok) assert.deepEqual(r.body, goodBody);
    assert.equal(seenUrl, "https://api.typesafe.ai/v1/systemone");
    assert.equal(seenAuth, "Bearer k123");
  });
  it("strips a trailing slash from a custom baseUrl", async () => {
    let seenUrl = "";
    const fetchImpl = (async (url: string) => {
      seenUrl = url;
      return resp(200, goodBody);
    }) as unknown as typeof fetch;
    await callJev({}, { apiKey: "k", baseUrl: "https://example.test/", fetchImpl });
    assert.equal(seenUrl, "https://example.test/v1/systemone");
  });
  it("maps 401/422/429/529 to friendly errors", async () => {
    for (const status of [401, 422, 429, 529]) {
      const fetchImpl = (async () => resp(status, {})) as unknown as typeof fetch;
      const r = await callJev({}, { apiKey: "k", fetchImpl });
      assert.equal(r.ok, false, String(status));
      if (!r.ok) assert.match(r.error, new RegExp(String(status)));
    }
  });
  it("reports an unexpected status", async () => {
    const fetchImpl = (async () => resp(500, {})) as unknown as typeof fetch;
    const r = await callJev({}, { apiKey: "k", fetchImpl });
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.error, /500/);
  });
  it("times out and reports it", async () => {
    const fetchImpl = ((_url: string, init: { signal: AbortSignal }) =>
      new Promise((_resolve, reject) => {
        init.signal.addEventListener("abort", () => reject(new Error("aborted")));
      })) as unknown as typeof fetch;
    const r = await callJev({}, { apiKey: "k", timeoutMs: 30, fetchImpl });
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.error, /timed out/);
  });
  it("reports network errors", async () => {
    const fetchImpl = (async () => {
      throw new Error("ECONNREFUSED");
    }) as unknown as typeof fetch;
    const r = await callJev({}, { apiKey: "k", fetchImpl });
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.error, /network error/);
  });
  it("treats a non-JSON body as a failure", async () => {
    const fetchImpl = (async () => ({
      status: 200,
      ok: true,
      json: async () => {
        throw new Error("bad json");
      },
    })) as unknown as typeof fetch;
    const r = await callJev({}, { apiKey: "k", fetchImpl });
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.error, /invalid JSON/);
  });
  it("never leaks the API key or the thrown message into the error", async () => {
    const fetchImpl = (async () => {
      throw new Error("boom secret-key=sk-abc123 in header");
    }) as unknown as typeof fetch;
    const r = await callJev({}, { apiKey: "sk-abc123", fetchImpl });
    assert.equal(r.ok, false);
    if (!r.ok) {
      assert.doesNotMatch(r.error, /sk-abc123/);
      assert.doesNotMatch(r.error, /boom/);
      assert.match(r.error, /network error/);
    }
  });
  it("reports caller cancellation distinctly", async () => {
    const ac = new AbortController();
    ac.abort();
    const fetchImpl = (async (_url: string, init: { signal: AbortSignal }) => {
      if (init.signal.aborted) throw new Error("aborted");
      await new Promise((r) => setTimeout(r, 50));
      return resp(200, goodBody);
    }) as unknown as typeof fetch;
    const r = await callJev({}, { apiKey: "k", signal: ac.signal, fetchImpl });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.cancelled, true);
  });
  it("classifies an abort during body-read as cancellation, not malformed", async () => {
    const ac = new AbortController();
    // Headers arrive, then the caller cancels while the body is still pending.
    const fetchImpl = (async (_url: string, init: { signal: AbortSignal }) => ({
      status: 200,
      ok: true,
      json: () =>
        new Promise((_resolve, reject) => {
          init.signal.addEventListener("abort", () => reject(new Error("aborted")));
        }),
    })) as unknown as typeof fetch;
    const p = callJev({}, { apiKey: "k", timeoutMs: 10000, signal: ac.signal, fetchImpl });
    await new Promise((r) => setTimeout(r, 10));
    ac.abort();
    const r = await p;
    assert.equal(r.ok, false);
    if (!r.ok) {
      assert.equal(r.cancelled, true);
      assert.match(r.error, /cancelled/);
    }
  });
});
