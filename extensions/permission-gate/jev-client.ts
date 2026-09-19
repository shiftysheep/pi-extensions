/**
 * Minimal TypeSafe (Jev) HTTP client — thin, testable.
 *
 * Uses Node's built-in fetch (Node 18+). `fetchImpl` is injectable so tests can
 * stub the network. Returns a discriminated result rather than throwing, so the
 * caller (permission-gate.ts) can fail open with a clear reason.
 *
 * Error strings are FIXED categories — never `err.message` — so a header or
 * body value (e.g. the API key, or response text) can never leak into a user-
 * facing warning.
 */

export type JevCallOptions = {
  apiKey: string;
  /** Per-call timeout in ms. Default 8000. */
  timeoutMs?: number;
  /** Override the API base URL (tests). Default https://api.typesafe.ai. */
  baseUrl?: string;
  /** Injectable fetch (tests). Defaults to global fetch. */
  fetchImpl?: typeof fetch;
  /**
   * Caller cancellation (e.g. the agent's abort signal). Combined with the
   * timeout; when it fires the result is reported as `cancelled`.
   */
  signal?: AbortSignal;
};

export type JevCallResult =
  | { ok: true; body: unknown }
  | { ok: false; error: string; cancelled?: boolean };

const DEFAULT_BASE_URL = "https://api.typesafe.ai";
const DEFAULT_TIMEOUT_MS = 8000;

/** POST a System One request to the Jev endpoint. Never throws. */
export async function callJev(request: unknown, opts: JevCallOptions): Promise<JevCallResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const baseUrl = (opts.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, "");
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  // Combine our timeout with any caller cancellation signal.
  const signal = opts.signal
    ? AbortSignal.any([controller.signal, opts.signal])
    : controller.signal;
  try {
    const res = await fetchImpl(`${baseUrl}/v1/systemone`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${opts.apiKey}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(request),
      signal,
    });
    if (!res.ok) {
      // Release the connection instead of leaving the body unconsumed.
      if (res.body) void res.body.cancel().catch(() => {});
      if (res.status === 401)
        return { ok: false, error: "authentication failed (401) — check TYPESAFE_API_KEY" };
      if (res.status === 422) return { ok: false, error: "request rejected by the API (422)" };
      if (res.status === 429 || res.status === 529)
        return { ok: false, error: `rate-limited or overloaded (${res.status})` };
      return { ok: false, error: `unexpected status ${res.status}` };
    }
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      // An abort (cancel or timeout) can reject res.json() mid-body-read; classify
      // it as such rather than a malformed response.
      if (opts.signal?.aborted) return { ok: false, error: "cancelled", cancelled: true };
      if (controller.signal.aborted) return { ok: false, error: `timed out after ${timeoutMs}ms` };
      return { ok: false, error: "invalid JSON response" };
    }
    return { ok: true, body };
  } catch {
    // Fixed categories only — never echo err.message (could carry secrets).
    if (opts.signal?.aborted) return { ok: false, error: "cancelled", cancelled: true };
    if (controller.signal.aborted) return { ok: false, error: `timed out after ${timeoutMs}ms` };
    return { ok: false, error: "network error" };
  } finally {
    clearTimeout(timer);
  }
}
