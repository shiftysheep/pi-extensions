# status-line

A lightweight status extension that adds response throughput to Pi's built-in
animated working indicator without replacing the footer or depending on footer
implementation details.

- **While streaming:** `[ response speed · ≈N tok/s ]`, estimated from cumulative
  UTF-8 output bytes divided by four.
- **After the stream completes:** `[ response speed · N tok/s* ]`, using the
  provider-reported output token count over the complete assistant message
  duration.
- **After the working indicator disappears:** the most recent measured rate is
  retained as a small widget above the editor and cleared when the next response
  starts.
- **Async subagent total:** a footer status line, `[ subagents · N tok $C.CCC ]`,
  shows the session's async subagent run cost. Sync subagent runs and runs
  awaited via `bg_wait` are already counted in Pi's built-in footer (pi-subagents
  sets an aggregated top-level `usage` on those tool results); async runs that
  complete WITHOUT a `bg_wait` only leave
  `{sessionDir}/subagent-artifacts/{runId}_{agent}[_{step}]_meta.json`, so the
  extension scans that directory on `agent_end` (throttled to 2 s, deduped by
  meta file name so multi-step runs sum every step, only runs COMPLETED after
  this session's first entry — the meta timestamp is a completion time) and
  shows the total via `ctx.ui.setStatus`, which the built-in footer appends
  below itself. The status line is the session's TOTAL async subagent cost —
  it intentionally overlaps the footer's `$` total for `bg_wait`-ed runs
  (which the footer already counts), so it is a subagent subtotal, not a
  delta. The scan is TUI-only; in other modes the extension stays inert.

The `≈` marker identifies a live estimate. The `*` marker identifies a
provider-confirmed rate. Text, thinking, and tool-call deltas contribute to the
live estimate. Responses shorter than 250 ms are omitted as too short to measure
reliably.

The extension intentionally leaves Pi's built-in footer responsible for the
working directory, token, cost, context, provider, subscription, compaction,
model, and extension-status information. It does not replace the footer, make
network requests, persist metrics, access credentials, or change provider
behavior.

The extension only updates the working indicator and widget in Pi's interactive
TUI. In RPC, JSON, and print modes it remains inert.
