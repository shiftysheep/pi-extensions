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
- **Async subagent total:** a second widget line, `[ subagents · N tok $C.CCC ]`,
  shows the session's async subagent run cost. Sync subagent runs are already
  counted in Pi's built-in footer (pi-subagents sets an aggregated top-level
  `usage` on the tool result); async runs only leave
  `{sessionDir}/subagent-artifacts/{runId}_{agent}_meta.json`, so the extension
  scans that directory (throttled to 2 s, deduped by runId, only runs started
  after this session's first entry) and shows the total alongside the rate.

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
