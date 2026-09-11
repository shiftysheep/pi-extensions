# status-line

Custom footer with a tok/s estimate while streaming. It mirrors pi's built-in footer layout (cwd/branch/session, token/cost/context line, extension status texts) and adds a trailing rate slot:

- **While streaming:** `≈N tok/s`, estimated from cumulative UTF-8 bytes/4 since first output.
- **After the stream completes:** dimmed `N tok/s*` using provider-reported output tokens over the complete assistant stream (streams shorter than 250 ms are considered too short to be meaningful).

Token/cost totals also include subagent runs: sync runs from the subagent tool result's `details.results[].usage`, async runs from `{sessionDir}/subagent-artifacts/{runId}_{agent}_meta.json` (deduped by runId, rescanned at most every 2 s).

Pass `undefined` to pi's `setFooter()` to restore the original footer.