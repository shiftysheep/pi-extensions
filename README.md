# pi-extensions

Custom [pi](https://pi.dev) coding-agent extensions, with the recommended stack bundled as npm references (fetched from the registry at install time — third-party code is not vendored into this repo).

## What's included

### Custom extensions (`extensions/`)

| Extension | What it does |
|---|---|
| `advisor.ts` | Consults a separate configured model as an independent second opinion (review, debugging, design). Model choices read from `~/.pi/agent/advisor.json`, manageable via the `/advisor` command. |
| `cron.ts` | In-session scheduled wakes: one-shot delays/timestamps (`+30m` or ISO) and repeating intervals. State is snapshotted into the session, so schedules survive `/reload` (not process exit). No OS-level cron jobs created. |
| `permission-gate.ts` | Heuristic guard: prompts for confirmation before potentially dangerous bash commands (recursive `rm`, `sudo`/`doas`/`pkexec`, world-writable `chmod`). Not a security boundary — see the file header. |
| `status-line.ts` | Custom footer with a tok/s estimate while streaming. Pass `undefined` to pi's `setFooter()` to restore the original footer. |

### Bundled recommended installs (declared as dependencies, resolved by npm at install time)

- `pi-web-access` — web search / fetch tools. Provider config lives in `~/.pi/agent/web-search.json`.
- `pi-subagents` (+ its skills and prompt templates loaded via the package manifest) — subagent delegation and workflow orchestration tooling.
- `@juicesharp/rpiv-ask-user-question` — structured question prompts (up to 4 at a time, multi-select, previews).
- `@juicesharp/rpiv-todo` — task list tracking with statuses, dependencies, tombstones.
- `@ff-labs/pi-fff` — fast fuzzy grep/find tools. Pulls platform-specific native binaries via optional deps; tested on linux-x64, other platforms resolve at install time but are less verified.

## Install

```bash
pi install git:github.com/shiftysheep/pi-extensions@v2.0.1
pi update --extensions   # reconcile this package to its pinned ref later
pi -e git:github.com/shiftysheep/pi-extensions    # try without installing (current run only)
pi config                # enable/disable individual extensions from here or the bundled packages
```

Third-party packs are plain npm dependencies: pi runs `npm install` after cloning, so installs need registry access and pin whatever version range resolves at that time. Our own entries carry caret ranges matching what this machine currently ships.

## Configuration

### advisor (if using `advisor.ts`)

`~/.pi/agent/advisor.json`:

```json
{
  "primary": { "provider": "<provider-id>", "model": "<model-id>" },
  "fallback": { "provider": "<provider-id>", "model": "<model-id>" },
  "reasoningEffort": "high"
}
```

Any configured Pi model (including custom providers) can be chosen per consultation; the optional `effort` argument overrides the default for one call (`none` through `max`). Missing file or invalid JSON fails gracefully to a generic second-model choice.

**How a consultation works (Claude-Code-advisor style):** the advisor automatically
receives the redacted session transcript (including tool calls and results made so far)
plus your precise question — pass the question, not pasted code. Set `includeSession: false`
on a tool call to omit the transcript. Two modes:

- **`review`** (default): a single model call answering from the question + transcript.
  Cheap and fast; it identifies missing evidence instead of inspecting the repo.
- **`explore`**: the advisor runs as a nested *read-only* agent and may inspect the
  workspace itself with `read`, `grep`, `find`, and `ls`. Bounded by hard spend caps
  (≤12 tool calls, ≤6 model requests, 10-minute timeout); exhausting a budget returns an
  explicit **incomplete** result, never an authoritative verdict. Use only when the question
  requires locating code or verifying repository facts.

Every result text ends with a model-visible status footer (`[advisor: mode=…, status=…,
toolCalls=…, elapsed=…s]`); the same envelope plus `model`/`source` is also carried in the
result `details` for logs and UI (`completed` / `timed_out` / `aborted` / `budget_exhausted`).
Usage is aggregated across all model requests, including every turn of an exploration.

Models are managed with `/advisor`:

```
/advisor                              show config + retry chain, then offer the interactive picker (asks per-model effort, too)
/advisor set <primary>,<fallback>     set both (provider/model ids; provider optional if unambiguous)
/advisor primary|fallback <spec>      change one slot
/advisor effort <level>               set the shared default reasoning effort (none..max)
/advisor clear [slot]                 remove a slot, the default effort ("effort"), or both
/advisor reset                        back up advisor.json to advisor.json.bak and start clean
```

Reasoning effort is layered: a tool-call `effort` override wins, then the model-specific
`effort` in `advisor.json`, then the shared `reasoningEffort`, then `medium`.
Per-model effort can be written inline with an `@` suffix (e.g. `/advisor primary
gpt-6-astra@max`) or by editing `advisor.json` (per-slot `"effort"` key).

Behavior notes:
- **Retry chain**: primary → fallback; if both fail, your *active* model is retried as a
  last resort. `/advisor show` prints the effective chain so this is never a surprise.
- **`"none"` effort** requests no reasoning level; the advisor session then uses its own
  default (an explicit "off" is not expressible through the agent API).
- **Session redaction** (transcript included by default; `includeSession: false` opts out)
is best-effort: PEM blocks, authorization
  headers, common `key = value` / quoted assignments, and known token prefixes
  (`sk-`, `gh[pousr]_`, `github_pat_`, `xox*`, `AKIA…`) are scrubbed, but don't treat it as
  a guarantee — prefer not to include secrets in the session you consult from.
- The config file is written atomically (temp + rename) and validated on read; a broken
  file never blocks explicit `provider`/`model` tool calls, and `/advisor reset` recovers it.

## Develop

Extensions are TypeScript and load directly — no build step:

```bash
pi -e ./extensions/advisor.ts   # isolated single-file test run
# or place extensions/ under ~/.pi/agent/extensions/ and /reload
```

## Notes for users of the bundled packages

These re-expose upstream projects (MIT-licensed) at their installed versions; consult each project's own README/license in `node_modules/<pack>` after install. This repo pins nothing beyond caret ranges matching currently verified versions — upgrades follow standard npm resolution until a range bumps or you edit `package.json` deliberately.

## Security reminder

Pi packages execute with full system access inside the pi process. Review this source before installing; treating bundled references as equally untrusted as our own code is fair game since both run under your Pi instance once installed.
