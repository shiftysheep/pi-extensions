# pi-extensions

Custom [pi](https://pi.dev) coding-agent extensions, with the recommended stack bundled as npm references (fetched from the registry at install time — third-party code is not vendored into this repo).

## What's included

### Custom extensions (`extensions/`)

| Extension | What it does |
|---|---|
| `advisor.ts` | Consults a separate configured model as an independent second opinion (review, debugging, design). Model choices read from `~/.pi/agent/advisor.json`. |
| `cron.ts` | In-session scheduled wakes: one-shot delays/timestamps (`+30m` or ISO) and repeating intervals. State is snapshotted into the session, so schedules survive `/reload` (not process exit). No OS-level cron jobs created. |
| `permission-gate.ts` | Prompts for confirmation before potentially dangerous bash commands (`rm -rf`, `sudo`, `chmod/chown ... 777`). |
| `status-line.ts` | Custom footer with a tok/s estimate while streaming. Pass `undefined` to pi's `setFooter()` to restore the original footer. |

### Bundled recommended installs (declared as dependencies, resolved by npm at install time)

- `pi-web-access` — web search / fetch tools. Provider config lives in `~/.pi/agent/web-search.json`.
- `pi-subagents` (+ its skills and prompt templates loaded via the package manifest) — subagent delegation and workflow orchestration tooling.
- `@juicesharp/rpiv-ask-user-question` — structured question prompts (up to 4 at a time, multi-select, previews).
- `@juicesharp/rpiv-todo` — task list tracking with statuses, dependencies, tombstones.
- `@ff-labs/pi-fff` — fast fuzzy grep/find tools. Pulls platform-specific native binaries via optional deps; tested on linux-x64, other platforms resolve at install time but are less verified.

## Install

```bash
pi install git:github.com/shiftysheep/pi-extensions@v2.0.0
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
