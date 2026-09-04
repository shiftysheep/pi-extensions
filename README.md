# pi-extensions

Custom [pi](https://github.com/earendil/pi) coding-agent extensions.

| Extension | What it does |
|---|---|
| `advisor.ts` | Adds an `advisor` tool that consults a separate configured model as an independent second opinion (review, debugging, design). Model choices are read from `~/.pi/agent/advisor.json`. |
| `cron.ts` | Adds a `cron` tool for in-session scheduled wakes: one-shot delays/timestamps (`+30m` or ISO) and repeating intervals. State is snapshotted into the session, so schedules survive `/reload` (but not process restart). No OS-level cron jobs are created. |
| `plan-mode/` | Adds plan mode with a task-plan workflow (extract todo-style steps, approve-before-execute gate). Two files: entry point + helpers. |
| `permission-gate.ts` | Prompts for confirmation before running potentially dangerous bash commands (`rm -rf`, `sudo`, `chmod/chown ... 777`). |
| `status-line.ts` | Replaces the built-in footer with a custom status line that adds a tok/s estimate while streaming. Pass `undefined` to pi's `setFooter()` to restore the original. |

## Install

```bash
pi install git:github.com/shiftysheep/pi-extensions@v1.0.0
```

Any tag or commit ref works; pin one so updates are explicit (`pi update --extensions`). To try without installing: `pi -e git:github.com/shiftysheep/pi-extensions`.

Individual extensions can be disabled via `pi config` (global mode), no reinstall needed.

## Configuration

### advisor.json

Default model configuration lives at `~/.pi/agent/advisor.json`:

```json
{
  "primary": { "provider": "<provider>", "model": "gpt-5.6-sol" },
  "fallback": { "provider": "<provider>", "model": "gpt-5.6-terra" },
  "reasoningEffort": "high"
}
```

Any configured Pi model (including custom providers) can be selected per consultation, optional `effort` parameter overrides the default level (`none`…`max`).

## Security

> **Pi packages run with full system access.** Extensions execute arbitrary code in your pi process. Review this source before installing.

## Develop

Extensions are TypeScript and load directly (no build step). For local development:

```bash
pi -e ./extensions/advisor.ts   # test one file without installing
# or symlink/copy the directory into ~/.pi/agent/extensions/ and /reload
```
