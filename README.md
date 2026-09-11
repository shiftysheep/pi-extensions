# pi-extensions

Custom [pi](https://pi.dev) coding-agent extensions, with the recommended stack bundled as npm references (fetched from the registry at install time — third-party code is not vendored into this repo).

## What's included

### Custom extensions (`extensions/`)

| Extension | What it does | Docs |
|---|---|---|
| `advisor.ts` (+ `advisor/` modules) | Consults a separate configured model as an independent second opinion (review, debugging, design). | [docs/advisor.md](docs/advisor.md) |
| `cron.ts` | In-session scheduled wakes: one-shot delays/timestamps and repeating intervals. Survives `/reload`, not process exit. | [docs/cron.md](docs/cron.md) |
| `permission-gate.ts` (+ `permission-gate/` modules) | Heuristic guard that prompts before dangerous bash/PowerShell commands (hard-blocks raw disk operations), plus an opt-in OS filesystem sandbox (bubblewrap / Landlock / `sandbox-exec`). | [docs/permission-gate.md](docs/permission-gate.md) |
| `status-line.ts` | Custom footer with a tok/s estimate while streaming. | [docs/status-line.md](docs/status-line.md) |

### Bundled recommended installs

Six third-party packs (web search/fetch, subagents, question prompts, todo, fuzzy grep/find, Context7 docs) are bundled as npm dependencies — see [docs/bundled-packages.md](docs/bundled-packages.md).

## Install

```bash
pi install git:github.com/shiftysheep/pi-extensions@v2.8.1
pi update --extensions   # reconcile this package to its pinned ref later
pi -e git:github.com/shiftysheep/pi-extensions    # try without installing (current run only)
pi config                # enable/disable individual extensions from here or the bundled packages
```

### Install a single custom extension (per-capability install)

The package's `pi` manifest lists each `extensions/*.ts` entry explicitly, so you can install the repo and load only the extension(s) you want — e.g. just the advisor, without cron, the permission gate, the status line, or any bundled pack:

```bash
# from the package's settings object (pi config / settings.json).
# Empty skills/prompts arrays keep the bundled packs' resources off too:
{
  "source": "git:github.com/shiftysheep/pi-extensions@v2.8.1",
  "extensions": ["extensions/advisor.ts"],
  "skills": [],
  "prompts": []
}
```

Or, for a local checkout, pass the extension file directly as a single-extension source (no npm deps needed — it only uses pi's bundled core packages; pi keeps a reference to the file, so keep `extensions/advisor/` and `extensions/lib/` in place):

```bash
pi install /path/to/pi-extensions/extensions/advisor.ts
pi -e ./extensions/advisor.ts    # current run only
```

## Quick start

- **Advisor** — run `/advisor` to pick your primary/fallback models, then ask the agent to consult the `advisor` tool for a second opinion.
- **Sandbox** — run `/sandbox on` to enable the OS filesystem sandbox for this project (the heuristic gate is always on); `/sandbox` shows live status, `/sandbox config` edits options.
- **Everything else** — cron, status line, and the bundled packs work out of the box once loaded.

## Develop

Extensions are TypeScript and load directly — no build step. See [docs/development.md](docs/development.md) and [AGENTS.md](AGENTS.md).

## Security reminder

Pi packages execute with full system access inside the pi process. Review this source before installing; treating bundled references as equally untrusted as our own code is fair game since both run under your Pi instance once installed.