# Development

Extensions are TypeScript and load directly — no build step:

```bash
pi -e ./extensions/advisor.ts   # isolated single-file test run
# or place extensions/ under ~/.pi/agent/extensions/ and /reload
```

Changes are tested with `pi -e ./extensions/<file>.ts` (isolated run) or by copying into `~/.pi/agent/extensions/` and `/reload`.

## Adding a new extension

1. Drop the file in `extensions/` and add `./extensions/<file>.ts` to the `pi.extensions` array in `package.json` — the manifest lists extension files **explicitly**, so a new top-level file that isn't listed will not load (and do not add an `extensions/<subdir>/index.ts`; only the manifest's explicit entries load). Shared code goes in subdirs like `extensions/lib/` or `extensions/advisor/`.
2. Add a row to the README's extensions table linking to a new page under `docs/`.
3. Keep new logic testable the way the existing extensions are: pure functions in the utils/rules modules with `node --test` coverage in `test/`, pi-specific wiring in the entry file.

Full contributor conventions (formatting, types, testing, gotchas, release process) live in [AGENTS.md](../AGENTS.md).