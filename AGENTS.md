# AGENTS.md

Agent instructions for this repository.

## What this is

A [pi](https://pi.dev) coding-agent package: four custom TypeScript extensions in
`extensions/` plus recommended third-party pi packages pulled in as npm dependencies
(declared in `dependencies` + `bundledDependencies`; resolved from the registry at
install time, never vendored). See README.md for user-facing docs — don't duplicate
that content here, keep it in the README.

## Commands

```bash
npm install                 # deps + dev tools (pi peer deps auto-install)
npm run check               # the gate: biome check + tsc --noEmit + tests (must pass before committing)
npm run lint                # biome only
npm run format              # biome check --write
npm run typecheck           # tsc --noEmit only
npm test                    # node --test via tsx (tests in test/)
npm run commit              # interactive conventional-commit prompt (commitizen)
pre-commit run --all-files  # run all git hooks manually
```

No build step. Extensions are plain TypeScript that pi loads directly — changes are
tested with `pi -e ./extensions/<file>.ts` (isolated run) or by copying into
`~/.pi/agent/extensions/` and `/reload`.

## Conventions

- **Formatting/lint**: Biome owns formatting (2-space indent, 100-char lines, double
  quotes) and linting. Run `npm run format` rather than hand-formatting; the pre-commit
  hook does this automatically for staged files. `biome.json` is the single source of
  truth — don't add Prettier/ESLint.
- **Types**: strict mode via `tsconfig.json` (`noEmit`). `any` and non-null assertions
  are warnings, not errors — pi event payloads are loosely typed, but prefer precise
  types where the pi packages export them.
- **Testing**: pure advisor helpers live in `extensions/lib/advisor-utils.ts` and
  are covered by `test/advisor-utils.test.ts` (`node --test` via tsx, wired into
  `check`). Keep new advisor logic testable the same way — pure functions in the
  utils module, pi-specific wiring in `advisor.ts`. Note: pi auto-loads every `*.ts`
  directly under `extensions/` as an extension, so shared code goes in a subdir like
  `extensions/lib/`.
- **Complexity**: cognitive complexity is capped at 80 (current peak is 75 in
  `advisor.ts`). Don't grow already-large functions; extract helpers instead.
- **Commits**: conventional commits, enforced by commitlint on the `commit-msg` hook.
  Use `npm run commit` or write `<type>: <summary>` messages (types: feat, fix, chore,
  docs, refactor, ...).
- **New extension file**: drop it in `extensions/` and add `./extensions/<file>.ts` to
  the `pi.extensions` array in `package.json`, plus a row in the README's extensions table.

## Versioning & release

Releases are git tags; installs pin the tag:
`pi install git:github.com/shiftysheep/pi-extensions@vX.Y.Z`

To cut a release, run **`cz bump --increment PATCH|MINOR|MAJOR`** (Python
commitizen, config in `.cz.toml`). It bumps the version in `package.json`,
`package-lock.json`, the README install line, and `.cz.toml` itself, makes a
`chore(release): vX.Y.Z` commit, and creates the `vX.Y.Z` tag. Then
`git push --follow-tags`. Use `cz bump --dry-run` to preview.

Note: npm's `cz` (`npm run commit`) is only the interactive commit-message
wizard; release bumps always go through Python commitizen's `cz bump`.

## Gotchas

- `bundledDependencies` matters: the listed packs must ship inside the published tarball,
  and the `pi` manifest in `package.json` references files *inside* them
  (`node_modules/...`). Don't remove a bundled dep without updating the manifest entries
  that point into it.
- Third-party packs are pinned with caret ranges matching what this machine verifies;
  bumping a range without testing the new resolved version is not OK.
- `permission-gate.ts` is a heuristic prompt guard, explicitly **not** a security
  boundary (see its file header) — keep it that way, don't harden it into a sandbox.
- `cron.ts` and `advisor.ts` keep process-level state on `globalThis` so it survives
  pi's `/reload` but not process exit. Preserve that pattern (nonce-guarded in `cron.ts`).
- `node_modules/` is gitignored but `package-lock.json` is committed — don't ignore it.

## Hook setup (fresh clone / CI)

```bash
pre-commit install && pre-commit install -t commit-msg   # or: npm run precommit:install
```

## Workflow: feature branches only

- `main` is branch-protected on GitHub (PRs required, CI status check `check`
  required, enforced for admins) — direct pushes are rejected server-side.
- The `block-main` pre-commit hook enforces the same rule locally:
  commits on `main` fail with a hint to run `git switch -c <type>/<short-desc>`.
- CI runs `npm run check` (biome + tsc) on every PR and push to `main` via
  `.github/workflows/ci.yml`.
