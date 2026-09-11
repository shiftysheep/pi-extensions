# AGENTS.md

Agent instructions for this repository.

## What this is

A [pi](https://pi.dev) coding-agent package: four custom TypeScript extensions in
`extensions/` plus recommended third-party pi packages pulled in as npm dependencies
(declared in `dependencies` + `bundledDependencies`; resolved from the registry at
install time, never vendored). User-facing docs live in README.md (landing page)
and docs/ (one page per extension) — don't duplicate that content here; keep it
in the README/docs pages.

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
- **Testing**: pure helpers are covered by `test/*.test.ts` (`node --test` via
  tsx, wired into `check`): advisor in `extensions/lib/advisor-utils.ts` →
  `test/advisor-utils.test.ts` (+ `test/advisor-child.test.ts`), sandbox in
  `extensions/lib/sandbox-utils.ts` + `extensions/permission-gate/rules.ts` →
  `test/sandbox-utils.test.ts` / `test/permission-gate.test.ts`, plus
  `test/sandbox-landlock.test.ts` (compiles the C helper; skips cleanly without
  cc/Landlock). Keep new logic testable the same way — pure functions in the
  utils/rules modules, pi-specific wiring in `extensions/advisor/` (split
  modules), `advisor.ts`, and `permission-gate.ts` (entry). Note: the `pi.extensions` manifest in `package.json` lists
  extension files **explicitly** — a new top-level `extensions/<file>.ts` must be
  added there or it will not load (and do not add an `extensions/<subdir>/index.ts`;
  only the manifest's explicit entries load). Shared code goes in subdirs like
  `extensions/lib/` or `extensions/advisor/`.
- **Complexity**: cognitive complexity is capped at 80 (current peak is 75 in
  `advisor.ts`). Don't grow already-large functions; extract helpers instead.
- **Commits**: conventional commits, enforced by commitlint on the `commit-msg` hook.
  Use `npm run commit` or write `<type>: <summary>` messages (types: feat, fix, chore,
  docs, refactor, ...).
- **New extension file**: drop it in `extensions/` and add `./extensions/<file>.ts` to
  the `pi.extensions` array in `package.json`, plus a row in the README's extensions
  table and a reference page under `docs/` (linked from that row).

## Versioning & release

Releases are git tags; installs pin the tag:
`pi install git:github.com/shiftysheep/pi-extensions@vX.Y.Z`

Releases are **automatic**: the `release` job in `.github/workflows/ci.yml`
runs after `check` on merge to `main`, runs `cz bump --yes` (Python
commitizen, config in `.cz.toml`), then ships the `chore(release): vX.Y.Z`
commit + `vX.Y.Z` tag on a `release/vX.Y.Z` branch and merges it via an
automatic PR once its `check` passes (main is branch-protected with PRs
only, and personal-account repos can't grant the Actions app a bypass). The
increment is inferred from the conventional
commits since the last tag: `feat` → minor, `fix`/`chore` → patch,
`BREAKING CHANGE` → major. It bumps the version in `package.json`,
`package-lock.json`, the README install line, and `.cz.toml` itself. Do NOT
run `cz bump` manually in a PR — CI bumps on merge, and a manual bump inside
the PR would trigger a second bump on top. Use `cz bump --dry-run` to
preview what the next merge will release.

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
- Advisor consultations run in an **isolated child `pi` process**
  (`extensions/advisor/transports.ts`): throwaway agent dir with a 0600 copy of
  `auth.json`, prompt delivered as an `@path` file, NDJSON events parsed by the
  shared `AdvisorEventAccumulator`. The child runs `--no-extensions`, so its model
  resolution is limited to the copied `models.json` / `models-store.json` / `auth.json`
  — a provider registered only by an extension is not visible to the child. It is a
  privilege boundary, **not** a filesystem sandbox — don't harden it into one, and
  don't move model turns back into the host process. The child environment is a minimal allowlist (`childBaseEnv`); child-scoped
  env extensions go through `buildChildEnv` (the `awsProfile`/`awsRegion`/`env` config keys), never ad-hoc `env` merges, and
  must never mutate the host `process.env`. `buildChildEnv` is a pure helper in `lib/advisor-utils.ts` (tested). Because of
  that allowlist, a model with no `auth.json` entry whose credential is resolved from a *set env var* (`OPENAI_API_KEY`,
  `ANTHROPIC_API_KEY`, `AWS_PROFILE`/region, …) does not resolve in the child (the var is stripped) unless the user opts the
  child into it via the child-scoped `env`/`awsProfile`/`awsRegion` config; ambient *file* credentials found via the
  inherited `HOME` (a GCP ADC file, the default `~/.aws` profile) still work. The child's
  `auth.json` copy has its OAuth refresh token STRIPPED (and is written read-only, transports.ts), so the child can never
  perform a refresh — that is what protects the host's refresh token from server-side rotation (a read-only file copy
  alone would NOT prevent it: a refresh rotates the token on the provider's side before any local write). The access
  token is pre-refreshed in the host first (`preRefreshProviderAuth`) so the child inherits a fresh token it uses
  directly; a token that expires mid-run degrades to an auth error handled by the fallback chain.
- `node_modules/` is gitignored but `package-lock.json` is committed — don't ignore it.

## Hook setup (fresh clone / CI)

```bash
pre-commit install && pre-commit install -t commit-msg   # or: npm run precommit:install
```

## Workflow: feature branches only

- `main` is branch-protected on GitHub (PRs required, CI status check `check`
  required, enforced for admins) — direct pushes are rejected server-side.
- The `no-commit-to-branch` pre-commit hook (from
  [pre-commit-hooks](https://github.com/pre-commit/pre-commit-hooks), configured
  for `main`) enforces the same rule locally: commits on `main` fail — run
  `git switch -c <type>/<short-desc>` and commit there instead.
- CI runs `npm run check` (biome + tsc) on every PR and push to `main` via
  `.github/workflows/ci.yml`.
