# Bundled packages

This package bundles the recommended third-party pi stack as npm dependencies (declared in `dependencies` + `bundledDependencies`; resolved from the registry at install time — third-party code is not vendored into this repo).

- `pi-web-access` — web search / fetch tools. Provider config lives in `~/.pi/agent/web-search.json`.
- `pi-subagents` (+ its skills and prompt templates loaded via the package manifest) — subagent delegation and workflow orchestration tooling.
- `@juicesharp/rpiv-ask-user-question` — structured question prompts (up to 4 at a time, multi-select, previews).
- `@juicesharp/rpiv-todo` — task list tracking with statuses, dependencies, tombstones.
- `@ff-labs/pi-fff` — fast fuzzy grep/find tools. Pulls platform-specific native binaries via optional deps; tested on linux-x64, other platforms resolve at install time but are less verified.
- `@upstash/context7-pi` (official Upstash/Context7 package, + its skill and prompt templates loaded via the package manifest) — `resolve-library-id` and `query-docs` tools for up-to-date library docs, plus a `/c7-docs <library> <question>` prompt. Works without config under IP-based limits; set `CONTEXT7_API_KEY` for higher quotas.

## Notes for users of the bundled packages

These re-expose upstream projects (MIT-licensed) at their installed versions; consult each project's own README/license in `node_modules/<pack>` after install. This repo pins nothing beyond caret ranges matching currently verified versions — upgrades follow standard npm resolution until a range bumps or you edit `package.json` deliberately.

Third-party packs are plain npm dependencies: pi runs `npm install` after cloning, so installs need registry access and pin whatever version range resolves at that time. Our own entries carry caret ranges matching what this machine currently ships.