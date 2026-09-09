# pi-extensions

Custom [pi](https://pi.dev) coding-agent extensions, with the recommended stack bundled as npm references (fetched from the registry at install time — third-party code is not vendored into this repo).

## What's included

### Custom extensions (`extensions/`)

| Extension | What it does |
|---|---|
| `advisor.ts` (+ `advisor/` modules) | Consults a separate configured model as an independent second opinion (review, debugging, design). Model choices read from `~/.pi/agent/advisor.json`, manageable via the `/advisor` command. |
| `cron.ts` | In-session scheduled wakes: one-shot delays/timestamps (`+30m` or ISO) and repeating intervals. State is snapshotted into the session, so schedules survive `/reload` (not process exit). No OS-level cron jobs created. |
| `permission-gate.ts` | Heuristic guard: prompts for confirmation before potentially dangerous bash commands (recursive `rm`, `sudo`/`doas`/`pkexec`, world-writable `chmod`). Not a security boundary — see the file header. |
| `status-line.ts` | Custom footer with a tok/s estimate while streaming. Pass `undefined` to pi's `setFooter()` to restore the original footer. |

### Bundled recommended installs (declared as dependencies, resolved by npm at install time)

- `pi-web-access` — web search / fetch tools. Provider config lives in `~/.pi/agent/web-search.json`.
- `pi-subagents` (+ its skills and prompt templates loaded via the package manifest) — subagent delegation and workflow orchestration tooling.
- `@juicesharp/rpiv-ask-user-question` — structured question prompts (up to 4 at a time, multi-select, previews).
- `@juicesharp/rpiv-todo` — task list tracking with statuses, dependencies, tombstones.
- `@ff-labs/pi-fff` — fast fuzzy grep/find tools. Pulls platform-specific native binaries via optional deps; tested on linux-x64, other platforms resolve at install time but are less verified.
- `@upstash/context7-pi` (official Upstash/Context7 package, + its skill and prompt templates loaded via the package manifest) — `resolve-library-id` and `query-docs` tools for up-to-date library docs, plus a `/c7-docs <library> <question>` prompt. Works without config under IP-based limits; set `CONTEXT7_API_KEY` for higher quotas.

## Install

```bash
pi install git:github.com/shiftysheep/pi-extensions@v2.2.2
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
  "source": "git:github.com/shiftysheep/pi-extensions@v2.2.2",
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

Third-party packs are plain npm dependencies: pi runs `npm install` after cloning, so installs need registry access and pin whatever version range resolves at that time. Our own entries carry caret ranges matching what this machine currently ships.

## Configuration

### advisor (if using `advisor.ts`)

`~/.pi/agent/advisor.json`:

```json
{
  "primary": { "provider": "<provider-id>", "model": "<model-id>" },
  "fallback": { "provider": "<provider-id>", "model": "<model-id>" },
  "reasoningEffort": "high",
  "activeModelFallback": true,
  "timeoutMs": 600000
}
```

`activeModelFallback` (optional, default `false`) opts into retrying the session's *active* model as a last resort — a self-review, and the result says so.

`timeoutMs` (optional) sets the consultation timeout in milliseconds, clamped to 30 s–30 min; it covers the whole consultation, fallback chain included (later attempts only get the time left). The per-call `timeoutMs` tool parameter overrides it, and the defaults are 5 min for `review` / 10 min for `explore`.

`piBinary` (optional) sets the path of the `pi` binary the advisor spawns for consultations (default: `pi` on `PATH`, or `$PI_BINARY` if set).

**Child-scoped environment** (`awsProfile`, `awsRegion`, `env`, all optional) applies variables to the advisor child process *only* — the host `process.env` is never mutated, so concurrent consultations cannot race on it. `awsRegion` sets both `AWS_REGION` and `AWS_DEFAULT_REGION`; `awsProfile` sets `AWS_PROFILE`; `env` is a map of extra variables (e.g. `{ "HTTPS_PROXY": "http://proxy:8080" }`) applied on top of the base allowlist and the AWS mapping, so an explicit `env` key wins. There is **no built-in profile or region default** — each is applied only when configured. This is how you point a Bedrock-hosted advisor at a different AWS profile/region (or a different proxy / credential set) than the host session.

The file is **strictly validated**: unknown keys (top level or in a model slot) are rejected with an error naming the field, and `primary`/`fallback` must be different models (a fallback that reruns the same model would just repeat the failure it exists to avoid).

**Upgrading from the old `exploreBudget` key:** it no longer exists — remove it from `advisor.json` (keep your model slots) so strict validation passes again. Until then the file is ignored with a warning in the result, and explicit `provider`/`model` tool calls still work.

Any configured Pi model (including custom providers) can be chosen per consultation; the optional `effort` argument overrides the default for one call (`none` through `max`). No model is ever picked implicitly: with no configured slots the advisor fails and points at `/advisor` (an explicit `provider`/`model` tool call still works if the config file is missing or unreadable).

**How a consultation works (ground-truth style):** every consultation runs in an
*isolated child `pi` process*, never in your session's process. The child gets a
throwaway agent dir (`mkdtemp`) holding only copies of `auth.json` plus the host's
model catalog (`models.json`, `models-store.json`, all mode `0600`, so file-backed
custom providers and model overrides resolve identically), receives the prompt as an
`@path` file reference, streams NDJSON events back, and its temp dir is removed on
every exit path (success, failure, timeout, abort). The child runs with
`--no-extensions`, so the child's model resolution is limited to those config
files: a provider or model that is *only* registered at runtime by an extension
(not written to `models.json` / `models-store.json`) is not visible to the child
and its consultation will not resolve it. This is a
**privilege boundary, not a filesystem sandbox**: the child's read tools still
reach anything the OS user can read, and the child inherits the user's own
credential store so the advisor
model can authenticate. The child runs with a **minimal environment allowlist**
(`childBaseEnv`: `PATH`, `HOME`, `TMPDIR`, `USER`, `SHELL`, locale and `XDG_*`)
— it gets the file-backed credential store (`auth.json`) plus `HOME`, but *not*
the host's ambient environment. Consequences for models with **no entry in
`auth.json`**: credentials resolved purely from a **set environment variable**
(`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `AWS_PROFILE`/`AWS_REGION`/`AWS_ACCESS_KEY_ID`,
`GOOGLE_CLOUD_PROJECT`/`LOCATION`, …) do not resolve, because those variables
are stripped; but ambient **file** credentials discovered through the standard
`HOME`-relative locations (e.g. a GCP application-default-credentials file, or
the default `~/.aws` profile) still work, because the child inherits `HOME`. For
env-var-based models, use `/login` or a stored API key, or set the
child-scoped `env` / `awsProfile` / `awsRegion` (see the config reference above). The child's `auth.json` copy has its OAuth **refresh
token stripped** (and is read-only), so the child can never perform a token
refresh — which is what protects the host's refresh token from being rotated
server-side. The access token is pre-refreshed in the host first, so a
near-expiry `/login` session still works and the child uses a fresh token.
Trade-off: if the pre-refresh could not complete and the copied token expires
mid-run, the child's refresh fails cleanly (no refresh token to send) and the
consultation degrades to an auth error handled by the fallback chain, rather than
rotating (and invalidating) the host's refresh token. A failed or no-response
child run is never reported as a
completed answer — it either degrades to the fallback model or the partial output
is explicitly marked incomplete.

The advisor does **not** receive your session by default. Cite workspace paths in the question for anything on disk,
and paste only evidence that exists nowhere on disk (command output, a test failure,
observed runtime behavior) — point, don't paste. Set `includeSession: true` on a tool
call to additionally attach the redacted transcript; it is then presented as *optional*
context the advisor must verify against the workspace, with each entry capped (8k
chars) and the whole transcript capped (120k chars). Accepted trade-off: the advisor
now depends on you citing the right paths — but that failure mode is visible ("I
could not find X") rather than silent (confident reasoning from a wrong summary).
Two modes:

- **`review`** (default): a single model call answering from the question.
  Cheap and fast; it identifies missing evidence instead of inspecting the repo.
- **`explore`**: the advisor child runs a *read-only* agent and verifies the
  question against the workspace itself with `read`, `grep`, `find`, and `ls`.
  Bounded by the consultation timeout only — there are no tool-call or model-request
  caps; a timed-out exploration returns whatever partial output it had, explicitly
  marked **incomplete**. Actual tool calls and model requests are always reported
  in the result (`toolCalls`/`elapsed` in the footer, `modelRequests` in the
  details) for cost visibility. Use when the question requires locating code
  or verifying repository facts.

Every result text ends with a model-visible status footer (`[advisor: mode=…, model=…,
status=…, toolCalls=…, elapsed=…s]`); the same envelope plus `model`/`source` is also
carried in the result `details` for logs and UI (`completed` / `timed_out` / `aborted`). When a later candidate answered after the primary was unavailable
the footer adds `fallbackFrom=<first candidate>`; when the answering model is the
session's active model it adds `independent=false` and a self-review warning.
Usage is aggregated across all model requests, including every turn of an exploration.

**Concurrency and size bounds:** at most 2 consultations run concurrently — extras queue
and still complete, they are never rejected. Returned advice is capped at 100k
characters and error diagnostics at 4k; anything larger is cut with a visible
`[truncated: N more characters omitted]` marker.

Models are managed with `/advisor`:

```
/advisor                              show config + retry chain, then offer the interactive picker (asks per-model effort, too)
/advisor set <primary>,<fallback>     set both (provider/model ids; provider optional if unambiguous)
/advisor primary|fallback <spec>      change one slot
/advisor effort <level>               set the shared default reasoning effort (none..max)
/advisor clear [slot]                 remove a slot, the default effort ("effort"), or both
/advisor reset                        back up advisor.json to advisor.json.bak and start clean

`/advisor reset` — and any `/advisor set|primary|fallback` run that repairs a broken file — backs the previous file up to `advisor.json.bak` first (only the latest backup is retained).
```

Reasoning effort is layered: a tool-call `effort` override wins, then the model-specific
`effort` in `advisor.json`, then the shared `reasoningEffort`, then `medium`.
Per-model effort can be written inline with an `@` suffix (e.g. `/advisor primary
gpt-6-astra@max`) or by editing `advisor.json` (per-slot `"effort"` key).

Behavior notes:
- **Retry chain**: primary → fallback. No model is picked implicitly — with no
  configured slots the advisor fails and points at `/advisor`. Your *active* model is
  only retried as a last resort when `"activeModelFallback": true` (a self-review,
  disclosed in the result footer). `/advisor` prints the effective chain so this is
  never a surprise.
- **`"none"` effort** requests no reasoning level; the advisor session then uses its own
  default (an explicit "off" is not expressible through the agent API).
- **Session redaction** (only when `includeSession: true` opts in) is best-effort:
  PEM blocks, authorization headers, common `key = value` / quoted assignments, and
  known token prefixes (`sk-`, `gh[pousr]_`, `github_pat_`, `xox*`, `AKIA…`) are
  scrubbed. Known gaps: JWTs, `xapp-` tokens, Google `AIza…` keys, single-line
  private keys, and `export FOO=…` assignments. Don't treat redaction as a
  guarantee — the safest way to keep secrets out of the advisor is to never let
  them enter the session at all.
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
