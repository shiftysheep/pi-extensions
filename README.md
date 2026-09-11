# pi-extensions

Custom [pi](https://pi.dev) coding-agent extensions, with the recommended stack bundled as npm references (fetched from the registry at install time — third-party code is not vendored into this repo).

## What's included

### Custom extensions (`extensions/`)

| Extension | What it does |
|---|---|
| `advisor.ts` (+ `advisor/` modules) | Consults a separate configured model as an independent second opinion (review, debugging, design). Model choices read from `~/.pi/agent/advisor.json`, manageable via the `/advisor` command. |
| `cron.ts` | In-session scheduled wakes: one-shot delays/timestamps (`+30m` or ISO) and repeating intervals. State is snapshotted into the session, so schedules survive `/reload` (not process exit). No OS-level cron jobs created. |
| `permission-gate.ts` (+ `permission-gate/` modules) | Heuristic guard: prompts for confirmation before potentially dangerous bash commands (recursive `rm`, `sudo`/`doas`/`pkexec`, world-writable `chmod`, power actions, destructive Git operations, curated remote destruction, database DROP/TRUNCATE) and dangerous PowerShell cmdlets (recursive `Remove-Item`, elevation, `Invoke-Expression`, ACL changes, machine-wide registry writes); raw host-disk operations (`dd`/redirect/`tee`/`cp`/`shred` to `/dev/*`, `wipefs`, `blkdiscard`, partition wipes, LVM/ZFS destroy, `mkfs`, PowerShell disk wipes) are **hard-blocked** — human-only, no prompt. Every rule is armed regardless of sandbox state. Optionally adds an **OS filesystem sandbox** (bubblewrap / Landlock on Linux, `sandbox-exec` on macOS) that makes the agent's bash commands read-only outside writable roots — opt-in via `sandbox.json` (global `~/.pi/agent/` or project `.pi/`). Toggle with `/sandbox on|off`, edit with `/sandbox config`. The gate alone is not a security boundary; the sandbox is an OS-level boundary. See [Configuration](#configuration). |
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

### permission-gate / sandbox

The heuristic gate is always on. The **filesystem sandbox** is opt-in: set `"enabled": true` in a `sandbox.json` (absent file = disabled, behavior identical to the gate alone). Two scopes are supported and merged **per-key, project wins**:

- **global** — `~/.pi/agent/sandbox.json`
- **project** — `<cwd>/.pi/sandbox.json` (only honored when the project is *trusted*; untrusted projects contribute nothing and can't be written to)

So a project can opt in or out independently of your global default — e.g. global `"enabled": false` + project `"enabled": true`, or vice versa.

```json
{
  "enabled": true,
  "runner": "auto",
  "writable": ["~/scratch"],
  "home": "ro",
  "homeCaches": "rw",
  "network": "allow",
  "userCommands": false
}
```

**Capability matrix** — what each runner actually enforces:

| Runner | Platform | Filesystem boundary | Network policy | Privilege to set up | Notes |
|---|---|---|---|---|---|
| `bwrap` | Linux | rw only under writable roots (fresh private `/tmp`, `/proc` under the default root set) | enforced (`--unshare-net`) | unprivileged user namespaces | preferred; canary-probed at session start |
| `landlock` | Linux ≥ 5.13 | rw only under writable roots | **not enforced** (warning) | C compiler (checked at session start), or a prebuilt `landlockHelper` | fallback; canary-probed |
| `sandbox-exec` | macOS | rw only under writable roots | enforced | none | Seatbelt; Apple-deprecated (removal ⇒ gate-only); canary-probed |
| *(none)* | Windows / no runner available | **gate-only** (heuristic prompts) | n/a | n/a | fail-open by default; `failIfUnavailable: true` blocks instead |

The story in one line: the gate is a heuristic prompt guard; the sandbox is the OS-level boundary; landlock cannot do network; and when no runner can be established you either get a loud fail-open warning or a fail-closed block — never a silent middle ground.

**Commands** (all take effect immediately, no `/reload` needed):

- `/sandbox` — live status (runner, writable roots, network policy, fallback reason, config paths).
- `/sandbox on` — enable, writing the **project** scope; the runner defaults to `"auto"` (an explicit `runner` already set in either scope is kept).
- `/sandbox off` — disable, writing the **project** scope (overrides a global `"enabled": true`).
- `/sandbox config` — interactive editor: pick the scope (project or global), then edit any option (`enabled`, `runner`, `network`, `home`, `homeCaches`, `userCommands`, `loginShell`, `landlockHelper`, `failIfUnavailable`, `writable`) and save. For `writable`, an empty value stores `[]` — "no extra writable paths in this scope"; because the project scope wins per-key, a project `[]` overrides a non-empty global list (a global `[]` never overrides a project one). cwd, /tmp, /dev, /proc stay writable either way.

- `runner` — `auto` (default), `bwrap`, `landlock`, `sandbox-exec`, or `none`. On Linux, `auto` prefers **bubblewrap** (user/pid namespaces, can also deny the network) and falls back to the **Landlock** helper — a tiny C program (`extensions/permission-gate/landlock-helper.c`) compiled on first use with `cc` to `~/.cache/pi-extensions/pi-sandbox-landlock`. On macOS only `sandbox-exec` (Seatbelt) is available; the generated profile is validated at session start by a canary probe (write-in-root OK, write-out-of-root denied) and covered by a darwin-gated integration test (`test/sandbox-seatbelt.test.ts`, validated on macOS 26.6.2). Note: `sandbox-exec` is **Apple-deprecated** — it still works, but if Apple removes it the macOS sandbox degrades to gate-only (the probe detects the absence and warns). In the Seatbelt profile, `/dev` is granted as specific safe devices only (`/dev/null`, `/dev/stdout`, `/dev/stderr`, `/dev/tty`), never a blanket subpath.
- `writable` — extra writable paths (leading `~` expands; relative = cwd-relative; **non-existent paths are omitted with a warning** — never widened to a parent, so a typo cannot make `/` writable). The workspace (cwd), `/tmp`, `/dev`, and `/proc` are always writable; everything else — **including `$HOME`** — is read-only unless listed or covered by `homeCaches`.
- `home` — `"ro"` (default) or `"rw"` for `$HOME`.
- `homeCaches` — `"ro"` (default) or `"rw"`. When `rw`, a curated set of `$HOME` cache/tool dirs is writable so common dev tooling works out of the box: `~/.cache` (XDG cache — pre-commit, pip, uv, virtualenv, …), `~/.npm`, `~/.pnpm-store`, `~/.yarn`, `~/.bun`, `~/.cargo`, `~/.rustup`, `~/.gem`, `~/.m2`, `~/.gradle`, `~/.ivy2`, `~/.nvm`, `~/.volta`, `~/.asdf`, `~/.pyenv`, `~/.rbenv`, `~/.rvm`, `~/.gvm`, `~/.sdkman`, `~/.local/share/uv`, `~/.local/bin` (see `HOME_CACHE_ROOTS` in `extensions/lib/sandbox-utils.ts`). Only dirs that **already exist** are added — a missing dir is skipped, never resolved up to `$HOME`. Credential/config dirs (`.ssh`, `.aws`, `.gnupg`, `.config`) are deliberately excluded; the default is `ro` because several of these dirs can hold credentials or executable shims — set `"rw"` to let common dev tooling write to them, or list extra dirs in `writable`.
- `network` — `"allow"` (default) or `"deny"`. Enforced by bwrap (`--unshare-net`) and seatbelt; a **no-op with a warning on landlock** (Landlock cannot restrict networks).
- `userCommands` — `true` also sandboxes user `!` commands (they normally bypass the agent's tool pipeline entirely).
- `loginShell` — `true` (default) or `false`. `true` runs sandboxed commands as `bash -lc` (login shell: sources `/etc/profile` + `~/.bash_profile` inside the sandbox, preserving login-profile env); `false` uses plain `bash -c` (no login profiles; the pi process's exported environment and `BASH_ENV` still apply).
- `landlockHelper` — explicit path to a prebuilt Landlock helper binary (Linux only). When set, the helper is used as-is and **no compilation happens** — useful in locked-down environments (no `cc`, or a `noexec` cache dir). A missing/unexecutable file fails the probe (no fallback to building). When unset, the helper compiles from `landlock-helper.c` on first use — after a SHA-256 source-integrity check — into `~/.cache/pi-extensions/pi-sandbox-landlock` (a `noexec` cache dir is detected and reported with an actionable message).
- `failIfUnavailable` — `false` (default) or `true`. When the sandbox is `enabled` but no runner can be resolved, `false` warns and runs commands **unsandboxed** (fail-open — interactive/dev default); `true` **blocks** bash/powershell/write/edit instead (fail-closed — for enforced/fleet adoption, e.g. native Windows or Linux with unprivileged userns disabled).

Every gate rule is armed **regardless of sandbox state**: the sandbox answers *where* a command may write, the gate answers *whether* the command needs human intent — confinement to writable roots does not make an irreversible action reversible. Irreversible-action rules (recursive `rm`, world-writable `chmod`, privilege escalation, power actions, destructive Git operations, curated remote destruction, database DROP/TRUNCATE) always prompt; raw host-disk operations (`dd`/redirect/`tee`/`cp`/`shred` to `/dev/*`, `wipefs`, `blkdiscard`, partition wipes, LVM/ZFS destroy, `mkfs`, PowerShell disk wipes) are **hard-blocked** — human-only, no prompt. `write`/`edit` tool calls target a path directly (no shell), so they get a separate guard: paths outside the writable roots prompt for confirmation. If no runner is available at session start (no bwrap + no Landlock kernel/compiler, or a broken bwrap — e.g. AppArmor `restrict_unprivileged_userns` on some Ubuntu setups), the extension warns and runs commands **unsandboxed** — unless `failIfUnavailable: true`, in which case it **blocks** them (fail-closed).

**Managed (admin) scope.** A third, highest-precedence config file exists for fleet/corporate enforcement: `/etc/pi/agent/sandbox.json` (Windows: `%ProgramData%\pi\agent\sandbox.json`). Scalar keys there win outright — an admin can pin `"enabled": true` (and `failIfUnavailable`) so developers cannot turn the sandbox off or fail open; `"writable"` can only be **narrowed** (the effective list is the intersection with the lower scopes), never widened. A malformed managed file **fails closed** (commands are blocked until it is fixed); a malformed user-scope file does not defeat the managed policy — the managed policy is enforced alone, with a warning. Note: PowerShell commands are never sandboxed (there is no PowerShell sandbox backend) — they are guarded by the heuristic gate only, and `failIfUnavailable` blocks them solely when no runner can be resolved.

The sandbox is a mistake/runaway-command boundary, not a security boundary against malicious code: it isolates the filesystem only, landlock cannot block the network, and the landlock helper's `PR_SET_NO_PRIVS` only stops setuid escalation. `/sandbox` prints the live status (runner, writable roots, network policy, fallback reason); `/sandbox on|off|config` manage it (see above).

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
