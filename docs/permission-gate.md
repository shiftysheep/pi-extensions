# permission-gate

Heuristic guard: prompts for confirmation before potentially dangerous bash commands (recursive `rm`, `sudo`/`doas`/`pkexec`, world-writable `chmod`, power actions, destructive Git operations, curated remote destruction, database DROP/TRUNCATE, download-to-shell pipes, service stops (`systemctl stop|disable|mask|kill`, `service … stop`), broad recursive `chown`, network socket redirects (`/dev/tcp`, `/dev/udp` — incl. the `bash -i >& /dev/tcp/…` reverse-shell form), and shell payloads — `bash -c`/`eval` are seen through: literal payloads are re-gated recursively, dynamic ones (command substitution) confirm) and dangerous PowerShell cmdlets (recursive `Remove-Item`, elevation, `Invoke-Expression`, ACL changes, machine-wide registry writes, `-EncodedCommand` — decoded and re-gated, and confirmed even when the decoded text is clean); raw host-disk operations (`dd`/redirect/`tee`/`cp`/`mv`/`shred` to `/dev/*`, `wipefs`, `blkdiscard`, partition wipes, LVM/ZFS destroy, `mkfs`, PowerShell disk wipes) are **hard-blocked** — human-only, no prompt. Rules also see through benign wrappers (`nohup`, `nice`, `time`, `exec`, `command`). Every rule is armed regardless of sandbox state.

Optionally adds an **OS filesystem sandbox** (bubblewrap / Landlock on Linux, `sandbox-exec` on macOS) that makes the agent's bash commands read-only outside writable roots — opt-in via `sandbox.json` (global `~/.pi/agent/` or project `.pi/`). Toggle with `/sandbox on|off`, edit with `/sandbox config`.

The gate alone is not a security boundary; the sandbox is an OS-level boundary. An optional **Jev danger classifier** (TypeSafe) can additionally screen commands the static rules miss — see [The Jev danger classifier](#the-jev-danger-classifier-opt-in).

## The gate (always on)

Every gate rule is armed **regardless of sandbox state**: the sandbox answers *where* a command may write, the gate answers *whether* the command needs human intent — confinement to writable roots does not make an irreversible action reversible. Irreversible-action rules (recursive `rm`, world-writable `chmod`, privilege escalation, power actions, destructive Git operations, curated remote destruction, database DROP/TRUNCATE) always prompt; raw host-disk operations (`dd`/redirect/`tee`/`cp`/`mv`/`shred` to `/dev/*`, `wipefs`, `blkdiscard`, partition wipes, LVM/ZFS destroy, `mkfs`, PowerShell disk wipes) are **hard-blocked** — human-only, no prompt. `write`/`edit` tool calls target a path directly (no shell), so they get a separate guard: paths outside the writable roots prompt for confirmation.

PowerShell commands are never sandboxed (there is no PowerShell sandbox backend) — they are guarded by the heuristic gate only, and `failIfUnavailable` blocks them solely when no runner can be resolved.

**Shell payloads and encoded execution.** Indirect invocation is the classic evasion of text matching, so the gate has a dedicated tier for it. When the static rules miss, `bash`/`sh`/`dash`/`zsh`/`ksh -c '…'` and `eval '…'` payloads are extracted and **re-gated recursively** (bounded to 3 nesting levels): a literal payload inherits the inner verdict — `bash -c 'dd of=/dev/sda'` is hard-blocked as a raw device write, `bash -c 'ls'` stays silent — while a payload containing command or process substitution (`$(…)`, backticks, `<(`) confirms as *dynamic shell payload*, and exhausted nesting confirms as *nested shell payload*. Downloader output piped into a stdin shell (`curl … | bash`, `wget -qO- … | sh -s`) confirms as *download to shell*. PowerShell `-EncodedCommand` values are decoded (UTF-16LE base64) and re-gated with the PowerShell rules; a decoded static miss, an undecodable value, or exhausted nesting still confirms — encoded execution never means "safe". Interpreter one-liners (`python -c`, `node -e`, …) and script files are deliberately left to the optional classifier: blanket-confirming them would interrupt routine inspection.

**Network socket redirects.** bash's virtual sockets `/dev/tcp/HOST/PORT` and `/dev/udp/HOST/PORT` are *network* endpoints, not block devices: a redirect there opens a connection (exfiltration or reverse-shell risk), so it **confirms** as *network socket redirect* rather than being hard-blocked as a raw disk write. All directions are covered — `>`, `>>`, `>&` (the classic `bash -i >& /dev/tcp/… 0>&1` form), `<`, and `<>` (`exec 3<>/dev/tcp/…`); heredocs, here-strings, and quoted examples are not matches.

**What happens when a call is blocked** (declined confirm, no UI available, hard deny, or fail-closed): by default the block reason is reported to the model as a tool error and the **turn continues**, so the model can read the reason and adapt (e.g. pick a different approach or tell you to run the human-only command manually). Set `"blockTerminates": true` in `sandbox.json` to restore the previous behavior, where a block stops the agent's turn after the current tool batch.

## The Jev danger classifier (opt-in)

A third, **optional** gate tier. When the static rules above do **not** match a command, the classifier asks TypeSafe's **Jev** model (a "System One" decision model) two yes/no questions — *is this command malicious?* and *is this command dangerous?* — in a single API call, and acts on the higher probability. It is the semantic safety net for what the deterministic text rules still miss (interpreter one-liners, script files, data exfiltration, novel obfuscation). Like the static rules it is a **heuristic, not a security boundary** — it can be evaded, and its verdicts are probabilistic. Static precedence is kept: a static match (confirm or deny) preempts the classifier, so the tiers combine as *static wins, classifier fills the gap*.

The request gives Jev a named state containing both the original command and its shell (`bash` or `powershell`). The questions explicitly separate malicious intent from legitimate-but-dangerous administration and ask whether an autonomous agent should require human confirmation, including shell expansion and indirect targets.

Off by default; enabling it makes **every** non-static-matched bash/PowerShell command pay a Jev round-trip (latency + API cost), so treat it as an opt-in for high-stakes sessions.

> **Privacy:** when enabled, each screened command's text is sent to TypeSafe's API (`api.typesafe.ai`) for classification. Enable it only where that is acceptable.

### Behavior

- `risk = max(malicious, dangerous)`.
- `risk ≥ classifierDenyThreshold` (default `0.85`) → **hard-block** (a model judgment, not a static rule — the message says so).
- `risk ≥ classifierConfirmThreshold` (default `0.7`) → **confirm** prompt naming the concern(s) and probabilities.
- otherwise → proceed.
- **Fails open**: if `TYPESAFE_API_KEY` is unset, or the call errors / times out / returns a malformed body, the command proceeds (with a one-time warning) — the static tier still guards the hard cases. Pressing Esc during the call aborts it (no warning); in headless/print/JSON modes the one-time warning goes to stderr so stdout stays clean.

### Config (`sandbox.json`)

| Key | Default | Meaning |
|---|---|---|
| `classifier` | `"off"` | `"off"` = static rules only; `"jev"` = enable the Jev classifier. |
| `classifierConfirmThreshold` | `0.7` | Probability at/above which a command prompts for confirmation. Clamped to never exceed the deny threshold. |
| `classifierDenyThreshold` | `0.85` | Probability at/above which a command is hard-blocked. |
| `classifierModel` | `"jev-latest"` | Jev model id. |
| `classifierTimeoutMs` | `8000` | Per-call request timeout (ms), capped at `60000`. |

The API key is read from the **`TYPESAFE_API_KEY` environment variable** — it is never stored in `sandbox.json`. All keys are editable in `/sandbox config` and shown in `/sandbox` status.

### Benchmarking

A dev/eval harness scores the gate against a labeled set of benign / dangerous / malicious commands (`scripts/classifier-benchmark-data.ts`) and reports per-command verdicts plus aggregate recall/false-positive rates. The corpus includes 124 duplicate-free Bash and PowerShell cases spanning routine development, repository history, services, local security/configuration, containers/orchestration, cloud/IaC, databases, disks, exfiltration, persistence, evasion, and encoded/reverse-shell execution. It needs a real `TYPESAFE_API_KEY` and network, so it is **not** part of `npm test` / `npm run check`:

```bash
npm run benchmark:classifier                                  # composed view (default): the real gate
npm run benchmark:classifier -- --view classifier             # classifier alone (no static backstop)
npm run benchmark:classifier -- --confirm 0.6 --deny 0.85     # tune thresholds
npm run benchmark:classifier -- --json                        # machine-readable
```

Two views (`--view`):
- **composed** (default) — the real gate: each case is routed by shell to its static rules first (bash vs PowerShell), and the classifier only runs on a miss. This shows the true residual gaps. Note a static *confirm* preempts the classifier, so the gate is non-monotonic — a static confirm can mask a classifier deny. The composed view only *calls* Jev on static misses (preempted cases are reported as `skipped`), so it costs one API call per residual case; `classifier`/`both` call every case so the classifier-alone view stays complete.
- **classifier** — the classifier alone (no static backstop), for comparing models/prompts.

Expectations: benign → proceed, dangerous → confirm/deny, malicious → deny. The run exits non-zero if any dangerous/malicious command is missed (the safety-critical failures); benign false-positives are reported but don't fail it. Extend the dataset in `scripts/classifier-benchmark-data.ts` to cover your threat model.

## The filesystem sandbox (opt-in)

Set `"enabled": true` in a `sandbox.json` (absent file = disabled, behavior identical to the gate alone). Two scopes are supported and merged **per-key, project wins**:

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

### Capability matrix

What each runner actually enforces:

| Runner | Platform | Filesystem boundary | Network policy | Privilege to set up | Notes |
|---|---|---|---|---|---|
| `bwrap` | Linux | rw only under writable roots (fresh private `/tmp`, `/proc` under the default root set) | enforced (`--unshare-net`) | unprivileged user namespaces | preferred; canary-probed at session start |
| `landlock` | Linux ≥ 5.13 | rw only under writable roots | **not enforced** (warning) | C compiler (checked at session start), or a prebuilt `landlockHelper` | fallback; canary-probed |
| `sandbox-exec` | macOS | rw only under writable roots | enforced | none | Seatbelt; Apple-deprecated (removal ⇒ gate-only); canary-probed |
| *(none)* | Windows / no runner available | **gate-only** (heuristic prompts) | n/a | n/a | fail-open by default; `failIfUnavailable: true` blocks instead |

The story in one line: the gate is a heuristic prompt guard; the sandbox is the OS-level boundary; landlock cannot do network; and when no runner can be established you either get a loud fail-open warning or a fail-closed block — never a silent middle ground.

### Commands

All take effect immediately, no `/reload` needed:

- `/sandbox` — live status (runner, writable roots, network policy, fallback reason, config paths).
- `/sandbox on` — enable, writing the **project** scope; the runner defaults to `"auto"` (an explicit `runner` already set in either scope is kept).
- `/sandbox off` — disable, writing the **project** scope (overrides a global `"enabled": true`).
- `/sandbox config` — interactive editor: pick the scope (project or global), then edit any option (`enabled`, `runner`, `network`, `home`, `homeCaches`, `userCommands`, `loginShell`, `landlockHelper`, `failIfUnavailable`, `blockTerminates`, `writable`, and the classifier options) and save. For `writable`, an empty value stores `[]` — "no extra writable paths in this scope"; because the project scope wins per-key, a project `[]` overrides a non-empty global list (a global `[]` never overrides a project one). cwd, /tmp, /dev, /proc stay writable either way.

### Options

- `runner` — `auto` (default), `bwrap`, `landlock`, `sandbox-exec`, or `none`. On Linux, `auto` prefers **bubblewrap** (user/pid namespaces, can also deny the network) and falls back to the **Landlock** helper — a tiny C program (`extensions/permission-gate/landlock-helper.c`) compiled on first use with `cc` to `~/.cache/pi-extensions/pi-sandbox-landlock`. On macOS only `sandbox-exec` (Seatbelt) is available; the generated profile is validated at session start by a canary probe (write-in-root OK, write-out-of-root denied) and covered by a darwin-gated integration test (`test/sandbox-seatbelt.test.ts`, validated on macOS 26.6.2). Note: `sandbox-exec` is **Apple-deprecated** — it still works, but if Apple removes it the macOS sandbox degrades to gate-only (the probe detects the absence and warns). In the Seatbelt profile, `/dev` is granted as specific safe devices only (`/dev/null`, `/dev/stdout`, `/dev/stderr`, `/dev/tty`), never a blanket subpath.
- `writable` — extra writable paths (leading `~` expands; relative = cwd-relative; **non-existent paths are omitted with a warning** — never widened to a parent, so a typo cannot make `/` writable). The workspace (cwd), `/tmp`, `/dev`, and `/proc` are always writable; everything else — **including `$HOME`** — is read-only unless listed or covered by `homeCaches`.
- `home` — `"ro"` (default) or `"rw"` for `$HOME`.
- `homeCaches` — `"ro"` (default) or `"rw"`. When `rw`, a curated set of `$HOME` cache/tool dirs is writable so common dev tooling works out of the box: `~/.cache` (XDG cache — pre-commit, pip, uv, virtualenv, …), `~/.npm`, `~/.pnpm-store`, `~/.yarn`, `~/.bun`, `~/.cargo`, `~/.rustup`, `~/.gem`, `~/.m2`, `~/.gradle`, `~/.ivy2`, `~/.nvm`, `~/.volta`, `~/.asdf`, `~/.pyenv`, `~/.rbenv`, `~/.rvm`, `~/.gvm`, `~/.sdkman`, `~/.local/share/uv`, `~/.local/bin` (see `HOME_CACHE_ROOTS` in `extensions/lib/sandbox-utils.ts`). Only dirs that **already exist** are added — a missing dir is skipped, never resolved up to `$HOME`. Credential/config dirs (`.ssh`, `.aws`, `.gnupg`, `.config`) are deliberately excluded; the default is `ro` because several of these dirs can hold credentials or executable shims — set `"rw"` to let common dev tooling write to them, or list extra dirs in `writable`.
- `network` — `"allow"` (default) or `"deny"`. Enforced by bwrap (`--unshare-net`) and seatbelt; a **no-op with a warning on landlock** (Landlock cannot restrict networks).
- `userCommands` — `true` also sandboxes user `!` commands (they normally bypass the agent's tool pipeline entirely).
- `loginShell` — `true` (default) or `false`. `true` runs sandboxed commands as `bash -lc` (login shell: sources `/etc/profile` + `~/.bash_profile` inside the sandbox, preserving login-profile env); `false` uses plain `bash -c` (no login profiles; the pi process's exported environment and `BASH_ENV` still apply).
- `landlockHelper` — explicit path to a prebuilt Landlock helper binary (Linux only). When set, the helper is used as-is and **no compilation happens** — useful in locked-down environments (no `cc`, or a `noexec` cache dir). A missing/unexecutable file fails the probe (no fallback to building). When unset, the helper compiles from `landlock-helper.c` on first use — after a SHA-256 source-integrity check — into `~/.cache/pi-extensions/pi-sandbox-landlock` (a `noexec` cache dir is detected and reported with an actionable message).
- `failIfUnavailable` — `false` (default) or `true`. When the sandbox is `enabled` but no runner can be resolved, `false` warns and runs commands **unsandboxed** (fail-open — interactive/dev default); `true` **blocks** bash/powershell/write/edit instead (fail-closed — for enforced/fleet adoption, e.g. native Windows or Linux with unprivileged userns disabled).
- `blockTerminates` — `false` (default) or `true`. Controls what happens after the gate **blocks** a call (declined confirm, no UI, hard deny, fail-closed): `false` reports the reason to the model as a tool error and the turn **continues**; `true` stops the agent's turn after the current tool batch (the pre-`blockTerminates` behavior).
- `classifier` — `"off"` (default) or `"jev"`. Enables the optional Jev danger classifier (see [The Jev danger classifier](#the-jev-danger-classifier-opt-in)).
- `classifierConfirmThreshold` / `classifierDenyThreshold` — Jev probability thresholds (defaults `0.7` / `0.85`) for confirm vs hard-block; confirm is clamped to never exceed deny.
- `classifierModel` / `classifierTimeoutMs` — Jev model id (default `jev-latest`) and per-call request timeout in ms (default `8000`, capped at `60000`).

If no runner is available at session start (no bwrap + no Landlock kernel/compiler, or a broken bwrap — e.g. AppArmor `restrict_unprivileged_userns` on some Ubuntu setups), the extension warns and runs commands **unsandboxed** — unless `failIfUnavailable: true`, in which case it **blocks** them (fail-closed).

### Managed (admin) scope

A third, highest-precedence config file exists for fleet/corporate enforcement: `/etc/pi/agent/sandbox.json` (Windows: `%ProgramData%\pi\agent\sandbox.json`). Scalar keys there win outright — an admin can pin `"enabled": true` (and `failIfUnavailable`) so developers cannot turn the sandbox off or fail open; `"writable"` can only be **narrowed** (the effective list is the intersection with the lower scopes), never widened. A malformed managed file **fails closed** (commands are blocked until it is fixed). Scopes are read independently: a malformed user-scope file neither defeats the managed policy (managed keys still win outright) nor discards the other valid scopes — e.g. a broken project file cannot drop a global `failIfUnavailable: true`. The remaining valid scopes are applied, with a warning.

### Scope and limitations

The sandbox is a mistake/runaway-command boundary, not a security boundary against malicious code: it isolates the filesystem only, landlock cannot block the network, and the landlock helper's `PR_SET_NO_PRIVS` only stops setuid escalation.
