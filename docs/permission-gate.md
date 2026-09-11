# permission-gate

Heuristic guard: prompts for confirmation before potentially dangerous bash commands (recursive `rm`, `sudo`/`doas`/`pkexec`, world-writable `chmod`, power actions, destructive Git operations, curated remote destruction, database DROP/TRUNCATE) and dangerous PowerShell cmdlets (recursive `Remove-Item`, elevation, `Invoke-Expression`, ACL changes, machine-wide registry writes); raw host-disk operations (`dd`/redirect/`tee`/`cp`/`shred` to `/dev/*`, `wipefs`, `blkdiscard`, partition wipes, LVM/ZFS destroy, `mkfs`, PowerShell disk wipes) are **hard-blocked** — human-only, no prompt. Every rule is armed regardless of sandbox state.

Optionally adds an **OS filesystem sandbox** (bubblewrap / Landlock on Linux, `sandbox-exec` on macOS) that makes the agent's bash commands read-only outside writable roots — opt-in via `sandbox.json` (global `~/.pi/agent/` or project `.pi/`). Toggle with `/sandbox on|off`, edit with `/sandbox config`.

The gate alone is not a security boundary; the sandbox is an OS-level boundary.

## The gate (always on)

Every gate rule is armed **regardless of sandbox state**: the sandbox answers *where* a command may write, the gate answers *whether* the command needs human intent — confinement to writable roots does not make an irreversible action reversible. Irreversible-action rules (recursive `rm`, world-writable `chmod`, privilege escalation, power actions, destructive Git operations, curated remote destruction, database DROP/TRUNCATE) always prompt; raw host-disk operations (`dd`/redirect/`tee`/`cp`/`shred` to `/dev/*`, `wipefs`, `blkdiscard`, partition wipes, LVM/ZFS destroy, `mkfs`, PowerShell disk wipes) are **hard-blocked** — human-only, no prompt. `write`/`edit` tool calls target a path directly (no shell), so they get a separate guard: paths outside the writable roots prompt for confirmation.

PowerShell commands are never sandboxed (there is no PowerShell sandbox backend) — they are guarded by the heuristic gate only, and `failIfUnavailable` blocks them solely when no runner can be resolved.

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
- `/sandbox config` — interactive editor: pick the scope (project or global), then edit any option (`enabled`, `runner`, `network`, `home`, `homeCaches`, `userCommands`, `loginShell`, `landlockHelper`, `failIfUnavailable`, `writable`) and save. For `writable`, an empty value stores `[]` — "no extra writable paths in this scope"; because the project scope wins per-key, a project `[]` overrides a non-empty global list (a global `[]` never overrides a project one). cwd, /tmp, /dev, /proc stay writable either way.

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

If no runner is available at session start (no bwrap + no Landlock kernel/compiler, or a broken bwrap — e.g. AppArmor `restrict_unprivileged_userns` on some Ubuntu setups), the extension warns and runs commands **unsandboxed** — unless `failIfUnavailable: true`, in which case it **blocks** them (fail-closed).

### Managed (admin) scope

A third, highest-precedence config file exists for fleet/corporate enforcement: `/etc/pi/agent/sandbox.json` (Windows: `%ProgramData%\pi\agent\sandbox.json`). Scalar keys there win outright — an admin can pin `"enabled": true` (and `failIfUnavailable`) so developers cannot turn the sandbox off or fail open; `"writable"` can only be **narrowed** (the effective list is the intersection with the lower scopes), never widened. A malformed managed file **fails closed** (commands are blocked until it is fixed); a malformed user-scope file does not defeat the managed policy — the managed policy is enforced alone, with a warning.

### Scope and limitations

The sandbox is a mistake/runaway-command boundary, not a security boundary against malicious code: it isolates the filesystem only, landlock cannot block the network, and the landlock helper's `PR_SET_NO_PRIVS` only stops setuid escalation.