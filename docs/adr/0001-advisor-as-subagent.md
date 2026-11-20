# ADR-0001: Redesign the advisor as a configured pi-subagents agent + thin wrapper

**Status:** Proposed (rebased on pi-subagents 0.89.1)
**Date:** 2026-02-14
**Deciders:** shiftysheep + advisor (openai-codex/gpt-6.2-sol, explore mode)
**Depends on:** `pi-subagents` **≥ 0.89.1** (bumped from `^0.65.0`; the design uses
0.89.x capabilities not present in 0.65.x)

## Context

The `advisor` extension lets the primary agent consult an independent expert
(typically a larger, more capable model) for design advice, second opinions,
and code review. The advisor talks to the primary agent, not the end user.

The current implementation spawns a **separate child `pi` process** with:
a throwaway agent dir, a stripped copy of `auth.json` (OAuth refresh tokens
removed), a minimal env allowlist, NDJSON event parsing back, process-group
kill/teardown, a 2-concurrent `globalThis` limiter, and a hand-rolled model
fallback chain. ~1500 lines across `extensions/advisor.ts`,
`extensions/advisor/` (transports, models, request, config), and
`extensions/lib/advisor-utils.ts`.

The stated reason for the separate process is **OAuth refresh-token rotation
isolation**: a separate process holding its own `auth.json` copy could refresh
and rotate the host's refresh token server-side, breaking the host credential.

### Key finding that drives the redesign

If the advisor runs as an **in-process subagent** (via the bundled
`pi-subagents` extension), the auth-rotation threat is substantially reduced:
the child shares the host's canonical `auth.json` **by file**, and stored
OAuth refresh is **lock-serialized** — `pi-ai`'s `resolveStoredOAuth`
rechecks expiry and refreshes inside `credentials.modify()`, and the
`auth-storage` backend reads/persists under an async file lock. Multiple
refresh callers (host + child) are serialized on the same canonical file, so
no rotation desync occurs on the standard stored-OAuth path.

**Caveat:** the child factory creates its *own* `ModelRuntime` (shared among
its children), not the host's runtime object. Auth sharing is by *canonical
file*, not by runtime object or process. This holds for Pi's standard
stored-OAuth path; it is **not yet proven** for every extension-backed
provider (which may use a different auth path). `pi-ai`'s `resolve.js`
deliberately decouples caller cancellation *after* lock acquisition and gives
refresh its own timeout — the generic pre-write abort check does *not* mean
ordinary caller cancellation drops the rotated token. Process termination, a
lost refresh response after server rotation, and extension-backed providers
remain real risks. The old transport's env allowlist and process-group
teardown are retired **only once** the supported providers and deployed host
are shown to use the same canonical file and refresh path, **and**
cancellation-during-refresh + termination-after-rotation are tested (spike
verification #4).

Additionally, `pi-subagents` **0.89.1** provides the capabilities the advisor
needs — and **ships an `advisor` agent** that is exactly this extension's
purpose.

### pi-subagents 0.89.1 capabilities the design relies on

- **Bundled `advisor`/`oracle` agent**: "A second opinion before acting. It
  challenges assumptions, catches drift, and recommends the safest next move
  **without editing**." `oracle` and `advisor` are the *same bundled role*
  (Claude Code-compatible name). The advisor's purpose is already a builtin —
  we *configure* it, we don't ship a new agent.
- **Agent overrides** (`subagents.agentOverrides.<name>` in settings):
  `model`, `tools`, `systemPrompt`, `thinking`, `defaultContext`, etc. The
  wrapper (or `/advisor` command) configures the bundled `oracle` agent's
  model/tools/prompt via `agentOverrides.oracle` — no custom agent file, no
  `pi.subagents.agents` manifest key. The canonical agent name is `oracle`
  (the `name:` field in `agents/oracle.md`); `advisor` is an alias. Override
  keys use the canonical name, not aliases.
- **Foreground children are in-process**: "Local foreground children never
  load the parent's ambient extensions: they share the parent's process." A
  `wait:true` (foreground, via the structured delegation API) advisor child is
  **in-process** — no detached runner, no env inheritance.
- **RPC `spawn` is async-only** (detached runner, inherits most of
  `process.env`). A `wait:false` (background, via the in-process RPC) advisor
  child is a **detached Node process** — env inheritance applies.
- **`toolBudget: { hard: 0, block: "*" }`** is explicitly supported for a
  **zero-tool leaf** — the tool-free *review* mode (single model call, no
  workspace inspection) is achievable via the delegation API.
- **Agent definitions + agent overrides** are the per-agent mechanism for the
  read-only guarantee: the bundled `oracle` agent's `tools` allowlist +
  `extensions` list (configured via `subagents.agentOverrides.oracle`) scope
  the advisor's tools and extensions *per agent*, not session-wide. This is
  the right mechanism for the advisor's read-only guarantee — a capability
  ceiling (`registerSubagentCapabilityCeiling`) is a *session-wide* policy
  boundary that restricts launches across the session and `denyExtensions`
  removes configured extensions too (not just ambient); using it for the
  advisor would block ordinary worker launches and strip Context7 from the
  advisor. The agent definition + override is the correct per-agent scoping.
  The bundled `oracle` agent ships `tools: read, grep, find, ls, bash` and
  `defaultContext: fork` + `inheritProjectContext: true` — the override must
  restrict `tools` to the read-only allowlist (removing `bash`) and set
  `defaultContext: "fresh"` (overriding the `fork` default).
- **`cost` RPC method**: per-child usage/cost accounting as data
  (`{ parent, children, childTotal, total, unresolvedAsyncChildren }`). The
  wrapper reads accounting directly instead of relying on the status-line's
  artifact scan.
- **`providerDiagnostics`** on delegation updates: observed assistant-request
  errors + Pi retries, with `rate_limited` / `transient_other` / `unknown`
  classification. The wrapper's fallback chain knows *why* a consultation
  failed (rate-limited vs. transient), improving the fallback decision.
- **Headless wait** (0.88.0): in `pi -p`, Pi waits for background subagent
  work at the end of a turn for as long as the `timeoutMs` setting allows;
  without `timeoutMs`, the wait is 30 minutes. The headless drain is
  `timeoutMs`-bounded, not a fixed 30 min.

## Decision

Redesign the advisor as a **configured pi-subagents `advisor` agent + a
dedicated thin wrapper tool**, integrated via the **structured delegation API**
(for `wait:true`, in-process foreground) and the **in-process RPC** (for
`wait:false`, async detached). Bump `pi-subagents` to `^0.89.1`.

- The advisor is the **bundled `oracle` agent** (alias `advisor`), configured
  via `subagents.agentOverrides.oracle` with: the model from `advisor.json`
  (primary/fallback), the read-only tool allowlist (`read`, `grep`, `find`,
  `ls`, `resolve-library-id`, `query-docs`), the second-opinion system prompt
  (the bundled `oracle` prompt, or our own if it differs), and `thinking`
  from `advisor.json`'s `reasoningEffort`. No custom agent file is shipped.
  The bundled `oracle` agent's defaults (`tools` includes `bash`,
  `defaultContext: fork`, `inheritProjectContext: true`) must be overridden
  to match the advisor's read-only, fresh-context requirements.
- The primary invokes the advisor via a **dedicated `advisor` tool** (the
  wrapper), not the generic `subagent` tool. The wrapper adds the
  consultation framing, provenance disclosure, and `independent=false`
  self-review marking that make the advisor an *advisor* rather than a
  *subagent alias*.
- The read-only guarantee is enforced by the **agent definition + override**:
  the bundled `advisor` agent's `tools` allowlist (`read`, `grep`, `find`,
  `ls`, `resolve-library-id`, `query-docs`) and `extensions` list (Context7,
  + web-access for `webSearch:true`) scope the advisor's tools and extensions
  *per agent*. This is a per-agent guarantee, not a session-wide policy
  boundary — ordinary worker launches are unaffected. **Caveat:** the agent
  definition's `tools` allowlist is a *configuration* guarantee, not a
  *structural* one — a model that calls a tool not in the allowlist gets a
  "tool not found" error (the tool isn't loaded), but the guarantee depends
  on the agent definition being respected at launch. The wrapper verifies the
  effective contract (prompt, tools, extensions) at launch and fails closed if
  it doesn't match the override (spike #1).

### Why a dedicated wrapper and not the generic `subagent` tool

Day-to-day, the primary reaches for "consult the advisor" (a consultation
gesture) vs. "delegate work to a subagent" (a worker gesture). These are
different relationships. The advisor tool encodes the consultation shape:
the second-opinion framing is baked in, the read-only guarantee is
structural (capability ceiling), the provenance is disclosed (which model
answered, fallback flags, `independent=false` on self-review), and the
brief-composition guidance is in the tool description. A generic `subagent`
result that happens to come from the `advisor` agent does not carry that
advisor-specific framing. The wrapper is essential because it is what makes
the advisor an *advisor*.

### Why the delegation API for `wait:true` and the RPC for `wait:false`

- **`wait:true` (blocking)** uses the **structured delegation API**
  (`pi-subagents/delegation`): foreground-only, **in-process** (no detached
  runner, no env inheritance), supports `toolBudget` (including `hard: 0` for
  the tool-free review mode), live progress, cancellation, and
  `providerDiagnostics`. The wrapper blocks on the terminal response event.
- **`wait:false` (background)** uses the **in-process RPC**
  (`subagents:rpc:v1:*`): `spawn` (async-only, detached runner), `status`,
  `interrupt`, `stop`, `resume`, `cost`. The wrapper launches async and returns
  the run handle; the result arrives via the completion event. The detached
  runner's env inheritance is the accepted trust-boundary change for
  `wait:false` (see Trust Boundary below).

The two APIs are used for their respective strengths: delegation for the
in-process foreground blocking case, RPC for the async background case. The
wrapper normalizes the two result shapes into one advisor result.

## Settled design decisions

| Area | Decision |
|---|---|
| **pi-subagents version** | **Bump to `^0.89.1`** (from `^0.65.0`). The design uses 0.89.x capabilities (bundled `advisor` agent, agent overrides, in-process foreground delegation, `toolBudget hard:0`, capability ceilings, `cost` method, `providerDiagnostics`, `timeoutMs`-bounded headless wait). The spike runs against 0.89.1, not 0.65.1. |
| **Integration** | Bundled `oracle` agent (canonical name; alias `advisor`), configured via `subagents.agentOverrides.oracle` + dedicated thin `advisor` wrapper tool. `wait:true` via the **structured delegation API** (in-process foreground); `wait:false` via the **in-process RPC** (async detached). The read-only guarantee is enforced by the **agent definition + override** (per-agent `tools` allowlist + `extensions` list), not a session-wide capability ceiling. The override must restrict `tools` to the read-only allowlist (removing `bash` from the bundled default) and set `defaultContext: "fresh"` (overriding the bundled `fork` default). No custom agent file shipped; no `pi.subagents.agents` manifest key. |
| **Agent configuration** | The wrapper (or `/advisor` command) sets `subagents.agentOverrides.oracle`: `model` (from `advisor.json` primary/fallback), `tools` (`read,grep,find,ls,resolve-library-id,query-docs`), `systemPrompt` (the bundled `oracle` prompt, or our own second-opinion prompt if it differs), `defaultContext: "fresh"`. **Reasoning effort**: `reasoningEffort` maps to the **model `:effort` suffix** on the `model` string (e.g. `openai-codex/gpt-6.2-sol:high`), NOT the dispatch-ignored `thinking` field (the delegation API ignores `thinking`; the `:effort` suffix is the model-level mechanism). Settings precedence: `agentOverrides.oracle` overrides the bundled agent's defaults; the wrapper's per-call `model` override (with `:effort` suffix) overrides `agentOverrides.oracle.model`. Changes take effect at the next launch (the override is read at launch time, not session start). The `webSearch` opt-in adds `web_search` to `tools` (the wrapper updates the override at `session_start` based on the flag). |
| **Consumption** | Hybrid `wait` flag, default `true`. `wait:true` = delegation (in-process foreground, blocking on the terminal response). `wait:false` = RPC `spawn` (async detached, return the run handle; result via completion event). |
| **Control surface** | The wrapper exposes `ask` (launch), `cancel` (delegation cancel event for `wait:true`; RPC `interrupt`/`stop` for `wait:false`), and `status` (RPC `status`, surfaced model-visibly). **Follow-up** is **deferred to v2** (see Resume below) — v1 is one-shot consultations. Steer is *not* an advisor surface (it's the `subagent` tool's job). |
| **Time** | No short/arbitrary timeout. The wrapper sets an **explicit `timeoutMs`** on the launch, validated and bounded. `wait:true` uses a generous default (30 min — the self-protection backstop; the primary blocks at most that long). `wait:false` uses a large default (~24 h) to approximate unbounded; the primary can `cancel` earlier. The `timeoutMs` also bounds the headless (`pi -p`) wait (0.88.0: the headless drain waits as long as `timeoutMs` allows). |
| **Model** | `advisor.json` `primary`/`fallback` drive model selection. The per-call `model` override does **not** carry the `advisor.json` fallback slot (execution sources fallback from `agent.fallbackModels`, which is static). Therefore the **wrapper implements its own bounded fallback chain** under one shared deadline: try `primary`; on failure (classified via `providerDiagnostics` — rate-limited vs. transient vs. unknown), try `fallback`; on failure, (if `activeModelFallback`) try the primary's own model last with `independent=false` disclosure. The wrapper does NOT rely on the runtime's model fallback for the advisor's chain. `reasoningEffort` maps to the **model `:effort` suffix** (not the dispatch-ignored `thinking` field). |
| **Recovery** | Package recovery for retained runs (RPC `resume` revival path). **No wrapper retry** on provider abort — but note the *runner* already attempts provider-abort recovery internally; "no wrapper retry" means the wrapper doesn't add a *second* retry layer. The wrapper reports the terminal status (`completed`/`timed_out`/`aborted`/`cancelled`/`interrupted`) and the primary can re-ask. |
| **Config migration** | `advisor.json` path stays (`~/.pi/agent/advisor.json`). Schema migrates in place: `primary`/`fallback`/`reasoningEffort`/`timeoutMs`/`activeModelFallback` stay; `piBinary`/`awsProfile`/`awsRegion`/`env` become **warn+ignore** (process-only, no-ops in-process); new `webSearch?: boolean` key (default `false`). Never mutate host `process.env`. |
| **Concurrency** | Wrapper imposes a small **active background-run cap** (default 2 simultaneous `wait:false` advisor runs), replacing the old synchronous 2-concurrent `globalThis` limiter with the right shape (active concurrency, not synchronous throughput). Configurable. The wrapper tracks active runs and reconciles stale cap slots on restart. |
| **Resource bound** | Three independent bounds: (1) **`toolBudget`** — `review` mode uses `{ hard: 0, block: "*" }` (zero-tool leaf: ANY tool call is blocked, since `toolCount > 0` triggers the block for `"*"`); `explore` mode uses `{ hard: 200, block: [read,grep,find,ls] }` (after 200 tool calls, `read`/`grep`/`find`/`ls` are hard-blocked; Context7/web_search remain available for a finalizing lookup). **Semantics**: `soft` (optional) is a *behavioral nudge* — when `toolCount >= soft`, the child receives a steer message urging it to finalize. `hard` is a *hard block* — when `toolCount > hard`, tools in the `block` list are actually blocked (the tool call fails with a message). The `block` list specifies which tools are blocked; `"*"` blocks all tools. **Caveat:** blocking tool execution does NOT prove a *single model call* — a blocked call can still prompt another model turn (the model sees the block and may respond with text). The `review` mode's `hard: 0` is a *tool-free* guarantee (no tools can be invoked), not a *single-turn* guarantee — the model can still produce multiple turns of text. (2) **Wall-clock `timeoutMs`** — the hard time bound. (3) **Usage bound** (`usageBudget: { tokens?, costUsd? }` if the launch accepts it) — the hard resource bound. Note: usage limits are based on *reported* usage and prevent *future* child launches, not stop a *running* child — the `timeoutMs` is the actual hard stop for a running run. Do not use a tool count to justify long runs. |
| **Result provenance** | Every terminal result (direct or notified) reports: actual model used, fallback/recovery flags, `independent=false` when effective model == primary's active model (self-review). Never let a same-model fallback pass as a stronger independent opinion. Accounting via the RPC `cost` method (not the status-line's artifact scan). |
| **Resume / follow-up** | **Deferred to v2.** v1 is **one-shot consultations** — no follow-up, no thread continuity. A "follow-up" in v1 is a *new* fresh-context consultation where the primary re-briefs with the prior advice included in the question. Reason: RPC `resume` in 0.89.1 may not accept `timeoutMs`/`usageBudget` (bounded revival unverified — spike #6); shipping follow-up as *unbounded* is a resource risk. The `followUp` param is *reserved* in the tool schema but returns "follow-up not yet available; re-brief a fresh consultation" in v1. v2 follow-up is gated on verifying bounded revival (RPC `resume` accepting `timeoutMs`/`usageBudget`) or an upstream change. |
| **Interaction** | The advisor is a **batch investigator**. It cannot ask-and-continue-in-place (no child→primary round-trip on the delegation/RPC seams; the read-only allowlist has no question tool; `ask_user_question` in a child would ask the end user, violating the advisor's "talks to the primary not the user" property). It stops with a question as its **final output**; the primary resolves it by re-briefing a fresh consultation (v1) or a follow-up (v2). The **consultation brief** (scope/paths/constraints/observed-failures) is assembled by the **primary** into the `question`; the tool description guides the primary to include it. The brief substitutes for the interactive clarification the advisor can't do. Initial consultations are explicitly `context:"fresh"` — the wrapper passes `context: "fresh"` in the launch params, which overrides the agent's `defaultContext` (an explicit launch param takes precedence over the agent-level preference). The `defaultContext: "fresh"` in the agent override is a safety net (if the wrapper forgets to pass `context`), but the explicit launch param is the primary mechanism. |
| **Live visibility** | The primary supervises a running advisor via the wrapper's `status` (RPC `status` for `wait:false`; delegation progress updates for `wait:true`), surfaced model-visibly in the tool result. The primary can watch the investigation (tool count, current tool, recent output, duration) and decide to `cancel` a runaway. |
| **Modes** | Two modes, matching the current advisor: **`review`** (tool-free — the advisor answers from the question alone, no workspace inspection; `toolBudget: { hard: 0, block: "*" }`) and **`explore`** (read-only tools — the advisor verifies against the workspace; `toolBudget: { hard: 200, block: [read,grep,find,ls] }`). The wrapper picks via a `mode` param (default `explore` for the "verify against the workspace" use case; `review` for the cheap tool-free second opinion). `includeSession` is preserved as a brief-attachment option (the primary can opt in to attaching the redacted transcript to the brief). **`wait:false` + `mode:"review"` is REJECTED in v1**: the delegation API's `hard: 0` path is private (foreground-only); the RPC `spawn` (async) goes through public execution normalization, which may not support the zero-tool leaf. v1 `wait:false` is `explore` mode only. If 0.89.1 proves an enforceable async equivalent (spike #2), `wait:false` + `review` is a v2 enhancement. |
| **web_search opt-in** | `webSearch: true` in `advisor.json` adds `web_search` to the advisor's tool allowlist. Implemented via `agentOverrides.advisor.tools` including `web_search` when the flag is on (the wrapper updates the override at `session_start` based on the flag). **Caveat:** if the generic `subagent` tool can launch the `advisor` agent directly, `webSearch:false` is a *wrapper preference*, not a host-wide opt-in — the primary could bypass the wrapper and launch the `advisor` agent via `subagent` with `web_search`. The guarantee is only within the wrapper's own calls (the agent override scopes the tools for wrapper-launched runs; a `subagent`-launched `advisor` agent uses the same override but the primary chose to bypass the wrapper's framing/provenance). |
| **Disclosure / trust boundary** | Read-only tools prevent edits, not disclosure: the advisor can read credentials and unrelated files accessible to the OS user (same as the primary). Context7 sends arbitrary query strings to the Context7 API (the query can reference workspace-derived content). `web_search` (opt-in) is a broader outbound channel. **The trust boundary differs by mode, and NEITHER mode preserves the old transport's env boundary**: `wait:true` (delegation, in-process foreground) shares the parent's process — there is no subprocess env copy, but the child runtime and loaded provider code CAN see `process.env` (sharing the process does NOT mean the child can't read env vars; it means there's no separate env to filter). The old transport supplied a *filtered* env + separate agent dir with stripped auth; the in-process child has neither. `wait:false` (RPC, async detached runner) inherits most of `process.env` (only extension-binding vars omitted). **Both modes have a wider env/trust surface than the old transport** — the old transport's env allowlist is retired (spike #4 gates the auth retirement, but the env boundary is gone regardless). **Accepted and documented**: the in-process advisor (both modes) has a wider env/trust surface than the old transport. No new sandbox for read tools (the permission-gate sandbox confines bash commands, not direct read-tool access or the child's env). |
| **Brief assembly** | The **primary** assembles the brief into the `question` (free-form), guided by the tool description. The wrapper does not over-structure it. |
| **`wait:false` delivery** | Completion is subscribable (the package's result-watcher emits a completion event), but the package **also posts its own notification** (via `pi.sendMessage`, which can trigger a parent turn). **0.89.1 does not provide a documented per-run suppression control** on RPC `spawn`. The wrapper **accepts the native delivery** (the primary gets the package's notification + the wrapper's labelled result with provenance — a minor duplicate, not a blocker). **Race condition**: the native notification may arrive *before* the wrapper's provenance result (the package posts the notification when the run completes; the wrapper's labelled result is posted when the wrapper processes the completion event). The primary must handle the case where the notification arrives first (the notification says "advisor completed" without provenance; the wrapper's result arrives shortly after with the full provenance). Collecting a result does not launch a follow-up. (Upstream per-run delivery control is a v2 enhancement if the duplicate becomes a real complaint.) |
| **Extension interactions** | The advisor child loads **only** the extensions explicitly listed in the agent definition (`extensions: [Context7, + web-access for `webSearch:true`]`) — the agent definition's `extensions` list scopes which extensions the child loads (ambient extensions are not loaded unless listed). No cron/status-line interference. The status-line's subagent-cost scan counts advisor runs as subagent cost (correct accounting; the wrapper's `cost` RPC method is the authoritative source for per-consultation accounting — the status-line scan is a session-level aggregate, not per-consultation). The permission-gate's bash wrapping doesn't protect child reads or the child's env (accepted — see Disclosure). Cron is unaffected. |
| **Headless mode** | In headless mode (`pi -p`), Pi waits for background subagent work at the end of a turn for as long as `timeoutMs` allows (0.88.0); without `timeoutMs`, the wait is 30 minutes. A `wait:false` run in headless mode is a deliberate long-lived background job; the `timeoutMs` bounds the wait. Documented + tested in the spike. |

## What is retired

- `extensions/advisor/transports.ts` (~490 lines) — separate-process spawn,
  NDJSON parsing, process-group kill, bounded teardown, throwaway agent dir,
  auth.json copy. **Retired once spike verification #4 confirms the supported
  providers use the canonical-file lock-serialized refresh path** (and
  cancellation-during-refresh + termination-after-rotation are tested). The
  env allowlist is retired **regardless** (the in-process child doesn't have a
  separate env to filter — see Disclosure/trust boundary).
- `stripRefreshTokens`, `preRefreshProviderAuth` — retired with the transport
  (same condition as transports.ts).
- `childBaseEnv` / `buildChildEnv` — retired with the transport (the
  in-process child doesn't need an env allowlist; the `wait:false` detached
  runner's env inheritance is a separate, accepted trust-boundary change).
- The 2-concurrent `globalThis` synchronous limiter — replaced by the active
  background-run cap (different shape).
- `test/advisor-child.test.ts` — the child-process tests are retired, but the
  **behavioral** tests (no-transcript-by-default, `includeSession` opt-in,
  tool-free review mode, provenance, redaction, shared-deadline) are
  **preserved or explicitly retired** — see migration plan.

## What is kept

- `extensions/advisor/config.ts` — `advisor.json` I/O (migrated schema).
- `extensions/advisor/models.ts` — model resolution, spec parsing, picker
  (the `/advisor` command still uses these).
- `extensions/advisor/request.ts` — the second-opinion system prompts
  (`REVIEW_SYSTEM_PROMPT`, `ADVISOR_SYSTEM_PROMPT`), used as the
  `agentOverrides.advisor.systemPrompt` (single source of truth). If the
  bundled `advisor` agent's prompt is sufficient, this is retired in favor of
  the bundled prompt.
- `extensions/lib/advisor-utils.ts` — the pure helpers that remain relevant:
  config parsing/validation, `redactSensitiveText` (for the `includeSession`
  brief attachment), effort parsing, the **bounded fallback chain** logic
  (re-purposed for the wrapper's own fallback under one deadline, informed by
  `providerDiagnostics`). Helpers that were transport-specific (NDJSON, child
  env, child prompt assembly, process-group kill) are retired.
- The `/advisor` command — config management (set primary/fallback, effort,
  webSearch toggle, reset). Updated for the migrated schema; writes
  `subagents.agentOverrides.advisor` for the model/tools/thinking.

## Spike verifications (facts to confirm against 0.89.1; the spike is a RELEASE GATE)

The first spike is a **packed-install lifecycle test** against **pi-subagents
0.89.1** (not 0.65.1). It must prove:

1. **Bundled `oracle` agent discovery + override + effective contract**: the
   bundled `oracle` agent is discovered (canonical name `oracle`, alias
   `advisor`); `subagents.agentOverrides.oracle` correctly sets
   `model`/`tools`/`systemPrompt`/`defaultContext`; the **effective contract**
   (prompt, tools, extensions, context) matches the override — verify the
   *effective* tools (not just the accepted settings), the *effective* prompt,
   and the *effective* extensions. The bundled `oracle` agent ships
   `tools: read, grep, find, ls, bash` and `defaultContext: fork` +
   `inheritProjectContext: true` — verify the override correctly restricts
   `tools` to the read-only allowlist (removing `bash`) and sets
   `defaultContext: "fresh"` (overriding the `fork` default and inherited
   project context). A conflicting project/user agent with the same name is
   detected (fail closed on the effective contract). **Pass/fail**: the
   effective contract matches the override exactly; any mismatch (extra tools,
   wrong prompt, inherited context) is a FAIL.
2. **In-process foreground delegation + env boundary**: a `wait:true`
   delegation child is **in-process** (no detached runner). Verify separately:
   (a) **process identity** — the child shares the parent's PID (no separate
   process); (b) **credential sources** — the child's `auth.json` is the same
   canonical file (not a copy); (c) **model-visible tool surface** — the child
   can only invoke the read-only allowlist tools (`bash`/`write`/`edit` are
   not loaded). The child loads **only** the extensions explicitly listed in
   the agent definition (Context7, + web-access for `webSearch:true`).
   **Do NOT assert "the child does NOT see host env vars"** — sharing the
   process means the child CAN see `process.env` (there's no separate env to
   filter). The env boundary is gone; the trust-boundary change is accepted
   (see Disclosure). **Pass/fail**: (a) same PID; (b) same `auth.json` file;
   (c) only read-only tools invocable; (d) only listed extensions loaded.
3. **Supported provider resolution**: the configured advisor model (esp. an
   extension-backed provider) resolves in the child runtime. Preflight
   projects candidates from supplied model info; actual resolution happens
   after extension load — verify the real resolution, not just preflight.
   **Pass/fail**: the configured model resolves and produces a response.
4. **Auth lock-serialization + cancellation-during-refresh +
   termination-after-rotation**: the in-process child's OAuth refresh is
   lock-serialized on the canonical `auth.json` (no rotation desync) for the
   supported providers. **Standard stored-OAuth path**: any provider that
   stores OAuth credentials in `auth.json` and has an `oauth` refresh handler
   uses `pi-ai`'s `resolveStoredOAuth`, which calls `credentials.modify()`
   under an async file lock. This includes `openai-codex` and any other
   provider registered via the standard `auth.json` path. **Extension-backed
   providers**: providers registered by extensions may use a different auth
   path (not the standard `auth.json` lock-serialized path) — spike #4 must
   verify which extension-backed providers (if any) are in the advisor's
   supported set and whether they use the standard path. **Test cancellation
   during a refresh** (the backend rechecks abort before write, but `pi-ai`
   decouples caller cancellation after lock acquisition — verify persistence
   behavior after a server-side rotation). **Test process termination after
   rotation but before write** (lock serialization does NOT close the window
   between server rotation and local persistence if the process dies). **State
   what recovery or residual risk is acceptable** (e.g., a lost refresh
   response after server rotation is recoverable by re-authenticating; a
   terminated process after rotation is NOT recoverable without
   re-authentication). **State when the old transport must remain** (if a
   supported provider uses a non-canonical auth path, or if
   cancellation-during-refresh loses the rotated token). This gates retiring
   the auth-strip / pre-refresh. **Pass/fail**: for the named providers
   (those using the standard stored-OAuth path), lock-serialization holds AND
   cancellation-during-refresh does not lose the rotated token AND the
   residual risk is acceptable; otherwise the old transport remains for those
   providers. Extension-backed providers that do NOT use the standard path
   require the old transport to remain for those providers.
5. **One provenance-bearing completion**: a `wait:true` consultation returns a
   result with the actual model, usage (via the **correlated delegation
   response** for foreground, NOT the `cost` RPC method which is for detached
   runs), and `independent=false` (on self-review) correctly disclosed.
   `providerDiagnostics` correctly classifies a rate-limited failure (the
   fallback chain advances correctly). **Pass/fail**: the result carries the
   actual model + usage + `independent` flag; `providerDiagnostics` classifies
   a simulated rate-limit correctly.
6. **Bounded revival (RPC `resume`)**: does RPC `resume` in 0.89.1 accept
   `timeoutMs`/`usageBudget` (bounded revival), or still drop them (unbounded)?
   This gates v2 follow-up. If unbounded, v2 follow-up requires an upstream
   change or a wrapper-side bound. **Pass/fail**: `resume` accepts
   `timeoutMs`/`usageBudget` (bounded) OR the wrapper-side bound is
   implemented and tested.
7. **Completion delivery + race condition**: the completion event is
   subscribable; the package's native notification fires (accepted — no
   suppression in 0.89.1). **Test the race**: the native notification may
   arrive *before* the wrapper's provenance result. Verify the primary handles
   the case where the notification arrives first (the notification says
   "advisor completed" without provenance; the wrapper's result arrives
   shortly after with the full provenance). The primary must not treat the
   notification as the final result (it lacks provenance). Collecting a result
   does not launch a follow-up. **Pass/fail**: the primary correctly handles
   the notification-before-result ordering; the provenance result is not lost.
8. **Headless mode — drain deadline vs. run deadline**: a `wait:false` run in
   headless mode (`pi -p`) — verify TWO separate clocks: (a) the **run
   deadline** (`timeoutMs` on the launch — bounds the run itself); (b) the
   **drain deadline** (the headless drain wait — 0.88.0 says it waits as long
   as `timeoutMs` allows, but the installed `src/extension/index.ts` calls
   `drainOutstandingWork` WITHOUT a timeout override, giving a separate 30-min
   default). **Test these two clocks independently**: what happens to a
   still-running detached job when the drain expires (does the job continue
   running detached, or is it killed)? **Pass/fail**: the two clocks are
   independent; a still-running detached job continues after the drain expires
   (it's detached, not killed); the drain expiry does NOT kill the run.
9. **Shutdown + cap reconciliation**: test shutdown while a launch is being
   registered; verify the active background-run cap reconciles stale slots on
   restart. **Pass/fail**: no orphaned cap slots after restart; a launch
   registered during shutdown is either completed or cancelled (not lost).
10. **Status-line accounting vs. `cost` RPC method**: the status-line's
    subagent-cost scan (session-level aggregate) and the wrapper's `cost` RPC
    method (per-consultation) are DIFFERENT granularities — do NOT require
    unconditional equality. The status-line scan counts ALL subagent runs in
    the session (aggregate); the `cost` method reports per-child usage for
    specific runs (per-consultation). Verify they agree for the **same settled
    runs**: the sum of per-child usage from the `cost` method for a set of
    runs should equal the status-line scan's count of those same runs (no
    double-counting, no missing runs). The `cost` method is the authoritative
    source for per-consultation accounting; the status-line scan is a
    session-level aggregate. **Pass/fail**: for the same settled runs, the sum
    of the `cost` method's per-child usage equals the status-line scan's
    aggregate for those runs (no double-counting, no missing runs).
11. **Agent definition + override enforcement**: the bundled `oracle` agent's
    `tools` allowlist + `extensions` list (configured via
    `subagents.agentOverrides.oracle`) correctly restricts wrapper-launched
    runs to the read-only tools + Context7. **Launch an ordinary worker
    concurrently** and verify it is NOT affected by the advisor's override
    (the override is per-agent, not session-wide). Verify the advisor's actual
    loaded extensions (not just the configured tool names). **Pass/fail**: the
    advisor run has only the read-only tools + listed extensions; the ordinary
    worker run is unaffected.

Pin or compatibility-test the supported Pi / pi-subagents versions (0.89.1+)
rather than treating a `^0.89.0` range as an exact pin.

## Migration plan

1. **Bump `pi-subagents`** from `^0.65.0` to `^0.89.1` in `package.json` +
   `package-lock.json`. Run `npm run check` (biome + tsc + tests) against the
   new version. (AGENTS.md: "bumping a range without testing the new resolved
   version is not OK.")
2. **Configure the bundled `oracle` agent**: the wrapper (or `/advisor`
   command) writes `subagents.agentOverrides.oracle` in settings with
   `model`/`tools`/`systemPrompt`/`defaultContext: "fresh"`. The
   `reasoningEffort` is encoded as the **model `:effort` suffix** on the
   `model` string (NOT the dispatch-ignored `thinking` field). No custom agent
   file shipped; no `pi.subagents.agents` manifest key.
3. **Rewrite the `advisor` tool** as a thin wrapper: read `advisor.json`,
   resolve the model (wrapper-owned bounded fallback chain under one deadline,
   informed by `providerDiagnostics`), pick the mode (`review` =
   `toolBudget {hard:0, block:"*"}` — **`wait:true` only in v1**; `explore` =
   `toolBudget {hard:200, block:[read,grep,find,ls]}`), launch via delegation
   (`wait:true`) or RPC `spawn` (`wait:false`) with the brief as `task`, the
   explicit `timeoutMs`, and `context:"fresh"`. **Async fallback**: for
   `wait:false`, the wrapper does NOT implement a fallback chain after `ask`
   returns (the detached run is fire-and-forget; if it fails, the primary
   re-asks). The fallback chain is **foreground-only** (`wait:true`): the
   wrapper blocks on the delegation response, classifies the failure via
   `providerDiagnostics`, and retries with the next model in the chain under
   one shared deadline. **Cancellation**: for `wait:true`, wire the executing
   tool's abort signal to the delegation cancellation (the blocked primary
   cannot issue a separate `cancel` call — the abort IS the cancellation).
   For `wait:false`, the primary issues an RPC `interrupt`/`stop`. Handle the
   terminal result: provenance disclosure, `independent=false` on self-review,
   accounting via the correlated delegation response (foreground) or the `cost`
   RPC method (detached). Enforce the active background-run cap. Accept the
   native completion notification (no suppression in 0.89.1); handle the
   notification-before-result race (spike #7).
4. **Migrate `advisor.json` schema**: keep `primary`/`fallback`/
   `reasoningEffort`/`timeoutMs`/`activeModelFallback`; add `webSearch?:
   boolean`; warn+ignore `piBinary`/`awsProfile`/`awsRegion`/`env` (one-time
   notice that they no longer apply in-process).
5. **Update the `/advisor` command**: add `webSearch on|off` subcommand;
   update `describeConfig` output for the migrated schema (deprecated keys
   shown as no-ops); write `subagents.agentOverrides.oracle` for the
   model/tools/systemPrompt/defaultContext (the `reasoningEffort` is encoded
   as the model `:effort` suffix).
6. **Retire the transport** (gated on spike #4): delete `transports.ts`, the
   auth-strip / pre-refresh / child-env helpers, the synchronous `globalThis`
   limiter. **Preserve the behavioral tests** (no-transcript-by-default,
   `includeSession` opt-in, tool-free review mode, provenance, redaction,
   shared-deadline) — port them to the wrapper or explicitly retire each with
   a reason. Replace `test/advisor-child.test.ts` (child-process) with wrapper
   tests (model resolution + fallback chain, mode picking, provenance
   disclosure, config migration, cap reconciliation, agent definition +
   override enforcement).
7. **Update docs**: `docs/advisor.md` (the new design, the delegation+RPC
   integration, the `wait`/`cancel`/`status`/`mode` params, provenance
   disclosure, the trust-boundary change for BOTH modes, headless-mode
   behavior (drain deadline vs. run deadline), the v2 follow-up reservation,
   the `wait:false` + `review` rejection); `README.md` (the advisor row);
   `AGENTS.md` (retire the separate-process gotchas; add the in-process-
   subagent gotchas — delegation+RPC integration, agent definition + override
   (not capability ceiling), active background cap, hard resource bounds,
   env boundary gone for BOTH modes, headless drain-vs-run deadlines, the
   pi-subagents 0.89.1 version dependency).

## Consequences

- **Simpler**: ~1500 lines of transport become a thin delegation+RPC wrapper
  (~200–300 lines) + `agentOverrides` configuration. The hard infrastructure
  (child process, retention, resume, async, status, accounting) is
  pi-subagents' job. No custom agent file shipped.
- **Capable**: the advisor gets retention, resume (v2), async, model-visible
  status, `cost` accounting, and `providerDiagnostics` from the 0.89.1
  surface — capabilities the separate-process transport didn't have.
- **Coupled to `pi-subagents` ≥ 0.89.1**: the advisor depends on the 0.89.x
  RPC + delegation contracts, the bundled `advisor` agent, agent overrides,
  and the `cost` method. A major version change altering these would break the
  advisor. Mitigation: the spike verifications pin the exact behaviors; pin or
  compatibility-test the supported versions.
- **Trust boundary changes for BOTH modes**: the old transport's env allowlist
  is gone for BOTH `wait:true` (in-process — the child CAN see
  `process.env`) and `wait:false` (detached — inherits most of
  `process.env`). Wider than the old transport's env allowlist. Accepted and
  documented. The auth-strip/pre-refresh retirement is gated on spike #4
  (lock-serialization + cancellation-during-refresh + termination-after-
  rotation for the named providers).
- **Config backward-compat**: existing `advisor.json` files with process-only
  keys still load (warn+ignore); upgrades don't break configs. The `webSearch`
  key is additive (default `false`).
- **`wait:false` + `review` rejected in v1**: the delegation API's `hard: 0`
  path is private (foreground-only); the RPC `spawn` (async) may not support
  the zero-tool leaf. v1 `wait:false` is `explore` mode only. `wait:false` +
  `review` is a v2 enhancement (gated on spike #2 proving an enforceable
  async equivalent).
- **Async fallback is foreground-only**: the wrapper's bounded fallback chain
  is `wait:true` only (the wrapper blocks on the delegation response and can
  retry under one shared deadline). `wait:false` is fire-and-forget (one
  detached attempt; if it fails, the primary re-asks). The async fallback
  chain (who owns it after `ask` returns, how failed attempts correlate to one
  consultation, how cancellation prevents another attempt) is NOT specified in
  v1 — it's a v2 concern.

## Alternatives considered

- **Stay on the separate-process transport** (status quo): rejected — the
  auth-rotation threat it solves is substantially reduced in-process
  (lock-serialized canonical-file refresh), and the transport is ~1500 lines
  of machinery for properties pi-subagents 0.89.1 provides. Retained as the
  fallback if spike #4 (auth + cancellation-during-refresh +
  termination-after-rotation) fails for a supported provider.
- **Stay on pi-subagents 0.65.1**: rejected — 0.65.1 lacks the bundled
  `advisor` agent, agent overrides, in-process foreground delegation,
  `toolBudget hard:0`, capability ceilings, the `cost` method, and
  `providerDiagnostics`. The 0.89.1 capabilities make the advisor
  substantially better (in-process `wait:true`, structural read-only
  guarantee via ceiling, tool-free review mode, clean accounting, informed
  fallback). The version bump is a one-time cost.
- **Thin wrapper over the structured delegation API only** (no RPC): rejected
  — the delegation API is foreground-only; `wait:false` (background) requires
  the RPC's async `spawn`. The hybrid (delegation for `wait:true`, RPC for
  `wait:false`) uses each API's strength.
- **Invoke the `subagent` tool's executor directly**: rejected — the executor
  is registered internally and has no public export. Importing `src/`
  internals couples the wrapper to pi-subagents' private structure.
- **Ship a custom `agents/advisor.md` agent**: rejected in favor of configuring
  the bundled `oracle` agent (alias `advisor`) via `agentOverrides.oracle` —
  the bundled agent already has the second-opinion framing + read-only tools;
  shipping a custom agent duplicates it and requires the `pi.subagents.agents`
  manifest key. (Revisit if the bundled `oracle` prompt doesn't match our needs
  — in that case, set `agentOverrides.oracle.systemPrompt` to our own prompt,
  still without shipping a custom agent file.)
- **Advisor as a generic configured subagent (no wrapper)**: rejected — loses
  the consultation framing, provenance disclosure, `independent=false`
  marking, and the capability-ceiling enforcement. Day-to-day, the primary
  reaches for "consult the advisor" as a distinct gesture from "delegate work
  to a subagent."
- **Require upstream `pi-subagents` changes** (per-run delivery suppression,
  bounded RPC `resume`): deferred to v2 — the 0.89.1 design accepts the
  native delivery duplicate and defers follow-up, so no upstream change is
  required for v1. Revisit if the duplicate or unbounded revival become real
  problems.