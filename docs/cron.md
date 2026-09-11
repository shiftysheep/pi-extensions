# cron

In-session scheduled wakes: one-shot delays/timestamps (`+30m` or ISO) and repeating intervals. When a job is due, its message is sent as a user message so an idle agent wakes up.

- **Session-scoped.** State is snapshotted into the session, so schedules survive `/reload` (not process exit). No OS-level cron jobs are created, and a schedule cannot wake pi after the process has exited.
- **Limits.** At most 20 jobs; repeating intervals are at least 1 minute; one-shot delays/repeats are at most about 24 days (Node's `setTimeout` ceiling).
- **Usage.** The agent drives it through the `cron` tool (`add`, `list`, `remove`, `pause`, `resume`, `clear`); there is no user-facing slash command.