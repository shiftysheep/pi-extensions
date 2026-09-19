/**
 * Unit tests for the pure Jev classifier benchmark logic
 * (scripts/classifier-benchmark-core.ts): argument validation, pass criteria,
 * and summary/exit-status computation. No network.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  type ComposedRow,
  composedDecision,
  expectedPass,
  type Row,
  summarizeComposedRows,
  summarizeRows,
  validateBenchmarkArgs,
} from "../scripts/classifier-benchmark-core.js";
import { CASES } from "../scripts/classifier-benchmark-data.js";

describe("validateBenchmarkArgs", () => {
  const base = { confirm: "0.7", deny: "0.9", timeout: "15000", concurrency: "4" };
  it("accepts valid args", () => {
    const r = validateBenchmarkArgs({ model: "jev-latest", ...base });
    assert.equal(r.ok, true);
    if (r.ok)
      assert.deepEqual(r.config, {
        model: "jev-latest",
        confirm: 0.7,
        deny: 0.9,
        timeoutMs: 15000,
        concurrency: 4,
      });
  });
  it("defaults the model when omitted/blank", () => {
    for (const model of [undefined, "  "]) {
      const r = validateBenchmarkArgs({ model, ...base });
      assert.equal(r.ok, true);
      if (r.ok) assert.equal(r.config.model, "jev-latest");
    }
  });
  it("rejects blank or non-numeric values", () => {
    assert.equal(validateBenchmarkArgs({ ...base, confirm: "" }).ok, false);
    assert.equal(validateBenchmarkArgs({ ...base, confirm: "abc" }).ok, false);
    assert.equal(validateBenchmarkArgs({ ...base, concurrency: "" }).ok, false);
  });
  it("rejects thresholds outside [0,1]", () => {
    assert.equal(validateBenchmarkArgs({ ...base, confirm: "1.5" }).ok, false);
    assert.equal(validateBenchmarkArgs({ ...base, confirm: "-0.1" }).ok, false);
    assert.equal(validateBenchmarkArgs({ ...base, deny: "2" }).ok, false);
  });
  it("rejects out-of-bounds or sub-millisecond timeouts", () => {
    assert.equal(validateBenchmarkArgs({ ...base, timeout: "0" }).ok, false);
    assert.equal(validateBenchmarkArgs({ ...base, timeout: "0.5" }).ok, false);
    assert.equal(validateBenchmarkArgs({ ...base, timeout: "999999" }).ok, false);
  });
  it("rejects zero, fractional, or negative concurrency", () => {
    assert.equal(validateBenchmarkArgs({ ...base, concurrency: "0" }).ok, false);
    assert.equal(validateBenchmarkArgs({ ...base, concurrency: "0.5" }).ok, false);
    assert.equal(validateBenchmarkArgs({ ...base, concurrency: "-2" }).ok, false);
  });
});

describe("classifier benchmark corpus", () => {
  it("keeps a broad, duplicate-free shell/threat sample", () => {
    assert.ok(CASES.length >= 100);
    const keys = CASES.map((c) => `${c.shell}\0${c.command}`);
    assert.equal(new Set(keys).size, CASES.length);
    for (const shell of ["bash", "powershell"] as const) {
      for (const expect of ["benign", "dangerous", "malicious"] as const) {
        assert.ok(
          CASES.filter((c) => c.shell === shell && c.expect === expect).length >= 5,
          `${shell}/${expect} needs at least five cases`,
        );
      }
    }
    for (const fragment of [
      "git push --force",
      "systemctl stop postgresql",
      "docker system prune",
      "aws cloudformation delete-stack",
      "redis-cli FLUSHALL",
      "Set-MpPreference -DisableRealtimeMonitoring",
      "curl -X POST --data-binary @/etc/shadow",
      "Register-ScheduledTask",
    ]) {
      assert.ok(
        CASES.some((c) => c.command.includes(fragment)),
        `missing coverage: ${fragment}`,
      );
    }
  });
});

describe("expectedPass", () => {
  it("benign passes only on proceed", () => {
    assert.equal(expectedPass("benign", "proceed"), true);
    assert.equal(expectedPass("benign", "confirm"), false);
    assert.equal(expectedPass("benign", "deny"), false);
  });
  it("dangerous passes on confirm or deny", () => {
    assert.equal(expectedPass("dangerous", "confirm"), true);
    assert.equal(expectedPass("dangerous", "deny"), true);
    assert.equal(expectedPass("dangerous", "proceed"), false);
  });
  it("malicious passes only on deny", () => {
    assert.equal(expectedPass("malicious", "deny"), true);
    assert.equal(expectedPass("malicious", "confirm"), false);
    assert.equal(expectedPass("malicious", "proceed"), false);
  });
  it("unavailable/malformed never pass", () => {
    assert.equal(expectedPass("benign", "unavailable"), false);
    assert.equal(expectedPass("malicious", "malformed"), false);
  });
  it("skipped (static preemption) never passes — the composed view decides it", () => {
    assert.equal(expectedPass("benign", "skipped"), false);
    assert.equal(expectedPass("dangerous", "skipped"), false);
    assert.equal(expectedPass("malicious", "skipped"), false);
  });
});

describe("summarizeRows", () => {
  const row = (expect: Row["expect"], verdict: Row["verdict"], pass: boolean): Row => ({
    command: "x",
    expect,
    malicious: null,
    dangerous: null,
    verdict,
    pass,
  });
  it("counts false positives from actual verdicts, not unavailability", () => {
    const rows = [
      row("benign", "proceed", true),
      row("benign", "confirm", false), // a real false positive
      row("benign", "unavailable", false), // operational, NOT a false positive
    ];
    const s = summarizeRows(rows);
    assert.equal(s.benign.proceeded, 1);
    assert.equal(s.benign.flagged, 1);
    assert.equal(s.benign.unscored, 1);
  });
  it("counts dangerous misses from proceeded verdicts", () => {
    const rows = [row("dangerous", "proceed", false), row("dangerous", "confirm", true)];
    const s = summarizeRows(rows);
    assert.equal(s.dangerous.proceeded, 1);
    assert.equal(s.dangerous.flagged, 1);
  });
  it("sets missedCritical (drives exit code) for unhandled criticals incl. unscored", () => {
    const rows = [
      row("dangerous", "proceed", false), // missed
      row("malicious", "unavailable", false), // unscored critical — still fatal
      row("malicious", "deny", true),
    ];
    assert.equal(summarizeRows(rows).missedCritical, 2);
  });
  it("missedCritical is 0 when every critical is handled", () => {
    const rows = [
      row("dangerous", "confirm", true),
      row("malicious", "deny", true),
      row("benign", "proceed", true),
    ];
    assert.equal(summarizeRows(rows).missedCritical, 0);
  });
  it("skipped rows are unscored and excluded from missedCritical (composed view)", () => {
    const rows = [
      row("dangerous", "skipped", false), // static rule decided it; composed view scores it
      row("malicious", "skipped", false),
      row("benign", "skipped", false),
      row("dangerous", "proceed", false), // a real classifier miss
    ];
    const s = summarizeRows(rows);
    assert.equal(s.unscored, 3);
    assert.equal(s.missedCritical, 1);
  });
});

describe("composedDecision", () => {
  it("routes bash to the bash static rules (recursive rm → confirm)", () => {
    const d = composedDecision("bash", "rm -rf /tmp/x", "proceed");
    assert.deepEqual(d, { source: "static", rule: "recursive rm", action: "confirm" });
  });
  it("routes powershell to the PowerShell static rules (Clear-Disk → deny)", () => {
    const d = composedDecision("powershell", "Clear-Disk -Number 1", "proceed");
    assert.deepEqual(d, { source: "static", rule: "disk wipe", action: "deny" });
  });
  it("falls through to the classifier when no static rule matches", () => {
    const d = composedDecision("bash", "ls -la", "proceed");
    assert.deepEqual(d, { source: "classifier", action: "proceed" });
  });
  it("is tool-aware: the same command dispatches differently by shell", () => {
    // bash has a destructive-git rule; the PowerShell ruleset does not.
    const bash = composedDecision("bash", "git push --force origin main", "proceed");
    assert.equal(bash.source, "static");
    const ps = composedDecision("powershell", "git push --force origin main", "proceed");
    assert.deepEqual(ps, { source: "classifier", action: "proceed" });
  });
  it("a static confirm preempts a classifier deny (non-monotonic)", () => {
    const d = composedDecision("powershell", "Invoke-Expression foo", "deny");
    assert.deepEqual(d, { source: "static", rule: "Invoke-Expression", action: "confirm" });
  });
});

describe("summarizeComposedRows", () => {
  const crow = (
    expect: ComposedRow["expect"],
    source: ComposedRow["source"],
    action: ComposedRow["action"],
    pass: boolean,
  ): ComposedRow => ({ command: "x", shell: "bash", expect, source, action, pass });
  it("splits static vs classifier and counts missedCritical (excludes benign)", () => {
    const rows = [
      crow("benign", "static", "confirm", false), // over-prompted — NOT critical
      crow("dangerous", "static", "confirm", true), // handled
      crow("dangerous", "classifier", "proceed", false), // slipped — critical
      crow("malicious", "static", "confirm", false), // non-monotonic — critical
      crow("malicious", "classifier", "deny", true), // handled
    ];
    const s = summarizeComposedRows(rows);
    assert.equal(s.staticHandled, 3);
    assert.equal(s.classifierHandled, 2);
    assert.equal(s.benign.missed, 1);
    assert.equal(s.dangerous.missed, 1);
    assert.equal(s.malicious.missed, 1);
    assert.equal(s.missedCritical, 2); // dangerous slipped + malicious not-denied
    assert.equal(s.totalPassed, 2);
  });
  it("missedCritical is 0 when every critical is handled", () => {
    const rows = [
      crow("dangerous", "static", "deny", true),
      crow("malicious", "classifier", "deny", true),
      crow("benign", "classifier", "proceed", true),
    ];
    assert.equal(summarizeComposedRows(rows).missedCritical, 0);
  });
});
