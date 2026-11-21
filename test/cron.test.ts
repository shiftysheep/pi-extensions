import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  advanceRecurringRunAt,
  type CronJob,
  createCronTrigger,
  formatDuration,
  MAX_MESSAGE_LENGTH,
  MAX_TIMER_DELAY_MS,
  nextRunAt,
  parseAt,
  parseDuration,
  parseEvery,
  parsePersistedJob,
  relativeTime,
  truncate,
  validateCronMessage,
  validateCronName,
} from "../extensions/lib/cron-utils.js";

const NOW = Date.UTC(2026, 5, 15, 10, 0, 0); // 2026-06-15T10:00:00Z

describe("parseDuration", () => {
  it("parses seconds/minutes/hours/days", () => {
    assert.equal(parseDuration("30s"), 30_000);
    assert.equal(parseDuration("15m"), 900_000);
    assert.equal(parseDuration("2h"), 7_200_000);
    assert.equal(parseDuration("1d"), 86_400_000);
  });

  it("trims surrounding whitespace", () => {
    assert.equal(parseDuration("  15m  "), 900_000);
  });

  it("rejects invalid shapes, zero, and out-of-range units", () => {
    for (const spec of ["15", "m", "0s", "10w", "1.5m", ""]) {
      assert.throws(() => parseDuration(spec), /invalid duration/);
    }
  });
});

describe("parseAt", () => {
  it("parses relative delays and adds them to now", () => {
    assert.equal(parseAt("+30s", NOW), NOW + 30_000);
    assert.equal(parseAt("+2h", NOW), NOW + 7_200_000);
    assert.equal(parseAt("+1d", NOW), NOW + 86_400_000);
  });

  it("rejects sub-second and over-limit relative delays", () => {
    assert.throws(() => parseAt("+0s", NOW), /minimum/);
    assert.throws(
      () => parseAt(`+${Math.floor(MAX_TIMER_DELAY_MS / 86_400_000) + 2}d`, NOW),
      /cannot exceed/,
    );
  });

  it("parses ISO timestamps with an explicit zone", () => {
    assert.equal(parseAt("2030-01-15T12:30:00Z", NOW), Date.UTC(2030, 0, 15, 12, 30, 0));
  });

  it("parses timestamps with a numeric zone offset", () => {
    const withColon = parseAt("2030-01-15 12:30:00+05:30", NOW);
    assert.equal(withColon, Date.UTC(2030, 0, 15, 7, 0, 0));
    const withoutColon = parseAt("2030-01-15 12:30:00+0530", NOW);
    assert.equal(withoutColon, Date.UTC(2030, 0, 15, 7, 0, 0));
  });

  it("rejects invalid timestamps and calendar dates", () => {
    for (const spec of [
      "2030-13-15T12:00",
      "2030-02-30T12:00",
      "2030-01-15T24:00",
      "2030-01-15T12:60",
      "not a timestamp",
      "2030-01",
    ]) {
      assert.throws(() => parseAt(spec, NOW), /invalid/);
    }
  });

  it("parses local timestamps without a zone as local time", () => {
    const expected = new Date(2030, 0, 15, 12, 30, 0).getTime();
    assert.equal(parseAt("2030-01-15T12:30", NOW), expected);
    assert.equal(parseAt("2030-01-15 12:30:00", NOW), expected);
  });
});

describe("parseEvery", () => {
  it("parses valid repeat intervals", () => {
    assert.equal(parseEvery("1m"), 60_000);
    assert.equal(parseEvery("15m"), 900_000);
    assert.equal(parseEvery("2h"), 7_200_000);
  });

  it("rejects intervals below 1 minute and above the max", () => {
    assert.throws(() => parseEvery("30s"), /too small/);
    assert.throws(() => parseEvery("25d"), /cannot exceed/);
  });
});

describe("createCronTrigger", () => {
  it("requires exactly one of at or every", () => {
    assert.throws(() => createCronTrigger({}, NOW), /exactly one/);
    assert.throws(() => createCronTrigger({ at: "+1h", every: "1h" }, NOW), /exactly one/);
  });

  it("builds a one-shot trigger for a future timestamp", () => {
    const trigger = createCronTrigger({ at: "+1h" }, NOW);
    assert.deepEqual(trigger, { kind: "once", atMs: NOW + 3_600_000 });
  });

  it("rejects one-shot timestamps in the past", () => {
    assert.throws(() => createCronTrigger({ at: "2020-01-01T00:00" }, NOW), /already in the past/);
  });

  it("rejects one-shot timestamps more than ~24 days away", () => {
    assert.throws(() => createCronTrigger({ at: "+30d" }, NOW), /cannot exceed/);
  });

  it("builds a repeating trigger anchored at now", () => {
    const trigger = createCronTrigger({ every: "15m" }, NOW);
    assert.deepEqual(trigger, {
      kind: "every",
      everyMs: 900_000,
      anchorAt: NOW,
      nextRunAt: NOW + 900_000,
    });
  });
});

describe("validateCronName", () => {
  it("accepts valid names", () => {
    assert.equal(validateCronName("morning-check"), "morning-check");
    assert.equal(validateCronName("A B._:-"), "A B._:-");
  });

  it("trims surrounding whitespace", () => {
    assert.equal(validateCronName("  wake  "), "wake");
  });

  it("rejects empty, invalid-start, and overlong names", () => {
    for (const bad of ["", "  ", ".start", "-start", "x".repeat(65)]) {
      assert.throws(() => validateCronName(bad), /valid name/);
    }
  });
});

describe("validateCronMessage", () => {
  it("accepts a non-empty message and trims it", () => {
    assert.equal(validateCronMessage("  hello  "), "hello");
  });

  it("rejects empty and over-limit messages", () => {
    assert.throws(() => validateCronMessage(""), /non-empty/);
    assert.throws(() => validateCronMessage("   "), /non-empty/);
    assert.throws(() => validateCronMessage("x".repeat(MAX_MESSAGE_LENGTH + 1)), /too long/);
  });
});

describe("parsePersistedJob", () => {
  it("parses a valid once job and preserves fields", () => {
    const raw = {
      name: "wake",
      trigger: { kind: "once", atMs: NOW + 60_000 },
      message: "  hello  ",
      paused: false,
      firedCount: 3.7,
      lastFiredAt: NOW - 1_000,
    };
    const job = parsePersistedJob(raw);
    assert.deepEqual(job, {
      name: "wake",
      trigger: { kind: "once", atMs: NOW + 60_000 },
      message: "hello",
      paused: false,
      firedCount: 3,
      lastFiredAt: NOW - 1_000,
    });
  });

  it("parses a valid every job", () => {
    const job = parsePersistedJob({
      name: "tick",
      trigger: { kind: "every", everyMs: 120_000, anchorAt: NOW, nextRunAt: NOW + 120_000 },
      message: "tick",
    });
    assert.equal(job?.trigger.kind, "every");
    assert.equal(job?.paused, false);
    assert.equal(job?.firedCount, 0);
  });

  it("rejects malformed jobs", () => {
    const malformed = [
      null,
      "string",
      { name: "bad name!", trigger: { kind: "once", atMs: NOW }, message: "x" },
      { name: "ok", trigger: { kind: "once", atMs: "soon" }, message: "x" },
      {
        name: "ok",
        trigger: { kind: "every", everyMs: 1_000, anchorAt: NOW, nextRunAt: NOW },
        message: "x",
      },
      { name: "ok", trigger: { kind: "every", everyMs: 60_000, anchorAt: NOW }, message: "x" },
      {
        name: "ok",
        trigger: { kind: "every", everyMs: 60_000, anchorAt: NOW, nextRunAt: Number.NaN },
        message: "x",
      },
      { name: "ok", trigger: { kind: "once", atMs: NOW }, message: "   " },
    ];
    for (const raw of malformed) {
      assert.equal(parsePersistedJob(raw), undefined, JSON.stringify(raw));
    }
  });

  it("truncates over-long persisted messages", () => {
    const job = parsePersistedJob({
      name: "long",
      trigger: { kind: "once", atMs: NOW + 60_000 },
      message: "x".repeat(MAX_MESSAGE_LENGTH + 50),
    });
    assert.equal(job?.message.length, MAX_MESSAGE_LENGTH);
  });
});

describe("nextRunAt / advanceRecurringRunAt", () => {
  it("returns the one-shot timestamp or recurring nextRunAt", () => {
    const once: CronJob = {
      name: "a",
      trigger: { kind: "once", atMs: 1 },
      message: "m",
      paused: false,
      firedCount: 0,
    };
    assert.equal(nextRunAt(once), 1);
    const every: CronJob = {
      name: "b",
      trigger: { kind: "every", everyMs: 10_000, anchorAt: 0, nextRunAt: 5_000 },
      message: "m",
      paused: false,
      firedCount: 0,
    };
    assert.equal(nextRunAt(every), 5_000);
  });

  it("advances the next slot past now by one cadence at a time", () => {
    const trigger: Extract<CronJob["trigger"], { kind: "every" }> = {
      kind: "every",
      everyMs: 10_000,
      anchorAt: 0,
      nextRunAt: 1_000,
    };
    assert.equal(advanceRecurringRunAt(trigger, 3_500), 11_000);
    assert.equal(advanceRecurringRunAt(trigger, 25_000), 31_000);
  });
});

describe("formatDuration / relativeTime", () => {
  it("formats durations in whole units", () => {
    assert.equal(formatDuration(86_400_000), "1d");
    assert.equal(formatDuration(7_200_000), "2h");
    assert.equal(formatDuration(900_000), "15m");
    assert.equal(formatDuration(30_000), "30s");
  });

  it("formats relative times", () => {
    assert.equal(relativeTime(100), "now");
    assert.equal(relativeTime(5_000), "in 5s");
    assert.equal(relativeTime(90_000), "in 1m 30s");
    assert.equal(relativeTime(3_700_000), "in 1.0h");
    assert.equal(relativeTime(86_400_000 * 2.5), "in 2.5d");
  });
});

describe("truncate", () => {
  it("joins multiline messages onto one line", () => {
    assert.equal(truncate("line1\nline2\r\nline3", 100), "line1 line2 line3");
  });

  it("truncates long messages with an ellipsis", () => {
    const out = truncate("x".repeat(200), 50);
    assert.equal(out.length, 50);
    assert.ok(out.endsWith("…"));
  });
});
