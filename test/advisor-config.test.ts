import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { describeConfig } from "../extensions/advisor/config.js";

describe("describeConfig", () => {
  it("masks child-env values in the /advisor output", () => {
    const out = describeConfig({
      env: { AWS_SECRET_ACCESS_KEY: "super-secret-value", AWS_REGION: "us-east-1" },
    });
    assert.match(out, /AWS_SECRET_ACCESS_KEY=<set>/);
    assert.match(out, /AWS_REGION=<set>/);
    assert.ok(!out.includes("super-secret-value"), "env values must never appear");
  });

  it("shows (none) when no child env is configured", () => {
    const out = describeConfig({});
    assert.match(out, /child env\s+\(none\)/);
  });
});
