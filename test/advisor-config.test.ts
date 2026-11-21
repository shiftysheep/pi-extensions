import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";

// The config module computes CONFIG_PATH from PI_CODING_AGENT_DIR at import time, so the
// env var must be set before any dynamic import. The whole suite shares one temp agent dir.
// The real ~/.pi/agent is never touched.
let hostDir: string;
let savedAgentDir: string | undefined;
let configModule: typeof import("../extensions/advisor/config.js");

before(async () => {
  hostDir = mkdtempSync(join(tmpdir(), "advisor-config-test-"));
  savedAgentDir = process.env.PI_CODING_AGENT_DIR;
  process.env.PI_CODING_AGENT_DIR = hostDir;
  configModule = await import("../extensions/advisor/config.js");
});

after(() => {
  if (savedAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
  else process.env.PI_CODING_AGENT_DIR = savedAgentDir;
  rmSync(hostDir, { recursive: true, force: true });
});

describe("describeConfig", () => {
  it("masks child-env values in the /advisor output", () => {
    const out = configModule.describeConfig({
      env: { AWS_SECRET_ACCESS_KEY: "super-secret-value", AWS_REGION: "us-east-1" },
    });
    assert.match(out, /AWS_SECRET_ACCESS_KEY=<set>/);
    assert.match(out, /AWS_REGION=<set>/);
    assert.ok(!out.includes("super-secret-value"), "env values must never appear");
  });

  it("shows (none) when no child env is configured", () => {
    const out = configModule.describeConfig({});
    assert.match(out, /child env\s+\(none\)/);
  });
});

describe("backupExistingConfig (filesystem)", () => {
  it("backs up a legacy config with 0600 perms for both the repair and reset paths", () => {
    const { saveConfigValidated, backupExistingConfig, CONFIG_PATH } = configModule;
    // Repair path: broken config + repair → .bak created with 0600, config re-written 0600.
    writeFileSync(CONFIG_PATH, "not json at all");
    const backedUp = saveConfigValidated({}, "broken previous file");
    assert.equal(backedUp, true);
    assert.ok(existsSync(`${CONFIG_PATH}.bak`), "backup file must exist");
    assert.equal((statSync(`${CONFIG_PATH}.bak`).mode & 0o777).toString(8), "600");
    assert.equal((statSync(CONFIG_PATH).mode & 0o777).toString(8), "600");
    assert.equal(readFileSync(CONFIG_PATH, "utf8"), "{}\n");
    assert.ok(statSync(`${CONFIG_PATH}.bak`).size > 0);
    // Reset path: back up the (valid) config → .bak with 0600.
    const backupPath = backupExistingConfig();
    assert.equal(backupPath, `${CONFIG_PATH}.bak`);
    assert.equal((statSync(backupPath as string).mode & 0o777).toString(8), "600");
    assert.ok(!existsSync(CONFIG_PATH), "backup renames the config away");
  });
});
