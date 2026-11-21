import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import { loadSandboxConfigs } from "../extensions/permission-gate/config.js";

describe("loadSandboxConfigs", () => {
  let hostDir: string;
  let projectDir: string;
  let savedAgentDir: string | undefined;

  beforeEach(() => {
    hostDir = fs.mkdtempSync(path.join(os.tmpdir(), "pi-sg-host-"));
    projectDir = fs.mkdtempSync(path.join(os.tmpdir(), "pi-sg-proj-"));
    savedAgentDir = process.env.PI_CODING_AGENT_DIR;
    process.env.PI_CODING_AGENT_DIR = hostDir;
    fs.mkdirSync(path.join(projectDir, ".pi"), { recursive: true });
  });

  afterEach(() => {
    if (savedAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = savedAgentDir;
    fs.rmSync(hostDir, { recursive: true, force: true });
    fs.rmSync(projectDir, { recursive: true, force: true });
  });

  const globalFile = () => path.join(hostDir, "sandbox.json");
  const projectFile = () => path.join(projectDir, ".pi", "sandbox.json");
  const managedFilePath = () => path.join(hostDir, "managed.json");

  it("merges valid global and project configs, project wins", () => {
    fs.writeFileSync(globalFile(), JSON.stringify({ enabled: true, home: "rw" }));
    fs.writeFileSync(projectFile(), JSON.stringify({ home: "ro", network: "deny" }));
    const loaded = loadSandboxConfigs(projectDir, true, managedFilePath());
    assert.equal(loaded.config.enabled, true);
    assert.equal(loaded.config.home, "ro");
    assert.equal(loaded.config.network, "deny");
    assert.equal(loaded.error, undefined);
  });

  it("does not read the project file when the project is untrusted", () => {
    fs.writeFileSync(globalFile(), JSON.stringify({ enabled: true }));
    fs.writeFileSync(projectFile(), JSON.stringify({ home: "rw" }));
    const loaded = loadSandboxConfigs(projectDir, false, managedFilePath());
    assert.equal(loaded.config.enabled, true);
    assert.equal(loaded.config.home, undefined);
    assert.equal(loaded.projectConfig.home, undefined);
  });

  it("retains the valid global policy when the project file is malformed", () => {
    fs.writeFileSync(globalFile(), JSON.stringify({ enabled: true, failIfUnavailable: true }));
    fs.writeFileSync(projectFile(), "{ not json");
    const loaded = loadSandboxConfigs(projectDir, true, managedFilePath());
    assert.equal(loaded.config.enabled, true);
    assert.equal(loaded.config.failIfUnavailable, true);
    assert.match(loaded.error ?? "", /project/);
  });

  it("fails closed when the managed file is malformed", () => {
    fs.writeFileSync(managedFilePath(), "{ not json");
    fs.writeFileSync(globalFile(), JSON.stringify({ enabled: true }));
    const loaded = loadSandboxConfigs(projectDir, true, managedFilePath());
    assert.equal(loaded.managedFailClosed, true);
    assert.equal(loaded.config.enabled, undefined);
    assert.equal(loaded.managedConfig.enabled, undefined);
    assert.match(loaded.error ?? "", /managed/);
  });

  it("managed keys win over valid lower scopes", () => {
    fs.writeFileSync(globalFile(), JSON.stringify({ enabled: true }));
    fs.writeFileSync(managedFilePath(), JSON.stringify({ enabled: true, network: "deny" }));
    const loaded = loadSandboxConfigs(projectDir, true, managedFilePath());
    assert.equal(loaded.config.network, "deny");
  });
});
