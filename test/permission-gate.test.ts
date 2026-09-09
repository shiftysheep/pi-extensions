/**
 * Unit tests for the permission-gate rules in extensions/permission-gate/rules.ts.
 * Run with `npm test` (node --test via tsx).
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { findDangerousRule, shouldGate } from "../extensions/permission-gate/rules.js";

describe("recursive rm (filesystem)", () => {
  it("matches recursive forms", () => {
    for (const cmd of [
      "rm -rf /",
      "rm -r foo",
      "rm -fr /x",
      "rm -r -f /x",
      "rm --recursive x",
      "FOO=1 rm -rf /",
    ]) {
      assert.equal(findDangerousRule(cmd)?.name, "recursive rm", cmd);
    }
  });
  it("does not match non-recursive rm or other commands", () => {
    for (const cmd of ["rm file.txt", "rm -f file.txt", "xrm -rf /", "inform -r /"]) {
      assert.equal(findDangerousRule(cmd), undefined, cmd);
    }
  });
  it("matches inside compound commands", () => {
    assert.equal(findDangerousRule("ls && sudo rm -rf /")?.name, "privilege escalation");
    assert.equal(findDangerousRule("cd /x; rm -R sub")?.name, "recursive rm");
  });
  it("system-category matches win over filesystem ones in mixed commands", () => {
    // While the sandbox is active, filesystem matches are suppressed; a mixed
    // command must still be gated on its system-category part.
    const mixed = findDangerousRule("rm -rf build; sudo apt update");
    assert.equal(mixed?.name, "privilege escalation");
    assert.equal(shouldGate(mixed, true), true);
    assert.equal(
      findDangerousRule("rm -rf build; dd if=/dev/zero of=/dev/sda")?.name,
      "raw device write (dd)",
    );
    assert.equal(findDangerousRule("rm -rf build; shutdown -h now")?.name, "power action");
  });
});

describe("world-writable chmod (filesystem)", () => {
  it("matches 777 forms", () => {
    for (const cmd of [
      "chmod 777 /etc/passwd",
      "chmod -R 777 /",
      "chmod 0777 x",
      "chmod a+w /etc",
    ]) {
      assert.equal(findDangerousRule(cmd)?.name, "world-writable chmod", cmd);
    }
  });
  it("does not match safe modes", () => {
    for (const cmd of ["chmod 644 file", "chmod 755 dir", "chmod u+w file"]) {
      assert.equal(findDangerousRule(cmd), undefined, cmd);
    }
  });
});

describe("privilege escalation (system)", () => {
  it("matches sudo/doas/pkexec as command word", () => {
    for (const cmd of [
      "sudo apt install x",
      "doas ls",
      "pkexec ls",
      "env FOO=1 sudo ls",
      "env -i sudo ls",
    ]) {
      assert.equal(findDangerousRule(cmd)?.name, "privilege escalation", cmd);
    }
  });
  it("does not match as substring of other words or args", () => {
    for (const cmd of ["echo sudo", "git push", "ls /usr/bin/sudo", "env FOO=1 ls"]) {
      assert.equal(findDangerousRule(cmd), undefined, cmd);
    }
  });
});

describe("raw device write dd (system)", () => {
  it("matches dd of=/dev/<raw device>", () => {
    for (const cmd of [
      "dd if=/dev/zero of=/dev/sda bs=1M",
      "dd of=/dev/sdb1 count=1",
      "cat x | dd of=/dev/nvme0n1",
    ]) {
      assert.equal(findDangerousRule(cmd)?.name, "raw device write (dd)", cmd);
    }
  });
  it("does not match safe /dev targets", () => {
    for (const cmd of ["dd if=/dev/urandom of=/dev/null", "dd of=/dev/stdout", "dd of=/tmp/file"]) {
      assert.equal(findDangerousRule(cmd), undefined, cmd);
    }
  });
});

describe("mkfs (system)", () => {
  it("matches mkfs and mkfs.<fs>", () => {
    for (const cmd of ["mkfs.ext4 /dev/sda1", "mkfs -t xfs /dev/sdb", "sudo mkfs.btrfs /dev/sdc"]) {
      assert.ok(findDangerousRule(cmd), cmd);
    }
  });
  it("does not match other commands", () => {
    assert.equal(findDangerousRule("mkfsx"), undefined);
    assert.equal(findDangerousRule("ls mkfs.txt"), undefined);
  });
});

describe("power actions (system)", () => {
  it("matches shutdown/reboot/poweroff/halt", () => {
    for (const cmd of ["shutdown -h now", "reboot", "poweroff", "halt"]) {
      assert.equal(findDangerousRule(cmd)?.name, "power action", cmd);
    }
  });
  it("does not match lookalikes or args", () => {
    for (const cmd of ["shutdowm", "echo reboot", "rebootd --help"]) {
      assert.equal(findDangerousRule(cmd), undefined, cmd);
    }
  });
});

describe("shouldGate", () => {
  it("gates system rules always", () => {
    const system = findDangerousRule("sudo ls");
    assert.ok(system);
    assert.equal(system.category, "system");
    assert.equal(shouldGate(system, true), true);
    assert.equal(shouldGate(system, false), true);
  });
  it("gates filesystem rules only without sandbox", () => {
    const fsRule = findDangerousRule("rm -rf /");
    assert.ok(fsRule);
    assert.equal(fsRule.category, "filesystem");
    assert.equal(shouldGate(fsRule, true), false); // kernel enforces it
    assert.equal(shouldGate(fsRule, false), true); // fallback: gate re-armed
  });
});
