import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { privateFile, STORAGE_DIR } from "./storage.js";

describe("private review storage", () => {
  it("creates private files and rejects symlink and hardlink targets", () => {
    const name = `security-test-${process.pid}`;
    const target = path.join(STORAGE_DIR, name);
    const external = fs.mkdtempSync(path.join(os.tmpdir(), "auto-mode-external-"));
    const sentinel = path.join(external, "sentinel");
    fs.writeFileSync(sentinel, "unchanged", { mode: 0o600 });
    try {
      const fd = privateFile(name, true);
      assert.equal(fs.fstatSync(fd).mode & 0o777, 0o600);
      fs.closeSync(fd);
      assert.equal(fs.lstatSync(STORAGE_DIR).mode & 0o777, 0o700);
      fs.unlinkSync(target);
      fs.symlinkSync(sentinel, target);
      assert.throws(() => privateFile(name, true));
      fs.unlinkSync(target);
      fs.linkSync(sentinel, target);
      assert.throws(() => privateFile(name, true));
      assert.equal(fs.readFileSync(sentinel, "utf8"), "unchanged");
      assert.throws(() => privateFile("../escape", true));
    } finally {
      fs.rmSync(target, { force: true });
      fs.rmSync(external, { recursive: true, force: true });
    }
  });
});
