import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

export const STORAGE_DIR = path.join(os.tmpdir(), `opencode-auto-mode-${process.getuid?.() ?? os.userInfo().username}`);

function owned(stat: fs.Stats): boolean {
  return (process.getuid === undefined || stat.uid === process.getuid()) && (stat.mode & 0o077) === 0;
}

export function privateFile(filename: string, write: boolean, append = false): number {
  if (path.basename(filename) !== filename) throw new Error("Invalid storage file");
  try { fs.mkdirSync(STORAGE_DIR, { mode: 0o700 }); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
  const directory = fs.lstatSync(STORAGE_DIR);
  if (!directory.isDirectory() || !owned(directory)) throw new Error("Unsafe storage directory");
  const fd = fs.openSync(path.join(STORAGE_DIR, filename),
    (write ? fs.constants.O_RDWR | fs.constants.O_CREAT : fs.constants.O_RDONLY) | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK |
      (append ? fs.constants.O_APPEND : 0), 0o600);
  const file = fs.fstatSync(fd);
  if (!file.isFile() || !owned(file) || file.nlink !== 1) {
    fs.closeSync(fd);
    throw new Error("Unsafe storage file");
  }
  return fd;
}
