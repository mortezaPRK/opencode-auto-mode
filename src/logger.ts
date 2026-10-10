import * as fs from "node:fs";
import { privateFile } from "./storage.js";

export interface Logger {
  log(line: string): void;
  logJSON(label: string, value: unknown): void;
}

export function createLogger(filename: string): Logger {
  const stamp = () => new Date().toISOString();
  const append = (line: string) => {
    let fd: number | undefined;
    try {
      fd = privateFile(filename, true, true);
      const size = fs.fstatSync(fd).size;
      if (size > 1_048_576) fs.ftruncateSync(fd, 0);
      fs.writeSync(fd, `[${stamp()}] ${line.slice(0, 1024).replace(/[\r\n]/g, " ")}\n`);
    } catch {} finally { if (fd !== undefined) fs.closeSync(fd); }
  };
  return {
    log: append,
    logJSON: (label, value) => append(`${label}: ${JSON.stringify(value)}`),
  };
}
