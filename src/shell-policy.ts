import { basename, posix } from "node:path";
import { parse, type ParseEntry } from "shell-quote";

/**
 * Command vocabulary and per-command safety policy for shell approval.
 *
 * Everything here works on parsed words rather than raw command text, so text that
 * merely mentions a dangerous word (a commit message, a search pattern, a heredoc
 * body) is never treated as a dangerous operation.
 */

export const SHELLS = new Set(["sh", "bash", "dash", "zsh", "ksh", "fish", "pwsh", "powershell", "cmd"]);
export const SCRIPT_HOSTS = new Set(["python", "python3", "node", "perl", "ruby", "php", "awk", "gawk", "lua"]);
export const STATEFUL = new Set(["alias", "unalias", "export", "unset", "set", "shopt", "trap", "umask",
  "readonly", "declare", "typeset", "local", "function"]);
export const DYNAMIC = new Set(["eval", "source", ".", "exec", "xargs"]);
export const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
export const CONTROL_OPERATORS = new Set([";", "&&", "||", "|", "|&", "&"]);
export const REDIRECT_OPERATORS = new Set([">", ">>", ">&", "<&", "<", "<<", "<<-", "<<<", "<>", ">|", "&>", "&>>"]);
/**
 * Characters a shell treats as word separators.
 *
 * JS `\s` is wider — it also matches CR, FF, VT, NBSP, U+2028/U+2029, and other
 * Unicode spaces — so every boundary scan here spells the shell set out, and
 * `hasNonShellWhitespace` rejects anything wider before parsing.
 */
const WORD_BREAK = /[ \t\n;|&()<>]/;

/** True when the text contains whitespace a shell does not treat as a separator. */
export function hasNonShellWhitespace(text: string): boolean {
  return /[^\S \t\n]/.test(text);
}

/**
 * Syntax this policy does not decode: whitespace a shell does not separate words
 * on, legacy `$[...]` arithmetic, and ANSI-C / locale quoting.
 *
 * Callers check both the raw text and the text after continuation removal:
 * normalization deletes `\`-newlines, which can assemble one of these forms from
 * characters that were separate in the raw source (`$`+`\`-newline+`'...'` is
 * ANSI-C quoting to a shell).
 */
export function hasUndecodedSyntax(text: string): boolean {
  return hasNonShellWhitespace(text) || text.includes("$[") ||
    text.includes("$'") || text.includes('$"');
}

/**
 * Matches text whose quotes are balanced and whose backslashes escape a character
 * on the same line.
 *
 * A prefix cut before an undecoded opener is only a complete command when this
 * matches; otherwise an open quote could turn quoted data into commands.
 */
export const BALANCED_QUOTES = /^(?:[^'"\\]|\\[^\r\n]|'[^']*'|"(?:[^"\\]|\\[^\r\n])*")*$/;

/**
 * True when removing `\`-newlines would assemble syntax this policy does not
 * decode. Parsing such a line can place a quote or word boundary differently
 * from the shell, so callers must not take a deny from it.
 */
export function hasAssembledUndecodedSyntax(text: string): boolean {
  return !hasUndecodedSyntax(text) && hasUndecodedSyntax(normalizeContinuations(text));
}

type OptionArity = "flag" | "value";

interface WrapperGrammar {
  short: Readonly<Record<string, OptionArity>>;
  long: Readonly<Record<string, OptionArity>>;
  /** A bare `-N` adjustment (`nice -5 cmd`) is an option rather than a command word. */
  numeric?: boolean;
}

/** Parses a short-option spec; a letter followed by `:` takes a value. */
function shortOptions(spec: string): Record<string, OptionArity> {
  const options: Record<string, OptionArity> = {};
  for (let index = 0; index < spec.length; index++) {
    if (spec[index] === ":") continue;
    options[spec[index]] = spec[index + 1] === ":" ? "value" : "flag";
  }
  return options;
}

/** Parses a whitespace-separated long-option spec; a trailing `:` takes a value. */
function longOptions(spec: string): Record<string, OptionArity> {
  const options: Record<string, OptionArity> = {};
  for (const option of spec.split(/\s+/).filter(Boolean)) {
    const takesValue = option.endsWith(":");
    options[takesValue ? option.slice(0, -1) : option] = takesValue ? "value" : "flag";
  }
  return options;
}

/**
 * Option grammar for every command wrapper. Options that take a value consume
 * the following word, so `stdbuf -o L sudo id` and `ionice -c 3 sudo id` resolve
 * to `sudo` rather than to the option value.
 */
const WRAPPER_GRAMMARS: Record<string, WrapperGrammar> = {
  // `env -S` / `--split-string` reparses its value into command words, so the
  // effective executable is not the next word. Leaving the option unknown makes
  // the invocation fail closed to manual approval instead of resolving past it.
  env: { short: shortOptions("u:C:i0v"), long: longOptions(
    "--unset: --chdir: --ignore-environment --null --debug --block-signal --default-signal --ignore-signal") },
  command: { short: shortOptions("pvV"), long: longOptions("") },
  builtin: { short: shortOptions(""), long: longOptions("") },
  exec: { short: shortOptions("a:cl"), long: longOptions("") },
  time: { short: shortOptions("f:o:pavql"), long: longOptions("--format: --output: --verbose --quiet --portability --append") },
  "!": { short: shortOptions(""), long: longOptions("") },
  nohup: { short: shortOptions(""), long: longOptions("--help --version") },
  setsid: { short: shortOptions("fwc"), long: longOptions("--fork --wait --ctty --help --version") },
  nice: { short: shortOptions("n:"), long: longOptions("--adjustment: --help --version"), numeric: true },
  ionice: { short: shortOptions("c:n:p:P:u:t"), long: longOptions(
    "--class: --classdata: --pid: --pgid: --uid: --ignore --help --version") },
  stdbuf: { short: shortOptions("i:o:e:"), long: longOptions("--input: --output: --error: --help --version") },
  timeout: { short: shortOptions("s:k:"), long: longOptions(
    "--signal: --kill-after: --foreground --preserve-status --verbose --help --version") },
};

export const WRAPPERS = new Set(Object.keys(WRAPPER_GRAMMARS));

const DANGEROUS = "dangerous shell operation";
const FORK_BOMB = /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/;
const MAX_NESTING = 2;

const DENY_EXECUTABLES = new Set(["sudo", "doas", "su", "shutdown", "reboot", "halt", "poweroff"]);

/**
 * The arity of a long option, accepting the unambiguous abbreviations GNU
 * option parsing allows (`stdbuf --out=L` means `--output`). An abbreviation
 * that could name options of different arity is unknowable.
 */
function longOptionArity(grammar: WrapperGrammar, option: string): OptionArity | undefined {
  if (Object.hasOwn(grammar.long, option)) return grammar.long[option];
  const arities = new Set(Object.keys(grammar.long)
    .filter((name) => name.startsWith(option))
    .map((name) => grammar.long[name]));
  return arities.size === 1 ? [...arities][0] : undefined;
}

/**
 * Index of the first word after a wrapper's options, or undefined when an
 * unknown option makes its arity — and therefore the effective executable —
 * unknowable. Unknown options fail closed to manual approval.
 */
function wrapperCommand(grammar: WrapperGrammar, words: readonly string[], start: number): number | undefined {
  let index = start;
  while (index < words.length) {
    const word = words[index];
    if (word === "--") return index + 1;
    if (word.startsWith("--")) {
      const separator = word.indexOf("=");
      const arity = longOptionArity(grammar, separator === -1 ? word : word.slice(0, separator));
      if (arity === undefined) return undefined;
      index += arity === "value" && separator === -1 ? 2 : 1;
      continue;
    }
    if (word.startsWith("-") && word.length > 1) {
      const letters = word.slice(1);
      if (grammar.numeric && /^\d+$/.test(letters)) { index++; continue; }
      let separateValue = false;
      for (let position = 0; position < letters.length; position++) {
        const arity = grammar.short[letters[position]];
        if (arity === undefined) return undefined;
        if (arity === "flag") continue;
        // Any remaining letters are the attached value (`-n5`).
        separateValue = position === letters.length - 1;
        break;
      }
      index += separateValue ? 2 : 1;
      continue;
    }
    return index;
  }
  return index;
}

/** Resolves leading assignments and wrapper options to the effective executable. */
export function resolveExecutable(words: readonly string[]): { name: string; index: number } | undefined {
  let index = 0;
  while (index < words.length && ASSIGNMENT.test(words[index])) index++;
  while (index < words.length) {
    const name = basename(words[index]);
    const grammar = WRAPPERS.has(name) ? WRAPPER_GRAMMARS[name] : undefined;
    if (grammar === undefined) break;
    const command = wrapperCommand(grammar, words, index + 1);
    if (command === undefined) return undefined;
    index = command;
    // `timeout DURATION COMMAND` consumes the duration before the command.
    if (name === "timeout") {
      if (index >= words.length) return undefined;
      index++;
    }
    while (index < words.length && ASSIGNMENT.test(words[index])) index++;
  }
  return index < words.length ? { name: basename(words[index]), index } : undefined;
}

/** Commands whose non-option operands are files they read or modify. */
const PATH_OPERAND_COMMANDS = new Set(["cat", "less", "more", "head", "tail", "strings", "xxd", "od",
  "hexdump", "file", "stat", "wc", "md5sum", "diff", "sort", "uniq", "cut", "bat", "cp", "mv", "rm",
  "chmod", "chown", "truncate", "install", "open", "ls", "du"]);
/** Commands whose first non-option operand is a pattern and whose rest are paths. */
const PATTERN_FIRST_COMMANDS = new Set(["grep", "rg"]);
/** `shasum`, `sha1sum`, `sha256sum`, `sha384sum`, `sha512sum`. */
const CHECKSUM_COMMAND = /^(?:shasum|sha(?:1|224|256|384|512)sum)$/;

/** How a value-taking option consumes its value: pattern data, or a file path. */
type ValueRole = "data" | "path";

/**
 * Known long options and the role of their value, used for exact matches and
 * unambiguous abbreviations: `--reg=.` is `--regexp=`, `--fil=` is `--file=`.
 * `data` values are patterns, types, encodings, labels, formats or numbers and
 * must never be read as paths; `path` values name files.
 */
const LONG_OPTION_VALUES = new Map<string, ValueRole>([
  // grep
  ["--regexp", "data"], ["--file", "path"], ["--exclude", "data"], ["--include", "data"],
  ["--exclude-dir", "data"], ["--include-dir", "data"], ["--exclude-from", "path"],
  ["--ignore-file", "path"],
  ["--label", "data"], ["--directories", "data"], ["--devices", "data"], ["--binary-files", "data"],
  ["--after-context", "data"], ["--before-context", "data"], ["--context", "data"], ["--max-count", "data"],
  // rg
  ["--type", "data"], ["--type-not", "data"], ["--type-add", "data"], ["--type-clear", "data"],
  ["--encoding", "data"], ["--replace", "data"], ["--glob", "data"], ["--iglob", "data"],
  ["--max-columns", "data"], ["--threads", "data"], ["--max-depth", "data"],
  ["--sort", "data"], ["--sortr", "data"], ["--field-match-separator", "data"],
  ["--field-context-separator", "data"], ["--context-separator", "data"],
  // sed
  ["--expression", "data"], ["--line-length", "data"],
  // jq
  ["--from-file", "path"],
  // git
  ["--grep", "data"], ["--format", "data"],
  // sort: a file of random bytes; value options that must not shift a path.
  ["--random-source", "path"], ["--key", "data"], ["--field-separator", "data"],
  ["--batch-size", "data"], ["--buffer-size", "data"], ["--parallel", "data"],
  // diff: a file compared from/to; formats and labels are data.
  ["--to-file", "path"], ["--line-format", "data"], ["--old-line-format", "data"],
  ["--new-line-format", "data"], ["--unchanged-line-format", "data"], ["--width", "data"],
  ["--horizon-lines", "data"], ["--palette", "data"], ["--ignore-matching-lines", "data"],
  // file: an alternate magic file.
  ["--magic-file", "path"],
  // tree: an input file of paths.
  ["--gitfile", "path"],
  // Writing, temporary, program and library paths; attached values are still
  // file operands for the scope and symlink checks. jq's --arg/--argjson are
  // data names, kept exact so `--arg` does not abbreviate to `--argfile`.
  ["--output", "path"], ["--temporary-directory", "path"], ["--compress-program", "path"],
  ["--library-path", "path"], ["--slurpfile", "path"], ["--rawfile", "path"], ["--argfile", "path"],
  ["--arg", "data"], ["--argjson", "data"],
]);

/** Resolve a long option or its unambiguous abbreviation, when it is known. */
export function resolveLongOption(option: string): string | undefined {
  if (LONG_OPTION_VALUES.has(option)) return option;
  if (!option.startsWith("--") || option.length <= 2) return undefined;
  const matches = [...LONG_OPTION_VALUES.keys()].filter((name) => name.startsWith(option));
  return matches.length === 1 ? matches[0] : undefined;
}

/** True when a long option's value is data this policy must not treat as a path. */
export function isDataOption(option: string): boolean {
  const resolved = resolveLongOption(option);
  return resolved !== undefined && LONG_OPTION_VALUES.get(resolved) === "data";
}

/** Value-taking letters for `grep -A 2`, `-m 1`, `-d skip`, `-e PATTERN`, `-f FILE`. */
const GREP_SHORT_VALUES: Record<string, ValueRole> = {
  e: "data", f: "path", A: "data", B: "data", C: "data", m: "data", d: "data", D: "data",
};
/** Value-taking letters for `rg -t ts`, `-g GLOB`, `-e PATTERN`, `-f FILE`, ... */
const RG_SHORT_VALUES: Record<string, ValueRole> = {
  e: "data", f: "path", g: "data", t: "data", T: "data", E: "data", j: "data", M: "data",
  r: "data", A: "data", B: "data", C: "data", m: "data",
};
/** sed's expression/script files and the numeric line length. */
const SED_SHORT_VALUES: Record<string, ValueRole> = { e: "data", f: "path", l: "data" };
/** jq's filter and library files. */
const JQ_SHORT_VALUES: Record<string, ValueRole> = { f: "path", L: "path" };
/** Numeric/format/size values of the plain readers and file tools. */
const PLAIN_SHORT_VALUES: Record<string, Record<string, ValueRole>> = {
  head: { n: "data", c: "data" },
  tail: { n: "data", c: "data", s: "data" },
  sort: { k: "data", t: "data", S: "data", o: "path", T: "path" },
  uniq: { f: "data", s: "data", w: "data" },
  diff: { U: "data", C: "data", I: "data", x: "data", X: "path", L: "data" },
  cut: { d: "data", f: "data", b: "data", c: "data" },
  xxd: { l: "data", s: "data", c: "data", g: "data" },
  od: { N: "data", j: "data", t: "data" },
  hexdump: { n: "data", s: "data", e: "data", f: "path" },
  strings: { n: "data", t: "data", e: "data" },
  stat: { c: "data" },
  less: { p: "data", o: "path", b: "data", h: "data", j: "data", x: "data", y: "data", z: "data" },
  more: { n: "data" },
  open: { a: "data", b: "data" },
  file: { f: "path", m: "path", e: "data", F: "data" },
  // `ls -I PATTERN` is an ignore glob; `-w`/`-T` take column/tab-size numbers.
  ls: { I: "data", w: "data", T: "data" },
  // `du -d N`/`--max-depth` is a number; `-X FILE` is the exclude-from file.
  du: { d: "data", X: "path" },
};
/** Git subcommands whose operands this policy can place. */
const GIT_HANDLED = new Set(["commit", "tag", "branch", "checkout", "switch", "push", "fetch"]);
const GIT_LONG_VALUES: Record<string, Record<string, ValueRole>> = {
  commit: { "--message": "data", "--file": "path", "--author": "data", "--date": "data",
    "--reuse-message": "data", "--reedit-message": "data", "--fixup": "data", "--squash": "data" },
  tag: { "--message": "data", "--file": "path" },
  branch: { "--contains": "data", "--points-at": "data", "--merged": "data", "--no-merged": "data" },
  checkout: { "--orphan": "data", "--conflict": "data" },
  switch: { "--orphan": "data", "--conflict": "data" },
  push: { "--push-option": "data", "--repo": "path" },
  fetch: { "--depth": "data", "--deepen": "data", "--upload-pack": "path" },
};
const GIT_SHORT_VALUES: Record<string, Record<string, ValueRole>> = {
  commit: { m: "data", F: "path", C: "data", c: "data" },
  tag: { m: "data", F: "path" },
  branch: { m: "data", M: "data", c: "data", C: "data" },
  checkout: { b: "data", B: "data" },
  switch: { c: "data", C: "data" },
};

/**
 * Which words of a simple command are files and which are data.
 *
 * A shell word is data or a path depending on the position a command gives it:
 * `cat auth` reads a file named `auth`, `grep auth file` searches for `auth`,
 * `sed s/.env/.x/p file` runs a script, and `jq .name file` evaluates a filter.
 * `paths` are indices of standalone file operands, `data` indices of pattern,
 * script, filter or option-value words, and `pathValues` are file values
 * attached to an option (`-fFILE`, `--file=FILE`). Every other word (the
 * executable, ordinary options) is neither; callers keep their own check for
 * it. Commands outside the grammar below report no roles at all.
 */
export interface OperandRoles {
  /** Indices of words the command consumes as file paths. */
  paths: number[];
  /** Indices of words the command consumes as data. */
  data: number[];
  /** File values attached to an option (`-fFILE`, `--file=FILE`). */
  pathValues: string[];
}

interface RoleSets { paths: Set<number>; data: Set<number>; pathValues: string[] }

interface ShortValue { letter: string; role: ValueRole; attached?: string }

/** Splits `--name=value` into its option name and attached value. */
function longOptionPart(word: string): { option: string; attached?: string } | undefined {
  if (!word.startsWith("--") || word.length <= 2) return undefined;
  const separator = word.indexOf("=");
  return separator === -1 ? { option: word } : { option: word.slice(0, separator), attached: word.slice(separator + 1) };
}

/**
 * Reads a short-option bundle letter by letter. The first letter that takes a
 * value wins: the rest of the word is its attached value (`-ifpats` is `-i -f
 * pats`), or the next word when the bundle ends at that letter (`-if pats`).
 * Unknown letters are ordinary flags.
 */
function shortOption(word: string, table: Record<string, ValueRole>): ShortValue | undefined {
  if (!word.startsWith("-") || word.startsWith("--") || word.length < 2) return undefined;
  const letters = word.slice(1);
  for (let index = 0; index < letters.length; index++) {
    const role = table[letters[index]];
    if (role === undefined) continue;
    const attached = letters.slice(index + 1);
    return { letter: letters[index], role, attached: attached.length ? attached : undefined };
  }
  return undefined;
}

/**
 * The flag letters of one short bundle, stopping at the first letter that takes
 * a value. An attached value (`-fpatterns`, `-Xcredentials`) is data or a path,
 * never a flag, so recursion checks cannot be spoofed by a value's spelling.
 */
function shortFlags(word: string, table: Record<string, ValueRole>): string {
  if (!word.startsWith("-") || word.startsWith("--") || word.length < 2) return "";
  const letters = word.slice(1);
  let position = 0;
  while (position < letters.length && table[letters[position]] === undefined) position++;
  return letters.slice(0, position);
}

/** Marks the value a short option consumes and returns the new word index. */
function takeShortValue(parsed: ShortValue, index: number, base: number,
  args: readonly string[], roles: RoleSets): number {
  if (parsed.role === "path") {
    if (parsed.attached !== undefined) roles.pathValues.push(parsed.attached);
    else if (index + 1 < args.length) {
      roles.paths.add(base + index + 1);
      return index + 1;
    }
  } else if (parsed.attached === undefined && index + 1 < args.length) {
    roles.data.add(base + index + 1);
    return index + 1;
  }
  return index;
}

/** Marks attached (`--grep=X`) and separate (`--grep X`) data option values. */
function dataOptionRoles(args: readonly string[], base: number): RoleSets {
  const roles: RoleSets = { paths: new Set(), data: new Set(), pathValues: [] };
  let endOfOptions = false;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (endOfOptions) continue;
    if (arg === "--") { endOfOptions = true; continue; }
    const part = longOptionPart(arg);
    if (part === undefined) continue;
    const resolved = resolveLongOption(part.option);
    if (resolved === undefined || LONG_OPTION_VALUES.get(resolved) !== "data") continue;
    if (part.attached !== undefined) { roles.data.add(base + index); continue; }
    if (index + 1 < args.length) { roles.data.add(base + index + 1); index++; }
  }
  return roles;
}

/** Marks attached (`--file=X`) path option values as file operands. */
function pathOptionRoles(args: readonly string[], roles: RoleSets): void {
  let endOfOptions = false;
  for (const arg of args) {
    if (endOfOptions) continue;
    if (arg === "--") { endOfOptions = true; continue; }
    const part = longOptionPart(arg);
    if (part === undefined || part.attached === undefined) continue;
    const resolved = resolveLongOption(part.option);
    if (resolved === undefined || LONG_OPTION_VALUES.get(resolved) !== "path") continue;
    roles.pathValues.push(part.attached);
  }
}

/** Adds every non-option positional as a path (`cat`, `sort`, checksums, ...). */
function plainRoles(name: string, args: readonly string[], base: number, roles: RoleSets): void {
  const table = PLAIN_SHORT_VALUES[name] ?? {};
  let endOfOptions = false;
  for (let index = 0; index < args.length; index++) {
    const word = args[index];
    if (!endOfOptions && word === "--") { endOfOptions = true; continue; }
    if (!endOfOptions && word.startsWith("-") && word.length > 1) {
      if (word.startsWith("--")) continue;
      const parsed = shortOption(word, table);
      if (parsed !== undefined) index = takeShortValue(parsed, index, base, args, roles);
      continue;
    }
    if (roles.data.has(base + index)) continue;
    roles.paths.add(base + index);
  }
}

/**
 * `grep`/`rg`: the first positional is a pattern unless `-e`/`--regexp` already
 * supplied one, and `-f`/`--file` names a pattern file. Every positional after
 * a pattern is a path.
 */
function grepRoles(name: string, args: readonly string[], base: number, roles: RoleSets): void {
  const table = name === "rg" ? RG_SHORT_VALUES : GREP_SHORT_VALUES;
  let seenPattern = false;
  let endOfOptions = false;
  for (let index = 0; index < args.length; index++) {
    const word = args[index];
    if (!endOfOptions && word === "--") { endOfOptions = true; continue; }
    if (!endOfOptions && word.startsWith("-") && word.length > 1) {
      if (word.startsWith("--")) {
        const part = longOptionPart(word);
        const resolved = part === undefined ? undefined : resolveLongOption(part.option);
        if (resolved === "--regexp") { seenPattern = true; continue; }
        // Any path-valued long option names a file: `--file` (pattern file),
        // `--exclude-from`/`--ignore-file` (files of patterns). Only `--file`
        // supplies the pattern; the others leave the next positional a pattern.
        if (resolved !== undefined && LONG_OPTION_VALUES.get(resolved) === "path") {
          if (part?.attached !== undefined) roles.pathValues.push(part.attached);
          else if (index + 1 < args.length) roles.paths.add(base + ++index);
          if (resolved === "--file") seenPattern = true;
          continue;
        }
        continue;
      }
      const parsed = shortOption(word, table);
      if (parsed === undefined) continue;
      index = takeShortValue(parsed, index, base, args, roles);
      if (parsed.letter === "e" || parsed.letter === "f") seenPattern = true;
      continue;
    }
    if (roles.data.has(base + index)) continue;
    if (!seenPattern) { roles.data.add(base + index); seenPattern = true; continue; }
    roles.paths.add(base + index);
  }
}

/**
 * `sed`: the first positional is the script unless `-e`/`--expression` supplied
 * one. `-f`/`--file` names a script file and also means every positional is a
 * file; `-l`/`--line-length` takes a number that is not an operand.
 */
function sedRoles(args: readonly string[], base: number, roles: RoleSets): void {
  let scripted = false;
  let endOfOptions = false;
  for (let index = 0; index < args.length; index++) {
    const word = args[index];
    if (!endOfOptions && word === "--") { endOfOptions = true; continue; }
    if (!endOfOptions && word.startsWith("-") && word.length > 1) {
      if (word.startsWith("--")) {
        const part = longOptionPart(word);
        const resolved = part === undefined ? undefined : resolveLongOption(part.option);
        if (resolved === "--expression") { scripted = true; continue; }
        if (resolved === "--file") {
          if (part?.attached !== undefined) roles.pathValues.push(part.attached);
          else if (index + 1 < args.length) roles.paths.add(base + ++index);
          scripted = true;
          continue;
        }
        continue;
      }
      const parsed = shortOption(word, SED_SHORT_VALUES);
      if (parsed === undefined) continue;
      index = takeShortValue(parsed, index, base, args, roles);
      if (parsed.letter === "e" || parsed.letter === "f") scripted = true;
      continue;
    }
    if (roles.data.has(base + index)) continue;
    if (!scripted) { roles.data.add(base + index); scripted = true; continue; }
    roles.paths.add(base + index);
  }
}

/**
 * `jq`: the first positional is the filter unless `-f`/`--from-file` supplies
 * one. All value-taking options are stated explicitly, so a bare `1` after a
 * flag (`-e`, `-r`, `--tab`) is the filter. `--arg`/`--argjson` take a name and
 * a value as data, `--slurpfile`/`--rawfile`/`--argfile` take a name (data) and
 * a file (path), and `--args`/`--jsonargs` make positionals string data.
 */
function jqRoles(args: readonly string[], base: number, roles: RoleSets): void {
  let filterSupplied = false;
  let positionalData = false;
  let endOfOptions = false;
  const takeValues = (index: number, count: number, role: ValueRole): number => {
    let taken = 0;
    while (taken < count && index + 1 < args.length) {
      const next = base + ++index;
      (role === "data" ? roles.data : roles.paths).add(next);
      taken++;
    }
    return index;
  };
  for (let index = 0; index < args.length; index++) {
    const word = args[index];
    if (!endOfOptions && word === "--") { endOfOptions = true; continue; }
    if (!endOfOptions && word.startsWith("-") && word.length > 1) {
      if (word.startsWith("--")) {
        const part = longOptionPart(word);
        const option = part?.option;
        const resolved = part === undefined ? undefined : resolveLongOption(part.option);
        if (resolved === "--from-file") {
          if (part?.attached !== undefined) roles.pathValues.push(part.attached);
          else if (index + 1 < args.length) roles.paths.add(base + ++index);
          filterSupplied = true;
          continue;
        }
        if (option === "--arg" || option === "--argjson") { index = takeValues(index, 2, "data"); continue; }
        if (option === "--slurpfile" || option === "--rawfile" || option === "--argfile") {
          index = takeValues(index, 1, "data");
          index = takeValues(index, 1, "path");
          continue;
        }
        if (option === "--args" || option === "--jsonargs") { positionalData = true; continue; }
        if (option === "--library-path") { index = takeValues(index, 1, "path"); continue; }
        if (option === "--indent") { index = takeValues(index, 1, "data"); continue; }
        continue;
      }
      const parsed = shortOption(word, JQ_SHORT_VALUES);
      if (parsed !== undefined) {
        index = takeShortValue(parsed, index, base, args, roles);
        if (parsed.letter === "f") filterSupplied = true;
      }
      continue;
    }
    if (roles.data.has(base + index)) continue;
    if (positionalData) { roles.data.add(base + index); continue; }
    if (!filterSupplied) { roles.data.add(base + index); filterSupplied = true; continue; }
    roles.paths.add(base + index);
  }
}

/** `find` tests whose value is a path read for comparison, not a pattern. */
const FIND_PATH_VALUE_TESTS = new Set(["-newer", "-anewer", "-cnewer", "-samefile",
  "-fprint", "-fprint0", "-fprintf", "-fls"]);
/** `find` tests whose value is data: patterns, types, sizes, times, ids. */
const FIND_DATA_VALUE_TESTS = new Set(["-name", "-iname", "-path", "-ipath", "-regex", "-iregex",
  "-wholename", "-iwholename", "-type", "-mtime", "-atime", "-ctime", "-mmin", "-amin", "-cmin",
  "-size", "-perm", "-user", "-group", "-uid", "-gid", "-links", "-inum", "-maxdepth", "-mindepth",
  "-printf", "-regextype", "-used", "-context"]);
/** `-exec`/`-execdir`/`-ok`/`-okdir` consume an inline command, not a path test. */
const FIND_EXEC_TESTS = new Set(["-exec", "-execdir", "-ok", "-okdir"]);

/** True for the tokens (an option, `(`, `)`, `!`) that start `find`'s expression. */
function startsFindExpression(word: string): boolean {
  return word === "(" || word === ")" || word === "!" || word.startsWith("-");
}

/**
 * Options `find` accepts before its starting paths: the symlink modes
 * `-H`/`-L`/`-P`, the optimisation level `-O[level]` and `-D debugopts`.
 */
function findLeadingOption(word: string): "flag" | "value" | undefined {
  if (word === "-H" || word === "-L" || word === "-P") return "flag";
  if (word === "-D") return "value";
  return /^-O\d*$/.test(word) ? "flag" : undefined;
}

/** Marks an inline `-exec ... ;`/`-exec ... +` command as data and returns its end index. */
function consumeFindExecArgs(args: readonly string[], start: number, base: number, roles: RoleSets): number {
  let index = start + 1;
  while (index < args.length && args[index] !== ";" && args[index] !== "+") { roles.data.add(base + index); index++; }
  return index;
}

/** Marks `find`'s leading options as data and returns the index its starting paths begin at. */
function consumeFindLeadingOptions(args: readonly string[], base: number, roles: RoleSets): number {
  let index = 0;
  while (index < args.length) {
    const option = findLeadingOption(args[index]);
    if (option === undefined) break;
    roles.data.add(base + index);
    if (option === "value" && index + 1 < args.length) roles.data.add(base + ++index);
    index++;
  }
  return index;
}

/**
 * `find [-H|-L|-P|-O[level]|-D debugopts] [path...] [expression]`: positionals
 * before the first expression token (an option, `(`, `)` or `!`) are starting
 * paths; `-exec`/`-execdir`/`-ok`/`-okdir` consume a command up to `;`/`+` as
 * data, and other tests consume their value as a path or data per the tables
 * above.
 */
function findRoles(args: readonly string[], base: number, roles: RoleSets): void {
  let sawExpression = false;
  for (let index = consumeFindLeadingOptions(args, base, roles); index < args.length; index++) {
    const word = args[index];
    if (!sawExpression) {
      if (!startsFindExpression(word)) { roles.paths.add(base + index); continue; }
      sawExpression = true;
    }
    if (FIND_EXEC_TESTS.has(word)) { index = consumeFindExecArgs(args, index, base, roles); continue; }
    if (FIND_PATH_VALUE_TESTS.has(word) && index + 1 < args.length) { roles.paths.add(base + ++index); continue; }
    if (FIND_DATA_VALUE_TESTS.has(word) && index + 1 < args.length) { roles.data.add(base + ++index); continue; }
  }
}

/**
 * Git subcommands whose operands are refs, messages or other data rather than
 * files: `commit -m` messages, `branch <name>`, `checkout`/`switch` branches,
 * `push`/`fetch` refspecs and `tag` names. `git add .env` stays an ordinary
 * word, so a file operand is still protected once `--` ends ref parsing.
 */
function gitRoles(args: readonly string[], base: number, roles: RoleSets): void {
  const subcommand = args[0];
  if (subcommand === undefined || !GIT_HANDLED.has(subcommand)) return;
  const rest = args.slice(1);
  const long = GIT_LONG_VALUES[subcommand] ?? {};
  const short = GIT_SHORT_VALUES[subcommand] ?? {};
  const refs = subcommand === "tag" || subcommand === "branch" || subcommand === "push" || subcommand === "fetch";
  let endOfOptions = false;
  for (let index = 0; index < rest.length; index++) {
    const word = rest[index];
    const position = base + 1 + index;
    if (!endOfOptions && word === "--") { endOfOptions = true; continue; }
    if (!endOfOptions && word.startsWith("--") && word.length > 2) {
      const part = longOptionPart(word);
      const role = part === undefined ? undefined : long[part.option];
      if (part === undefined || role === undefined) continue;
      if (part.attached !== undefined) {
        if (role === "path") roles.pathValues.push(part.attached);
        else roles.data.add(position);
        continue;
      }
      if (index + 1 < rest.length) {
        const next = base + 1 + ++index;
        (role === "data" ? roles.data : roles.paths).add(next);
      }
      continue;
    }
    if (!endOfOptions && word.startsWith("-") && word.length > 1) {
      const parsed = shortOption(word, short);
      if (parsed !== undefined) index = takeShortValue(parsed, index, base + 1, rest, roles);
      continue;
    }
    if (roles.data.has(position)) continue;
    // `checkout`/`switch` treat positionals before `--` as refs and after it as
    // paths; `commit` positionals are always paths.
    if (refs || ((subcommand === "checkout" || subcommand === "switch") && !endOfOptions))
      roles.data.add(position);
    else roles.paths.add(position);
  }
}

/** The path and data roles of one simple command's argv. */
export function operandRoles(words: readonly string[]): OperandRoles {
  const executable = resolveExecutable(words);
  if (executable === undefined) return { paths: [], data: [], pathValues: [] };
  const args = words.slice(executable.index + 1);
  const roles = dataOptionRoles(args, executable.index + 1);
  pathOptionRoles(args, roles);
  const name = executable.name;
  if (PATTERN_FIRST_COMMANDS.has(name)) grepRoles(name, args, executable.index + 1, roles);
  else if (name === "sed") sedRoles(args, executable.index + 1, roles);
  else if (name === "jq") jqRoles(args, executable.index + 1, roles);
  else if (name === "git") gitRoles(args, executable.index + 1, roles);
  else if (name === "find") findRoles(args, executable.index + 1, roles);
  else if (PATH_OPERAND_COMMANDS.has(name) || CHECKSUM_COMMAND.test(name))
    plainRoles(name, args, executable.index + 1, roles);
  const ascending = (left: number, right: number) => left - right;
  return {
    paths: [...roles.paths].sort(ascending),
    data: [...roles.data].sort(ascending),
    pathValues: [...new Set(roles.pathValues)],
  };
}

/** The standalone words one simple command consumes as files. */
export function pathOperands(words: readonly string[]): string[] {
  return operandRoles(words).paths.map((index) => words[index]);
}

/**
 * True when an argument names one of the given long options, including the
 * abbreviations GNU option parsing accepts (`sort --out=/tmp/out` means
 * `--output`). Abbreviations fail closed: any prefix that could name a dangerous
 * option requires review rather than approval.
 */
function hasLongOption(args: readonly string[], names: readonly string[]): boolean {
  return args.some((arg) => {
    const option = arg.split("=", 1)[0];
    if (!option.startsWith("--") || option.length === 2) return false;
    return names.some((name) => name.startsWith(option));
  });
}

/**
 * True when an argument is a long option or an unambiguous GNU-style abbreviation
 * of it (`--forc` means `--force`). Abbreviations fail closed: any prefix of a
 * dangerous option is treated as that option.
 */
export function isLongOption(argument: string, name: string): boolean {
  const option = argument.split("=", 1)[0];
  return option === name || (option.length > 2 && option.startsWith("--") && name.startsWith(option));
}

function hasShortOption(args: readonly string[], letters: string): boolean {
  return args.some((arg) => arg.startsWith("-") && !arg.startsWith("--") &&
    [...arg.slice(1)].some((character) => letters.includes(character)));
}

function isWorldWritableMode(arg: string): boolean {
  // `chmod +w` and `chmod +rwx` omit the `who` part, which means "all users".
  // Only a leading `-` is a removal; a leading `+` has to be read as `a+`.
  const mode = arg.replace(/^-+/, "").replace(/^\+/, "a+");
  return /^[0-7]{3,4}$/.test(mode) ? (Number.parseInt(mode, 8) & 0o002) !== 0 :
    /(?:^|,)(?:[ug]*o[ugoa]*|a|)[+=][rwxXst]*w/.test(mode);
}

/** chmod options, including the BSD flags, that never consume the mode operand. */
const CHMOD_FLAGS = /^-[RcfvHhLP]+$/;

/** The mode operand chmod applies, ignoring options and earlier operands. */
function chmodMode(args: readonly string[]): string | undefined {
  let end = false;
  for (const arg of args) {
    if (end) return arg;
    if (arg === "--") { end = true; continue; }
    // `--reference` copies a mode from another file, so there is no mode operand.
    if (arg === "--reference" || arg.startsWith("--reference=")) return undefined;
    if (arg.startsWith("--") || CHMOD_FLAGS.test(arg)) continue;
    return arg;
  }
  return undefined;
}

/** True when a path names the filesystem root rather than a directory below it. */
function isFilesystemRoot(target: string): boolean {
  if (!target.startsWith("/")) return false;
  const trimmed = target.replace(/\/+$/, "").replace(/\/\*+$/, "");
  return trimmed === "" || posix.normalize(trimmed) === "/";
}

/**
 * True when `rm` removes the filesystem root recursively. Force is irrelevant:
 * a writable root is already destroyed by `rm -r / --no-preserve-root`.
 *
 * `--` ends option parsing, so every later argument is a target: `rm -- -r /`
 * asks `rm` to remove the files `-r` and `/` without recursion, which fails on
 * the root instead of deleting it, while `rm -r -- /` still denies.
 */
function isRecursiveRootRemoval(args: readonly string[]): boolean {
  let recursive = false;
  let endOfOptions = false;
  const targets: string[] = [];
  for (const arg of args) {
    if (endOfOptions) { targets.push(arg); continue; }
    if (arg === "--") { endOfOptions = true; continue; }
    if (arg.startsWith("--")) {
      // GNU option parsing accepts `--recursi` for `--recursive`.
      if (isLongOption(arg, "--recursive")) recursive = true;
      continue;
    }
    if (arg.startsWith("-") && arg.length > 1) {
      const letters = arg.slice(1);
      if (letters.includes("r") || letters.includes("R")) recursive = true;
      continue;
    }
    targets.push(arg);
  }
  if (!recursive || targets.length === 0) return false;
  return targets.some(isFilesystemRoot);
}

/** Shell options that take no value and may follow `-c` before its script. */
const SHELL_FLAGS = new Set(["-a", "-b", "-C", "-e", "-f", "-h", "-i", "-k", "-l", "-m", "-n", "-p", "-r", "-s",
  "-t", "-u", "-v", "-x", "-B", "-E", "-H", "-P", "-T", "--login", "--noprofile", "--norc", "--posix",
  "--restricted", "--verbose", "--noediting"]);
/** Shell options that consume the next word as their value. */
const SHELL_VALUE_OPTIONS = new Set(["-o", "-O", "--rcfile", "--init-file"]);
const SHELL_FLAG_LETTERS = "abcCefhiklmnprstuvxBEHPT";

/**
 * The script operand that follows the `-c` option at `start`.
 *
 * A shell keeps parsing options after `-c`, so `sh -c -e 'pwd`+newline+`sudo id'`
 * runs the quoted string, not `-e`, and `sh -c -- script` runs `script`. Known
 * flags and their values are skipped; an unknown option could consume the script
 * itself, so its arity is unknowable and the caller must fail closed.
 */
function shellScript(args: readonly string[], start: number): string | undefined {
  let index = start;
  while (index < args.length) {
    const arg = args[index];
    if (arg === "--") return args[index + 1];
    if (SHELL_VALUE_OPTIONS.has(arg)) { index += 2; continue; }
    if (SHELL_FLAGS.has(arg)) { index++; continue; }
    if (/^-[^-]+$/.test(arg) && [...arg.slice(1)].every((letter) => SHELL_FLAG_LETTERS.includes(letter))) {
      index++;
      continue;
    }
    if (arg.startsWith("-") && arg.length > 1) return undefined;
    return arg;
  }
  return undefined;
}

/** The script a shell or `eval` would run, when invoked non-interactively. */
function scriptArgument(name: string, args: readonly string[]): string | undefined {
  if (name === "eval") return args.length ? args.join(" ") : undefined;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === "--") return undefined;
    if (!arg.startsWith("-") || arg.startsWith("--")) continue;
    if (arg.slice(1).includes("c")) return shellScript(args, index + 1);
  }
  return undefined;
}

/**
 * Removes file-descriptor prefixes (`2` in `2>/dev/null`) that are adjacent to
 * the redirection operator in the source.
 *
 * Only an unquoted, unescaped digit run that starts a word is a descriptor. A
 * numeric operand separated by whitespace (`chmod 777 > /dev/null secret`) is
 * preserved, as is a quoted (`"2">file`) or escaped (`\2>file`) digit argument.
 */
export function stripDescriptorPrefixes(command: string): string {
  let result = "";
  let boundary = true;
  let index = 0;
  while (index < command.length) {
    const character = command[index];
    if (character === "\\") {
      result += command.slice(index, index + 2);
      boundary = false;
      index += 2;
      continue;
    }
    if (character === "'") {
      const end = command.indexOf("'", index + 1);
      const stop = end === -1 ? command.length : end + 1;
      result += command.slice(index, stop);
      boundary = false;
      index = stop;
      continue;
    }
    // ANSI-C quoting (`$'...'`) is the one quoted form where a backslash escapes
    // the closing quote, so its body needs the same escape handling as `"..."`.
    if (character === "$" && command[index + 1] === "'") {
      let cursor = index + 2;
      while (cursor < command.length && command[cursor] !== "'") cursor += command[cursor] === "\\" ? 2 : 1;
      const stop = Math.min(cursor + 1, command.length);
      result += command.slice(index, stop);
      boundary = false;
      index = stop;
      continue;
    }
    if (character === '"') {
      let cursor = index + 1;
      while (cursor < command.length && command[cursor] !== '"') cursor += command[cursor] === "\\" ? 2 : 1;
      const stop = Math.min(cursor + 1, command.length);
      result += command.slice(index, stop);
      boundary = false;
      index = stop;
      continue;
    }
    if (boundary && /\d/.test(character)) {
      let cursor = index;
      while (cursor < command.length && /\d/.test(command[cursor])) cursor++;
      if (command[cursor] === ">" || command[cursor] === "<") {
        // Replace the run with a space instead of deleting it: `&2>` is `&`
        // followed by a redirect, and deleting the `2` would fuse `&` and `>`
        // into the different `&>` operator.
        result += " ";
        index = cursor;
        continue;
      }
      result += command.slice(index, cursor);
      boundary = false;
      index = cursor;
      continue;
    }
    result += character;
    boundary = /[ \t\n;|&()<>]/.test(character);
    index++;
  }
  return result;
}

/**
 * Escapes a `#` that is part of a word so `shell-quote` does not mistake it for
 * the start of a comment.
 *
 * Shell comments begin only at the start of a word. `shell-quote` instead ends
 * the command at any unquoted `#`, which can hide a later command
 * (`echo a#b ; sudo id`). Escaping that literal hash preserves the word text and
 * lets the deny pass see the rest of the line. A real word-start comment is left
 * untouched, and quoted or escaped hashes are already literal.
 */
export function escapeLiteralHashes(command: string): string {
  let result = "";
  let wordStart = true;
  let quote: "'" | '"' | "$'" | undefined;
  for (let index = 0; index < command.length; index++) {
    const character = command[index];
    if (quote === "'") {
      result += character;
      if (character === "'") quote = undefined;
      continue;
    }
    if (quote === "$'") {
      result += character;
      if (character === "\\") {
        if (index + 1 < command.length) result += command[++index];
      } else if (character === "'") quote = undefined;
      continue;
    }
    if (quote === '"') {
      result += character;
      if (character === "\\") {
        if (index + 1 < command.length) result += command[++index];
      } else if (character === '"') quote = undefined;
      continue;
    }
    if (character === "\\") {
      result += character;
      if (index + 1 < command.length) {
        const escaped = command[++index];
        result += escaped;
        if (escaped !== "\n") wordStart = false;
      } else wordStart = false;
      continue;
    }
    if (character === "'" || character === '"' || (character === "$" && command[index + 1] === "'")) {
      result += character;
      wordStart = false;
      if (character === "'" || character === '"') quote = character;
      else {
        quote = "$'";
        result += command[++index];
      }
      continue;
    }
    if (character === "#") {
      if (wordStart) {
        result += command.slice(index);
        break;
      }
      result += "\\#";
      continue;
    }
    if (WORD_BREAK.test(character)) {
      result += character;
      wordStart = true;
      continue;
    }
    result += character;
    wordStart = false;
  }
  return result;
}

export interface HeredocMarker { delimiter: string; quoted: boolean; stripTabs: boolean }

/**
 * Reads the here-document marker that starts at `<<`, returning the marker and
 * the offset just past its delimiter.
 *
 * Only delimiters this parser decodes exactly are accepted: a bare word of
 * `[A-Za-z0-9_]`, or one fully quoted word. Single quotes keep a backslash
 * literal, so `'E\OF'` decodes to `E\OF`; a double-quoted word decodes `\\`,
 * `\$`, `` \` ``, and `\"`, so the raw text is not the delimiter and any
 * backslash there is unsupported. Escapes, expansion, concatenated words, and
 * an unterminated quote all return undefined, and callers fail closed.
 */
function heredocMarkerAt(line: string, index: number): { marker: HeredocMarker; end: number } | undefined {
  if (line[index] !== "<" || line[index + 1] !== "<" || line[index + 2] === "<" || line[index - 1] === "<")
    return undefined;
  let cursor = index + 2;
  const stripTabs = line[cursor] === "-";
  if (stripTabs) cursor++;
  while (line[cursor] === " " || line[cursor] === "\t") cursor++;
  let delimiter = "";
  let quoted = false;
  if (line[cursor] === "'" || line[cursor] === '"') {
    const closing = line[cursor];
    quoted = true;
    cursor++;
    let closed = false;
    while (cursor < line.length) {
      const character = line[cursor];
      if (character === closing) { closed = true; cursor++; break; }
      if (closing === '"' && character === "\\") return undefined;
      delimiter += character;
      cursor++;
    }
    if (!closed) return undefined;
  } else {
    while (cursor < line.length && /[A-Za-z0-9_]/.test(line[cursor])) delimiter += line[cursor++];
  }
  if (!delimiter) return undefined;
  // The delimiter word must end here; a quoted run glued to more word text is a
  // concatenation this parser does not decode.
  if (cursor < line.length && !WORD_BREAK.test(line[cursor])) return undefined;
  return { marker: { delimiter, quoted, stripTabs }, end: cursor };
}

interface HeredocScan { markers: HeredocMarker[]; unsupported: boolean }

/**
 * Scans one command line for here-document markers, ignoring markers inside
 * quoted strings and comments.
 *
 * `unsupported` reports a marker this parser cannot decode exactly: an escaped
 * or expanded delimiter (`<<\EOF`, `<<$name`), a delimiter word assembled from
 * quoted and unquoted parts (`<<E'OF'`, `<<'EOF'x`), a backslash inside a
 * double-quoted delimiter, or an unterminated quote. A wrong delimiter would
 * move the body boundary, so callers fail closed instead.
 */
function scanHeredoc(line: string): HeredocScan {
  const markers: HeredocMarker[] = [];
  let unsupported = false;
  let wordStart = true;
  let quote: "'" | '"' | undefined;
  for (let index = 0; index < line.length; index++) {
    const character = line[index];
    if (quote === "'") { if (character === "'") quote = undefined; continue; }
    if (quote === '"') {
      if (character === "\\") { index++; continue; }
      if (character === '"') quote = undefined;
      continue;
    }
    if (character === "'" || character === '"') { quote = character; wordStart = false; continue; }
    if (character === "\\") { index++; wordStart = false; continue; }
    if (character === "#" && wordStart) break;
    if (character === "<") {
      const parsed = heredocMarkerAt(line, index);
      if (parsed === undefined) {
        if (line[index + 1] === "<" && line[index + 2] !== "<" && line[index - 1] !== "<") unsupported = true;
      } else {
        markers.push(parsed.marker);
        index = parsed.end - 1;
        wordStart = false;
        continue;
      }
    }
    wordStart = WORD_BREAK.test(character);
  }
  return { markers, unsupported };
}

/** Reads heredoc markers on one line, ignoring markers inside quoted strings and comments. */
export function heredocMarkers(line: string): HeredocMarker[] {
  return scanHeredoc(line).markers;
}

/**
 * True when the text contains a here-document operator outside quotes.
 * Heredoc bodies are data, so callers that already located a body scan only
 * the command line.
 */
export function hasHeredoc(text: string): boolean {
  let quote: "'" | '"' | undefined;
  for (let index = 0; index < text.length; index++) {
    const character = text[index];
    if (quote === "'") { if (character === "'") quote = undefined; continue; }
    if (quote === '"') {
      if (character === "\\") { index++; continue; }
      if (character === '"') quote = undefined;
      continue;
    }
    if (character === "'" || character === '"') { quote = character; continue; }
    if (character === "\\") { index++; continue; }
    if (character === "<" && text[index + 1] === "<" && text[index + 2] !== "<" &&
        text[index - 1] !== "<") return true;
  }
  return false;
}

/**
 * The raw command line that starts at `start`, and the offset of the newline
 * that ends it. Quoted newlines and `\`-newlines stay inside the line; a
 * comment's newline ends it.
 */
function commandLineAt(command: string, start: number): { line: string; end: number } {
  let quote: "'" | '"' | "$'" | undefined;
  let wordStart = true;
  for (let index = start; index < command.length; index++) {
    const character = command[index];
    if (quote === "'") { if (character === "'") quote = undefined; continue; }
    if (quote === "$'") {
      if (character === "\\") index++;
      else if (character === "'") quote = undefined;
      continue;
    }
    if (quote === '"') {
      if (character === "\\") index++;
      else if (character === '"') quote = undefined;
      continue;
    }
    if (character === "\\") { index++; continue; }
    if (character === "'" || character === '"') { quote = character; wordStart = false; continue; }
    if (character === "$" && command[index + 1] === "'") { quote = "$'"; index++; wordStart = false; continue; }
    if (character === "#" && wordStart) {
      const end = command.indexOf("\n", index);
      return { line: command.slice(start, end === -1 ? command.length : end),
        end: end === -1 ? command.length : end };
    }
    if (character === "\n") return { line: command.slice(start, index), end: index };
    wordStart = WORD_BREAK.test(character);
  }
  return { line: command.slice(start), end: command.length };
}

export interface RawHeredocScript {
  /**
   * Raw logical command lines that are certainly script, through the first header
   * whose boundary cannot be read. Here-document bodies are omitted.
   */
  lines: string[];
  /** True when a raw header's marker or delimiter cannot be placed exactly. */
  ambiguous: boolean;
}

/**
 * Projects the raw source onto its command lines up to the first here-document
 * header this reader cannot decode, skipping the bodies of headers it can.
 *
 * Every header is validated here, not only the first line: a continuation in a
 * later header (`cat <<'A'`+newline+`a`+newline+`A`+newline+`cat <<\`+newline+
 * `'EOF'`) is invisible to a first-line check, and normalization would then join
 * the marker and treat a following `\`-newline body line as script, hiding a
 * command Bash runs. Bodies are copied with the same raw comparison as
 * `logicalLines`, so data is never returned as a script line; an unquoted body
 * whose continuation can move its own terminator stops the scan because the
 * existing projection already asks for it.
 *
 * A `\`-newline in the header, an undecodable marker, or a marker that only
 * appears after normalization ends the certain prefix: the header line itself
 * still runs, but nothing after it can be trusted.
 */
export function rawHeredocScript(command: string): RawHeredocScript {
  const lines: string[] = [];
  let start = 0;
  while (start < command.length) {
    const { line, end } = commandLineAt(command, start);
    lines.push(line);
    const scan = scanHeredoc(line);
    const rawMarker = hasHeredoc(line);
    const normalizedMarker = hasHeredoc(normalizeContinuations(line));
    if (rawMarker || normalizedMarker) {
      if (line.includes("\\\n") || scan.unsupported) return { lines, ambiguous: true };
      // A `<<` the reader cannot place without a continuation is just as unknown.
      if (!scan.markers.length) return { lines, ambiguous: true };
      const bodies = heredocBodies(command, end + 1, scan.markers);
      if (bodies.unstable) return { lines, ambiguous: false };
      start = bodies.end;
      continue;
    }
    start = end + 1;
  }
  return { lines, ambiguous: false };
}

/** The copied bodies and the offset where the command script resumes. */
interface HeredocCopy {
  text: string;
  end: number;
  /**
   * True when an unquoted body line ends with a backslash. A shell removes that
   * `\`-newline before matching the terminator, so the body can run past the line
   * the raw text compares and the terminator may match somewhere else entirely —
   * including on a line the collector treats as script.
   */
  unstable: boolean;
}

/**
 * Copies here-document bodies verbatim, returning the copied text and the
 * offset where the command script resumes.
 */
function heredocBodies(command: string, start: number, markers: readonly HeredocMarker[]): HeredocCopy {
  let index = start;
  let text = "";
  let unstable = false;
  for (const marker of markers) {
    let closed = false;
    while (index < command.length) {
      const newline = command.indexOf("\n", index);
      const stop = newline === -1 ? command.length : newline + 1;
      const line = command.slice(index, newline === -1 ? command.length : newline);
      text += command.slice(index, stop);
      index = stop;
      if ((marker.stripTabs ? line.replace(/^\t+/, "") : line) === marker.delimiter) { closed = true; break; }
      // A quoted body keeps its backslashes, so only an unquoted one can move.
      if (!marker.quoted && line.endsWith("\\")) unstable = true;
    }
    if (!closed) break;
  }
  return { text, end: index, unstable };
}

/**
 * Removes `\`-newline continuations so the command is validated and parsed as
 * the shell would run it.
 *
 * A shell deletes a backslash-newline pair while reading a command line, so
 * `sudo echo first \`+newline+`second` is one `sudo` invocation, and a continued
 * flag such as `rm -r`+newline+`f` is the dangerous `-rf`. Removing the pair
 * before quote validation and before the source scans keeps every later check
 * on the same text the shell sees.
 *
 * Continuations are kept wherever the shell keeps them:
 * - single quotes and `$'...'` hold the backslash and the newline as data,
 * - an escaped backslash (`\\`+newline) leaves a real newline that ends the line,
 * - a comment ends at its newline, so a trailing backslash does not continue it,
 * - here-document bodies are data and are copied unchanged.
 */
export function normalizeContinuations(command: string): string {
  if (!command.includes("\n")) return command;
  let result = "";
  let index = 0;
  let wordStart = true;
  let pending: HeredocMarker[] = [];
  while (index < command.length) {
    const character = command[index];
    if (character === "\\") {
      const next = command[index + 1];
      if (next === "\n") { index += 2; continue; }
      if (next === undefined) { result += character; break; }
      result += character + next;
      wordStart = false;
      index += 2;
      continue;
    }
    if (character === "'") {
      const end = command.indexOf("'", index + 1);
      const stop = end === -1 ? command.length : end + 1;
      result += command.slice(index, stop);
      wordStart = false;
      index = stop;
      continue;
    }
    if (character === "$" && command[index + 1] === "'") {
      let cursor = index + 2;
      while (cursor < command.length && command[cursor] !== "'") cursor += command[cursor] === "\\" ? 2 : 1;
      const stop = Math.min(cursor + 1, command.length);
      result += command.slice(index, stop);
      wordStart = false;
      index = stop;
      continue;
    }
    if (character === '"') {
      let cursor = index + 1;
      let quoted = "\"";
      while (cursor < command.length) {
        const inner = command[cursor];
        if (inner === "\\") {
          const next = command[cursor + 1];
          if (next === "\n") { cursor += 2; continue; }
          quoted += next === undefined ? inner : inner + next;
          cursor += next === undefined ? 1 : 2;
          continue;
        }
        quoted += inner;
        cursor++;
        if (inner === '"') break;
      }
      result += quoted;
      wordStart = false;
      index = cursor;
      continue;
    }
    if (character === "#" && wordStart) {
      const end = command.indexOf("\n", index);
      const stop = end === -1 ? command.length : end;
      result += command.slice(index, stop);
      index = stop;
      continue;
    }
    if (character === "<") {
      const parsed = heredocMarkerAt(command, index);
      if (parsed !== undefined) {
        result += command.slice(index, parsed.end);
        pending.push(parsed.marker);
        wordStart = false;
        index = parsed.end;
        continue;
      }
    }
    if (character === "\n") {
      result += character;
      index++;
      wordStart = true;
      if (pending.length) {
        const bodies = heredocBodies(command, index, pending);
        result += bodies.text;
        index = bodies.end;
        pending = [];
      }
      continue;
    }
    result += character;
    wordStart = WORD_BREAK.test(character);
    index++;
  }
  return result;
}

export interface LogicalScript {
  /** One entry per logical command line, in source order; heredoc bodies are omitted. */
  lines: string[];
  /**
   * How many leading entries in `lines` are certainly script. A here-document
   * header this scanner cannot decode, or an unquoted body whose continuation can
   * move its own terminator, ends that prefix: the header line itself still runs,
   * but later entries may be body data.
   */
  certain: number;
}

/**
 * Splits a script into the logical command lines a shell would run.
 *
 * The scan is quote-aware: a newline inside `'...'`, `"..."`, or `$'...'` is part
 * of the word being built, so `sudo echo 'first`+newline+`second'` stays one
 * invocation and a blocked command is visible as a whole instead of becoming two
 * harmless-looking fragments. A `\`-newline keeps an escaped character attached
 * to its word (callers normalize continuations first, so only the escaped form
 * remains here), and a comment ends its own physical line without hiding the next.
 *
 * Here-document bodies are data, not commands: they are skipped, so the `sudo` in
 * `cat <<'EOF'`+newline+`sudo id`+newline+`EOF` is plain text, while a command
 * after the terminator is still analyzed. `certain` reports the prefix of lines
 * whose script/data split is known; callers must not auto-approve past it.
 */
export function logicalLines(command: string): LogicalScript {
  const lines: string[] = [];
  let certain: number | undefined;
  let start = 0;
  let wordStart = true;
  let quote: "'" | '"' | "$'" | undefined;
  let pending: HeredocMarker[] = [];
  /** Records that everything from the line at `line` onwards may be data. */
  const markUncertain = (line: number) => {
    if (certain === undefined) certain = line + 1;
  };
  /** Ends the current line at `end` and jumps past the bodies of its markers. */
  const endLine = (end: number) => {
    lines.push(command.slice(start, end));
    start = end + 1;
    if (!pending.length) return;
    const bodies = heredocBodies(command, start, pending);
    if (bodies.unstable) markUncertain(lines.length - 1);
    start = bodies.end;
    pending = [];
  };
  for (let index = 0; index < command.length; index++) {
    const character = command[index];
    if (quote === "'") {
      if (character === "'") quote = undefined;
      continue;
    }
    if (quote === "$'") {
      if (character === "\\") index++;
      else if (character === "'") quote = undefined;
      continue;
    }
    if (quote === '"') {
      if (character === "\\") index++;
      else if (character === '"') quote = undefined;
      continue;
    }
    if (character === "\\") {
      if (index + 1 < command.length) {
        if (command[++index] !== "\n") wordStart = false;
      } else wordStart = false;
      continue;
    }
    if (character === "'" || character === '"' || (character === "$" && command[index + 1] === "'")) {
      wordStart = false;
      if (character === "'" || character === '"') quote = character;
      else { quote = "$'"; index++; }
      continue;
    }
    if (character === "#" && wordStart) {
      // A comment runs to the end of the physical line; quotes inside it are text.
      const end = command.indexOf("\n", index);
      if (end === -1) break;
      endLine(end);
      index = start - 1;
      wordStart = true;
      continue;
    }
    if (character === "<") {
      const parsed = heredocMarkerAt(command, index);
      if (parsed !== undefined) {
        pending.push(parsed.marker);
        wordStart = false;
        index = parsed.end - 1;
        continue;
      }
      if (command[index + 1] === "<" && command[index + 2] !== "<" && command[index - 1] !== "<")
        markUncertain(lines.length);
    }
    if (character === "\n") {
      endLine(index);
      // Resume after the bodies, if this line opened any.
      index = start - 1;
      wordStart = true;
      continue;
    }
    wordStart = WORD_BREAK.test(character);
  }
  lines.push(command.slice(start));
  return { lines, certain: certain ?? lines.length };
}

/**
 * Parses the command a shell would run: continuations are removed, descriptor
 * prefixes and midword comment markers are stripped, and the remainder is handed
 * to `shell-quote`. Nested scripts (`sh -c`, `eval`) reach this same parser, so
 * they get the same normalization as a top-level command line.
 *
 * Text with whitespace a shell does not treat as a separator is refused instead
 * of parsed: `shell-quote` splits on JS `\s`, which would move word and heredoc
 * boundaries. Callers treat the throw as unparseable and ask.
 */
export function parseShell(command: string): ParseEntry[] {
  if (hasNonShellWhitespace(command)) throw new Error("shell whitespace is not supported");
  return parse(escapeLiteralHashes(stripDescriptorPrefixes(normalizeContinuations(command))));
}

/**
 * True when a descriptor close (`>&-` or `<&-`) is immediately followed by more
 * word characters.
 *
 * Bash reads `2>&-sudo id` as closing file descriptor 2 and then running
 * `sudo id`, while shell-quote and other shells read `-sudo` as the redirection
 * word and drop the command. The two readings disagree about which command
 * runs, so ambiguous invocations must not be approved automatically.
 */
export function hasAmbiguousDescriptorClose(command: string): boolean {
  const delimiter = /[ \t\n;|&()<>]/;
  let boundary = true;
  let index = 0;
  while (index < command.length) {
    const character = command[index];
    if (character === "\\") { index += 2; boundary = false; continue; }
    if (character === "'") {
      const end = command.indexOf("'", index + 1);
      index = end === -1 ? command.length : end + 1;
      boundary = false;
      continue;
    }
    if (character === "$" && command[index + 1] === "'") {
      let cursor = index + 2;
      while (cursor < command.length && command[cursor] !== "'") cursor += command[cursor] === "\\" ? 2 : 1;
      index = Math.min(cursor + 1, command.length);
      boundary = false;
      continue;
    }
    if (character === '"') {
      let cursor = index + 1;
      while (cursor < command.length && command[cursor] !== '"') cursor += command[cursor] === "\\" ? 2 : 1;
      index = Math.min(cursor + 1, command.length);
      boundary = false;
      continue;
    }
    if (boundary && character === "#") {
      const end = command.indexOf("\n", index);
      index = end === -1 ? command.length : end;
      continue;
    }
    if ((character === ">" || character === "<") && command[index + 1] === "&" && command[index + 2] === "-") {
      const next = command[index + 3];
      if (next !== undefined && !delimiter.test(next)) return true;
    }
    boundary = delimiter.test(character);
    index++;
  }
  return false;
}

/** Splits a script into simple commands, dropping redirection targets. */
function invocations(command: string): string[][] {
  let tokens;
  try { tokens = parseShell(command); } catch { return []; }
  const result: string[][] = [];
  let words: string[] = [];
  let skipNext = false;
  for (const token of tokens) {
    if (typeof token === "string") {
      if (!skipNext) words.push(token);
      skipNext = false;
      continue;
    }
    if ("comment" in token) continue;
    if ("op" in token) {
      if (token.op === "glob") {
        if (!skipNext) words.push(token.pattern);
        skipNext = false;
        continue;
      }
      if (CONTROL_OPERATORS.has(token.op)) {
        if (words.length) result.push(words);
        words = [];
        skipNext = false;
        continue;
      }
      // A redirection does not end a simple command; only its target is dropped.
      // Descriptor prefixes were already removed from the source before parsing.
      if (REDIRECT_OPERATORS.has(token.op)) skipNext = true;
    }
  }
  if (words.length) result.push(words);
  return result;
}

/** Offset of the first `$'`, `$"`, or `$[` in the normalized text. */
function undecodedSyntaxIndex(text: string): number | undefined {
  let earliest: number | undefined;
  for (const opener of ["$'", '$"', "$["]) {
    const index = text.indexOf(opener);
    if (index !== -1 && (earliest === undefined || index < earliest)) earliest = index;
  }
  return earliest;
}

/**
 * Code whose contents this prefix parse does not project. A line containing one of
 * these forms is skipped rather than guessed at, because the words inside it are
 * commands or data that this scan cannot place.
 */
const NESTED_DYNAMIC_SYNTAX = /\$\(|`|[<>]\(/;

/**
 * Deny reason visible in the clean prefix before the first syntax this policy
 * refuses to decode, or undefined when that prefix has no mandatory deny.
 *
 * The marker and everything after it are never parsed: an undecoded quote can
 * move word and line boundaries, and normalization may have assembled it from a
 * `\`-newline. The prefix is projected with the shared `logicalLines` scan, so
 * heredoc bodies stay data. A line whose quotes are not balanced at the cut, or
 * that still contains nested dynamic syntax, is skipped instead of guessed at.
 * Callers use this before falling back to ask.
 */
export function denyCleanPrefix(normalized: string, depth = 0): string | undefined {
  const cut = undecodedSyntaxIndex(normalized);
  if (cut === undefined) return undefined;
  const { lines, certain } = logicalLines(normalized.slice(0, cut));
  for (const line of lines.slice(0, certain)) {
    if (NESTED_DYNAMIC_SYNTAX.test(line) || !BALANCED_QUOTES.test(line)) continue;
    for (const words of invocations(line)) {
      const reason = denyInvocation(words, depth);
      if (reason !== undefined) return reason;
    }
  }
  return undefined;
}

/**
 * Deny reason for a nested script (`sh -c`, `eval`), or undefined when nothing in
 * it is a dangerous operation.
 *
 * The script is projected onto the commands a shell would actually run, using the
 * same quote-aware `logicalLines` split as a top-level script: newlines separate
 * commands only outside quotes, so `sh -c 'pwd`+newline+`sudo id'` still shows the
 * mandatory deny, while `sh -c 'echo "first`+newline+`second"'` stays one word.
 * Here-document bodies are data and are never scanned as commands.
 *
 * When the split between script and data is unknown — an undecodable header, a
 * continuation in a raw header, or an unquoted body that can move its own
 * terminator — only the raw command lines that are certainly script are checked.
 * The header line always runs: `cat <<\EOF; sudo id` still runs `sudo id`, and a
 * marker's delimiter is only a redirection target. Every header is validated, not
 * just the first, because a later continued header has the same boundary problem.
 * Guessing past an undecodable header could deny quoted here-document data, so it
 * is left to manual approval.
 */
function denyScript(command: string, depth: number): string | undefined {
  if (FORK_BOMB.test(command)) return DANGEROUS;
  const normalized = normalizeContinuations(command);
  const raw = rawHeredocScript(command);
  if (raw.ambiguous) {
    for (const line of raw.lines) {
      // A line whose own normalization assembles unsupported quoting cannot be
      // parsed safely; its deny is left to the caller's manual approval.
      if (hasAssembledUndecodedSyntax(line)) continue;
      for (const words of invocations(line)) {
        const reason = denyInvocation(words, depth);
        if (reason !== undefined) return reason;
      }
    }
    return undefined;
  }
  // Normalization can assemble quoting this reader does not decode. The inner
  // shell could then run a command the projection does not place, so the rest of
  // the projection stands down; a deny already visible in the clean prefix still
  // keeps its precedence, and the caller asks when there is none.
  if (!hasUndecodedSyntax(command) && hasUndecodedSyntax(normalized))
    return denyCleanPrefix(normalized, depth);
  const { lines, certain } = logicalLines(normalized);
  for (const line of lines.slice(0, certain)) {
    for (const words of invocations(line)) {
      const reason = denyInvocation(words, depth);
      if (reason !== undefined) return reason;
    }
  }
  return undefined;
}

/**
 * Deny reason for one parsed simple command, or undefined when it is not a
 * dangerous operation. Nested shell scripts are checked recursively.
 */
export function denyInvocation(words: readonly string[], depth = 0): string | undefined {
  if (depth > MAX_NESTING) return undefined;
  const executable = resolveExecutable(words);
  if (executable === undefined) return undefined;
  const args = words.slice(executable.index + 1);
  if (executable.name === "sshpass" || executable.name === "printenv" ||
      (executable.name === "env" && args.length === 0)) return DANGEROUS;
  if (["terraform", "tofu", "pulumi"].includes(executable.name) && args.includes("destroy")) return DANGEROUS;
  if (executable.name === "printf") {
    // `printf -vPATH x` sets a variable exactly like `printf -v PATH x`; `--` ends
    // option parsing, so `printf -- -v` prints the literal text.
    const flag = args[0] ?? "";
    const variable = flag === "-v" ? args[1] : flag.startsWith("-v") && flag.length > 2 ? flag.slice(2) : undefined;
    if (variable !== undefined && /^(?:PATH|CDPATH|ENV|BASH_ENV|SHELLOPTS|LD_.*|DYLD_.*)$/.test(variable)) return DANGEROUS;
  }
  if (executable.name === "jq" && args.some((arg) => /(?:^|[^a-zA-Z_])(?:env|\$ENV)(?:$|[^a-zA-Z_])/.test(arg))) return DANGEROUS;
  if (executable.name === "gh" && ((args[0] === "auth" && args[1] === "token") ||
      (args[0] === "api" && args.some((arg) => /^(?:-[fF]|--(?:raw-)?field(?:=|$)|--input(?:=|$))/.test(arg))))) return DANGEROUS;
  if (["npm", "pnpm", "yarn", "bun", "node"].includes(executable.name) &&
      args.some((arg) => /^(?:--(?:preload|require|import)(?:=|$)|-r)/.test(arg))) return DANGEROUS;
  if (executable.name.startsWith("mkfs")) return DANGEROUS;
  if (DENY_EXECUTABLES.has(executable.name)) return DANGEROUS;
  if (executable.name === "chmod" && isWorldWritableMode(chmodMode(args) ?? "")) return DANGEROUS;
  if (executable.name === "rm" && isRecursiveRootRemoval(args)) return DANGEROUS;
  if (executable.name === "dd" && args.some((arg) => /^of=\/(?:dev|sd|nvme|hd)/.test(arg))) return DANGEROUS;
  if (SHELLS.has(executable.name) || executable.name === "eval") {
    const script = scriptArgument(executable.name, args);
    if (script !== undefined) return denyScript(script, depth + 1);
  }
  return undefined;
}

const UNIQ_FLAGS = new Set(["c", "d", "D", "i", "u"]);
const UNIQ_VALUE_FLAGS = new Set(["f", "s", "w"]);
const UNIQ_LONG_FLAGS = new Set(["--count", "--repeated", "--ignore-case", "--unique", "--zero-terminated",
  "--help", "--version"]);
const UNIQ_LONG_OPTIONAL_FLAGS = new Set(["--all-repeated", "--group"]);
const UNIQ_LONG_VALUE_FLAGS = new Set(["--skip-fields", "--skip-chars", "--check-chars"]);

/**
 * `uniq INPUT OUTPUT` writes OUTPUT. macOS stops option parsing at the first
 * operand, so `uniq in.txt -out.txt` writes a file named `-out.txt`; every
 * argument after an operand is therefore counted as an operand. Unknown leading
 * flags fail closed, while known flags keep `uniq -f 2 file` read-only.
 *
 * An unquoted expansion can turn one operand into several (`uniq *.txt` becomes
 * `uniq a.txt b.txt` and overwrites the last match), which
 * `isReadOnlyInvocation` already refuses before any policy runs.
 */
function isReadOnlyUniq(args: readonly string[]): boolean {
  let operands = 0;
  let endOfOptions = false;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (endOfOptions || operands > 0) { operands++; continue; }
    if (arg === "--") { endOfOptions = true; continue; }
    if (arg === "-") { operands++; continue; }
    if (arg.startsWith("--") && arg.length > 2) {
      const name = arg.split("=", 1)[0];
      const attached = arg.length > name.length;
      if (UNIQ_LONG_VALUE_FLAGS.has(name)) {
        if (!attached) index++;
        continue;
      }
      if (UNIQ_LONG_OPTIONAL_FLAGS.has(name) || (UNIQ_LONG_FLAGS.has(name) && !attached)) continue;
      operands++;
      continue;
    }
    if (arg.startsWith("-")) {
      const letters = arg.slice(1);
      let known = true;
      for (let position = 0; position < letters.length; position++) {
        if (UNIQ_VALUE_FLAGS.has(letters[position])) {
          if (position === letters.length - 1) index++;
          break;
        }
        if (!UNIQ_FLAGS.has(letters[position])) { known = false; break; }
      }
      if (!known) operands++;
      continue;
    }
    operands++;
  }
  return operands <= 1;
}

const DATE_FLAGS = new Set(["u", "R", "j"]);
const DATE_VALUE_FLAGS = new Set(["d", "r", "f"]);
const DATE_LONG_FLAGS = new Set(["--utc", "--universal", "--rfc-email", "--rfc-2822", "--iso-8601",
  "--debug", "--help", "--version"]);
const DATE_LONG_VALUE_FLAGS = new Set(["--date", "--reference", "--file", "--rfc-3339"]);

/**
 * `date` is read-only only when every argument is a known read-only option or a
 * `+FORMAT` operand. A positional operand sets the system clock
 * (`date 010100002030`), so it requires review.
 */
function isReadOnlyDate(args: readonly string[]): boolean {
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg.startsWith("+")) continue;
    if (arg === "--") return args.slice(index + 1).every((operand) => operand.startsWith("+"));
    if (arg.startsWith("--") && arg.length > 2) {
      const name = arg.split("=", 1)[0];
      const attached = arg.length > name.length;
      // `--file DATEFILE` reads dates from a file, which may be project data.
      if (name === "--file" || resolveLongOption(name) === "--file") return false;
      if (DATE_LONG_VALUE_FLAGS.has(name)) {
        if (!attached) index++;
        continue;
      }
      if (DATE_LONG_FLAGS.has(name)) continue;
      return false;
    }
    if (!arg.startsWith("-") || arg === "-") return false;
    for (let position = 1; position < arg.length; position++) {
      const letter = arg[position];
      if (letter === "I") break;
      // `-f FILE` / `-fFILE` also reads a date file.
      if (letter === "f") return false;
      // `-rFILE` hides the reference file from the word scan; only the separate
      // `-r FILE` form stays available to the path check.
      if (letter === "r") {
        if (position !== arg.length - 1) return false;
        index++;
        break;
      }
      if (DATE_VALUE_FLAGS.has(letter)) {
        if (position === arg.length - 1) index++;
        break;
      }
      if (!DATE_FLAGS.has(letter)) return false;
    }
  }
  return true;
}

/**
 * `jq -f`/`--from-file` runs a filter file and `--run-tests` runs a test file;
 * either can read the environment or any file it names, so all their spellings
 * (including attached `-fscript` and `--from-file=script`) need review.
 */
function isReadOnlyJq(args: readonly string[]): boolean {
  for (const arg of args) {
    if (arg === "--") break;
    if (arg.startsWith("--")) {
      const separator = arg.indexOf("=");
      const option = separator === -1 ? arg : arg.slice(0, separator);
      if (option === "--run-tests" || resolveLongOption(option) === "--from-file") return false;
      continue;
    }
    if (shortOption(arg, JQ_SHORT_VALUES)?.letter === "f") return false;
  }
  return true;
}

/**
 * `grep -r`/`-R` and `-d recurse` follow directories instead of reading only
 * the named operands, so they can dump protected or external trees. `-R` also
 * follows symlinks. A named protected path still denies before this policy.
 */
function isReadOnlyGrep(args: readonly string[]): boolean {
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (/[rR]/.test(shortFlags(arg, GREP_SHORT_VALUES))) return false;
    const parsed = shortOption(arg, GREP_SHORT_VALUES);
    if (parsed?.letter === "d" && (parsed.attached ?? args[index + 1]) === "recurse") return false;
    if (!arg.startsWith("--") || arg.length <= 2) continue;
    const separator = arg.indexOf("=");
    const option = separator === -1 ? arg : arg.slice(0, separator);
    if ("--recursive".startsWith(option) || "--dereference-recursive".startsWith(option)) return false;
    if ("--directories".startsWith(option) &&
        (separator === -1 ? args[index + 1] : arg.slice(separator + 1)) === "recurse") return false;
  }
  return true;
}

/**
 * `rg --hidden`, `-u`/`--no-ignore` and `-L`/`--follow` reach files the default
 * ignore rules and the named operands exclude (hidden config, ignored trees,
 * symlink targets), so those searches need review rather than a low score.
 */
function isReadOnlyRg(args: readonly string[]): boolean {
  if (hasLongOption(args, ["--pre", "--pre-glob", "--hostname-bin", "--search-zip", "--hidden",
    "--follow", "--unrestricted", "--no-ignore", "--no-ignore-vcs", "--no-ignore-parent",
    "--no-ignore-global", "--no-ignore-dot", "--no-ignore-files", "--no-ignore-exclude"])) return false;
  return !args.some((arg) => /[uLz]/.test(shortFlags(arg, RG_SHORT_VALUES)));
}

/**
 * `diff -N`/`--new-file` treats absent files as empty and `-r` walks whole
 * trees, so a directory comparison can dump protected or external files. A
 * named protected path still denies before this policy.
 */
function isReadOnlyDiff(args: readonly string[]): boolean {
  if (hasLongOption(args, ["--new-file", "--unidirectional-new-file", "--recursive"])) return false;
  return !args.some((arg) => /[rN]/.test(shortFlags(arg, PLAIN_SHORT_VALUES.diff ?? {})));
}

const POLICIES: Record<string, (args: readonly string[]) => boolean> = {
  rg: isReadOnlyRg,
  // `grep -r`/`-R`/`-d recurse` walks whole trees, including protected and
  // external directories: the search is no longer a bounded read.
  grep: isReadOnlyGrep,
  // `diff -N`/`--new-file` and `-r` dump whole trees, including files that do
  // not exist on the other side.
  diff: isReadOnlyDiff,
  sort: (args) => !hasLongOption(args, ["--output", "--compress-program", "--temporary-directory",
    "--files0-from"]) && !hasShortOption(args, "oT"),
  // `wc --files0-from FILE` reads a file of paths.
  wc: (args) => !hasLongOption(args, ["--files0-from"]),
  tree: (args) => !hasLongOption(args, ["--output", "--fromfile", "--fromtabfile", "--gitfile"]) &&
    !hasShortOption(args, "o"),
  // `file -f/--files-from FILE` reads a list of files; `-C` compiles magic.
  file: (args) => !hasLongOption(args, ["--compile", "--files-from"]) && !hasShortOption(args, "Cf"),
  // `--files0-from` and `--exclude-from` read a file of paths; `-X` is the
  // short form of `--exclude-from`.
  du: (args) => !hasLongOption(args, ["--files0-from", "--exclude-from"]) && !hasShortOption(args, "X"),
  // `cache --build` / `--clear` mutate the cache, and `--lessopen` runs the
  // configured pager preprocessor.
  bat: (args) => !hasLongOption(args, ["--pager", "--config-file", "--config-dir", "--generate-config-file",
    "--build", "--clear", "--lessopen"]),
  // `uniq INPUT OUTPUT` writes OUTPUT; only a single literal operand is read-only.
  uniq: isReadOnlyUniq,
  // A bare argument sets the host name; `--` ends options and `-` is an operand.
  hostname: (args) => {
    let endOfOptions = false;
    for (const arg of args) {
      if (endOfOptions) return false;
      if (arg === "--") { endOfOptions = true; continue; }
      if (arg === "-" || !arg.startsWith("-")) return false;
    }
    return !hasLongOption(args, ["--file", "--boot"]) && !hasShortOption(args, "Fb");
  },
  date: isReadOnlyDate,
  jq: isReadOnlyJq,
};

const READ_ONLY = new Set(["pwd", "whoami", "id", "groups", "ls", "cat", "head", "tail", "wc", "echo", "printf",
  "true", ":", "grep", "cut", "tr", "jq", "stat", "du", "df", "which", "type", "basename", "dirname", "realpath",
  "diff", "test", "sleep", "uname"]);

function isReadOnlyGit(args: readonly string[]): boolean {
  if (args.some((arg) =>
    /^(?:-c|--git-dir|--work-tree|--exec-path|--config-env)(?:=|$)/.test(arg) ||
    arg === "--ext-diff" || arg === "--exec" || arg.startsWith("--output"))) return false;
  const subcommand = args[0];
  if (subcommand === undefined) return false;
  if (["status", "diff", "log", "show", "rev-parse"].includes(subcommand)) return true;
  if (subcommand !== "branch") return false;
  if (args.length === 1) return true;
  return args.slice(1).every((arg) =>
    ["--show-current", "--list", "-a", "-r", "-v", "-vv", "--merged", "--no-merged", "--contains", "--points-at", "--format"]
      .some((safe) => arg === safe || arg.startsWith(`${safe}=`)));
}

function isReadOnlySed(args: readonly string[]): boolean {
  // One narrowly decoded print script, then literal filenames only. Attached
  // -e/-f forms are scripts too, not inert filenames.
  return args[0] === "-n" && args[1] !== undefined && /^\d+(?:,\d+)?p$/.test(args[1]) &&
    args.slice(2).every((arg) => !arg.startsWith("-"));
}

function isReadOnlyGh(args: readonly string[]): boolean {
  const [group, subcommand] = args;
  if (group === "label" && subcommand === "list") return true;
  if (group === "api") {
    return !args.some((arg) => arg === "-X" || arg === "--method" || arg.startsWith("-X") ||
      arg.startsWith("--method=") || ["-f", "--field", "-F", "--raw-field", "--input"].includes(arg));
  }
  return new Set(["pr view", "pr list", "pr diff", "pr checks", "issue view", "issue list", "run view",
    "run list", "repo view", "auth status", "status", "search"]).has(`${group} ${subcommand}`);
}

/**
 * True only when one parsed simple command is read-only. Callers pass an
 * already-split segment, so chaining, redirection and wrappers are handled
 * before this point.
 *
 * `globs` marks words that came from an unquoted expansion (`*`, `?`, `[ab]`,
 * `{a,b}`, `$name`), which Bash can turn into several arguments. A literal flag
 * policy cannot see what those arguments will be: `sort --out{put,put}=out file`
 * becomes two `--output=out` options and writes a file, and `uniq *.txt` can
 * become `uniq a.txt b.txt`. An invocation with an uncertain word is therefore
 * never read-only. Quoted expansions stay one literal word and are judged as
 * written, so `uniq '*.txt'` remains a single operand.
 */
export function isReadOnlyInvocation(words: readonly string[], globs: readonly boolean[] = []): boolean {
  if (globs.some(Boolean)) return false;
  // Path-qualified binaries may be repo-controlled lookalikes, not system tools.
  if ((words[0] ?? "").includes("/")) return false;
  const command = basename(words[0] ?? "");
  const args = words.slice(1);
  if (command === "printf") {
    // Any `-v` option assigns a shell variable, attached or separate. `--` ends
    // option parsing, so `printf -- -v` keeps `-v` as literal format text.
    for (const arg of args) {
      if (arg === "--") break;
      if (/^-v/.test(arg)) return false;
    }
  }
  // Own properties only: `./constructor` must not resolve to `Object`.
  if (Object.hasOwn(POLICIES, command)) return POLICIES[command](args);
  if (READ_ONLY.has(command)) return true;
  if (command === "git") return isReadOnlyGit(args);
  if (command === "find")
    return !args.some((arg) => /^--?(?:fprint|fprint0|fprintf|fls)$/.test(arg) || /^--?files0/.test(arg));
  if (command === "sed") return isReadOnlySed(args);
  if (command === "gh") return isReadOnlyGh(args);
  if (command === "docker") return args[0] === "logs";
  if (command === "bun")
    return args[0] === "test" || (args[0] === "run" && (args[1] === "lint" || args[1] === "typecheck"));
  return false;
}
