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
const FORK_BOMB = /^:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/;
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

/** True for a word a command may read as an option (`-x`, `--long`), but not a lone `-`. */
function isOptionWord(word: string): boolean {
  return word.startsWith("-") && word.length > 1;
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
      const consumed = wrapperLongOption(grammar, word);
      if (consumed === undefined) return undefined;
      index += consumed;
      continue;
    }
    if (isOptionWord(word)) {
      const consumed = wrapperShortOption(grammar, word);
      if (consumed === undefined) return undefined;
      index += consumed;
      continue;
    }
    return index;
  }
  return index;
}

/** Words a long wrapper option consumes, or undefined when its arity is unknown. */
function wrapperLongOption(grammar: WrapperGrammar, word: string): number | undefined {
  const separator = word.indexOf("=");
  const arity = longOptionArity(grammar, separator === -1 ? word : word.slice(0, separator));
  if (arity === undefined) return undefined;
  return arity === "value" && separator === -1 ? 2 : 1;
}

/** Words a short wrapper option bundle consumes, or undefined when its arity is unknown. */
function wrapperShortOption(grammar: WrapperGrammar, word: string): number | undefined {
  const letters = word.slice(1);
  if (grammar.numeric && /^\d+$/.test(letters)) return 1;
  for (let position = 0; position < letters.length; position++) {
    const arity = grammar.short[letters[position]];
    if (arity === undefined) return undefined;
    if (arity === "flag") continue;
    // Any remaining letters are the attached value (`-n5`).
    return position === letters.length - 1 ? 2 : 1;
  }
  return 1;
}

/** Skips leading `NAME=value` assignments. */
function skipAssignments(words: readonly string[], start: number): number {
  let index = start;
  while (index < words.length && ASSIGNMENT.test(words[index])) index++;
  return index;
}

/** Resolves leading assignments and wrapper options to the effective executable. */
export function resolveExecutable(words: readonly string[]): { name: string; index: number } | undefined {
  let index = skipAssignments(words, 0);
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
    index = skipAssignments(words, index);
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
const GIT_HANDLED = new Set(["add", "restore", "commit", "tag", "branch", "checkout", "switch", "push", "fetch"]);
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
  pathValueSources: { value: string; index: number }[];
}

interface RoleSets { paths: Set<number>; data: Set<number>; pathValues: string[]; pathValueSources: { value: string; index: number }[] }

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
    if (parsed.attached !== undefined) recordPathValue(roles, parsed.attached, base + index);
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
  const roles: RoleSets = { paths: new Set(), data: new Set(), pathValues: [], pathValueSources: [] };
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
function pathOptionRoles(args: readonly string[], base: number, roles: RoleSets): void {
  let endOfOptions = false;
  for (const [index, arg] of args.entries()) {
    if (endOfOptions) continue;
    if (arg === "--") { endOfOptions = true; continue; }
    const part = longOptionPart(arg);
    if (part === undefined || part.attached === undefined) continue;
    const resolved = resolveLongOption(part.option);
    if (resolved === undefined || LONG_OPTION_VALUES.get(resolved) !== "path") continue;
    recordPathValue(roles, part.attached, base + index);
  }
}

/** Marks an attached (`--file=X`) or separate (`--file X`) path option value. */
function takePathOption(attached: string | undefined, index: number, base: number,
  args: readonly string[], roles: RoleSets): number {
  if (attached !== undefined) {
    recordPathValue(roles, attached, base + index);
    return index;
  }
  if (index + 1 < args.length) roles.paths.add(base + ++index);
  return index;
}

/** The resolved name of a long option word, when it names one. */
function resolvedLongOption(part: { option: string } | undefined): string | undefined {
  return part === undefined ? undefined : resolveLongOption(part.option);
}

/** The value role of a resolved long option, when it is known. */
function longOptionRole(resolved: string | undefined): ValueRole | undefined {
  return resolved === undefined ? undefined : LONG_OPTION_VALUES.get(resolved);
}

/** Adds every non-option positional as a path (`cat`, `sort`, checksums, ...). */
function plainRoles(name: string, args: readonly string[], base: number, roles: RoleSets): void {
  const table = PLAIN_SHORT_VALUES[name] ?? {};
  let endOfOptions = false;
  for (let index = 0; index < args.length; index++) {
    const word = args[index];
    if (!endOfOptions && word === "--") { endOfOptions = true; continue; }
    if (!endOfOptions && isOptionWord(word)) {
      index = takePlainOption(word, table, index, base, args, roles);
      continue;
    }
    if (roles.data.has(base + index)) continue;
    roles.paths.add(base + index);
  }
}

/** Consumes one option word of a plain reader, returning the index it ended at. */
function takePlainOption(word: string, table: Record<string, ValueRole>, index: number,
  base: number, args: readonly string[], roles: RoleSets): number {
  if (word.startsWith("--")) return index;
  const parsed = shortOption(word, table);
  return parsed === undefined ? index : takeShortValue(parsed, index, base, args, roles);
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
    if (!endOfOptions && isOptionWord(word)) {
      const scan = grepOption(word, table, index, base, args, roles, seenPattern);
      index = scan.index;
      seenPattern = scan.seenPattern;
      continue;
    }
    if (roles.data.has(base + index)) continue;
    if (!seenPattern) { roles.data.add(base + index); seenPattern = true; continue; }
    roles.paths.add(base + index);
  }
}

/** The result of reading one `grep`/`rg` option word. */
interface GrepScan { index: number; seenPattern: boolean }

/** Reads one `grep`/`rg` option word, recording its pattern or file value. */
function grepOption(word: string, table: Record<string, ValueRole>, index: number, base: number,
  args: readonly string[], roles: RoleSets, seenPattern: boolean): GrepScan {
  if (word.startsWith("--")) return grepLongOption(word, index, base, args, roles, seenPattern);
  const parsed = shortOption(word, table);
  if (parsed === undefined) return { index, seenPattern };
  const next = takeShortValue(parsed, index, base, args, roles);
  return { index: next, seenPattern: seenPattern || parsed.letter === "e" || parsed.letter === "f" };
}

function grepLongOption(word: string, index: number, base: number, args: readonly string[],
  roles: RoleSets, seenPattern: boolean): GrepScan {
  const part = longOptionPart(word);
  const resolved = resolvedLongOption(part);
  if (resolved === "--regexp") return { index, seenPattern: true };
  // Any path-valued long option names a file: `--file` (pattern file),
  // `--exclude-from`/`--ignore-file` (files of patterns). Only `--file`
  // supplies the pattern; the others leave the next positional a pattern.
  if (longOptionRole(resolved) !== "path") return { index, seenPattern };
  const next = takePathOption(part?.attached, index, base, args, roles);
  return { index: next, seenPattern: seenPattern || resolved === "--file" };
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
    if (!endOfOptions && isOptionWord(word)) {
      const scan = sedOption(word, index, base, args, roles, scripted);
      index = scan.index;
      scripted = scan.scripted;
      continue;
    }
    if (roles.data.has(base + index)) continue;
    if (!scripted) { roles.data.add(base + index); scripted = true; continue; }
    roles.paths.add(base + index);
  }
}

/** The result of reading one `sed` option word. */
interface SedScan { index: number; scripted: boolean }

/** Reads one `sed` option word, recording its script or script file. */
function sedOption(word: string, index: number, base: number, args: readonly string[],
  roles: RoleSets, scripted: boolean): SedScan {
  if (word.startsWith("--")) return sedLongOption(word, index, base, args, roles, scripted);
  const parsed = shortOption(word, SED_SHORT_VALUES);
  if (parsed === undefined) return { index, scripted };
  const next = takeShortValue(parsed, index, base, args, roles);
  return { index: next, scripted: scripted || parsed.letter === "e" || parsed.letter === "f" };
}

function sedLongOption(word: string, index: number, base: number, args: readonly string[],
  roles: RoleSets, scripted: boolean): SedScan {
  const part = longOptionPart(word);
  const resolved = resolvedLongOption(part);
  if (resolved === "--expression") return { index, scripted: true };
  if (resolved !== "--file") return { index, scripted };
  return { index: takePathOption(part?.attached, index, base, args, roles), scripted: true };
}

/** `jq` options whose next two words are data (`--arg NAME VALUE`). */
const JQ_DATA_VALUE_OPTIONS = new Set(["--arg", "--argjson"]);
/** `jq` options that take a name (data) and then a file (path). */
const JQ_FILE_VALUE_OPTIONS = new Set(["--slurpfile", "--rawfile", "--argfile"]);

/** Filter state shared across `jq`'s arguments. */
interface JqScanState { filterSupplied: boolean; positionalData: boolean }

/**
 * `jq`: the first positional is the filter unless `-f`/`--from-file` supplies
 * one. All value-taking options are stated explicitly, so a bare `1` after a
 * flag (`-e`, `-r`, `--tab`) is the filter. `--arg`/`--argjson` take a name and
 * a value as data, `--slurpfile`/`--rawfile`/`--argfile` take a name (data) and
 * a file (path), and `--args`/`--jsonargs` make positionals string data.
 */
function jqRoles(args: readonly string[], base: number, roles: RoleSets): void {
  const state: JqScanState = { filterSupplied: false, positionalData: false };
  let endOfOptions = false;
  for (let index = 0; index < args.length; index++) {
    const word = args[index];
    if (!endOfOptions && word === "--") { endOfOptions = true; continue; }
    if (!endOfOptions && isOptionWord(word)) {
      index = jqOption(word, index, base, args, roles, state);
      continue;
    }
    if (roles.data.has(base + index)) continue;
    if (state.positionalData) { roles.data.add(base + index); continue; }
    if (!state.filterSupplied) { roles.data.add(base + index); state.filterSupplied = true; continue; }
    roles.paths.add(base + index);
  }
}

/** Reads one `jq` option word, returning the index it ended at. */
function jqOption(word: string, index: number, base: number, args: readonly string[],
  roles: RoleSets, state: JqScanState): number {
  if (word.startsWith("--")) return jqLongOption(word, index, base, args, roles, state);
  const parsed = shortOption(word, JQ_SHORT_VALUES);
  if (parsed === undefined) return index;
  const next = takeShortValue(parsed, index, base, args, roles);
  if (parsed.letter === "f") state.filterSupplied = true;
  return next;
}

function jqLongOption(word: string, index: number, base: number, args: readonly string[],
  roles: RoleSets, state: JqScanState): number {
  const part = longOptionPart(word);
  if (resolvedLongOption(part) === "--from-file") {
    state.filterSupplied = true;
    return takePathOption(part?.attached, index, base, args, roles);
  }
  return jqNamedOption(part?.option, part?.attached, index, base, args, roles, state);
}

function jqNamedOption(option: string | undefined, attached: string | undefined, index: number,
  base: number, args: readonly string[], roles: RoleSets, state: JqScanState): number {
  if (JQ_DATA_VALUE_OPTIONS.has(option ?? "")) return takeJqValues(args, index, base, roles, 2, "data");
  if (JQ_FILE_VALUE_OPTIONS.has(option ?? "")) {
    const next = takeJqValues(args, index, base, roles, 1, "data");
    return takeJqValues(args, next, base, roles, 1, "path");
  }
  if (option === "--args" || option === "--jsonargs") { state.positionalData = true; return index; }
  if (option === "--library-path") return takePathOption(attached, index, base, args, roles);
  if (option === "--indent") return takeJqValues(args, index, base, roles, 1, "data");
  return index;
}

/** Marks up to `count` following words as values of the given role. */
function takeJqValues(args: readonly string[], index: number, base: number, roles: RoleSets,
  count: number, role: ValueRole): number {
  let taken = 0;
  while (taken < count && index + 1 < args.length) {
    const next = base + ++index;
    (role === "data" ? roles.data : roles.paths).add(next);
    taken++;
  }
  return index;
}

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

/** Subcommands whose positionals are refs, messages or other data, never files. */
const GIT_REF_SUBCOMMANDS = new Set(["tag", "branch", "push", "fetch"]);

/** Which operands a git subcommand treats as refs/data rather than paths. */
interface GitRoleContext {
  long: Record<string, ValueRole>;
  short: Record<string, ValueRole>;
  refs: boolean;
  checkoutLike: boolean;
}

/** Loop state of the git operand scan. */
interface GitRoleState { index: number; endOfOptions: boolean }

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
  const context: GitRoleContext = {
    long: GIT_LONG_VALUES[subcommand] ?? {},
    short: GIT_SHORT_VALUES[subcommand] ?? {},
    refs: GIT_REF_SUBCOMMANDS.has(subcommand),
    checkoutLike: subcommand === "checkout" || subcommand === "switch",
  };
  const state: GitRoleState = { index: 0, endOfOptions: false };
  while (state.index < rest.length) {
    const word = rest[state.index];
    if (consumeGitOption(state, word, base + 1, rest, roles, context)) continue;
    const position = base + 1 + state.index;
    if (!roles.data.has(position)) markGitPosition(state, position, roles, context);
    state.index++;
  }
}

/** Consumes a `--` terminator or one git option word; false for an operand. */
function consumeGitOption(state: GitRoleState, word: string, base: number, rest: readonly string[],
  roles: RoleSets, context: GitRoleContext): boolean {
  if (!state.endOfOptions && word === "--") { state.endOfOptions = true; state.index++; return true; }
  if (!state.endOfOptions && word.startsWith("--") && word.length > 2) {
    state.index = gitLongRole(word, state.index, base, rest, roles, context.long) + 1;
    return true;
  }
  if (!state.endOfOptions && isOptionWord(word)) {
    const parsed = shortOption(word, context.short);
    const end = parsed === undefined ? state.index : takeShortValue(parsed, state.index, base, rest, roles);
    state.index = end + 1;
    return true;
  }
  return false;
}

/** Records a git option's attached or separate value; returns its last word index. */
function gitLongRole(word: string, index: number, base: number, rest: readonly string[],
  roles: RoleSets, long: Record<string, ValueRole>): number {
  const part = longOptionPart(word);
  const role = part === undefined ? undefined : long[part.option];
  if (part === undefined || role === undefined) return index;
  if (part.attached !== undefined) {
    if (role === "path") recordPathValue(roles, part.attached, base + index);
    else roles.data.add(base + index);
    return index;
  }
  if (index + 1 < rest.length) {
    (role === "data" ? roles.data : roles.paths).add(base + index + 1);
    return index + 1;
  }
  return index;
}

/** Marks a positional operand as ref/data, or as a path, per the subcommand. */
function markGitPosition(state: GitRoleState, position: number, roles: RoleSets, context: GitRoleContext): void {
  // `checkout`/`switch` treat positionals before `--` as refs and after it as
  // paths; `commit` positionals are always paths.
  if (context.refs || (context.checkoutLike && !state.endOfOptions)) roles.data.add(position);
  else roles.paths.add(position);
}

/** The path and data roles of one simple command's argv. */
export function operandRoles(words: readonly string[]): OperandRoles {
  const executable = resolveExecutable(words);
  if (executable === undefined) return { paths: [], data: [], pathValues: [], pathValueSources: [] };
  const args = words.slice(executable.index + 1);
  const roles = dataOptionRoles(args, executable.index + 1);
  if (hasFileGrammar(executable.name)) pathOptionRoles(args, executable.index + 1, roles);
  const name = executable.name;
  if (PATTERN_FIRST_COMMANDS.has(name)) grepRoles(name, args, executable.index + 1, roles);
  else if (name === "sed") sedRoles(args, executable.index + 1, roles);
  else if (name === "jq") jqRoles(args, executable.index + 1, roles);
  else if (name === "git") gitRoles(args, executable.index + 1, roles);
  else if (name === "find") findRoles(args, executable.index + 1, roles);
  else if (PATH_OPERAND_COMMANDS.has(name) || CHECKSUM_COMMAND.test(name))
    plainRoles(name, args, executable.index + 1, roles);
  extraFileRoles(name, args, executable.index + 1, roles);
  const ascending = (left: number, right: number) => left - right;
  return {
    paths: [...roles.paths].sort(ascending),
    data: [...roles.data].sort(ascending),
    pathValues: [...new Set(roles.pathValues)],
    pathValueSources: roles.pathValueSources,
  };
}

function hasFileGrammar(name: string): boolean {
  return PATH_OPERAND_COMMANDS.has(name) || PATTERN_FIRST_COMMANDS.has(name) ||
    CHECKSUM_COMMAND.test(name) || ["git", "jq", "sed", "find"].includes(name);
}

function extraFileRoles(name: string, args: readonly string[], base: number, roles: RoleSets): void {
  if (["curl", "wget"].includes(name)) {
    args.forEach((arg, index) => { if (/^file:/i.test(arg)) roles.paths.add(base + index); });
  }
  if (name === "git" && ["show", "diff"].includes(args[0])) {
    gitRevisionFiles(args, base, roles);
  }
  if (name === "gh" && args[0] === "api") ghApiFileRoles(args.slice(1), base + 1, roles);
  if (name === "date") dateFileRoles(args, base, roles);
}

function dateFileRoles(args: readonly string[], base: number, roles: RoleSets): void {
  for (let index = 0; index < args.length; index++) {
    const parsed = shortOption(args[index], { r: "path", f: "path" });
    if (parsed) index = takeShortValue(parsed, index, base, args, roles);
  }
}

function ghApiFileRoles(args: readonly string[], base: number, roles: RoleSets): void {
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === "--input") { if (args[index + 1]) recordPathValue(roles, args[++index], base + index); continue; }
    if (arg.startsWith("--input=")) { recordPathValue(roles, arg.slice(8), base + index); continue; }
    const typed = /^(?:-F|--field=)(.+)$/.exec(arg)?.[1] ??
      (["-F", "--field"].includes(arg) ? args[++index] : undefined);
    const file = typedFile(typed);
    if (file) recordPathValue(roles, file, base + index);
  }
}

function typedFile(value?: string): string | undefined { return value?.match(/^[^=]+=@(.+)$/)?.[1]; }

function recordPathValue(roles: RoleSets, value: string, index: number): void {
  roles.pathValues.push(value);
  roles.pathValueSources.push({ value, index });
}

function gitRevisionFiles(args: readonly string[], base: number, roles: RoleSets): void {
  for (let index = 1; index < args.length; index++) {
    const word = args[index];
    if (word === "--") return;
    if (word.startsWith("-")) {
      const skip = revisionOptionValue(word);
      if (skip === undefined) return;
      index += skip;
      continue;
    }
    if (/^[^:]+:.+/.test(word)) recordPathValue(roles, word.slice(word.indexOf(":") + 1), base + index);
  }
}

function revisionOptionValue(word: string): number | undefined {
  if (REVISION_REQUIRED.includes(word)) return 1;
  if (REVISION_OPTIONAL.includes(word)) return 0;
  if ([...REVISION_REQUIRED, ...REVISION_OPTIONAL].some((option) => word.startsWith(`${option}=`))) return 0;
  return ["-p", "-s", "--patch", "--no-patch", "--stat", "--name-only", "--name-status"].includes(word) ? 0 : undefined;
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

/** Whether an `rm` argument is recursive, and its non-option targets. */
interface RootRemovalScan { recursive: boolean; targets: string[] }

/** True for an option that makes `rm` recursive (`-r`, `-R`, `--recursi`). */
function isRecursiveRemovalOption(arg: string): boolean {
  if (arg.startsWith("--")) return isLongOption(arg, "--recursive");
  return /[rR]/.test(arg.slice(1));
}

/** Splits `rm` arguments into the recursion flag and its targets. */
function scanRootRemoval(args: readonly string[]): RootRemovalScan {
  let recursive = false;
  let endOfOptions = false;
  const targets: string[] = [];
  for (const arg of args) {
    if (endOfOptions) { targets.push(arg); continue; }
    if (arg === "--") { endOfOptions = true; continue; }
    if (isOptionWord(arg)) { recursive = recursive || isRecursiveRemovalOption(arg); continue; }
    targets.push(arg);
  }
  return { recursive, targets };
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
  const scan = scanRootRemoval(args);
  if (!scan.recursive || scan.targets.length === 0) return false;
  return scan.targets.some(isFilesystemRoot);
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

/** A copied slice of the command, the offset after it, and the new word boundary. */
interface CommandSegment { text: string; next: number; boundary: boolean }

/** Copies a `\`-escaped character (or a trailing lone backslash). */
function escapeSegment(command: string, index: number): CommandSegment {
  return { text: command.slice(index, index + 2), next: index + 2, boundary: false };
}

/** Copies a single-quoted run, which has no escapes. */
function singleQuotedSegment(command: string, index: number): CommandSegment {
  const end = command.indexOf("'", index + 1);
  const stop = end === -1 ? command.length : end + 1;
  return { text: command.slice(index, stop), next: stop, boundary: false };
}

/** Copies a `$'...'` run, where a backslash escapes the closing quote. */
function ansiQuotedSegment(command: string, index: number): CommandSegment {
  let cursor = index + 2;
  while (cursor < command.length && command[cursor] !== "'") cursor += command[cursor] === "\\" ? 2 : 1;
  const stop = Math.min(cursor + 1, command.length);
  return { text: command.slice(index, stop), next: stop, boundary: false };
}

/** Copies a `"..."` run, where a backslash escapes the next character. */
function doubleQuotedSegment(command: string, index: number): CommandSegment {
  let cursor = index + 1;
  while (cursor < command.length && command[cursor] !== '"') cursor += command[cursor] === "\\" ? 2 : 1;
  const stop = Math.min(cursor + 1, command.length);
  return { text: command.slice(index, stop), next: stop, boundary: false };
}

/** Copies a digit run; a run adjacent to a redirection is a descriptor and becomes a space. */
function descriptorSegment(command: string, index: number): CommandSegment {
  let cursor = index;
  while (cursor < command.length && /\d/.test(command[cursor])) cursor++;
  // Replace the run with a space instead of deleting it: `&2>` is `&`
  // followed by a redirect, and deleting the `2` would fuse `&` and `>`
  // into the different `&>` operator.
  if (command[cursor] === ">" || command[cursor] === "<") return { text: " ", next: cursor, boundary: true };
  return { text: command.slice(index, cursor), next: cursor, boundary: false };
}

/** The segment starting at `index`, or undefined when it is one ordinary character. */
function descriptorSegmentAt(command: string, index: number, boundary: boolean): CommandSegment | undefined {
  const character = command[index];
  if (character === "\\") return escapeSegment(command, index);
  if (character === "'") return singleQuotedSegment(command, index);
  if (character === "$" && command[index + 1] === "'") return ansiQuotedSegment(command, index);
  if (character === '"') return doubleQuotedSegment(command, index);
  if (boundary && /\d/.test(character)) return descriptorSegment(command, index);
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
    const segment = descriptorSegmentAt(command, index, boundary);
    if (segment === undefined) {
      const character = command[index];
      result += character;
      boundary = /[ \t\n;|&()<>]/.test(character);
      index++;
      continue;
    }
    result += segment.text;
    boundary = segment.boundary;
    index = segment.next;
  }
  return result;
}

/** The quote forms the hash scan tracks. */
type HashQuote = "'" | '"' | "$'";

/** One consumed slice of a hash scan, with the quote and word-start state after it. */
interface HashSegment { text: string; next: number; quote: HashQuote | undefined; wordStart: boolean }

/** Copies one character inside a quoted run; a backslash escapes the next one outside `'...'`. */
function quotedHashSegment(command: string, index: number, quote: HashQuote): HashSegment {
  const character = command[index];
  const closing = quote === "$'" ? "'" : quote;
  if (character === "\\" && quote !== "'") {
    const stop = Math.min(index + 2, command.length);
    return { text: command.slice(index, stop), next: stop, quote, wordStart: false };
  }
  return { text: character, next: index + 1, quote: character === closing ? undefined : quote, wordStart: false };
}

/** Copies a `\`-escaped character; a `\`-newline keeps the current word start. */
function escapedHashSegment(command: string, index: number, wordStart: boolean): HashSegment {
  if (index + 1 >= command.length) return { text: "\\", next: index + 1, quote: undefined, wordStart: false };
  const escaped = command[index + 1];
  return { text: command.slice(index, index + 2), next: index + 2, quote: undefined,
    wordStart: escaped === "\n" ? wordStart : false };
}

/** Opens a quoted run at its `'`, `"`, or `$'` opener. */
function openHashQuote(command: string, index: number): HashSegment {
  const character = command[index];
  if (command[index + 1] === "'" && character === "$")
    return { text: command.slice(index, index + 2), next: index + 2, quote: "$'", wordStart: false };
  return { text: character, next: index + 1, quote: character as "'" | '"', wordStart: false };
}

/** Copies a `#` at a word start as a comment through the end of the command. */
function commentHashSegment(command: string, index: number, wordStart: boolean): HashSegment {
  if (wordStart) return { text: command.slice(index), next: command.length, quote: undefined, wordStart };
  return { text: "\\#", next: index + 1, quote: undefined, wordStart };
}

/** One consumed slice of an unquoted run of the hash scan. */
function unquotedHashSegment(command: string, index: number, wordStart: boolean): HashSegment {
  const character = command[index];
  if (character === "\\") return escapedHashSegment(command, index, wordStart);
  if (character === "'" || character === '"' || (character === "$" && command[index + 1] === "'"))
    return openHashQuote(command, index);
  if (character === "#") return commentHashSegment(command, index, wordStart);
  if (WORD_BREAK.test(character)) return { text: character, next: index + 1, quote: undefined, wordStart: true };
  return { text: character, next: index + 1, quote: undefined, wordStart: false };
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
  let quote: HashQuote | undefined;
  let wordStart = true;
  let index = 0;
  while (index < command.length) {
    const segment: HashSegment = quote === undefined
      ? unquotedHashSegment(command, index, wordStart)
      : quotedHashSegment(command, index, quote);
    result += segment.text;
    index = segment.next;
    quote = segment.quote;
    wordStart = segment.wordStart;
  }
  return result;
}

export interface HeredocMarker { delimiter: string; quoted: boolean; stripTabs: boolean }

/** Index just past the closing quote of a quoted run whose body starts at `start`. */
function skipQuotedRun(text: string, start: number, closing: string, escapes: boolean): number {
  let index = start;
  while (index < text.length) {
    const character = text[index];
    if (character === closing) return index + 1;
    index += escapes && character === "\\" ? 2 : 1;
  }
  return index;
}

/** Index past a `'...'` or `"..."` run that opens at `index`, when one does. */
function quotedEndAt(text: string, index: number): number | undefined {
  const character = text[index];
  if (character === "'") return skipQuotedRun(text, index + 1, "'", false);
  if (character === '"') return skipQuotedRun(text, index + 1, '"', true);
  return undefined;
}

/** Index past a `'...'`, `"..."`, or `$'...'` run that opens at `index`, when one does. */
function quotedRunEndAt(text: string, index: number): number | undefined {
  if (text[index] === "$" && text[index + 1] === "'") return skipQuotedRun(text, index + 2, "'", true);
  return quotedEndAt(text, index);
}

/** True for the `<<` of a here-document (not `<<<`, and not the tail of a longer `<`). */
function isHeredocOperator(line: string, index: number): boolean {
  return line[index] === "<" && line[index + 1] === "<" && line[index + 2] !== "<" && line[index - 1] !== "<";
}

/** True for a `<<` this reader cannot place (not `<<<`, and not the tail of a longer `<`). */
function isUndecodableHeredocStart(line: string, index: number): boolean {
  return line[index + 1] === "<" && line[index + 2] !== "<" && line[index - 1] !== "<";
}

/** Skips spaces and tabs. */
function skipBlanks(line: string, start: number): number {
  let index = start;
  while (line[index] === " " || line[index] === "\t") index++;
  return index;
}

/** A here-document delimiter word and the offset after it. */
interface DelimiterRead { delimiter: string; quoted: boolean; end: number }

/** Reads a quoted here-document delimiter word, rejecting escapes this reader cannot decode. */
function readQuotedDelimiter(line: string, start: number): DelimiterRead | undefined {
  const closing = line[start];
  let index = start + 1;
  let delimiter = "";
  while (index < line.length) {
    const character = line[index];
    if (character === closing) return { delimiter, quoted: true, end: index + 1 };
    if (closing === '"' && character === "\\") return undefined;
    delimiter += character;
    index++;
  }
  return undefined;
}

/** Reads a bare here-document delimiter word (`[A-Za-z0-9_]`). */
function readBareDelimiter(line: string, start: number): DelimiterRead {
  let index = start;
  while (index < line.length && /[A-Za-z0-9_]/.test(line[index])) index++;
  return { delimiter: line.slice(start, index), quoted: false, end: index };
}

/** Reads a here-document delimiter word, quoted or bare. */
function readDelimiter(line: string, start: number): DelimiterRead | undefined {
  if (line[start] === "'" || line[start] === '"') return readQuotedDelimiter(line, start);
  return readBareDelimiter(line, start);
}

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
  if (!isHeredocOperator(line, index)) return undefined;
  const stripTabs = line[index + 2] === "-";
  const read = readDelimiter(line, skipBlanks(line, index + (stripTabs ? 3 : 2)));
  if (read === undefined || !read.delimiter) return undefined;
  // The delimiter word must end here; a quoted run glued to more word text is a
  // concatenation this parser does not decode.
  if (read.end < line.length && !WORD_BREAK.test(line[read.end])) return undefined;
  return { marker: { delimiter: read.delimiter, quoted: read.quoted, stripTabs }, end: read.end };
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
  let index = 0;
  while (index < line.length) {
    const quoted = quotedEndAt(line, index);
    if (quoted !== undefined) { index = quoted; wordStart = false; continue; }
    const character = line[index];
    if (character === "\\") { index += 2; wordStart = false; continue; }
    if (character === "#" && wordStart) break;
    if (character === "<") {
      const parsed = heredocMarkerAt(line, index);
      if (parsed !== undefined) {
        markers.push(parsed.marker);
        index = parsed.end;
        wordStart = false;
        continue;
      }
      unsupported = unsupported || isUndecodableHeredocStart(line, index);
    }
    wordStart = WORD_BREAK.test(character);
    index++;
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
  let index = 0;
  while (index < text.length) {
    const quoted = quotedEndAt(text, index);
    if (quoted !== undefined) { index = quoted; continue; }
    const character = text[index];
    if (character === "\\") { index += 2; continue; }
    if (character === "<" && isUndecodableHeredocStart(text, index)) return true;
    index++;
  }
  return false;
}

/** A raw command line and the offset of the newline that ends it. */
interface CommandLine { line: string; end: number }

/** The line up to a comment's newline, which ends the line. */
function commentLineAt(command: string, start: number, index: number): CommandLine {
  const end = command.indexOf("\n", index);
  const stop = end === -1 ? command.length : end;
  return { line: command.slice(start, stop), end: stop };
}

/**
 * The raw command line that starts at `start`, and the offset of the newline
 * that ends it. Quoted newlines and `\`-newlines stay inside the line; a
 * comment's newline ends it.
 */
function commandLineAt(command: string, start: number): CommandLine {
  let wordStart = true;
  let index = start;
  while (index < command.length) {
    const quoted = quotedRunEndAt(command, index);
    if (quoted !== undefined) { index = quoted; wordStart = false; continue; }
    const character = command[index];
    if (character === "\\") { index += 2; continue; }
    if (character === "#" && wordStart) return commentLineAt(command, start, index);
    if (character === "\n") return { line: command.slice(start, index), end: index };
    wordStart = WORD_BREAK.test(character);
    index++;
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

/** One consumed slice of the continuation scan, with the word-start state after it. */
interface ContinuationStep { text: string; next: number; wordStart: boolean; marker?: HeredocMarker }

/** Copies a `\`-newline (removed), a trailing `\`, or a `\`-escaped character. */
function backslashStep(command: string, index: number, wordStart: boolean): ContinuationStep {
  const next = command[index + 1];
  if (next === "\n") return { text: "", next: index + 2, wordStart };
  if (next === undefined) return { text: "\\", next: index + 1, wordStart };
  return { text: command.slice(index, index + 2), next: index + 2, wordStart: false };
}

/** Copies a single-quoted run, which holds a backslash and a newline as data. */
function singleQuotedStep(command: string, index: number): ContinuationStep {
  const end = command.indexOf("'", index + 1);
  const stop = end === -1 ? command.length : end + 1;
  return { text: command.slice(index, stop), next: stop, wordStart: false };
}

/** Copies a `$'...'` run, which holds a backslash and a newline as data. */
function ansiQuotedStep(command: string, index: number): ContinuationStep {
  let cursor = index + 2;
  while (cursor < command.length && command[cursor] !== "'") cursor += command[cursor] === "\\" ? 2 : 1;
  const stop = Math.min(cursor + 1, command.length);
  return { text: command.slice(index, stop), next: stop, wordStart: false };
}

/** Copies a `"..."` run, deleting `\`-newlines a shell removes inside it. */
function doubleQuotedStep(command: string, index: number): ContinuationStep {
  let cursor = index + 1;
  let text = "\"";
  while (cursor < command.length) {
    const inner = command[cursor];
    if (inner === "\\") {
      const next = command[cursor + 1];
      if (next === "\n") { cursor += 2; continue; }
      text += next === undefined ? inner : inner + next;
      cursor += next === undefined ? 1 : 2;
      continue;
    }
    text += inner;
    cursor++;
    if (inner === '"') break;
  }
  return { text, next: cursor, wordStart: false };
}

/** Copies a comment, which runs to (but not past) its newline. */
function commentContinuationStep(command: string, index: number): ContinuationStep {
  const end = command.indexOf("\n", index);
  const stop = end === -1 ? command.length : end;
  return { text: command.slice(index, stop), next: stop, wordStart: false };
}

/** Copies a here-document marker word and records it for its body. */
function heredocContinuationStep(command: string, index: number): ContinuationStep | undefined {
  const parsed = heredocMarkerAt(command, index);
  if (parsed === undefined) return undefined;
  return { text: command.slice(index, parsed.end), next: parsed.end, wordStart: false, marker: parsed.marker };
}

/** The step for a character that starts a quoted run, comment, or marker. */
function continuationStepAt(command: string, index: number, wordStart: boolean): ContinuationStep | undefined {
  const character = command[index];
  if (character === "\\") return backslashStep(command, index, wordStart);
  if (character === "'") return singleQuotedStep(command, index);
  if (character === "$" && command[index + 1] === "'") return ansiQuotedStep(command, index);
  if (character === '"') return doubleQuotedStep(command, index);
  if (character === "#" && wordStart) return commentContinuationStep(command, index);
  if (character === "<") return heredocContinuationStep(command, index);
  return undefined;
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
    if (command[index] === "\n") {
      result += "\n";
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
    const step = continuationStepAt(command, index, wordStart);
    if (step === undefined) {
      result += command[index];
      wordStart = WORD_BREAK.test(command[index]);
      index++;
      continue;
    }
    result += step.text;
    index = step.next;
    wordStart = step.wordStart;
    if (step.marker !== undefined) pending.push(step.marker);
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

/** State shared across the logical-line scan. */
interface LogicalScan {
  lines: string[];
  start: number;
  pending: HeredocMarker[];
  certain: number | undefined;
}

/** Records that everything from the line at `line` onwards may be data. */
function markUncertain(scan: LogicalScan, line: number): void {
  if (scan.certain === undefined) scan.certain = line + 1;
}

/** Ends the current line at `end` and jumps past the bodies of its markers. */
function endLogicalLine(scan: LogicalScan, command: string, end: number): void {
  scan.lines.push(command.slice(scan.start, end));
  scan.start = end + 1;
  if (!scan.pending.length) return;
  const bodies = heredocBodies(command, scan.start, scan.pending);
  if (bodies.unstable) markUncertain(scan, scan.lines.length - 1);
  scan.start = bodies.end;
  scan.pending = [];
}

/** One scan step: the next index and word-start state. */
interface LogicalStep { next: number; wordStart: boolean }

/** Skips the `\`-escaped character at `index`. */
function backslashLogicalStep(command: string, index: number, wordStart: boolean): LogicalStep {
  if (index + 1 >= command.length) return { next: index + 1, wordStart: false };
  const escaped = command[index + 1];
  return { next: index + 2, wordStart: escaped === "\n" ? wordStart : false };
}

/** Ends the line at a comment's newline and jumps past its heredoc bodies. */
function commentLogicalStep(scan: LogicalScan, command: string, index: number): LogicalStep {
  const end = command.indexOf("\n", index);
  if (end === -1) return { next: command.length, wordStart: true };
  endLogicalLine(scan, command, end);
  return { next: scan.start, wordStart: true };
}

/** Ends the line at a newline and jumps past its heredoc bodies. */
function newlineLogicalStep(scan: LogicalScan, command: string, index: number): LogicalStep {
  endLogicalLine(scan, command, index);
  return { next: scan.start, wordStart: true };
}

/** Records a heredoc marker at `index`; returns the index after it, or undefined when none. */
function heredocLogicalStep(scan: LogicalScan, command: string, index: number): number | undefined {
  const parsed = heredocMarkerAt(command, index);
  if (parsed === undefined) {
    if (isUndecodableHeredocStart(command, index)) markUncertain(scan, scan.lines.length);
    return undefined;
  }
  scan.pending.push(parsed.marker);
  return parsed.end;
}

/** One step of the logical-line scan at `index`. */
function logicalStepAt(scan: LogicalScan, command: string, index: number, wordStart: boolean): LogicalStep {
  const quoted = quotedRunEndAt(command, index);
  if (quoted !== undefined) return { next: quoted, wordStart: false };
  const character = command[index];
  if (character === "\\") return backslashLogicalStep(command, index, wordStart);
  if (character === "#" && wordStart) return commentLogicalStep(scan, command, index);
  if (character === "<") {
    const markerEnd = heredocLogicalStep(scan, command, index);
    if (markerEnd !== undefined) return { next: markerEnd, wordStart: false };
  }
  if (character === "\n") return newlineLogicalStep(scan, command, index);
  return { next: index + 1, wordStart: WORD_BREAK.test(character) };
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
  const scan: LogicalScan = { lines: [], start: 0, pending: [], certain: undefined };
  let wordStart = true;
  let index = 0;
  while (index < command.length) {
    const step = logicalStepAt(scan, command, index, wordStart);
    index = step.next;
    wordStart = step.wordStart;
  }
  scan.lines.push(command.slice(scan.start));
  return { lines: scan.lines, certain: scan.certain ?? scan.lines.length };
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
  return parse(escapeLiteralHashes(stripDescriptorPrefixes(normalizeContinuations(command))), (key) => `$${key}`);
}

/** True when a descriptor close (`>&-` or `<&-`) starts at `index`. */
function isDescriptorClose(command: string, index: number): boolean {
  const character = command[index];
  return (character === ">" || character === "<") && command[index + 1] === "&" && command[index + 2] === "-";
}

/** True when a descriptor close is immediately followed by more word text. */
function hasDescriptorCloseTail(command: string, index: number, delimiter: RegExp): boolean {
  if (!isDescriptorClose(command, index)) return false;
  const next = command[index + 3];
  return next !== undefined && !delimiter.test(next);
}

/** The offset just past a comment's newline, or the end of the command. */
function skipComment(command: string, index: number): number {
  const end = command.indexOf("\n", index);
  return end === -1 ? command.length : end + 1;
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
    const quoted = quotedRunEndAt(command, index);
    if (quoted !== undefined) { index = quoted; boundary = false; continue; }
    const character = command[index];
    if (character === "\\") { index += 2; boundary = false; continue; }
    if (boundary && character === "#") { index = skipComment(command, index); continue; }
    if (hasDescriptorCloseTail(command, index, delimiter)) return true;
    boundary = delimiter.test(character);
    index++;
  }
  return false;
}

/** Builder state for one script's simple commands. */
interface InvocationBuilder { words: string[]; commands: string[][]; skipNext: boolean }

/** Adds a word unless the previous token was a redirection operator. */
function pushTokenWord(builder: InvocationBuilder, word: string): void {
  if (!builder.skipNext) builder.words.push(word);
  builder.skipNext = false;
}

/** Folds one parsed token into the current simple command. */
function consumeToken(builder: InvocationBuilder, token: ParseEntry): void {
  if (typeof token === "string") { pushTokenWord(builder, token); return; }
  if ("comment" in token) return;
  if (!("op" in token)) return;
  if (token.op === "glob") { pushTokenWord(builder, token.pattern); return; }
  if (CONTROL_OPERATORS.has(token.op)) {
    if (builder.words.length) builder.commands.push(builder.words);
    builder.words = [];
    builder.skipNext = false;
    return;
  }
  // A redirection does not end a simple command; only its target is dropped.
  // Descriptor prefixes were already removed from the source before parsing.
  if (REDIRECT_OPERATORS.has(token.op)) builder.skipNext = true;
}

/** Splits a script into simple commands, dropping redirection targets. */
function invocations(command: string): string[][] {
  let tokens;
  try { tokens = parseShell(command); } catch { return []; }
  const builder: InvocationBuilder = { words: [], commands: [], skipNext: false };
  for (const token of tokens) consumeToken(builder, token);
  if (builder.words.length) builder.commands.push(builder.words);
  return builder.commands;
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

/** Deny reason for any of `lines`, stopping at the first dangerous invocation. */
function denyLines(lines: readonly string[], depth: number): string | undefined {
  for (const line of lines) {
    for (const words of invocations(line)) {
      const reason = denyInvocation(words, depth);
      if (reason !== undefined) return reason;
    }
  }
  return undefined;
}

/** Deny reason in the certain prefix of a raw heredoc script. */
function denyRawLines(lines: readonly string[], depth: number): string | undefined {
  for (const line of lines) {
    // A line whose own normalization assembles unsupported quoting cannot be
    // parsed safely; its deny is left to the caller's manual approval.
    if (hasAssembledUndecodedSyntax(line)) continue;
    const reason = denyLines([line], depth);
    if (reason !== undefined) return reason;
  }
  return undefined;
}

/** Deny reason in the certain prefix of a normalized script. */
function denyLogicalLines(normalized: string, depth: number): string | undefined {
  const { lines, certain } = logicalLines(normalized);
  return denyLines(lines.slice(0, certain), depth);
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
  if (raw.ambiguous) return denyRawLines(raw.lines, depth);
  // Normalization can assemble quoting this reader does not decode. The inner
  // shell could then run a command the projection does not place, so the rest of
  // the projection stands down; a deny already visible in the clean prefix still
  // keeps its precedence, and the caller asks when there is none.
  if (!hasUndecodedSyntax(command) && hasUndecodedSyntax(normalized))
    return denyCleanPrefix(normalized, depth);
  return denyLogicalLines(normalized, depth);
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
  if (directProhibition(executable.name, args)) return DANGEROUS;
  if (POSIX_SHELLS.has(executable.name) || executable.name === "eval") {
    const script = scriptArgument(executable.name, args);
    if (script !== undefined) return denyScript(script, depth + 1);
  }
  return undefined;
}

const POSIX_SHELLS = new Set(["sh", "bash", "dash", "zsh", "ksh"]);
export function supportsPosixReview(shell?: { platform?: string; interpreter?: string }): boolean {
  const platform = shell?.platform ?? process.platform;
  return platform !== "win32" && (shell?.interpreter === undefined || POSIX_SHELLS.has(basename(shell.interpreter)));
}

function directProhibition(name: string, args: readonly string[]): boolean {
  return !helpOnly(args) && (DENY_EXECUTABLES.has(name) || (name === "gh" && args[0] === "auth" && args[1] === "token") ||
    (name === "rm" && isRecursiveRootRemoval(args)) || deviceDestruction(name, args));
}

const RAW_DEVICE = /^\/dev\/(?:[shv]d[a-z]+\d*|xvd[a-z]+\d*|nvme\d+n\d+(?:p\d+)?|r?disk\d+(?:s\d+)*|mapper\/[^/]+|mmcblk\d+(?:p\d+)?)$/;
function deviceDestruction(name: string, args: readonly string[]): boolean {
  if (/^mkfs(?:\.[a-z0-9]+)?$/.test(name)) return RAW_DEVICE.test(mkfsTarget(args) ?? "");
  return name === "dd" && args.some((arg) => arg.startsWith("of=") && RAW_DEVICE.test(arg.slice(3)));
}

/** Powerful capabilities are review evidence, not proof of a prohibited action. */
export function capabilityNeedsReview(words: readonly string[]): boolean {
  const executable = resolveExecutable(words);
  if (!executable) return true;
  const name = executable.name;
  const args = words.slice(executable.index + 1);
  return ["sshpass", "printenv", "env", "terraform", "tofu", "pulumi"].includes(name) ||
    runtimeCapability(name, args) || (name === "chmod" && isWorldWritableMode(chmodMode(args) ?? ""));
}

function runtimeCapability(name: string, args: readonly string[]): boolean {
  if (name === "printf") return args[0]?.startsWith("-v") === true;
  if (name === "jq") return args.some((arg) => /\b(?:env|ENV)\b/.test(arg));
  return ["npm", "pnpm", "yarn", "bun", "node"].includes(name) &&
    args.some((arg) => /^(?:--(?:preload|require|import)(?:=|$)|-r)/.test(arg));
}

const UNIQ_FLAGS = new Set(["c", "d", "D", "i", "u"]);
const UNIQ_VALUE_FLAGS = new Set(["f", "s", "w"]);
const UNIQ_LONG_FLAGS = new Set(["--count", "--repeated", "--ignore-case", "--unique", "--zero-terminated",
  "--help", "--version"]);
const UNIQ_LONG_OPTIONAL_FLAGS = new Set(["--all-repeated", "--group"]);
const UNIQ_LONG_VALUE_FLAGS = new Set(["--skip-fields", "--skip-chars", "--check-chars"]);

/** Loop state of the `uniq` operand scan. */
interface UniqScan { operands: number; endOfOptions: boolean }

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
  const scan: UniqScan = { operands: 0, endOfOptions: false };
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (scan.endOfOptions || scan.operands > 0 || arg === "-") { scan.operands++; continue; }
    if (arg === "--") { scan.endOfOptions = true; continue; }
    if (arg.startsWith("--") && arg.length > 2) { index = uniqLongOption(scan, args, index); continue; }
    if (arg.startsWith("-")) { index = uniqShortOption(scan, args, index); continue; }
    scan.operands++;
  }
  return scan.operands <= 1;
}

/** Reads one `--long` option of `uniq`; returns the index it ended at. */
function uniqLongOption(scan: UniqScan, args: readonly string[], index: number): number {
  const arg = args[index];
  const name = arg.split("=", 1)[0];
  const attached = arg.length > name.length;
  if (UNIQ_LONG_VALUE_FLAGS.has(name)) return attached ? index : index + 1;
  if (UNIQ_LONG_OPTIONAL_FLAGS.has(name) || (UNIQ_LONG_FLAGS.has(name) && !attached)) return index;
  scan.operands++;
  return index;
}

/** Reads one short `uniq` option bundle; returns the index it ended at. */
function uniqShortOption(scan: UniqScan, args: readonly string[], index: number): number {
  const letters = args[index].slice(1);
  for (let position = 0; position < letters.length; position++) {
    if (UNIQ_VALUE_FLAGS.has(letters[position]))
      return position === letters.length - 1 ? index + 1 : index;
    if (!UNIQ_FLAGS.has(letters[position])) { scan.operands++; return index; }
  }
  return index;
}

const DATE_FLAGS = new Set(["u", "R", "j"]);
const DATE_VALUE_FLAGS = new Set(["d", "r", "f"]);
const DATE_LONG_FLAGS = new Set(["--utc", "--universal", "--rfc-email", "--rfc-2822", "--iso-8601",
  "--debug", "--help", "--version"]);
const DATE_LONG_VALUE_FLAGS = new Set(["--date", "--reference", "--file", "--rfc-3339"]);

/** The next `date` argument to inspect, or undefined when the call is not read-only. */
function dateLongOptionNext(args: readonly string[], index: number): number | undefined {
  const arg = args[index];
  const name = arg.split("=", 1)[0];
  const attached = arg.length > name.length;
  // `--file DATEFILE` reads dates from a file, which may be project data.
  if (name === "--file" || resolveLongOption(name) === "--file") return undefined;
  if (DATE_LONG_VALUE_FLAGS.has(name)) return attached ? index + 1 : index + 2;
  if (DATE_LONG_FLAGS.has(name)) return index + 1;
  return undefined;
}

/** The next `date` argument to inspect, or undefined when a short bundle is not read-only. */
function dateShortOptionNext(args: readonly string[], index: number): number | undefined {
  const arg = args[index];
  for (let position = 1; position < arg.length; position++) {
    const letter = arg[position];
    if (letter === "I") break;
    // `-f FILE` / `-fFILE` also reads a date file.
    if (letter === "f") return undefined;
    // `-rFILE` hides the reference file from the word scan; only the separate
    // `-r FILE` form stays available to the path check.
    if (letter === "r") return position === arg.length - 1 ? index + 2 : undefined;
    if (DATE_VALUE_FLAGS.has(letter)) return position === arg.length - 1 ? index + 2 : index + 1;
    if (!DATE_FLAGS.has(letter)) return undefined;
  }
  return index + 1;
}

/** The next `date` argument to inspect, or undefined when this one needs review. */
function dateOptionNext(args: readonly string[], index: number): number | undefined {
  const arg = args[index];
  if (arg.startsWith("--") && arg.length > 2) return dateLongOptionNext(args, index);
  if (!arg.startsWith("-") || arg === "-") return undefined;
  return dateShortOptionNext(args, index);
}

/**
 * `date` is read-only only when every argument is a known read-only option or a
 * `+FORMAT` operand. A positional operand sets the system clock
 * (`date 010100002030`), so it requires review.
 */
function isReadOnlyDate(args: readonly string[]): boolean {
  let index = 0;
  while (index < args.length) {
    const arg = args[index];
    if (arg.startsWith("+")) { index++; continue; }
    if (arg === "--") return args.slice(index + 1).every((operand) => operand.startsWith("+"));
    const next = dateOptionNext(args, index);
    if (next === undefined) return false;
    index = next;
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

/** True for a long option that makes `grep` follow directories or symlinks. */
function isRecursiveGrepLongOption(option: string, value: string | undefined): boolean {
  if ("--recursive".startsWith(option) || "--dereference-recursive".startsWith(option)) return true;
  return "--directories".startsWith(option) && value === "recurse";
}

/** True when one `grep` argument selects recursive or symlink-following search. */
function isRecursiveGrepArg(args: readonly string[], index: number): boolean {
  const arg = args[index];
  if (/[rR]/.test(shortFlags(arg, GREP_SHORT_VALUES))) return true;
  const parsed = shortOption(arg, GREP_SHORT_VALUES);
  if (parsed?.letter === "d" && (parsed.attached ?? args[index + 1]) === "recurse") return true;
  if (!arg.startsWith("--") || arg.length <= 2) return false;
  const separator = arg.indexOf("=");
  const option = separator === -1 ? arg : arg.slice(0, separator);
  const value = separator === -1 ? args[index + 1] : arg.slice(separator + 1);
  return isRecursiveGrepLongOption(option, value);
}

/**
 * `grep -r`/`-R` and `-d recurse` follow directories instead of reading only
 * the named operands, so they can dump protected or external trees. `-R` also
 * follows symlinks. A named protected path still denies before this policy.
 */
function isReadOnlyGrep(args: readonly string[]): boolean {
  for (let index = 0; index < args.length; index++) {
    if (isRecursiveGrepArg(args, index)) return false;
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

/** True for `status`, `rev-parse`, `diff`, `log`, `show` and the checked `branch` forms. */
function isReadOnlyGit(args: readonly string[]): boolean {
  if (hasGitGlobalOverride(args)) return false;
  const subcommand = args[0];
  if (subcommand === undefined) return false;
  if (subcommand === "branch") return isReadOnlyGitBranch(args);
  return ["status", "diff", "log", "show", "rev-parse"].includes(subcommand);
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

/** True when `printf` gets a `-v` variable-assignment option before `--`. */
function hasPrintfVariableOption(args: readonly string[]): boolean {
  for (const arg of args) {
    if (arg === "--") return false;
    if (/^-v/.test(arg)) return true;
  }
  return false;
}

/** True only when `find` has no output (`-fprint`, `-fprint0`, `-fprintf`, `-fls`) or files-from option. */
function isReadOnlyFind(args: readonly string[]): boolean {
  return !args.some((arg) => /^--?(?:fprint|fprint0|fprintf|fls)$/.test(arg) || /^--?files0/.test(arg));
}

/** True only for `docker logs`. */
function isReadOnlyDocker(args: readonly string[]): boolean {
  return args[0] === "logs";
}

/** True for `bun test`, `bun run lint`, and `bun run typecheck`. */
function isReadOnlyBun(args: readonly string[]): boolean {
  if (args[0] === "test") return true;
  return args[0] === "run" && (args[1] === "lint" || args[1] === "typecheck");
}

/** Read-only policy for commands that need a bespoke check rather than a table. */
function specialReadOnlyPolicy(command: string, args: readonly string[]): boolean {
  if (command === "git") return isReadOnlyGit(args);
  if (command === "find") return isReadOnlyFind(args);
  if (command === "sed") return isReadOnlySed(args);
  if (command === "gh") return isReadOnlyGh(args);
  if (command === "docker") return isReadOnlyDocker(args);
  if (command === "bun") return isReadOnlyBun(args);
  return false;
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
  // Any `-v` option assigns a shell variable, attached or separate. `--` ends
  // option parsing, so `printf -- -v` keeps `-v` as literal format text.
  if (command === "printf" && hasPrintfVariableOption(args)) return false;
  // Own properties only: `./constructor` must not resolve to `Object`.
  if (Object.hasOwn(POLICIES, command)) return POLICIES[command](args);
  if (READ_ONLY.has(command)) return true;
  return specialReadOnlyPolicy(command, args);
}

/** True when a git option replaces configuration, a diff helper or the output target. */
function hasGitGlobalOverride(args: readonly string[]): boolean {
  return args.some((arg) =>
    /^(?:-c|--git-dir|--work-tree|--exec-path|--config-env)(?:=|$)/.test(arg) ||
    arg === "--ext-diff" || arg === "--exec" || arg.startsWith("--output"));
}

function isReadOnlyGitBranch(args: readonly string[]): boolean {
  if (args.length === 1) return true;
  return args.slice(1).every((arg) =>
    ["--show-current", "--list", "-a", "-r", "-v", "-vv", "--merged", "--no-merged", "--contains", "--points-at", "--format"]
      .some((safe) => arg === safe || arg.startsWith(`${safe}=`)));
}

const REVISION_REQUIRED = ["--date", "--encoding"];
const REVISION_OPTIONAL = ["--format", "--pretty", "--abbrev", "--stat", "--decorate", "--color", "--word-diff", "--unified"];
function helpOnly(args: readonly string[]): boolean {
  return args.length === 1 && ["--help", "--version"].includes(args[0]);
}

function mkfsTarget(args: readonly string[]): string | undefined {
  let end = false;
  const operands: string[] = [];
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (!end && arg === "--") { end = true; continue; }
    if (!end && arg.startsWith("-")) {
      const skip = mkfsOptionArity(arg);
      if (skip === undefined) return undefined;
      index += skip;
    } else operands.push(arg);
  }
  return mkfsOperandTarget(operands);
}

function mkfsOperandTarget(operands: readonly string[]): string | undefined {
  if (operands.length > 2) return undefined;
  if (operands[1] !== undefined && !/^\d+$/.test(operands[1])) return undefined;
  return operands[0];
}

function mkfsOptionArity(arg: string): number | undefined {
  if (arg === "-n") return undefined; // Explicit no-write mode is review, not formatting.
  if (/^-[FqvcV]+$/.test(arg)) return 0;
  if (/^-[tLUbimNIOEMJGgel]$/.test(arg)) return 1;
  if (/^-[tLUbimNIOEMJGgel].+/.test(arg)) return 0;
  return undefined;
}
