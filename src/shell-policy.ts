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

function hasShortOption(args: readonly string[], letters: string): boolean {
  return args.some((arg) => arg.startsWith("-") && !arg.startsWith("--") &&
    [...arg.slice(1)].some((character) => letters.includes(character)));
}

function isWorldWritableMode(arg: string): boolean {
  const mode = arg.replace(/^[-+]+/, "");
  return mode === "777" || mode === "0777";
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
      if (arg === "--recursive") recursive = true;
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

/** The script a shell or `eval` would run, when invoked non-interactively. */
function scriptArgument(name: string, args: readonly string[]): string | undefined {
  if (name === "eval") return args.length ? args.join(" ") : undefined;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === "--") return undefined;
    if (!arg.startsWith("-") || arg.startsWith("--")) continue;
    if (arg.slice(1).includes("c")) return args[index + 1];
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
 * The raw command line, up to the newline a shell would treat as its end.
 * Quoted newlines and `\`-newlines stay inside the line; a comment's newline
 * ends it.
 */
function commandLine(command: string): string {
  let quote: "'" | '"' | "$'" | undefined;
  let wordStart = true;
  for (let index = 0; index < command.length; index++) {
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
      return end === -1 ? command : command.slice(0, end);
    }
    if (character === "\n") return command.slice(0, index);
    wordStart = WORD_BREAK.test(character);
  }
  return command;
}

/**
 * True when a here-document header cannot be tracked reliably from the raw
 * source, so the guard must fail closed instead of normalizing bytes it cannot
 * place.
 *
 * Deleting a `\`-newline is only safe once the marker and its delimiter are
 * visible: a continuation in the header can split `<`+`<`, split the delimiter
 * (`<<`+newline+`EOF`, `<<E`+newline+`OF`), or hide the entire marker
 * (`cat <<`+newline+`'EOF'`). Guessing there can move the body boundary past a
 * trailing command, so these and delimiters the reader cannot decode exactly
 * (escapes, expansion, concatenated words, a backslash inside double quotes)
 * require approval.
 */
export function hasAmbiguousHeredoc(command: string): boolean {
  const header = commandLine(command);
  if (!hasHeredoc(header) && !hasHeredoc(normalizeContinuations(header))) return false;
  if (header.includes("\\\n")) return true;
  return scanHeredoc(header).unsupported;
}

/**
 * Copies here-document bodies verbatim, returning the copied text and the
 * offset where the command script resumes.
 */
function heredocBodies(command: string, start: number, markers: readonly HeredocMarker[]): { text: string; end: number } {
  let index = start;
  let text = "";
  for (const marker of markers) {
    let closed = false;
    while (index < command.length) {
      const newline = command.indexOf("\n", index);
      const stop = newline === -1 ? command.length : newline + 1;
      const line = command.slice(index, newline === -1 ? command.length : newline);
      text += command.slice(index, stop);
      index = stop;
      if ((marker.stripTabs ? line.replace(/^\t+/, "") : line) === marker.delimiter) { closed = true; break; }
    }
    if (!closed) break;
  }
  return { text, end: index };
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
  /** True when a here-document header could not be decoded, so the code/data split is unknowable. */
  unsupported: boolean;
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
 * after the terminator is still analyzed. `unsupported` reports a header this
 * scanner cannot decode, where the terminator — and therefore the boundary
 * between script and data — is unknown, so callers must fail closed.
 */
export function logicalLines(command: string): LogicalScript {
  const lines: string[] = [];
  let unsupported = false;
  let start = 0;
  let wordStart = true;
  let quote: "'" | '"' | "$'" | undefined;
  let pending: HeredocMarker[] = [];
  /** Ends the current line at `end` and jumps past the bodies of its markers. */
  const endLine = (end: number) => {
    lines.push(command.slice(start, end));
    start = end + 1;
    if (!pending.length) return;
    start = heredocBodies(command, start, pending).end;
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
        unsupported = true;
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
  return { lines, unsupported };
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
 * A header this scanner cannot decode leaves the code/data split unknown, so the
 * deny pass stands down: the caller has already failed closed to manual approval
 * for the surrounding shell invocation, and guessing here could deny quoted data.
 */
function denyScript(command: string, depth: number): string | undefined {
  if (FORK_BOMB.test(command)) return DANGEROUS;
  if (hasAmbiguousHeredoc(command)) return undefined;
  const script = normalizeContinuations(command);
  const { lines, unsupported } = logicalLines(script);
  if (unsupported) return undefined;
  for (const line of lines) {
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
      if (DATE_VALUE_FLAGS.has(letter)) {
        if (position === arg.length - 1) index++;
        break;
      }
      if (!DATE_FLAGS.has(letter)) return false;
    }
  }
  return true;
}

const POLICIES: Record<string, (args: readonly string[]) => boolean> = {
  // Flags that read a program from a file, run a command, or write output.
  rg: (args) => !hasLongOption(args, ["--pre", "--pre-glob", "--hostname-bin", "--search-zip"]) &&
    !hasShortOption(args, "z"),
  sort: (args) => !hasLongOption(args, ["--output", "--compress-program", "--temporary-directory"]) &&
    !hasShortOption(args, "oT"),
  tree: (args) => !hasLongOption(args, ["--output"]) && !hasShortOption(args, "o"),
  file: (args) => !hasLongOption(args, ["--compile"]) && !hasShortOption(args, "C"),
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
  if (args.some((arg) => arg === "-i" || arg.startsWith("--in-place") || arg === "-e" ||
      arg === "--expression" || arg === "-f" || arg === "--file")) return false;
  return args[0] === "-n" && args[1] !== undefined && /^\d+(?:,\d+)?p$/.test(args[1]);
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
  const command = basename(words[0] ?? "");
  const args = words.slice(1);
  // Own properties only: `./constructor` must not resolve to `Object`.
  if (Object.hasOwn(POLICIES, command)) return POLICIES[command](args);
  if (READ_ONLY.has(command)) return true;
  if (command === "git") return isReadOnlyGit(args);
  if (command === "find") return !args.some((arg) => /^-(?:fprint|fprint0|fprintf|fls)$/.test(arg));
  if (command === "sed") return isReadOnlySed(args);
  if (command === "gh") return isReadOnlyGh(args);
  if (command === "docker") return args[0] === "logs";
  if (command === "bun")
    return args[0] === "test" || (args[0] === "run" && (args[1] === "lint" || args[1] === "typecheck"));
  return false;
}
