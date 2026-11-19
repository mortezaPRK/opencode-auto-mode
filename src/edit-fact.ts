import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, join, normalize, relative, resolve, sep } from "node:path";
import type { Generate } from "@opencode/schema/generate";
import { redactHttpBodies } from "./audit.js";
import {
  capturedEditArgs,
  isUsableEditPath,
  readEditCapture,
  sameEditCapture,
  verifyCapturedEdit,
  type EditCaptureIdentity,
  type EditPayload,
} from "./edit-capture.js";
import { freezeQuestion, isRecord, MAX_CAPTURED_BODY_BYTES } from "./guards.js";
import { classifyPath, isInside } from "./path-policy.js";
import type { OperationEvidence } from "./reviewer.js";
import { getWorktreeScope } from "./worktree.js";

export type { EditCaptureIdentity, EditPayload } from "./edit-capture.js";

/**
 * Edit/write facts come only from a payload minted by `prepareCapturedEdit`;
 * a clone or JSON round-trip has no WeakMap provenance and is rejected before
 * any provider call. The digest covers the full original args, binding the
 * actual `path`/`filePath` alias and any `replaceAll` flag.
 *
 * The capture identity is a structural binding, not permission or proof: the
 * host supplying both the minted payload and `expectedEditCapture` is trusted.
 * `includeEditPayload` is host opt-in, not consent, and `complete` is not
 * consulted because a full payload can be complete while operation evidence
 * stayed incomplete. Explicit operation targets win over permission resources,
 * which may be an external wildcard boundary, and any unusable target entry
 * rejects the whole set. A fact is never permission.
 */
export interface EditFactRequest {
  action: string;
  resources: readonly string[];
  projectDir?: string;
  /**
   * Host-declared session root; never scope proof, since the target's own
   * checkout is discovered from its path. Accepted for host-shape
   * compatibility only.
   */
  worktreeRoot?: string;
  operation?: OperationEvidence;
  editPayload?: EditPayload;
  /** Host-owned identity of the same original call; not agent prose or metadata. */
  expectedEditCapture?: EditCaptureIdentity;
  /** Read only as an eligibility flag for the metadata-only project edit path. */
  staticAnalysis?: { band: string; reason: string; findings?: readonly string[] };
}

/** The bounded payload serialized for the native call. Args are rebuilt from the
 * frozen capture; the capture digest and other provenance never egress. */
export interface EditCandidate {
  input: {
    args: Record<string, string | boolean>;
    target: string;
    tool: "edit" | "write";
  };
}

export type EditCandidateResult =
  | { ok: true; candidate: EditCandidate }
  | { ok: false; reason: string };

export const LOCAL_EDIT_QUESTION: Generate.ChoiceQuestion = freezeQuestion({
  type: "choice",
  name: "edit_effect",
  instructions: "Classify complete tool-call effects, not safety or permission.",
  choices: [
    {
      value: "local_edit",
      description: "The full captured payload directly edits or writes the named local target: a complete oldString/newString edit pair or a complete write content, confined to that one local file path.",
    },
    {
      value: "other",
      description: "Payload incomplete or truncated, opaque execution or executor effect, remote API or network transmission, or effects mixed across local and non-local targets.",
    },
  ],
});

export const EDIT_EXPECTED: { readonly name: string; readonly values: readonly (string | boolean)[] } =
  Object.freeze({ name: "edit_effect", values: Object.freeze(["local_edit", "other"]) });

/** Metadata-only and content-free: a `true` at or above the floor certifies
 * only the `project_edit` fact kind. */
export const EDIT_IN_PROJECT_QUESTION: Generate.ChoiceQuestion = freezeQuestion({
  type: "choice",
  name: "edit_in_project",
  instructions: "Is this an ordinary edit to project files (source, tests, docs, config) inside the project, not to secrets, credentials, VCS internals or files outside the project? Answer false if unsure.",
  choices: [
    {
      value: true,
      description: "An ordinary edit to project files (source, tests, docs, config) inside the project.",
    },
    {
      value: false,
      description: "An edit to secrets, credentials, VCS internals or files outside the project, or unsure.",
    },
  ],
});

export const EDIT_IN_PROJECT_EXPECTED: { readonly name: string; readonly values: readonly (string | boolean)[] } =
  Object.freeze({ name: "edit_in_project", values: Object.freeze([true, false]) });

/** Metadata-only in-project edit candidate; never a body or authority. */
export interface ProjectEditCandidate {
  input: {
    tool: string;
    targets: string[];
    projectDir: string;
  };
}

export type ProjectEditCandidateResult =
  | { ok: true; candidate: ProjectEditCandidate }
  | { ok: false; reason: string };

export const MAX_EDIT_PAYLOAD_BYTES = MAX_CAPTURED_BODY_BYTES;
const MAX_TARGETS = 64;
const EDIT_TOOLS = new Set(["edit", "write"]);
const BUILTIN_ACTIONS = new Set(["edit", "write"]);
/** Only a plain `edit` action with a single-path `edit` or `write` tool
 * qualifies; multi-path patch tools and `external_directory` stay on the body path. */
const PROJECT_EDIT_ACTION = "edit";
const PROJECT_EDIT_TOOLS = new Set(["edit", "write"]);
const PROJECT_EDIT_INTERNALS = new Set([".git", ".jj", ".svn", "node_modules"]);
/** The shared spelling policy does not flag every Terraform state file, so the
 * generic suffix is rejected explicitly. */
const PROJECT_EDIT_STATE = /\.tfstate$/i;
/** Path aliases stay last so path-only inputs are byte-identical. */
const EDIT_INPUT_KEYS = ["newString", "oldString", "replaceAll", "path", "filePath"] as const;
const WRITE_INPUT_KEYS = ["content", "path", "filePath"] as const;
const EXTERNAL_ACTION = "external_directory";
const PRIVATE_KEY = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/;
const CLOUD_TOKEN = /\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{16,}|xox[baprs]-[A-Za-z0-9-]{10,})\b/;
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\./;
// Any request line is suspicious, even in prose or after an escaped line break:
// a text field can embed an HTTP body without being a shell command at all.
const RAW_HTTP = /(?:POST|PUT|PATCH)\s+\S+\s+HTTP\/\d/i;
const SECRET_HEADER = /\b(?:authorization|proxy-authorization|cookie|set-cookie)["'`]?\s*:\s*/i;
const CREDENTIAL_ASSIGNMENT = /(?:api[_-]?key|apikey|secret(?:[_-]?key)?|client[_-]?secret|private[_-]?key|password|passwd|passphrase|token|access[_-]?token|refresh[_-]?token|auth[_-]?token|authorization|credentials?)["'`]?\s*[:=]\s*(?:["'`][^"'`\n]{4,}["'`]|[A-Za-z0-9+_=-]{16,})/i;
const SECRET_FIELD = /(?:^|[-_])(?:authorization|proxy-authorization|cookie|set-cookie|api[_-]?key|apikey|secret(?:[_-]?key)?|client[_-]?secret|private[_-]?key|password|passwd|passphrase|token|access[_-]?token|refresh[_-]?token|auth[_-]?token|credentials?)$/i;
const JSON_ESCAPE = /\\+(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|["\\/bfnrt])/g;
const SIMPLE_ESCAPE: Record<string, string> = {
  '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t",
};
const MAX_SCAN_NODES = 4_096;
const MAX_SCAN_DEPTH = 32;
const MIXED_TOKEN = /[A-Za-z0-9+_=-]{40,}/g;
const TOKEN_CLASSES = [/[a-z]/, /[A-Z]/, /\d/];

const isEditTool = (value: unknown): value is "edit" | "write" =>
  typeof value === "string" && EDIT_TOOLS.has(value);

const blocked = (reason: string): EditCandidateResult => ({ ok: false, reason });

const toolOf = (operation: OperationEvidence | undefined): "edit" | "write" | undefined =>
  isEditTool(operation?.tool) ? operation.tool : undefined;

/** Built-in actions are obvious; external_directory needs an edit/write tool. */
export function isEditLike(request: EditFactRequest): boolean {
  if (BUILTIN_ACTIONS.has(request.action)) return true;
  if (request.action === EXTERNAL_ACTION && toolOf(request.operation) !== undefined) return true;
  return request.editPayload !== undefined;
}

function expectedTool(request: EditFactRequest): "edit" | "write" | undefined {
  if (request.action === "edit" || request.action === "write") return request.action;
  return request.action === EXTERNAL_ACTION ? toolOf(request.operation) : undefined;
}

function normalizeTarget(value: string, projectDir?: string): string | undefined {
  if (!isUsableEditPath(value)) return undefined;
  const base = projectDir !== undefined && isAbsolute(projectDir) ? projectDir : process.cwd();
  return isAbsolute(value) ? normalize(value) : resolve(base, value);
}

/** Any unusable entry rejects the whole set; skipping it would let a truncated
 * scope masquerade as one target. */
function targetsOf(values: readonly unknown[], projectDir?: string): Set<string> | undefined {
  const targets = new Set<string>();
  for (const value of values) {
    if (typeof value !== "string") return undefined;
    const normalized = normalizeTarget(value, projectDir);
    if (normalized === undefined) return undefined;
    targets.add(normalized);
  }
  return targets;
}

/** Explicit operation targets win over permission resources; an explicit empty
 * target set is rejected rather than guessed. Resources may be an external
 * boundary such as `/outside/*`, never the edited file. */
function targetScope(request: EditFactRequest): readonly unknown[] | undefined {
  const operationTargets = request.operation?.targets;
  if (operationTargets !== undefined) {
    return Array.isArray(operationTargets) ? operationTargets : undefined;
  }
  const resources: unknown = request.resources;
  return Array.isArray(resources) ? resources : undefined;
}

/** Every supplied alias must normalize to the one captured target. */
function argumentTargetMatches(operation: OperationEvidence | undefined, target: string,
  projectDir?: string): boolean {
  const args = operation?.arguments;
  if (operation === undefined || !isRecord(args)) return false;
  let found = false;
  for (const key of ["path", "filePath"]) {
    const value = args[key];
    if (value === undefined) continue;
    found = true;
    if (typeof value !== "string" || normalizeTarget(value, projectDir) !== target) return false;
  }
  return found;
}

/** The payload path must be the one normalized target in the complete set. */
function targetMatches(request: EditFactRequest, payload: EditPayload): boolean {
  const target = normalizeTarget(payload.path, request.projectDir);
  if (target === undefined) return false;
  const source = targetScope(request);
  if (source === undefined) return false;
  const targets = targetsOf(source, request.projectDir);
  return targets !== undefined && targets.size === 1 && targets.has(target) &&
    argumentTargetMatches(request.operation, target, request.projectDir);
}

function operationConsistent(request: EditFactRequest, payload: EditPayload): boolean {
  const operation = request.operation;
  // `complete` is not consulted: the old producer omitted writer bodies and
  // marked writes incomplete, while this payload is a full validated capture.
  if (operation === undefined) return false;
  // The action/tool already prove write capability; a missing access field is
  // not a contradiction, but read/execute/unknown access is.
  if (operation.access !== undefined && operation.access !== "write") return false;
  if (operation.tool !== undefined && operation.tool !== payload.tool) return false;
  if (request.action === EXTERNAL_ACTION) return toolOf(operation) === payload.tool;
  return true;
}

/** The separate, host-owned expected identity must name this exact minted capture. */
function captureBlock(request: EditFactRequest, payload: EditPayload): string | undefined {
  const expected = readEditCapture(request.expectedEditCapture);
  if (expected === undefined || !sameEditCapture(expected, payload.capture))
    return "Edit payload capture identity does not match the expected host capture";
  return undefined;
}

function obviousSecret(value: string): boolean {
  return PRIVATE_KEY.test(value) || CLOUD_TOKEN.test(value) || JWT.test(value) ||
    RAW_HTTP.test(value) || SECRET_HEADER.test(value) || CREDENTIAL_ASSIGNMENT.test(value);
}

function mixedClassToken(value: string): boolean {
  return (value.match(MIXED_TOKEN) ?? []).some((token) =>
    TOKEN_CLASSES.every((pattern) => pattern.test(token)));
}

function textLeak(value: string): boolean {
  return obviousSecret(value) || mixedClassToken(value);
}

function decodeEscape(code: string): string {
  const simple = SIMPLE_ESCAPE[code];
  return simple ?? String.fromCharCode(Number.parseInt(code.slice(1), 16));
}

/** Decodes bounded JSON escapes so an escaped request line or key stays visible
 * to the plain-text screens; escape layers are capped, not expanded forever. */
function unescapeText(value: string): string {
  let text = value;
  for (let round = 0; round < 3; round++) {
    const next = text.replace(JSON_ESCAPE, (_match, code: string) => decodeEscape(code));
    if (next === text) break;
    text = next;
  }
  return text;
}

interface JsonScan { nodes: number }

const secretFieldValue = (value: unknown): boolean =>
  value !== undefined && value !== null && value !== "";

/** Budget exhaustion blocks rather than declaring the body safe. */
function scanJson(value: unknown, depth: number, state: JsonScan): boolean {
  if (++state.nodes > MAX_SCAN_NODES || depth > MAX_SCAN_DEPTH) return true;
  if (typeof value === "string") return textLeak(value) || nestedJsonLeak(value, depth + 1, state);
  if (Array.isArray(value)) return value.some((item) => scanJson(item, depth + 1, state));
  if (!isRecord(value)) return false;
  return Object.entries(value).some(([key, item]) =>
    SECRET_FIELD.test(key) ? secretFieldValue(item) : scanJson(item, depth + 1, state));
}

function nestedJsonLeak(value: string, depth: number, state: JsonScan): boolean {
  const trimmed = value.trim();
  if (depth > MAX_SCAN_DEPTH || !/^[{["]/.test(trimmed)) return false;
  try {
    return scanJson(JSON.parse(trimmed), depth, state);
  } catch {
    return false;
  }
}

/** JSON wrapping and escaping must not hide a request body or credential field. */
function jsonLeak(value: string): boolean {
  return nestedJsonLeak(value, 0, { nodes: 0 });
}

function textSafe(value: string): boolean {
  return redactHttpBodies(value) === value && !textLeak(value) && !jsonLeak(value);
}

/** Any redaction loss or obvious secret blocks egress; nothing is redacted and sent. */
function safeBody(value: string): boolean {
  return textSafe(value) && textSafe(unescapeText(value));
}

function payloadTexts(payload: EditPayload): string[] {
  return payload.tool === "edit"
    ? [payload.oldString ?? "", payload.newString ?? ""]
    : [payload.content ?? ""];
}

function privacyOk(payload: EditPayload): boolean {
  // Prefixed, multiline, JSON-wrapped and JSON-escaped request lines or
  // credential fields block egress instead of being redacted.
  return payloadTexts(payload).every(safeBody);
}

/** Rebuilds the payload body from the frozen args, keeping the alias and `replaceAll`. */
function modelArgs(original: Readonly<Record<string, string | boolean>>,
  keys: readonly string[]): Record<string, string | boolean> {
  const args: Record<string, string | boolean> = {};
  for (const key of keys) {
    const value = original[key];
    if (value !== undefined) args[key] = value;
  }
  return args;
}

function buildInput(payload: EditPayload): EditCandidate["input"] | undefined {
  const original = capturedEditArgs(payload);
  if (original === undefined) return undefined;
  const keys = payload.tool === "edit" ? EDIT_INPUT_KEYS : WRITE_INPUT_KEYS;
  return { args: modelArgs(original, keys), target: payload.path, tool: payload.tool };
}

function boundedInput(input: EditCandidate["input"]): EditCandidate | undefined {
  const bytes = Buffer.byteLength(JSON.stringify(input));
  return bytes <= MAX_EDIT_PAYLOAD_BYTES ? { input } : undefined;
}

function earlyBlock(request: EditFactRequest, includeEditPayload: boolean): string | undefined {
  if (includeEditPayload !== true) return "Edit payload capture is not enabled";
  if (request.resources.length > MAX_TARGETS || (request.operation?.targets?.length ?? 0) > MAX_TARGETS)
    return "Edit operation target scope is too large";
  return undefined;
}

function consistencyBlock(request: EditFactRequest, payload: EditPayload): string | undefined {
  if (payload.tool !== expectedTool(request)) return "Edit payload tool does not match the operation";
  if (!operationConsistent(request, payload)) return "Edit operation capability does not match the payload";
  if (!targetMatches(request, payload)) return "Edit payload path does not match the single operation target";
  return undefined;
}

const PATH_POLICY_BLOCK = "Edit payload path is protected, ambiguous or unresolved";
const MAX_GIT_MARKER_BYTES = 4_096;

/** `.git` is checkout evidence, not a permission source. A symlink marker is
 * rejected, and the whole-path credential guard still runs first. */
function gitMarker(root: string): boolean {
  const marker = join(root, ".git");
  try {
    const fact = lstatSync(marker);
    if (fact.isSymbolicLink()) return false;
    if (fact.isDirectory()) return true;
    return fact.isFile() && fact.size <= MAX_GIT_MARKER_BYTES &&
      linkedGitDir(root, readFileSync(marker, "utf8"));
  } catch { return false; }
}

function linkedGitDir(root: string, contents: string): boolean {
  const line = contents.split(/\r?\n/, 1)[0]?.trim() ?? "";
  if (!line.startsWith("gitdir:")) return false;
  const value = line.slice("gitdir:".length).trim();
  if (value.length === 0) return false;
  try { return lstatSync(isAbsolute(value) ? value : resolve(root, value)).isDirectory(); }
  catch { return false; }
}

function existingDirectory(target: string): string | undefined {
  let current = dirname(target);
  while (true) {
    try { return realpathSync(current); }
    catch {
      const parent = dirname(current);
      if (parent === current) return undefined;
      current = parent;
    }
  }
}

/** The fallback location is not a verified worktree root. */
function targetWorktreeRoot(target: string): string | undefined {
  const location = existingDirectory(target);
  if (location === undefined) return undefined;
  try {
    const root = getWorktreeScope(location).worktreeRoot;
    return gitMarker(root) ? root : undefined;
  } catch { return undefined; }
}

type ComponentState = "bad" | "missing" | "ok";

/** Only a live regular file with a single link is an edit target; a missing
 * path is a creation candidate that the caller's component walk must still
 * prove, and symlinks, devices, FIFOs and hardlinks are never one-file edits. */
function plainTarget(target: string): boolean {
  try {
    const fact = lstatSync(target);
    return fact.isFile() && fact.nlink === 1;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT";
  }
}

function componentState(target: string): ComponentState {
  try {
    const stat = lstatSync(target);
    return stat.isSymbolicLink() || (!stat.isFile() && !stat.isDirectory()) ? "bad" : "ok";
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT" ? "missing" : "bad";
  }
}

/** Missing suffixes can be created, but an existing symlink or special file
 * anywhere below the root rejects the whole path. */
function clearComponents(root: string, target: string): boolean {
  let current = root;
  for (const part of relative(root, target).split(sep)) {
    if (part.length === 0 || part === "." || part === "..") return false;
    current = join(current, part);
    const state = componentState(current);
    if (state === "bad") return false;
    if (state === "missing") return true;
  }
  return true;
}

/** A review caused only by dot-prefixed ancestors above the target's own
 * checkout is re-evaluated with that checkout as the base. */
function scopedPath(target: string): boolean {
  const root = targetWorktreeRoot(target);
  if (root === undefined || !isInside(root, target) || !clearComponents(root, target)) return false;
  const policy = classifyPath(target, root);
  return policy.kind === "ordinary" && !policy.review;
}

/** A relative root is never widened into the process directory, and the
 * compatibility-only `worktreeRoot` declaration is never containment proof:
 * only a Git root discovered from the project directory may widen it, with the
 * canonical project directory itself as the non-Git fallback. */
function projectRoot(request: EditFactRequest): string | undefined {
  const projectDir = request.projectDir;
  if (projectDir === undefined || !isAbsolute(projectDir)) return undefined;
  const canonical = canonicalPath(projectDir);
  return discoveredRoot(canonical) ?? canonical;
}

/** Keeps the lexical spelling when the project directory does not exist yet. */
function canonicalPath(value: string): string {
  try { return realpathSync(value); } catch { return normalize(value); }
}

/** A discovered root still needs a real marker and containment of the project
 * directory before it may stand in for the project-directory boundary. */
function discoveredRoot(projectDir: string): string | undefined {
  try {
    const root = getWorktreeScope(projectDir).worktreeRoot;
    return gitMarker(root) && isInside(root, projectDir, true) ? root : undefined;
  } catch { return undefined; }
}

/** Keeps a not-yet-created suffix so a symlinked ancestor cannot move the target. */
function canonicalTargetPath(target: string): string | undefined {
  let current = target;
  const missing: string[] = [];
  while (true) {
    try { return join(realpathSync(current), ...missing); }
    catch {
      const parent = dirname(current);
      if (parent === current) return undefined;
      missing.unshift(basename(current));
      current = parent;
    }
  }
}

/** An external permission boundary must not hide behind an in-project target. */
function projectScopeValues(request: EditFactRequest): readonly unknown[] | undefined {
  const declared = request.operation?.targets;
  const resources: readonly unknown[] = Array.isArray(request.resources) ? request.resources : [];
  if (declared === undefined) return resources.length > 0 ? resources : undefined;
  if (!Array.isArray(declared) || declared.length === 0) return undefined;
  return [...declared, ...resources];
}

/** The shared path policy decides credentials, dot names and ambiguity; the
 * dependency/VCS exclusions stay explicit because spelling alone allows them. */
function projectPathAllowed(root: string, canonical: string, rel: string): boolean {
  if (rel.split(sep).some((part) => PROJECT_EDIT_INTERNALS.has(part.toLowerCase()))) return false;
  if (PROJECT_EDIT_STATE.test(rel)) return false;
  const policy = classifyPath(canonical, root);
  return policy.kind === "ordinary" && !policy.review;
}

/** Both policy branches require an existing target to be a regular single-link
 * file; only a missing suffix stays a creation candidate after the review
 * branch's component walk. That branch discovers the target's own root, so
 * `request.worktreeRoot` stays host context rather than proof. */
function pathBlock(payload: EditPayload, request: EditFactRequest): string | undefined {
  const policy = classifyPath(payload.path, request.projectDir);
  if (policy.kind !== "ordinary") return PATH_POLICY_BLOCK;
  const target = normalizeTarget(payload.path, request.projectDir);
  if (target === undefined || !plainTarget(target)) return PATH_POLICY_BLOCK;
  if (policy.review && !scopedPath(target)) return PATH_POLICY_BLOCK;
  return undefined;
}

/** Pre-call gate for the edit fact. Only a factory-minted payload whose capture
 * identity equals the host-expected identity reaches generation; the same-call
 * operation must carry `path`/`filePath` and the effective target list must
 * contain exactly that one normalized path. The payload path is classified
 * before generation: protected and unresolved paths never egress, and a path
 * with only a dot-prefixed ancestor above its own verified worktree root is
 * reclassified with that root. Privacy screening blocks anything that merely
 * looks like a request body or credential. */
export function prepareEditCandidate(request: EditFactRequest, includeEditPayload: boolean): EditCandidateResult {
  try {
    const early = earlyBlock(request, includeEditPayload);
    if (early !== undefined) return blocked(early);
    const payload = verifyCapturedEdit(request.editPayload);
    if (payload === undefined)
      return blocked("Edit payload capture proof is missing, malformed or not factory-minted");
    const captureMismatch = captureBlock(request, payload);
    if (captureMismatch !== undefined) return blocked(captureMismatch);
    const inconsistent = consistencyBlock(request, payload);
    if (inconsistent !== undefined) return blocked(inconsistent);
    const input = buildInput(payload);
    if (input === undefined)
      return blocked("Edit payload capture proof cannot be rebuilt from its original args");
    const candidate = boundedInput(input);
    if (candidate === undefined) return blocked("Edit payload exceeds the 16 KiB classification bound");
    const pathRejected = pathBlock(payload, request);
    if (pathRejected !== undefined) return blocked(pathRejected);
    if (!privacyOk(payload)) return blocked("Edit payload contains obvious credentials, HTTP bodies or unredactable secrets");
    return { ok: true, candidate };
  } catch {
    return blocked("Edit payload could not be structurally validated");
  }
}

interface ProjectEditScope {
  readonly tool: string;
  readonly projectDir: string;
  readonly root: string;
}

function projectEditTool(operation: OperationEvidence | undefined): string | undefined {
  if (operation === undefined || operation.tool === undefined || !PROJECT_EDIT_TOOLS.has(operation.tool)) return undefined;
  return operation.access === undefined || operation.access === "write" ? operation.tool : undefined;
}

function projectEditStatic(request: EditFactRequest): boolean {
  const analysis = request.staticAnalysis;
  return analysis !== undefined && (analysis.findings?.length ?? 0) === 0;
}

function projectEditScope(request: EditFactRequest): ProjectEditScope | undefined {
  const tool = projectEditTool(request.operation);
  if (tool === undefined || request.action !== PROJECT_EDIT_ACTION || !projectEditStatic(request)) return undefined;
  const projectDir = request.projectDir;
  if (projectDir === undefined || !isAbsolute(projectDir)) return undefined;
  const root = projectRoot(request);
  return root === undefined ? undefined : { tool, projectDir, root };
}

/** Ancestor spellings of `value`, outermost filesystem root first. */
function ancestorSpellings(value: string): string[] {
  const spellings: string[] = [];
  let current = value;
  while (true) {
    spellings.push(current);
    const parent = dirname(current);
    if (parent === current) return spellings.reverse();
    current = parent;
  }
}

/** The outermost spelling prefix of `resolved` that resolves to the checkout
 * root. Choosing the outermost one keeps a symlinked root spelling working
 * while any descendant alias of the root stays visible to the component walk. */
function rootSpelling(root: string, resolved: string): string | undefined {
  for (const spelling of ancestorSpellings(resolved)) {
    try {
      if (realpathSync(spelling) === root) return spelling;
    } catch { /* missing suffix: keep walking toward the filesystem root */ }
  }
  return undefined;
}

interface ProjectTarget { readonly canonical: string; readonly rel: string }

/** Existing components must stay non-symlink and a final file must have one link;
 * a missing suffix is a new file only while every existing ancestor below the
 * containment root is safe. */
function safeProjectTarget(root: string, resolved: string, canonical: string): boolean {
  const base = rootSpelling(root, resolved);
  return base !== undefined && clearComponents(base, resolved) && plainTarget(canonical);
}

function projectTarget(value: unknown, scope: ProjectEditScope): ProjectTarget | undefined {
  if (typeof value !== "string" || !isUsableEditPath(value)) return undefined;
  const resolved = normalizeTarget(value, scope.projectDir);
  const canonical = resolved === undefined ? undefined : canonicalTargetPath(resolved);
  if (resolved === undefined || canonical === undefined) return undefined;
  if (!isInside(scope.root, canonical) || !safeProjectTarget(scope.root, resolved, canonical))
    return undefined;
  const rel = relative(scope.root, canonical);
  if (!projectPathAllowed(scope.root, canonical, rel)) return undefined;
  return { canonical, rel };
}

/** Original argument aliases get the full target policy, not only
 * canonicalization: a protected or symlink designation must not ride an
 * ordinary resource path onto the same canonical file. */
function argumentTarget(operation: OperationEvidence | undefined,
  scope: ProjectEditScope): string | undefined {
  const args = operation?.arguments;
  if (!isRecord(args)) return undefined;
  const targets = new Set<string>();
  for (const key of ["path", "filePath"]) {
    const value = args[key];
    if (value === undefined) continue;
    const target = projectTarget(value, scope);
    if (target === undefined) return undefined;
    targets.add(target.canonical);
  }
  return targets.size === 1 ? [...targets][0] : undefined;
}

function projectEditTargets(request: EditFactRequest, scope: ProjectEditScope): string[] | undefined {
  const values = projectScopeValues(request);
  const captured = argumentTarget(request.operation, scope);
  if (values === undefined || values.length > MAX_TARGETS || captured === undefined) return undefined;
  const canonical = new Set<string>();
  const relatives = new Set<string>();
  for (const value of values) {
    const target = projectTarget(value, scope);
    if (target === undefined) return undefined;
    canonical.add(target.canonical);
    relatives.add(target.rel);
  }
  if (canonical.size !== 1 || !canonical.has(captured)) return undefined;
  return [...relatives].sort();
}

function projectEditInput(tool: string, targets: string[], projectDir: string): ProjectEditCandidateResult {
  const input = { tool, targets, projectDir: basename(projectDir) };
  const text = JSON.stringify(input);
  if (Buffer.byteLength(text) > MAX_EDIT_PAYLOAD_BYTES || !textSafe(text))
    return { ok: false, reason: "Metadata-only edit fact input is unbounded or unsafe" };
  return { ok: true, candidate: { input } };
}

/** Metadata-only path used when body capture is disabled: never reads content,
 * never produces permission, and only a plain in-project `edit`/`write` call
 * with one canonical, policy-allowed target qualifies. */
export function prepareProjectEditCandidate(request: EditFactRequest): ProjectEditCandidateResult {
  try {
    const scope = projectEditScope(request);
    if (scope === undefined) return { ok: false, reason: "Metadata-only edit fact is not eligible" };
    const targets = projectEditTargets(request, scope);
    if (targets === undefined) return { ok: false, reason: "Metadata-only edit fact has no eligible target scope" };
    return projectEditInput(scope.tool, targets, scope.projectDir);
  } catch {
    return { ok: false, reason: "Metadata-only edit fact could not be prepared" };
  }
}
