/** Fact classification only: never a permission, approval or safety verdict. */
import { lstatSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, parse, resolve, sep } from "node:path";
import { Model } from "@opencode/schema/model";
import type { Generate } from "@opencode/schema/generate";
import { DEFAULT_FACT_REVIEW_CONFIDENCE, MIN_FACT_REVIEW_CONFIDENCE } from "./config.js";
import {
  buildDecisionEvidence,
  type DecisionEvidence,
  type DecisionEvidenceOperation,
  type OperationAccess,
} from "./decision-evidence.js";
import type { DecisionContext, DecisionInput } from "./decision.js";
import {
  EDIT_EXPECTED,
  EDIT_IN_PROJECT_EXPECTED,
  EDIT_IN_PROJECT_QUESTION,
  isEditLike,
  LOCAL_EDIT_QUESTION,
  prepareEditCandidate,
  prepareProjectEditCandidate,
  type EditCaptureIdentity,
  type EditPayload,
} from "./edit-fact.js";
import { errorKindOf, ReviewFailure, type ReviewErrorKind } from "./errors.js";
import {
  formatProbability,
  freezeQuestion,
  freshQuestion,
  isChoiceValue,
  isProbability,
  isRecord,
  MAX_CAPTURED_BODY_BYTES,
  MAX_REQUEST_BYTES,
  probabilityDistribution,
} from "./guards.js";
import { classifyPath, envName, isInside, PROTECTED_NAME, PROTECTED_SUFFIX } from "./path-policy.js";
import type { PermissionRequest } from "./reviewer.js";
import { splitShellSegmentsWithLeadingCd, type ShellSegmentSplit } from "./shell-segments.js";
import { withTimeout } from "./timeout.js";

export type { EditCaptureIdentity, EditPayload } from "./edit-fact.js";

/** Operation facts only; user messages and transcripts are outside this stage.
 * Static analysis is only an eligibility flag, never a classification input. */
export type OperationFactRequest = Pick<PermissionRequest, "action" | "resources" | "operation" | "projectDir" | "worktreeRoot" | "staticAnalysis"> & {
  /** Host-minted binding of the captured body; never agent assertions. */
  editPayload?: EditPayload;
  /** Host-owned identity of the same capture; edit classification requires both
   * payload and identity. Supplied structurally by the host, never by agent
   * prose or model output; a binding, never a permission or approval. */
  expectedEditCapture?: EditCaptureIdentity;
};

export interface OperationFactOptions {
  model: string;
  minConfidence?: number;
  /** Both calls share this deadline. */
  timeoutMs?: number;
  /** Opt-in capture of the edit/write body for `local_edit`; defaults to false.
   * Not user consent: the caller must obtain explicit consent, and both the
   * payload and its expected capture identity must be present or no call is made. */
  includeEditPayload?: boolean;
}

/** A factual class only, never an effect-safety review, permission or approval.
 * `local_edit` names one captured body; `project_edit` one metadata-only
 * in-project edit; `delegation` says nothing about the child's actions. A local
 * edit can add network code when later executed, so no impact claim is made. */
export type OperationFactKind = "inspection" | "test_run" | "shell_segments" | "command_local" | "local_edit" | "project_edit" | "delegation" | "unknown";

export interface OperationFactResult {
  kind: OperationFactKind;
  probability?: number;
  reason: string;
  errorKind?: ReviewErrorKind;
}

/** Frozen binary inspection question; never an authorization or safety ask. */
export const INSPECTION_QUESTION: Generate.ChoiceQuestion = freezeQuestion({
  type: "choice",
  name: "inspection",
  instructions: "Classify the complete actual operation effects; shell wrappers do not sanitize writes or egress.",
  choices: [
    {
      value: true,
      description: "Only reads, searches, lists or inspects data, no writes/deletes/arbitrary scripts or transmission of local data.",
    },
    {
      value: false,
      description: "Writes/deletes/executes opaque code/transmits local data/modifies remote state, or effects uncertain.",
    },
  ],
});

/** Appended to segment questions: the input adds `fullCommand` context, but the answer judges `command` alone. */
const SEGMENT_CONTEXT_SUFFIX = " Judge only `command`; `fullCommand` is context (e.g. a segment that only filters or prints the output of the previous one).";

export const SEGMENT_INSPECTION_QUESTION: Generate.ChoiceQuestion = freezeQuestion({
  type: "choice",
  name: "inspection",
  instructions: `${INSPECTION_QUESTION.instructions}${SEGMENT_CONTEXT_SUFFIX}`,
  choices: INSPECTION_QUESTION.choices.map((choice) => ({ ...choice })),
});

/** Frozen five-label question; never a run authorization. */
export const OPERATION_KIND_QUESTION: Generate.ChoiceQuestion = freezeQuestion({
  type: "choice",
  name: "operation_kind",
  instructions: "Identify what the complete command does, not whether it is authorized. All chained effects must fit one category; if mixed choose other.",
  choices: [
    { value: "test_run", description: "Runs the project test tooling, e.g. go test, bun test; does not publish or install." },
    { value: "repository_read", description: "Reads repository history or state only, e.g. git log, git show, git tag, git status; changes nothing." },
    { value: "local_branch_create", description: "Creates a local git branch only, e.g. git switch -c, git checkout -b; no push, no history rewrite." },
    { value: "history_rewrite", description: "Rewrites existing commits, e.g. git rebase, git commit --amend, git reset --hard." },
    { value: "other", description: "Chained effects are mixed across categories, or the command is not one of the above." },
  ],
});

/** Frozen binary segment question, asked only when that segment's `inspection`
 * missed the floor; it never authorizes the command. */
export const SEGMENT_LOCAL_QUESTION: Generate.ChoiceQuestion = freezeQuestion({
  type: "choice",
  name: "segment_local",
  instructions: "Does this single command segment only read files or repository state, run the project's own tests/checks/linters/typecheck/formatters/code generation, or write, change or delete files only inside the working directory — with no network access, package/tool installation, git commit/push/history rewrite/worktree or branch changes, docker/containers, or deleting anything outside the working directory? Answer false if unsure." + SEGMENT_CONTEXT_SUFFIX,
  choices: [
    {
      value: true,
      description: "Only reads files or repository state, runs the project's own tests/checks/linters/typecheck/formatters/code generation, or writes, changes or deletes files only inside the working directory, with no network access.",
    },
    {
      value: false,
      description: "Network access, package/tool installation, git commit/push/history rewrite/worktree or branch changes, docker/containers, writing, changing or deleting files outside the working directory, any other effect, or unsure.",
    },
  ],
});

/** Frozen binary whole-command question. `true` certifies `command_local`, never
 * `inspection`, because it may write to tempDir outside the project, so the full
 * safety and authorization review still runs. */
export const COMMAND_LOCAL_QUESTION: Generate.ChoiceQuestion = freezeQuestion({
  type: "choice",
  name: "command_local",
  instructions: "Does this complete command only read files or repository state, run the project's own tests/checks/linters/formatters/code generation, and write files only inside the working directory or inside tempDir — with no network access, package/tool installation, git commit/push/history rewrite/worktree or branch changes, docker/containers, or deleting anything outside tempDir? Answer false if unsure.",
  choices: [
    {
      value: true,
      description: "Only reads files or repository state, runs the project's own tests/checks/linters/formatters/code generation, and writes files only inside the working directory or inside tempDir.",
    },
    {
      value: false,
      description: "Network access, package/tool installation, git commit/push/history rewrite/worktree or branch changes, docker/containers, deleting anything outside tempDir, any other effect, or unsure.",
    },
  ],
});

/** Frozen binary read-only question for one non-shell, non-file tool call; never an authorization or safety ask. */
export const TOOL_READONLY_QUESTION: Generate.ChoiceQuestion = freezeQuestion({
  type: "choice",
  name: "tool_readonly",
  instructions: "Does this tool call only read or search information (local or remote) and never create, send, post, update, delete, publish, comment, react, merge, or otherwise change any state, here or in any external system? For scripts, every tool the script calls must be read-only. Answer false if unsure.",
  choices: [
    {
      value: true,
      description: "Only reads or searches information, local or remote, and changes no state anywhere; every scripted tool call is read-only.",
    },
    {
      value: false,
      description: "Creates, sends, posts, updates, deletes, publishes, comments, reacts, merges or otherwise changes state, or unsure.",
    },
  ],
});

interface ExpectedChoice {
  name: string;
  values: readonly (string | boolean)[];
}

const INSPECTION_EXPECTED: ExpectedChoice = { name: "inspection", values: [true, false] };
const OPERATION_KIND_EXPECTED: ExpectedChoice = {
  name: "operation_kind",
  values: ["test_run", "repository_read", "local_branch_create", "history_rewrite", "other"],
};
const SEGMENT_LOCAL_EXPECTED: ExpectedChoice = { name: "segment_local", values: [true, false] };
const COMMAND_LOCAL_EXPECTED: ExpectedChoice = { name: "command_local", values: [true, false] };
const TOOL_READONLY_EXPECTED: ExpectedChoice = { name: "tool_readonly", values: [true, false] };

const DEFAULT_TIMEOUT_MS = 3_000;
/** Distributions must sum to 1 within 1e-6; invalid vectors abstain rather than being renormalized. */
const TOLERANCE = 1e-6;
const SHELL_ACTIONS = new Set(["shell", "bash"]);
const SHELL_TOOLS = new Set(["shell", "bash"]);
const WORKDIR_KEYS = ["workdir", "cwd", "directory"] as const;
/** Delegation actions; an `execute` script is a captured tool call, not delegation. */
const OPAQUE_ACTIONS = new Set(["subagent", "task"]);
const DELEGATION_TOOLS = new Set(["subagent", "task"]);
/** File tools keep their existing paths; the tool-call question never replaces them. */
const FILE_TOOLS = new Set(["read", "list", "ls", "glob", "grep", "edit", "write", "patch", "multiedit", "apply_patch"]);
const EXECUTE_TOOL = "execute";
/** Tools that create, modify or delete state; none may certify a read-only fact,
 * even when the action name is not edit-like and the access is read or unknown. */
const WRITE_CAPABLE_TOOLS = new Set(["edit", "write", "patch", "multiedit", "apply_patch", "todowrite"]);
const OPAQUE_REASON = "Opaque execution or delegation has no reusable operation fact";
const DELEGATION_REASON = "Delegation operation has a complete captured prompt; authorization is reviewed separately";
const NO_SCRIPT_REASON = "Execute operation has no bounded captured script";
const SCRIPT_PROTECTED_REASON = "Execute script names a protected path or credential store";
const WRITE_ACCESS_REASON = "Declared write access has no read-only operation fact";
/** Shared with fact-review: a write-capable tool can never certify inspection. */
export const WRITE_TOOL_REFUSAL_REASON = "Write-capable tool has no read-only operation fact";
const NO_ARGUMENTS_REASON = "Tool operation has no captured arguments";
const NO_COMMAND_REASON = "Shell operation has no complete captured command";
const NO_CWD_REASON = "Shell operation has no usable explicit cwd";
const UNCONFINED_CD_REASON = "Shell leading cd target is not a confined literal path";
/** Glob, home, variable or shell-substitution expansion, a backtick, or a newline means the cwd is not concrete. */
const UNUSABLE_CWD = /[*?$`\n]|^~/;

const isShellAction = (action: string): boolean => SHELL_ACTIONS.has(action);

type ParsedChoice = { selected: string | boolean; probability: number };

type StageLimits = { model: ReturnType<typeof Model.Ref.parse>; minConfidence: number; deadline: number };

function modelRef(value: string): ReturnType<typeof Model.Ref.parse> {
  try {
    return Model.Ref.parse(value);
  } catch (error) {
    throw new ReviewFailure("context", "Invalid operation fact model", { cause: error });
  }
}

function stageLimits(options: OperationFactOptions): StageLimits {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const minConfidence = options.minConfidence ?? DEFAULT_FACT_REVIEW_CONFIDENCE;
  if (typeof options.model !== "string" || options.model.trim().length === 0 ||
      !Number.isFinite(timeoutMs) || timeoutMs <= 0 || !isProbability(minConfidence) ||
      minConfidence < MIN_FACT_REVIEW_CONFIDENCE)
    throw new ReviewFailure("context", "Invalid operation fact options");
  // One deadline for both stages: a second call never receives a fresh budget.
  return { model: modelRef(options.model), minConfidence, deadline: Date.now() + timeoutMs };
}

/** Copies exactly the five allowed evidence fields; raw metadata/source and user authority are never selected. */
function restrictedRequest(request: OperationFactRequest): OperationFactRequest {
  return {
    action: request.action,
    resources: request.resources,
    ...(request.operation === undefined ? {} : { operation: request.operation }),
    ...(request.projectDir === undefined ? {} : { projectDir: request.projectDir }),
    ...(request.worktreeRoot === undefined ? {} : { worktreeRoot: request.worktreeRoot }),
  };
}

const evidenceFor = (request: OperationFactRequest): DecisionEvidence =>
  buildDecisionEvidence(restrictedRequest(request));

/**
 * Stable factual input contract, version v2. Inputs are built only from
 * `buildDecisionEvidence` output, never the raw request: `{action, resources,
 * operation, projectDir, worktreeRoot}` in that order with absent fields
 * omitted, the nested operation in the producer's exact key order, and shell
 * inputs as `{command, cwd}`. Changing these keys, their order or their
 * derivation requires a new contract version.
 */
export const OPERATION_FACT_INPUT_CONTRACT_VERSION = "v2";

const withoutUndefined = <T extends object>(value: T): T =>
  Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined)) as T;

type OperationFactInput = {
  action: string;
  resources: readonly string[];
  operation?: DecisionEvidenceOperation;
  projectDir?: string;
  worktreeRoot?: string;
};

function operationFactOperation(operation: DecisionEvidenceOperation): DecisionEvidenceOperation {
  return withoutUndefined({
    tool: operation.tool,
    access: operation.access,
    targets: operation.targets,
    arguments: operation.arguments,
    complete: operation.complete,
  });
}

function buildOperationFactInput(evidence: DecisionEvidence): OperationFactInput {
  return withoutUndefined({
    action: evidence.action,
    resources: evidence.resources,
    operation: evidence.operation === undefined ? undefined : operationFactOperation(evidence.operation),
    projectDir: evidence.projectDir,
    worktreeRoot: evidence.worktreeRoot,
  });
}

type ShellFactInput = { command: string; cwd?: string };

/** Complete original captured command; never rebuilt from resources or targets,
 * and never synthesized when the capture lost it. */
function capturedCommand(evidence: DecisionEvidence): string | undefined {
  const command = evidence.operation?.arguments?.command;
  return typeof command === "string" && command.trim().length > 0 ? command : undefined;
}

type ExplicitCwd = { value?: string; unusable: boolean };

type PhysicalWalk = { readonly path: string; readonly parentAfterSymlink: boolean };

/** Physical path, resolved component by component so a captured `..` follows the
 * link target's parent instead of lexically erasing the link (as macOS realpath
 * normalizes `link/..`); undefined when any component does not resolve. Also
 * reports a `..` after a symlink: Bash folds a folded `cd` logically (`link/..`
 * deletes the name), so such a walk names a directory Bash never enters. */
function physicalWalk(value: string): PhysicalWalk | undefined {
  if (!isAbsolute(value)) return undefined;
  const root = parse(value).root;
  let current = root;
  let symlinked = false;
  let parentAfterSymlink = false;
  for (const part of value.slice(root.length).split(sep)) {
    if (part === "" || part === ".") continue;
    if (part === "..") {
      parentAfterSymlink = parentAfterSymlink || symlinked;
      current = dirname(current);
      continue;
    }
    const candidate = current.endsWith(sep) ? `${current}${part}` : `${current}${sep}${part}`;
    try {
      symlinked = symlinked || lstatSync(candidate).isSymbolicLink();
      current = realpathSync(candidate);
    } catch {
      return undefined;
    }
  }
  return { path: current, parentAfterSymlink };
}

const physicalPath = (value: string): string | undefined => physicalWalk(value)?.path;

/** Absolute spelling against its base before normalization: realpath must see the
 * literal components so a symlink followed by `..` cannot be flattened. */
function absoluteTarget(value: string, base: string | undefined): string | undefined {
  if (isAbsolute(value)) return value;
  return base !== undefined && isAbsolute(base) ? `${base}${sep}${value}` : undefined;
}

/** Confines a captured cwd against the root: when the root exists physically the
 * target must exist and stay inside it, else a synthetic root keeps the lexical
 * check. A missing directory or escaping symlink is unusable, never a fallback. */
function confinedPath(target: string, root: string): string | undefined {
  const realRoot = physicalPath(root);
  if (realRoot !== undefined) {
    const realTarget = physicalPath(target);
    return realTarget !== undefined && isInside(realRoot, realTarget, true) ? realTarget : undefined;
  }
  const resolved = resolve(target);
  return isInside(resolve(root), resolved, true) ? resolved : undefined;
}

/** Explicit workdir confined to the worktree root, or projectDir when there is no
 * worktree root; an unrelatable or escaping path is unusable, never a fallback. */
function confinedWorkdir(value: string, projectDir: string | undefined,
  worktreeRoot: string | undefined): string | undefined {
  const root = worktreeRoot ?? projectDir;
  if (root === undefined || !isAbsolute(root)) return undefined;
  const target = absoluteTarget(value, projectDir);
  return target === undefined ? undefined : confinedPath(target, root);
}

/** Folded leading `cd` resolved against the effective shell cwd with the same
 * containment as an explicit workdir; a `..` after a symlink has no usable cwd
 * because Bash's logical `cd` lands where the physical walk does not. */
function foldedCwd(target: string, cwd: string | undefined, evidence: DecisionEvidence): string | undefined {
  const root = evidence.worktreeRoot ?? evidence.projectDir;
  if (root === undefined || !isAbsolute(root)) return undefined;
  const value = absoluteTarget(target, cwd);
  if (value === undefined) return undefined;
  const walk = physicalWalk(value);
  if (walk?.parentAfterSymlink === true) return undefined;
  return confinedPath(value, root);
}

/** First explicit workdir, cwd or directory in canonical key order; expansion or
 * escape makes it unusable, never a fallback. */
function explicitCwd(evidence: DecisionEvidence): ExplicitCwd {
  const args = evidence.operation?.arguments;
  for (const key of WORKDIR_KEYS) {
    const value = args?.[key];
    if (typeof value !== "string") continue;
    if (value.trim().length === 0 || UNUSABLE_CWD.test(value)) return { unusable: true };
    const resolved = confinedWorkdir(value, evidence.projectDir, evidence.worktreeRoot);
    return resolved === undefined ? { unusable: true } : { value: resolved, unusable: false };
  }
  return { unusable: false };
}

/** Command first, cwd only when established. */
const shellInput = (command: string, cwd: string | undefined): ShellFactInput =>
  cwd === undefined ? { command } : { command, cwd };

/** Secondary shell input; undefined when no original command was captured or the
 * cwd is unusable, since that operation cannot be classified at all. */
function buildShellFactInput(evidence: DecisionEvidence): ShellFactInput | undefined {
  const command = capturedCommand(evidence);
  if (command === undefined) return undefined;
  const explicit = explicitCwd(evidence);
  if (explicit.unusable) return undefined;
  return shellInput(command, explicit.value ?? evidence.projectDir);
}

/** Segment first, then the whole captured command as context, its index and the established segment cwd. */
type SegmentFactInput = { command: string; fullCommand: string; segmentIndex: number; cwd?: string };

const segmentInput = (command: string, fullCommand: string, segmentIndex: number,
  cwd: string | undefined): SegmentFactInput =>
  withoutUndefined({ command, fullCommand, segmentIndex, cwd });

/** Exact captured command, the established cwd, and the host temp directory the command may write inside. */
type CommandLocalInput = { command: string; cwd?: string; tempDir: string };

const commandLocalInput = (shell: ShellFactInput, tempDir: string): CommandLocalInput =>
  withoutUndefined({ command: shell.command, cwd: shell.cwd, tempDir });

const concreteScope = (value: unknown): boolean =>
  typeof value === "string" && value.trim().length > 0 && value !== "*";

function rawScope(request: OperationFactRequest): boolean {
  return request.resources.some(concreteScope) || (request.operation?.targets ?? []).some(concreteScope);
}

/** The producer-trusted operation advertises its own capability; unknown or
 * incomplete capabilities never reach generation, so they cannot yield a fact. */
function capableOperation(evidence: DecisionEvidence): boolean {
  const operation = evidence.operation;
  if (operation === undefined || operation.complete !== true || operation.tool === undefined) return false;
  if (operation.access === "unknown") return false;
  if (!isShellAction(evidence.action)) return true;
  return operation.access === "execute" && SHELL_TOOLS.has(operation.tool);
}

/** `{tool, access, arguments}` for an ordinary tool, `{tool, access, script}` for
 * a Code Mode script; the declared access travels with the call. */
type ToolFactInput =
  | { tool: string; access: OperationAccess; arguments: Record<string, unknown> }
  | { tool: "execute"; access: OperationAccess; script: string };

type ToolFactPlan =
  | { readonly kind: "none" }
  | { readonly kind: "input"; readonly input: ToolFactInput }
  | { readonly kind: "refuse"; readonly reason: string };

type ToolCall =
  | { readonly kind: "none" }
  | { readonly kind: "tool"; readonly tool: string; readonly access: OperationAccess }
  | { readonly kind: "refuse"; readonly reason: string };

const eligibleTool = (tool: string): boolean =>
  !SHELL_TOOLS.has(tool) && !FILE_TOOLS.has(tool) && !DELEGATION_TOOLS.has(tool);

/** A write-capable tool is never eligible for a read-only fact or the generic inspection question. */
export const isWriteCapableTool = (tool: string | undefined): boolean =>
  tool !== undefined && WRITE_CAPABLE_TOOLS.has(tool);

const accessOf = (evidence: DecisionEvidence): OperationAccess => evidence.operation?.access ?? "unknown";

/** Structural delegation eligibility, never a model ask: complete capture, no
 * redaction, non-empty captured `prompt`. Probability 1 because it is a
 * deterministic capture fact, and it says nothing about the child's actions. */
function delegationFact(evidence: DecisionEvidence): OperationFactResult | undefined {
  const operation = evidence.operation;
  if (!OPAQUE_ACTIONS.has(evidence.action) || evidence.incompleteEvidence !== undefined) return undefined;
  if (operation === undefined || operation.complete !== true || operation.tool === undefined) return undefined;
  const prompt = operation.arguments?.prompt;
  if (!DELEGATION_TOOLS.has(operation.tool) || typeof prompt !== "string" || prompt.trim().length === 0)
    return undefined;
  return { kind: "delegation", probability: 1, reason: DELEGATION_REASON };
}

/** Complete eligible tool name. A declared write access and write-capable tools
 * refuse before any `tool_readonly` question; `read`/`unknown` stay eligible. */
function toolCallTool(evidence: DecisionEvidence): ToolCall {
  const operation = evidence.operation;
  const tool = operation?.tool;
  if (operation === undefined || tool === undefined || operation.complete !== true) return { kind: "none" };
  if (isShellAction(evidence.action) || OPAQUE_ACTIONS.has(evidence.action)) return { kind: "none" };
  if (operation.access === "write") return { kind: "refuse", reason: WRITE_ACCESS_REASON };
  if (isWriteCapableTool(tool)) return { kind: "refuse", reason: WRITE_TOOL_REFUSAL_REASON };
  return eligibleTool(tool) ? { kind: "tool", tool, access: operation.access } : { kind: "none" };
}

/** One quoted string literal in a Code Mode script; escapes stay intact. */
const SCRIPT_STRING = /(["'`])((?:\\[\s\S]|(?!\1)[^\\])*)\1/g;
/** Credential-store directories anywhere in one script string. */
const PROTECTED_DIRECTORY = /^(?:\.ssh|\.aws|\.gnupg|\.git|\.docker|\.kube)$/i;
const NETWORK_LITERAL = /^(?:[a-z][a-z0-9+.-]*:\/\/|\/\/[^/])/i;

const scriptSegments = (value: string): string[] =>
  value.split(/[\\/\s]+/).filter((segment) => segment.length > 0);

const protectedSegment = (segment: string): boolean =>
  PROTECTED_DIRECTORY.test(segment) || PROTECTED_NAME.test(segment) || PROTECTED_SUFFIX.test(segment) ||
  envName(segment);

/** Lexical protected-name match, or the repository's path policy for a
 * path-shaped literal; unresolved metadata fails closed. */
function protectedScriptString(value: string, projectDir: string | undefined): boolean {
  if (scriptSegments(value).some(protectedSegment)) return true;
  const target = value.trim();
  if (target.length === 0 || target.includes("\0") || NETWORK_LITERAL.test(target)) return false;
  try {
    return classifyPath(target, projectDir).kind === "protected";
  } catch {
    return true;
  }
}

/** A raw literal with an escape or template interpolation is not the string the
 * runtime sees (`'\u002eenv'`, `` `${'.'}env` ``), so it cannot be screened. */
function unresolvedLiteral(quote: string, value: string): boolean {
  return value.includes("\\") || (quote === "`" && value.includes("${"));
}

/** Code Mode is opaque code: any quoted protected path, or any literal that
 * hides one behind escapes or interpolation, abstains before asking. */
function scriptNamesProtectedPath(script: string, projectDir: string | undefined): boolean {
  for (const match of script.matchAll(SCRIPT_STRING)) {
    const value = match[2] ?? "";
    if (unresolvedLiteral(match[1] ?? "", value) || protectedScriptString(value, projectDir)) return true;
  }
  return false;
}

/** The script must be the only, non-empty, bounded resource and must not name a protected store. */
function executeFactInput(evidence: DecisionEvidence): ToolFactPlan {
  const [script] = evidence.resources;
  if (evidence.resources.length !== 1 || typeof script !== "string" || script.trim().length === 0 ||
      Buffer.byteLength(script) > MAX_CAPTURED_BODY_BYTES)
    return { kind: "refuse", reason: NO_SCRIPT_REASON };
  if (scriptNamesProtectedPath(script, evidence.projectDir))
    return { kind: "refuse", reason: SCRIPT_PROTECTED_REASON };
  return { kind: "input", input: { tool: EXECUTE_TOOL, access: accessOf(evidence), script } };
}

/** A non-shell, non-file tool call is eligible only as a complete operation; a
 * missing, extra, empty, oversized or protected script never reaches generation. */
function toolFactPlan(evidence: DecisionEvidence): ToolFactPlan {
  const call = toolCallTool(evidence);
  if (call.kind === "none") return { kind: "none" };
  if (call.kind === "refuse") return { kind: "refuse", reason: call.reason };
  if (call.tool === EXECUTE_TOOL) return executeFactInput(evidence);
  const args = evidence.operation?.arguments;
  return args === undefined
    ? { kind: "refuse", reason: NO_ARGUMENTS_REASON }
    : { kind: "input", input: { tool: call.tool, access: call.access, arguments: args } };
}

/** Both shell aliases need one complete captured command and a usable explicit cwd. */
function shellInputFailure(evidence: DecisionEvidence): OperationFactResult | undefined {
  if (!isShellAction(evidence.action)) return undefined;
  if (capturedCommand(evidence) === undefined)
    return { kind: "unknown", reason: NO_COMMAND_REASON, errorKind: "context" };
  if (explicitCwd(evidence).unusable)
    return { kind: "unknown", reason: NO_CWD_REASON, errorKind: "context" };
  return undefined;
}

/** Malformed or lossy envelopes never reach a fact call. */
const unusableEvidence = (request: OperationFactRequest, evidence: DecisionEvidence): boolean =>
  !Array.isArray(request.resources) || evidence.incompleteEvidence !== undefined;

function precallResult(request: OperationFactRequest, evidence: DecisionEvidence,
  toolEligible: boolean): OperationFactResult | undefined {
  if (OPAQUE_ACTIONS.has(evidence.action))
    return { kind: "unknown", reason: OPAQUE_REASON };
  if (unusableEvidence(request, evidence))
    return { kind: "unknown", reason: "Operation evidence is incomplete, redacted or bounded", errorKind: "context" };
  // A write declaration is never a read-only fact, whatever the tool name.
  if (evidence.operation?.access === "write")
    return { kind: "unknown", reason: WRITE_ACCESS_REASON, errorKind: "context" };
  if (toolEligible) return undefined;
  // Any other execute request is still opaque: no captured script to classify.
  if (evidence.action === EXECUTE_TOOL)
    return { kind: "unknown", reason: OPAQUE_REASON };
  if (!capableOperation(evidence))
    return { kind: "unknown", reason: "Operation capability or completion is unknown", errorKind: "context" };
  const shellFailure = shellInputFailure(evidence);
  if (shellFailure !== undefined) return shellFailure;
  if (!rawScope(request))
    return { kind: "unknown", reason: "Operation scope is missing", errorKind: "context" };
  return undefined;
}

function requestInput(limits: StageLimits, question: Generate.ChoiceQuestion, text: string): DecisionInput {
  const input: DecisionInput = {
    model: limits.model,
    input: [{ type: "text", text }],
    questions: [freshQuestion(question)],
  };
  if (Buffer.byteLength(JSON.stringify(input)) > MAX_REQUEST_BYTES)
    throw new ReviewFailure("context", "Operation fact request too large");
  return input;
}

/** A provider may surface the local deadline as a generic AbortError; the bounded
 * signal's TimeoutError reason identifies it, while any outer abort stays a cancellation. */
function localTimeout(bounded: AbortSignal, signal: AbortSignal | undefined): boolean {
  if (signal?.aborted === true || !bounded.aborted) return false;
  const reason: unknown = bounded.reason;
  return typeof reason === "object" && reason !== null &&
    (reason as { name?: unknown }).name === "TimeoutError";
}

async function ask(ctx: DecisionContext, limits: StageLimits, question: Generate.ChoiceQuestion,
  text: string, signal: AbortSignal | undefined): Promise<unknown> {
  const remaining = limits.deadline - Date.now();
  if (remaining <= 0) throw new ReviewFailure("timeout", "Operation facts timed out");
  const input = requestInput(limits, question, text);
  const bounded = signal === undefined
    ? AbortSignal.timeout(remaining)
    : AbortSignal.any([signal, AbortSignal.timeout(remaining)]);
  try {
    return await withTimeout(ctx.experimental.generate.decisions(input, { signal: bounded }), remaining, signal);
  } catch (error) {
    if (localTimeout(bounded, signal))
      throw new ReviewFailure("timeout", "Operation facts timed out", { cause: error });
    throw error;
  }
}

function answerItem(response: unknown, expected: ExpectedChoice): Record<string, unknown> {
  const answers = isRecord(response) ? response.answers : undefined;
  if (!Array.isArray(answers) || answers.length !== 1)
    throw new ReviewFailure("invalid-output", "Invalid operation fact answer count");
  const item = answers[0];
  if (!isRecord(item) || item.type !== "choice" || item.name !== expected.name)
    throw new ReviewFailure("invalid-output", "Invalid operation fact answer");
  return item;
}

function parseChoice(response: unknown, expected: ExpectedChoice): ParsedChoice {
  const item = answerItem(response, expected);
  const selected = item.choice;
  if (!isChoiceValue(selected) || !expected.values.includes(selected))
    throw new ReviewFailure("invalid-output", "Invalid operation fact choice");
  const probabilities = probabilityDistribution(item.probabilities, expected.values, TOLERANCE, selected);
  const probability = probabilities?.get(selected);
  if (probability === undefined)
    throw new ReviewFailure("invalid-output", "Invalid operation fact distribution");
  return { selected, probability };
}

function inspectionFact(parsed: ParsedChoice, threshold: number): OperationFactResult | undefined {
  if (parsed.selected !== true || parsed.probability < threshold) return undefined;
  return {
    kind: "inspection",
    probability: parsed.probability,
    reason: `Operation fact inspection-only at native probability ${formatProbability(parsed.probability)}`,
  };
}

/** A true answer at or above the floor certifies the same `inspection` kind as the read-only operation question. */
function toolReadonlyFact(parsed: ParsedChoice, threshold: number): OperationFactResult {
  if (parsed.selected !== true) return unresolved("Tool call is not a read-only fact", parsed);
  if (parsed.probability < threshold) return unresolved("Tool call is below the native threshold", parsed);
  return {
    kind: "inspection",
    probability: parsed.probability,
    reason: `Tool call fact read-only at native probability ${formatProbability(parsed.probability)}`,
  };
}

async function toolCallFacts(ctx: DecisionContext, limits: StageLimits, input: ToolFactInput,
  signal: AbortSignal | undefined): Promise<OperationFactResult> {
  const parsed = parseChoice(
    await ask(ctx, limits, TOOL_READONLY_QUESTION, JSON.stringify(input), signal),
    TOOL_READONLY_EXPECTED,
  );
  return toolReadonlyFact(parsed, limits.minConfidence);
}

function unresolved(reason: string, parsed: ParsedChoice): OperationFactResult {
  return {
    kind: "unknown",
    probability: parsed.probability,
    reason: `${reason} (selected ${String(parsed.selected)} at ${formatProbability(parsed.probability)})`,
  };
}

/** Only `test_run` and `repository_read` become facts; the latter certifies `inspection`. */
function operationKindFact(parsed: ParsedChoice, threshold: number): OperationFactResult {
  const kind = parsed.selected === "test_run" ? "test_run"
    : parsed.selected === "repository_read" ? "inspection" : undefined;
  if (kind === undefined || parsed.probability < threshold)
    return unresolved("Shell operation is not an atomic test_run or repository_read fact", parsed);
  const label = kind === "inspection" ? "repository_read" : "test_run";
  return {
    kind,
    probability: parsed.probability,
    reason: `Shell operation fact ${label} at native probability ${formatProbability(parsed.probability)}`,
  };
}

/** Per segment: `inspection` under the segment cwd, then one `segment_local` for a
 * segment below the floor. All read-only certifies `inspection`, else all local
 * certifies `shell_segments`; the fact reports the weakest probability. */
async function segmentFacts(ctx: DecisionContext, limits: StageLimits, segments: readonly string[],
  fullCommand: string, cwd: string | undefined, signal: AbortSignal | undefined): Promise<OperationFactResult> {
  let probability = 1;
  let allReadOnly = true;
  for (const [segmentIndex, segment] of segments.entries()) {
    const input = JSON.stringify(segmentInput(segment, fullCommand, segmentIndex, cwd));
    const inspection = parseChoice(await ask(ctx, limits, SEGMENT_INSPECTION_QUESTION, input, signal), INSPECTION_EXPECTED);
    if (inspection.selected === true && inspection.probability >= limits.minConfidence) {
      probability = Math.min(probability, inspection.probability);
      continue;
    }
    allReadOnly = false;
    const local = parseChoice(await ask(ctx, limits, SEGMENT_LOCAL_QUESTION, input, signal), SEGMENT_LOCAL_EXPECTED);
    if (local.selected !== true) return unresolved("Shell segment is not a local-only fact", local);
    if (local.probability < limits.minConfidence)
      return unresolved("Shell segment is below the native threshold", local);
    probability = Math.min(probability, local.probability);
  }
  const reason = allReadOnly
    ? `Shell segments fact ${segments.length} read-only at native probability ${formatProbability(probability)}`
    : `Shell segments fact ${segments.length} local at native probability ${formatProbability(probability)}`;
  return { kind: allReadOnly ? "inspection" : "shell_segments", probability, reason };
}

/** One `command_local` call after an unsplittable command's `operation_kind` did
 * not certify. `true` certifies `command_local`, never `inspection`: it may write
 * outside the project, so the full review still runs. */
async function commandLocalFacts(ctx: DecisionContext, limits: StageLimits,
  shell: ShellFactInput, signal: AbortSignal | undefined): Promise<OperationFactResult> {
  const input = JSON.stringify(commandLocalInput(shell, resolve(tmpdir())));
  const parsed = parseChoice(await ask(ctx, limits, COMMAND_LOCAL_QUESTION, input, signal), COMMAND_LOCAL_EXPECTED);
  if (parsed.selected !== true) return unresolved("Shell command is not a local-only fact", parsed);
  if (parsed.probability < limits.minConfidence)
    return unresolved("Shell command is below the native threshold", parsed);
  return {
    kind: "command_local",
    probability: parsed.probability,
    reason: `Shell command fact local-only at native probability ${formatProbability(parsed.probability)}`,
  };
}

/** Factual only: a local edit can add network code when later executed; no impact claim. */
function localEditFact(parsed: ParsedChoice, threshold: number): OperationFactResult {
  if (parsed.selected !== "local_edit" || parsed.probability < threshold)
    return unresolved("Edit operation is not an atomic local_edit fact", parsed);
  return {
    kind: "local_edit",
    probability: parsed.probability,
    reason: `Edit operation fact local_edit at native probability ${formatProbability(parsed.probability)}`,
  };
}

/** Metadata-only: the answer is only that the named targets look like ordinary in-project files. */
function projectEditFact(parsed: ParsedChoice, threshold: number): OperationFactResult {
  if (parsed.selected !== true || parsed.probability < threshold)
    return unresolved("Edit operation is not an ordinary in-project edit", parsed);
  return {
    kind: "project_edit",
    probability: parsed.probability,
    reason: `Edit operation fact project_edit (metadata-only) at native probability ${formatProbability(parsed.probability)}`,
  };
}

/** Body capture uses the `edit_effect` payload path only; otherwise an eligible
 * in-project edit gets one metadata-only `edit_in_project` question, and an
 * ineligible edit abstains without a call. */
async function classifyEditFacts(ctx: DecisionContext, limits: StageLimits, request: OperationFactRequest,
  includeEditPayload: boolean, signal: AbortSignal | undefined): Promise<OperationFactResult> {
  if (includeEditPayload) {
    const prepared = prepareEditCandidate(request, true);
    if (!prepared.ok) return { kind: "unknown", reason: prepared.reason, errorKind: "context" };
    const text = JSON.stringify(prepared.candidate.input);
    const parsed = parseChoice(await ask(ctx, limits, LOCAL_EDIT_QUESTION, text, signal), EDIT_EXPECTED);
    return localEditFact(parsed, limits.minConfidence);
  }
  const project = prepareProjectEditCandidate(request);
  if (!project.ok) return { kind: "unknown", reason: "Edit payload capture is not enabled", errorKind: "context" };
  const parsed = parseChoice(
    await ask(ctx, limits, EDIT_IN_PROJECT_QUESTION, JSON.stringify(project.candidate.input), signal),
    EDIT_IN_PROJECT_EXPECTED,
  );
  return projectEditFact(parsed, limits.minConfidence);
}

/** Classifies split segments under the effective cwd; a folded leading `cd` must
 * stay inside the same containment root as an explicit workdir. */
async function splitFacts(ctx: DecisionContext, limits: StageLimits, shellCwd: string | undefined,
  shellCommand: string, split: ShellSegmentSplit, evidence: DecisionEvidence,
  signal: AbortSignal | undefined): Promise<OperationFactResult> {
  if (split.leadingCd === undefined) return segmentFacts(ctx, limits, split.segments, shellCommand, shellCwd, signal);
  const cwd = foldedCwd(split.leadingCd, shellCwd, evidence);
  if (cwd === undefined) return { kind: "unknown", reason: UNCONFINED_CD_REASON, errorKind: "context" };
  return segmentFacts(ctx, limits, split.segments, shellCommand, cwd, signal);
}

/** Second stage only after `inspection` missed the floor: a splittable command is
 * classified per segment, otherwise one `operation_kind` question, then one
 * `command_local` fallback. Never a blind call without the captured command. */
async function afterInspection(ctx: DecisionContext, limits: StageLimits,
  evidence: DecisionEvidence, inspection: ParsedChoice, signal: AbortSignal | undefined): Promise<OperationFactResult> {
  const fact = inspectionFact(inspection, limits.minConfidence);
  if (fact !== undefined) return fact;
  // Use the pre-await evidence snapshot, never the mutable caller request.
  if (!isShellAction(evidence.action)) return unresolved("Operation does not establish inspection-only", inspection);
  const shell = buildShellFactInput(evidence);
  if (shell === undefined) return { kind: "unknown", reason: NO_COMMAND_REASON, errorKind: "context" };
  const split = splitShellSegmentsWithLeadingCd(shell.command);
  if (split !== undefined) return splitFacts(ctx, limits, shell.cwd, shell.command, split, evidence, signal);
  const kind = parseChoice(await ask(ctx, limits, OPERATION_KIND_QUESTION, JSON.stringify(shell), signal), OPERATION_KIND_EXPECTED);
  const operation = operationKindFact(kind, limits.minConfidence);
  return operation.kind === "unknown" ? await commandLocalFacts(ctx, limits, shell, signal) : operation;
}

const failureResult = (error: unknown, signal: AbortSignal | undefined): OperationFactResult =>
  ({ kind: "unknown", reason: "Operation facts unavailable or returned invalid output", errorKind: signal?.aborted ? "cancelled" : errorKindOf(error) });

/** A non-edit-like operation whose tool is write-capable abstains before any call
 * instead of letting fact-only inspection allow certify it. */
function writeCapableRefusal(evidence: DecisionEvidence): OperationFactResult | undefined {
  return isWriteCapableTool(evidence.operation?.tool)
    ? { kind: "unknown", reason: WRITE_TOOL_REFUSAL_REASON, errorKind: "context" }
    : undefined;
}

/** Non-edit classification shared by every plain operation request. */
async function classifyPlainOperation(ctx: DecisionContext, limits: StageLimits, request: OperationFactRequest,
  evidence: DecisionEvidence, signal: AbortSignal | undefined): Promise<OperationFactResult> {
  const writeRefusal = writeCapableRefusal(evidence);
  if (writeRefusal !== undefined) return writeRefusal;
  const delegation = delegationFact(evidence);
  if (delegation !== undefined) return delegation;
  const toolPlan = toolFactPlan(evidence);
  if (toolPlan.kind === "refuse")
    return { kind: "unknown", reason: toolPlan.reason, errorKind: "context" };
  const blocked = precallResult(request, evidence, toolPlan.kind === "input");
  if (blocked !== undefined) return blocked;
  if (toolPlan.kind === "input") return await toolCallFacts(ctx, limits, toolPlan.input, signal);
  const evidenceText = JSON.stringify(buildOperationFactInput(evidence));
  const inspection = parseChoice(await ask(ctx, limits, INSPECTION_QUESTION, evidenceText, signal), INSPECTION_EXPECTED);
  return await afterInspection(ctx, limits, evidence, inspection, signal);
}

/**
 * Classifies only what the operation is, never authorization, intent, permission
 * or safety. Edit-like requests use only the bounded opt-in payload or the
 * metadata-only `edit_in_project` question. A complete eligible tool call gets
 * one `tool_readonly` question; other operations try inspection first, then a
 * shell command is classified per segment, else by `operation_kind`, else by one
 * `command_local` fallback. A complete `subagent`/`task` capture becomes the
 * structural `delegation` fact with no call; every other opaque action abstains.
 */
export async function classifyOperationFacts(
  ctx: DecisionContext,
  options: OperationFactOptions,
  request: OperationFactRequest,
  signal?: AbortSignal,
): Promise<OperationFactResult> {
  try {
    if (signal?.aborted) throw new ReviewFailure("cancelled", "Operation facts cancelled");
    const limits = stageLimits(options);
    if (typeof request.action !== "string" || !Array.isArray(request.resources))
      return { kind: "unknown", reason: "Operation request is malformed", errorKind: "context" };
    if (isEditLike(request))
      return await classifyEditFacts(ctx, limits, request, options.includeEditPayload === true, signal);
    return await classifyPlainOperation(ctx, limits, request, evidenceFor(request), signal);
  } catch (error) {
    return failureResult(error, signal);
  }
}
