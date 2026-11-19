import { EvidenceFailure, ReviewFailure } from "./errors.js";

export const DEFAULT_AUTHORITY_MAX_BYTES = 12_000;
export const DEFAULT_AUTHORITY_MAX_DEPTH = 16;

const CANCELLED = "Authority collection cancelled";
const MISSING_INFO = "Session authority metadata is unavailable";
const MISSING_CONTEXT = "Session authority context is unavailable";
const INVALID_CUTOFF = "Session authority cutoff is invalid";
const INVALID_TIME = "Session user message timestamp is invalid";
const COMPACTED_CONTEXT = "Session authority context is degraded by compaction";
const FORK_REVIEW = "Fork authority provenance requires review";

/** Minimal session facts needed to follow the parent chain. */
export interface AuthoritySessionInfo {
  readonly parentID?: string;
  readonly fork?: { readonly sessionID?: string; readonly boundary?: unknown } | null;
}

/** Messages are classified structurally by `type`; metadata is never trusted. */
export interface AuthorityContextMessage {
  readonly type?: unknown;
  readonly text?: unknown;
  readonly time?: { readonly created?: unknown };
}

export interface AuthorityLookups {
  get(sessionID: string, signal?: AbortSignal): Promise<AuthoritySessionInfo | undefined>;
  context(sessionID: string, signal?: AbortSignal): Promise<readonly AuthorityContextMessage[]>;
}

export interface AuthorityOptions {
  readonly signal?: AbortSignal;
  readonly maxBytes?: number;
  readonly maxDepth?: number;
  /** Request start time; user messages created later cannot be authority. */
  readonly asOf?: number;
}

export interface AuthorityDelegation {
  readonly sessionID: string;
  readonly messages: readonly string[];
}

export interface AuthorityEvidence {
  /** Root-session user messages, in their original order and without truncation. */
  readonly userMessages: string[];
  /** Descendant user messages from the root-adjacent child down to the current session. */
  readonly delegations: readonly AuthorityDelegation[];
}

interface ChainEntry {
  readonly sessionID: string;
  readonly info: AuthoritySessionInfo;
}

function ensureActive(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new ReviewFailure("cancelled", CANCELLED);
}

/** Settles promptly even when a lookup ignores the abort signal. */
function raceAbort<T>(work: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (signal === undefined) return work;
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const finish = (action: () => void) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      action();
    };
    const onAbort = () => finish(() => reject(new ReviewFailure("cancelled", CANCELLED)));
    work.then((value) => finish(() => resolve(value)), (error) => finish(() => reject(error)));
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) onAbort();
  });
}

async function lookup<T>(work: () => Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  ensureActive(signal);
  try { return await raceAbort(work(), signal); }
  catch (error) {
    if (signal?.aborted) throw new ReviewFailure("cancelled", CANCELLED);
    throw error;
  }
}

function missing(error: unknown, message: string): never {
  if (error instanceof EvidenceFailure) throw error;
  if (error instanceof ReviewFailure && error.kind === "cancelled") throw error;
  throw new EvidenceFailure(message, { cause: error });
}

async function readInfo(
  lookups: AuthorityLookups,
  sessionID: string,
  signal: AbortSignal | undefined,
): Promise<AuthoritySessionInfo> {
  try {
    const info = await lookup(() => lookups.get(sessionID, signal), signal);
    if (typeof info !== "object" || info === null) return missing(undefined, MISSING_INFO);
    return info;
  } catch (error) { return missing(error, MISSING_INFO); }
}

async function readContext(
  lookups: AuthorityLookups,
  sessionID: string,
  signal: AbortSignal | undefined,
): Promise<readonly AuthorityContextMessage[]> {
  try {
    const messages = await lookup(() => lookups.context(sessionID, signal), signal);
    if (!Array.isArray(messages)) return missing(undefined, MISSING_CONTEXT);
    return messages;
  } catch (error) { return missing(error, MISSING_CONTEXT); }
}

function limitOf(value: number | undefined, fallback: number): number {
  const limit = value ?? fallback;
  if (!Number.isSafeInteger(limit) || limit < 1) throw new EvidenceFailure("Session authority limit is invalid");
  return limit;
}

function cutoffOf(value: number | undefined): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isFinite(value)) throw new EvidenceFailure(INVALID_CUTOFF);
  return value;
}

function isMessage(value: unknown): value is AuthorityContextMessage {
  return typeof value === "object" && value !== null;
}

function createdOf(message: AuthorityContextMessage): number {
  const created = message.time?.created;
  if (typeof created !== "number" || !Number.isFinite(created))
    throw new EvidenceFailure(INVALID_TIME);
  return created;
}

function appendUserText(
  message: AuthorityContextMessage,
  asOf: number | undefined,
  texts: string[],
): void {
  if (asOf !== undefined && createdOf(message) > asOf) return;
  if (typeof message.text !== "string")
    throw new EvidenceFailure("Session user message is unavailable");
  texts.push(message.text);
}

function assertNoFork(info: AuthoritySessionInfo): void {
  // Live Session.Info reports fork: null for every ordinary session.
  if (info.fork != null) throw new EvidenceFailure(FORK_REVIEW);
}

/** Walks to the root, rejecting repeats, forks and overlong chains. */
async function walkChain(
  sessionID: string,
  lookups: AuthorityLookups,
  signal: AbortSignal | undefined,
  maxDepth: number,
): Promise<ChainEntry[]> {
  const chain: ChainEntry[] = [];
  const visited = new Set<string>();
  let current = sessionID;
  while (true) {
    ensureActive(signal);
    if (!current || visited.has(current)) throw new EvidenceFailure("Session authority chain is cyclic");
    if (chain.length >= maxDepth) throw new EvidenceFailure("Session authority chain is too deep");
    visited.add(current);
    const info = await readInfo(lookups, current, signal);
    assertNoFork(info);
    chain.push({ sessionID: current, info });
    if (info.parentID === undefined) return chain;
    if (typeof info.parentID !== "string" || info.parentID.length === 0)
      throw new EvidenceFailure("Session authority parent is invalid");
    current = info.parentID;
  }
}

function userTexts(
  messages: readonly AuthorityContextMessage[],
  asOf: number | undefined,
): string[] {
  const texts: string[] = [];
  for (const message of messages) {
    if (!isMessage(message)) continue;
    if (message.type === "compaction") throw new EvidenceFailure(COMPACTED_CONTEXT);
    if (message.type !== "user") continue;
    appendUserText(message, asOf, texts);
  }
  return texts;
}

async function delegationOf(
  entry: ChainEntry,
  lookups: AuthorityLookups,
  signal: AbortSignal | undefined,
  asOf: number | undefined,
): Promise<AuthorityDelegation | undefined> {
  const messages = userTexts(await readContext(lookups, entry.sessionID, signal), asOf);
  return messages.length === 0 ? undefined : { sessionID: entry.sessionID, messages };
}

async function delegationsOf(
  chain: readonly ChainEntry[],
  lookups: AuthorityLookups,
  signal: AbortSignal | undefined,
  asOf: number | undefined,
): Promise<AuthorityDelegation[]> {
  const delegations: AuthorityDelegation[] = [];
  for (const entry of chain.slice(0, -1).reverse()) {
    const delegation = await delegationOf(entry, lookups, signal, asOf);
    if (delegation !== undefined) delegations.push(delegation);
  }
  return delegations;
}

function evidenceBytes(
  userMessages: readonly string[],
  delegations: readonly AuthorityDelegation[],
): number {
  const texts = [...userMessages];
  for (const delegation of delegations) texts.push(...delegation.messages);
  return Buffer.byteLength(texts.join("\n"), "utf8");
}

/** Collects user authority from the root session and delegation from every
 * descendant. Missing evidence, cycles, depth overflow and oversized text are
 * terminal. */
export async function collectAuthority(
  sessionID: string,
  lookups: AuthorityLookups,
  options: AuthorityOptions = {},
): Promise<AuthorityEvidence> {
  const { signal } = options;
  ensureActive(signal);
  if (typeof sessionID !== "string" || sessionID.length === 0)
    throw new EvidenceFailure("Session authority session is unavailable");
  const maxBytes = limitOf(options.maxBytes, DEFAULT_AUTHORITY_MAX_BYTES);
  const maxDepth = limitOf(options.maxDepth, DEFAULT_AUTHORITY_MAX_DEPTH);
  const asOf = cutoffOf(options.asOf);
  const chain = await walkChain(sessionID, lookups, signal, maxDepth);
  const root = chain[chain.length - 1]!;
  const userMessages = userTexts(await readContext(lookups, root.sessionID, signal), asOf);
  if (userMessages.length === 0)
    throw new EvidenceFailure("Root user authorization evidence is unavailable");
  const delegations = await delegationsOf(chain, lookups, signal, asOf);
  if (evidenceBytes(userMessages, delegations) > maxBytes)
    throw new EvidenceFailure("User authorization evidence is too large");
  ensureActive(signal);
  return { userMessages, delegations };
}
