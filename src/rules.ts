import { celEnv, CelScalar, parse, plan } from "@bufbuild/cel";
import { Worker } from "node:worker_threads";
import type { UserRule } from "./config.js";
import type { PermissionRequest } from "./reviewer.js";

const environment = celEnv({ variables: {
  action: CelScalar.STRING, resource: CelScalar.STRING, agent: CelScalar.STRING,
  projectDir: CelScalar.STRING, isDelegation: CelScalar.BOOL,
} });

export function compileExpression(expression: string) {
  if (typeof expression !== "string" || !expression.trim() || expression.length > 4096)
    throw new Error("Invalid CEL expression");
  const parsed = parse(expression);
  type Expr = NonNullable<typeof parsed.expr>;
  const pending: { expr: Expr; depth: number }[] = [];
  if (parsed.expr) pending.push({ expr: parsed.expr, depth: 1 });
  let count = 0;
  while (pending.length) {
    const { expr, depth } = pending.pop()!;
    if (++count > 512 || depth > 32) throw new Error("CEL expression is too complex");
    const kind = expr.exprKind;
    const children: Expr[] = [];
    if (kind.case === "comprehensionExpr") throw new Error("CEL collection macros are disabled");
    if (kind.case === "callExpr") {
      children.push(...kind.value.args);
      if (kind.value.target) children.push(kind.value.target);
    } else if (kind.case === "selectExpr" && kind.value.operand) children.push(kind.value.operand);
    else if (kind.case === "listExpr") children.push(...kind.value.elements);
    else if (kind.case === "structExpr") {
      for (const entry of kind.value.entries) {
        if (entry.keyKind.case === "mapKey") children.push(entry.keyKind.value);
        if (entry.value) children.push(entry.value);
      }
    }
    for (const child of children) pending.push({ expr: child, depth: depth + 1 });
  }
  return plan(environment, parsed);
}

export type RuleMatch = { rule: UserRule; any: boolean; coverage: boolean[] };
export type RuleBindings = { action: string; agent: string; projectDir: string; isDelegation: boolean };

export async function evaluateRules(rules: UserRule[], request: PermissionRequest): Promise<RuleMatch[]> {
  if (!rules.length) return [];
  const resources = request.resources.length ? request.resources : [""];
  const bindings: RuleBindings = { action: request.action, agent: request.agent ?? "",
    projectDir: request.projectDir ?? "", isDelegation: request.isDelegation === true };
  const strings = [...resources, bindings.action, bindings.agent, bindings.projectDir];
  if (resources.length > 256 || rules.length * resources.length > 4096 ||
      strings.some((value) => typeof value !== "string" || value.length > 4096) ||
      strings.reduce((sum, value) => sum + Buffer.byteLength(value), 0) > 65_536)
    throw new Error("CEL request exceeds evaluation limits");
  const worker = new Worker(new URL("./rules-worker.ts", import.meta.url), {
    workerData: { rules, resources, bindings, hasResources: request.resources.length > 0 },
  });
  try {
    const matches = await new Promise<{ any: boolean; coverage: boolean[] }[]>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("CEL evaluation timed out")), 1000);
      const fail = () => { clearTimeout(timer); reject(new Error("CEL evaluation failed")); };
      worker.once("error", fail);
      worker.once("exit", fail);
      worker.once("message", (value: unknown) => {
        clearTimeout(timer);
        if (!Array.isArray(value) || value.length !== rules.length || value.some((match) =>
          !match || typeof match.any !== "boolean" || !Array.isArray(match.coverage) ||
          match.coverage.length !== request.resources.length || match.coverage.some((item: unknown) => typeof item !== "boolean"))) { fail(); return; }
        resolve(value);
      });
    });
    return matches.map((match, index) => ({ ...match, rule: rules[index] }));
  } finally { await worker.terminate(); }
}
