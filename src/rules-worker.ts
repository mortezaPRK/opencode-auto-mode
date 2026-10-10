import { parentPort, workerData } from "node:worker_threads";
import { compileExpression, type RuleBindings } from "./rules.js";
import type { UserRule } from "./config.js";

const { rules, resources, bindings, hasResources } = workerData as {
  rules: UserRule[]; resources: string[]; bindings: RuleBindings; hasResources: boolean;
};
function evaluate() {
  const results = rules.map(() => ({ any: false, coverage: hasResources ? resources.map(() => false) : [] }));
  for (const decision of ["deny", "ask", "allow"]) {
    let failed = false;
    for (const [index, rule] of rules.entries()) {
      if (rule.decision !== decision) continue;
      try {
        const predicate = compileExpression(rule.expression);
        const matches = resources.map(() => false);
        for (const [resourceIndex, resource] of resources.entries()) {
          try {
            const result = predicate({ ...bindings, resource });
            if (typeof result !== "boolean") throw new Error("CEL rules must return a boolean");
            matches[resourceIndex] = result;
            if (result && decision !== "allow") {
              results[index] = { any: true, coverage: hasResources ? matches : [] };
              return results;
            }
          } catch { failed = true; }
        }
        results[index] = { any: matches.some(Boolean), coverage: hasResources ? matches : [] };
      } catch { failed = true; }
    }
    if (failed) return null;
  }
  return results;
}

parentPort!.postMessage(evaluate());
