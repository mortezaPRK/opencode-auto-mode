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
        const matches = resources.map((resource) => {
          const result = predicate({ ...bindings, resource });
          if (typeof result !== "boolean") throw new Error("CEL rules must return a boolean");
          return result;
        });
        results[index] = { any: matches.some(Boolean), coverage: hasResources ? matches : [] };
        if (results[index].any && decision !== "allow") return results;
      } catch { failed = true; }
    }
    if (failed) return null;
  }
  return results;
}

parentPort!.postMessage(evaluate());
