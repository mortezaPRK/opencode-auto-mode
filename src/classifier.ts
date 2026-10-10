import { classify } from "./tiers.js";
import type { ClassifierStage } from "./config.js";
import type { PermissionRequest, ReviewResult } from "./reviewer.js";
import { evaluateRules, type RuleMatch } from "./rules.js";
import { guardShell } from "./shell.js";

function ruleDecision(matches: RuleMatch[]): ReviewResult | undefined {
  for (const decision of ["deny", "ask"] as const) {
    if (matches.some((match) => match.rule.decision === decision && match.any))
      return { decision, reason: `user rule: ${decision}` };
  }
  if (matches[0]?.coverage.length && matches[0].coverage.every((_, index) =>
      matches.some((match) => match.rule.decision === "allow" && match.coverage[index])))
    return { decision: "allow", reason: "all resources match CEL allow rules" };
  return undefined;
}

export async function compositeDecision(
  stages: ClassifierStage[],
  request: PermissionRequest,
  review: (stage: Exclude<ClassifierStage, { type: "static" } | { type: "rules" }>) => Promise<ReviewResult | undefined>,
): Promise<ReviewResult> {
  const shellResult = request.action === "shell" ? guardShell(request.resources) : undefined;
  if (shellResult?.decision === "deny") return shellResult;
  for (const stage of stages) {
    if (stage.type !== "static") continue;
    const result = classify(request.action, request.resources);
    if (result.tier === "auto-deny") return { decision: "deny", reason: result.reason };
  }
  let matches: RuleMatch[];
  try { matches = await evaluateRules(stages.flatMap((stage) => stage.type === "rules" ? stage.rules : []), request); }
  catch { return { decision: "ask", reason: "CEL rule evaluation failed; please decide yourself" }; }
  for (const decision of ["deny", "ask"] as const) {
    const result = ruleDecision(matches.filter((match) => match.rule.decision === decision));
    if (result) return result;
  }
  if (shellResult) return shellResult;
  for (const stage of stages) {
    if (stage.type === "static") {
      const result = classify(request.action, request.resources, {
        projectDir: request.projectDir, allowInProjectEdits: stage.allowInProjectEdits,
      });
      if (result.tier === "auto-allow") return { decision: "allow", reason: result.reason };
    } else if (stage.type === "rules") {
      const result = ruleDecision(matches.filter((match) => stage.rules.includes(match.rule)));
      if (result) return result;
    } else {
      const result = await review(stage);
      if (result) return result;
    }
  }
  return { decision: "ask", reason: "No classifier made a decision" };
}
