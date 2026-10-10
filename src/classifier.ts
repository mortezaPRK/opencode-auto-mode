import { classify } from "./tiers.js";
import type { ClassifierStage, UserRule } from "./config.js";
import type { PermissionRequest, ReviewResult } from "./reviewer.js";

export function matches(pattern: string, value: string): boolean {
  const parts = pattern.split("*");
  if (!value.startsWith(parts[0])) return false;
  let offset = parts[0].length;
  for (let i = 1; i < parts.length - 1; i++) {
    const next = value.indexOf(parts[i], offset);
    if (next < 0) return false;
    offset = next + parts[i].length;
  }
  return parts.length === 1 ? value === pattern : value.slice(offset).endsWith(parts.at(-1)!);
}

function matching(rule: UserRule, request: PermissionRequest, resource: string): boolean {
  return (rule.action === "*" || rule.action === request.action) && matches(rule.resource ?? "*", resource);
}

export function ruleDecision(rules: UserRule[], request: PermissionRequest): ReviewResult | undefined {
  const resources = request.resources.length ? request.resources : [""];
  for (const decision of ["deny", "ask"] as const) {
    if (rules.some((rule) => rule.decision === decision && resources.some((resource) => matching(rule, request, resource))))
      return { decision, reason: `user rule: ${decision}` };
  }
  if (request.resources.length > 0 && request.resources.every((resource) =>
      rules.some((rule) => rule.decision === "allow" && matching(rule, request, resource))))
    return { decision: "allow", reason: "all resources match user allow rules" };
  return undefined;
}

export async function compositeDecision(
  stages: ClassifierStage[],
  request: PermissionRequest,
  review: (stage: Exclude<ClassifierStage, { type: "static" } | { type: "rules" }>) => Promise<ReviewResult | undefined>,
): Promise<ReviewResult> {
  for (const stage of stages) {
    if (stage.type !== "rules") continue;
    const result = ruleDecision(stage.rules.filter((rule) => rule.decision === "deny"), request);
    if (result) return result;
  }
  for (const stage of stages) {
    if (stage.type !== "static") continue;
    const result = classify(request.action, request.resources);
    if (result.tier === "auto-deny") return { decision: "deny", reason: result.reason };
  }
  for (const stage of stages) {
    if (stage.type !== "rules") continue;
    const result = ruleDecision(stage.rules.filter((rule) => rule.decision === "ask"), request);
    if (result) return result;
  }
  for (const stage of stages) {
    if (stage.type === "static") {
      const result = classify(request.action, request.resources, {
        projectDir: request.projectDir, allowInProjectEdits: stage.allowInProjectEdits,
      });
      if (result.tier === "auto-allow") return { decision: "allow", reason: result.reason };
    } else if (stage.type === "rules") {
      const result = ruleDecision(stage.rules, request);
      if (result) return result;
    } else {
      const result = await review(stage);
      if (result) return result;
    }
  }
  return { decision: "ask", reason: "No classifier made a decision" };
}
