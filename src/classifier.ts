import { classify } from "./tiers.js";
import type { ClassifierStage } from "./config.js";
import type { PermissionRequest, ReviewResult, StageResult } from "./reviewer.js";
import { guardShell } from "./shell.js";
import type { ReviewErrorKind } from "./errors.js";

export async function compositeDecision(
  stages: ClassifierStage[],
  request: PermissionRequest,
  review: (stage: Exclude<ClassifierStage, { type: "static" }>) => Promise<StageResult>,
): Promise<ReviewResult> {
  const shellResult = request.action === "shell" ? guardShell(request.resources) : undefined;
  if (shellResult?.decision === "deny") return { ...shellResult, stage: "shell-guard" };
  for (const stage of stages) {
    if (stage.type !== "static") continue;
    const result = classify(request.action, request.resources);
    if (result.tier === "auto-deny") return { decision: "deny", reason: result.reason, stage: "static" };
  }
  if (shellResult) {
    // Parsed read-only results feed the static stage, but never bypass a model-only pipeline.
    const hasStatic = stages.some((stage) => stage.type === "static");
    if (shellResult.decision !== "allow" || hasStatic)
      return { ...shellResult, stage: shellResult.decision === "allow" ? "static" : "shell-guard" };
  }
  let abstained: string | undefined;
  let abstainedKind: ReviewErrorKind | undefined;
  for (const stage of stages) {
    if (stage.type === "static") {
      const result = classify(request.action, request.resources, {
        projectDir: request.projectDir, allowInProjectEdits: stage.allowInProjectEdits,
      });
      if (result.tier === "auto-allow") return { decision: "allow", reason: result.reason, stage: "static" };
    } else {
      const result = await review(stage);
      if (result.decision === "abstain") {
        abstained = result.reason;
        abstainedKind ??= result.errorKind;
        continue;
      }
      return { decision: result.decision, reason: result.reason, stage: result.stage ?? stage.type };
    }
  }
  return {
    decision: "ask",
    reason: abstained ? `No classifier made a decision (${abstained})` : "No classifier made a decision",
    stage: "none",
    ...(abstainedKind === undefined ? {} : { errorKind: abstainedKind }),
  };
}
