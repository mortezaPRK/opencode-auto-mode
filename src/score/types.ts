/** The risk band a permission request falls into, with the reason shown to the user. */
export interface RequestScore {
  band: "low" | "medium" | "high";
  reason: string;
  deny?: boolean;
  ask?: boolean;
}

export const low = (reason: string): RequestScore => ({ band: "low", reason });
export const medium = (reason: string): RequestScore => ({ band: "medium", reason });
export const high = (reason: string): RequestScore => ({ band: "high", reason });
export const deny = (reason: string): RequestScore => ({ band: "high", reason, deny: true });
/** Missing VCS preconditions gate history changes into manual review, not a hard deny. */
export const ask = (reason: string): RequestScore => ({ band: "high", reason, ask: true });
