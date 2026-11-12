export interface EnforcementLabel {
  tone: "ok" | "warn" | "bad";
  label: string;
}

export function enforcementLabel(input: {
  denied: boolean;
  outcomeSource?: string | null;
  credential?: Record<string, any> | null;
}): EnforcementLabel {
  if (input.denied) return { tone: "bad", label: "Policy denied" };
  if (input.outcomeSource === "broker_observed") {
    return { tone: "ok", label: "Level 1 · broker-observed" };
  }
  if (input.credential?.credentialType === "broker_grant") {
    return { tone: "ok", label: "Level 1 · broker-held" };
  }
  if (input.credential) {
    return { tone: "warn", label: "Level 2 · scoped credential" };
  }
  return { tone: "warn", label: "Caller-asserted authority" };
}
