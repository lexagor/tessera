import { describe, expect, it } from "vitest";

import { enforcementLabel } from "../src/lib/enforcement";

describe("enforcement labels", () => {
  it("labels broker-observed actions as Level 1", () => {
    expect(
      enforcementLabel({ denied: false, outcomeSource: "broker_observed", credential: {} }).label,
    ).toBe("Level 1 · broker-observed");
  });

  it("labels broker-held grants as Level 1 even before an outcome", () => {
    expect(
      enforcementLabel({
        denied: false,
        outcomeSource: "not recorded",
        credential: { credentialType: "broker_grant" },
      }).label,
    ).toBe("Level 1 · broker-held");
  });

  it("labels scoped credentials as Level 2", () => {
    expect(
      enforcementLabel({ denied: false, credential: { credentialType: "bearer" } }).label,
    ).toBe("Level 2 · scoped credential");
  });

  it("labels missing credentials as caller-asserted", () => {
    expect(enforcementLabel({ denied: false, credential: null }).label).toBe(
      "Caller-asserted authority",
    );
  });

  it("labels denied actions explicitly", () => {
    expect(enforcementLabel({ denied: true, credential: null })).toEqual({
      tone: "bad",
      label: "Policy denied",
    });
  });
});
