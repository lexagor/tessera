import type { IssueRequest, IssuedCredential, Issuer } from "./index.js";

/**
 * Stripe issuer: map an intent to the narrowest pre-provisioned restricted key.
 * TODO: provision restricted-key families per resource/operation and hand out the
 * narrowest match via an ephemeral envelope.
 */
export class StripeIssuer implements Issuer {
  readonly provider = "stripe";

  constructor(private readonly opts: { accountId: string; restrictedKeys: Record<string, string> }) {}

  async issue(req: IssueRequest): Promise<IssuedCredential> {
    void this.opts;
    throw new Error(`stripe issuer not implemented (resource=${req.resource})`);
  }
}
