import type { IssueRequest, IssuedCredential, Issuer } from "./index.js";

/**
 * Generic OAuth2 token-exchange issuer (RFC 8693). Useful for providers that support
 * downscoped, short-lived access tokens.
 */
export class OAuth2Issuer implements Issuer {
  readonly provider = "oauth2";

  constructor(private readonly opts: { tokenEndpoint: string; clientId: string; clientSecret: string }) {}

  async issue(req: IssueRequest): Promise<IssuedCredential> {
    void this.opts;
    throw new Error(`oauth2 issuer not implemented (resource=${req.resource})`);
  }
}
