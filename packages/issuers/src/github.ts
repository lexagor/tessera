import type { IssueRequest, IssuedCredential, Issuer } from "./index.js";

/**
 * GitHub App issuer: installation access token with minimum permissions/repositories.
 * TODO: implement via a GitHub App JWT -> installation token exchange.
 */
export class GitHubIssuer implements Issuer {
  readonly provider = "github";

  constructor(private readonly opts: { appId: string; privateKeyPem: string }) {}

  async issue(req: IssueRequest): Promise<IssuedCredential> {
    void this.opts;
    throw new Error(`github issuer not implemented (resource=${req.resource})`);
  }
}
