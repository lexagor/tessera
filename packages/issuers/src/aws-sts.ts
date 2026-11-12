import type { IssueRequest, IssuedCredential, Issuer } from "./index.js";

/**
 * AWS STS issuer: AssumeRole with an inline session policy, DurationSeconds <= 900.
 * TODO: implement with @aws-sdk/client-sts; build the session policy from `req.scope`.
 */
export class AwsStsIssuer implements Issuer {
  readonly provider = "aws";

  constructor(private readonly opts: { region: string; roleArn: string }) {}

  async issue(req: IssueRequest): Promise<IssuedCredential> {
    void this.opts;
    throw new Error(`aws sts issuer not implemented (resource=${req.resource})`);
  }
}
