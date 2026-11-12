export interface IssueRequest {
  provider: string;
  resource: string;
  scope: string[];
  ttlSeconds: number;
  argsHash: string;
}

export interface IssuedCredential {
  provider: string;
  token: string;
  ttlSeconds: number;
  singleUse: boolean;
  argsHash: string;
}

export interface Issuer {
  provider: string;
  /** Request the minimum scope; throw on failure. */
  issue(req: IssueRequest): Promise<IssuedCredential>;
}

export { AwsStsIssuer } from "./aws-sts.js";
export { GitHubIssuer } from "./github.js";
export { StripeIssuer } from "./stripe.js";
export { OAuth2Issuer } from "./oauth2.js";
