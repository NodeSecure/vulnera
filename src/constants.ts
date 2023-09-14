export const NPM_TOKEN = typeof process.env.NODE_SECURE_TOKEN === "string" ?
  { token: process.env.NODE_SECURE_TOKEN } : {};
export const SNYK_ORG = process.env.SNYK_ORG;
export const SNYK_TOKEN = process.env.SNYK_TOKEN;

export const VULN_MODE = Object.freeze({
  GITHUB_ADVISORY: "github-advisory",
  SNYK: "snyk",
  SONATYPE: "sonatype",
  NONE: "none"
});
export type Kind = typeof VULN_MODE[keyof typeof VULN_MODE];
