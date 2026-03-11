export const NPM_TOKEN = typeof process.env.NODE_SECURE_TOKEN === "string" ?
  { token: process.env.NODE_SECURE_TOKEN } : {};

export const VULN_MODE = Object.freeze({
  GITHUB_ADVISORY: "github-advisory",
  SNYK: "snyk",
  SONATYPE: "sonatype",
  OSV: "osv",
  NONE: "none"
});
export type Kind = typeof VULN_MODE[keyof typeof VULN_MODE];
