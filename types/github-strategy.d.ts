import { AuditAdvisory } from "@pnpm/audit";

export = GitHubAdvisoryStrategy;

declare namespace GitHubAdvisoryStrategy {
  export type NpmAuditAdvisory = {
    /** The unique cache key for this vuln or metavuln. **/
    id?: string;
    /** The name of the package that this vulnerability is about**/
    name: string;
    /** For metavulns, the dependency that causes this package to be have a vulnerability. For advisories, the same as name. **/
    dependency: string;
    /** The text title of the advisory or metavuln **/
    title: string;
    /** The url for the advisory (null for metavulns) **/
    url: string;
    /** Publicly-known vulnerabilities have identification numbers, known as Common Vulnerabilities and Exposures (CVEs) */
    cwe?: string[];
    /** The Common Vulnerability Scoring System (CVSS) is a method used to supply a qualitative measure of severity. CVSS is not a measure of risk. */
    cvss?: Cvss;
    /** The severity level **/
    severity: "info" | "low" | "moderate" | "high" | "critical";
    /** The range that is vulnerable **/
    range: string;
    /** The set of versions that are vulnerable **/
    vulnerableVersions?: string[];
  }

  export type PnpmAuditAdvisory= AuditAdvisory;
  export type Vulnerability = PnpmAuditAdvisory | NpmAuditAdvisory;

  export interface Cvss {
    score: number;
    vectorString: string;
  }
}
