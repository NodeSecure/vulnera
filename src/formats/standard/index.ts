// Import Internal Dependencies
import { VULN_MAPPERS } from "./mappers.js";
import type { Kind } from "../../constants.js";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface StandardPatch {
  id: string;
  comments: string[];
  modificationTime: string;
  urls: string[];
  version: string;
}

export interface StandardVulnerability {
  /** Unique identifier for the vulnerability **/
  id?: string;
  /** Vulnerability origin, either Snyk, Sonatype, GitHub or NodeSWG **/
  origin: Exclude<Kind, "none">;
  /** Package associated with the vulnerability **/
  package: string;
  /** Vulnerability title **/
  title: string;
  /** Vulnerability description **/
  description?: string;
  /** Vulnerability link references on origin's website **/
  url?: string;
  /** Vulnerability severity levels given the strategy **/
  severity?: Severity;
  /** Common Vulnerabilities and Exposures dictionary */
  cves?: string[];
  /**
   * Common Vulnerability Scoring System (CVSS) provides a way to capture the
   * principal characteristics of a vulnerability, and produce a numerical score reflecting its severity,
   * as well as a textual representation of that score.
   * **/
  cvssVector?: string;
  /** CVSS Score **/
  cvssScore?: number;
  /** The range of vulnerable versions provided when too many versions are vulnerables */
  vulnerableRanges: string[];
  /** The set of versions that are vulnerable **/
  vulnerableVersions: string[];
  /** The set of versions that are patched **/
  patchedVersions?: string;
  /** Overview of available patches to get rid of listed vulnerabilities **/
  patches?: StandardPatch[];
}

export type StandardizeKind = keyof typeof VULN_MAPPERS;

function useStrategyVulnerabilityMapper(
  strategy: StandardizeKind,
  vulnerabilities: any[]
): StandardVulnerability[] {
  if (!(strategy in VULN_MAPPERS)) {
    return [];
  }

  return vulnerabilities.map(VULN_MAPPERS[strategy]);
}

export function standardizeVulnsPayload(useStandardFormat = false) {
  return function formatVulnerabilities(
    strategy: StandardizeKind,
    vulnerabilities: any[]
  ) {
    if (useStandardFormat) {
      return useStrategyVulnerabilityMapper(
        strategy, vulnerabilities
      );
    }

    // identity function
    return vulnerabilities;
  };
}

