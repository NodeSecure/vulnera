// Import Internal Dependencies
import { VULN_MODE } from "../../constants.js";
import * as utils from "../../utils.js";

// Import types
import type {
  SonatypeVulnerability,
  SnykVulnerability,
  NpmAuditAdvisory,
  PnpmAuditAdvisory,
  StandardVulnerability
} from "../../index.js";

function mapFromNPM(vuln: NpmAuditAdvisory): StandardVulnerability {
  const hasCVSS = typeof vuln.cvss !== "undefined";

  return {
    id: String(vuln.source),
    origin: VULN_MODE.GITHUB_ADVISORY,
    package: vuln.name,
    title: vuln.title,
    url: vuln.url,
    severity: utils.standardizeNpmSeverity(vuln.severity),
    vulnerableRanges: utils.fromMaybeStringToArray(vuln.range),
    vulnerableVersions: utils.fromMaybeStringToArray(vuln.vulnerableVersions),
    ...(hasCVSS ?
      { cvssScore: vuln.cvss!.score, cvssVector: vuln.cvss!.vectorString } :
      {}
    )
  };
}

function mapFromPnpm(vuln: PnpmAuditAdvisory): StandardVulnerability {
  const hasCVSS = typeof vuln.cvss !== "undefined";

  return {
    id: String(vuln.id),
    origin: VULN_MODE.GITHUB_ADVISORY,
    package: vuln.module_name,
    title: vuln.title,
    description: vuln.overview,
    url: vuln.url,
    severity: utils.standardizeNpmSeverity(vuln.severity),
    cves: vuln.cves,
    patchedVersions: vuln.patched_versions,
    vulnerableRanges: [],
    vulnerableVersions: utils.fromMaybeStringToArray(vuln.vulnerable_versions),
    ...(hasCVSS ?
      { cvssScore: vuln.cvss.score, cvssVector: vuln.cvss.vectorString } :
      {}
    )
  };
}

function mapFromSnyk(vuln: SnykVulnerability): StandardVulnerability {
  function concatVulnerableVersions(vulnFunctions) {
    return vulnFunctions
      .reduce((ranges, functions) => [...ranges, ...functions.version], []);
  }

  return {
    id: vuln.id,
    origin: VULN_MODE.SNYK,
    package: vuln.package,
    title: vuln.title,
    url: vuln.url,
    description: vuln.description,
    severity: vuln.severity,
    vulnerableVersions: concatVulnerableVersions(vuln.functions),
    vulnerableRanges: vuln.semver.vulnerable,
    cves: vuln.identifiers.CVE,
    cvssVector: vuln.CVSSv3,
    cvssScore: vuln.cvssScore,
    patches: vuln.patches
  };
}

function mapFromSonatype(vuln: SonatypeVulnerability): StandardVulnerability {
  return {
    id: vuln.id,
    origin: VULN_MODE.SONATYPE,
    package: vuln.package,
    title: vuln.title,
    url: vuln.reference,
    description: vuln.description,
    vulnerableRanges: vuln.versionRanges ?? [],
    vulnerableVersions: vuln.versionRanges ?? [],
    cves: utils.fromMaybeStringToArray(vuln.cve),
    cvssVector: vuln.cvssVector,
    cvssScore: vuln.cvssScore
  };
}

export const VULN_MAPPERS = Object.freeze({
  [VULN_MODE.GITHUB_ADVISORY]: mapFromNPM,
  "github-advisory_pnpm": mapFromPnpm,
  [VULN_MODE.SNYK]: mapFromSnyk,
  [VULN_MODE.SONATYPE]: mapFromSonatype
});

