// Import Internal Dependencies
import { VULN_MODE } from "../../constants.ts";
import * as utils from "../../utils.ts";
import type {
  SonatypeVulnerability,
  SnykVulnerability,
  NpmAuditAdvisory,
  PnpmAuditAdvisory,
  StandardVulnerability
} from "../../index.ts";
type Severity = "info" | "low" | "medium" | "high" | "critical";

/** Minimal OSV shape needed by mapFromOSV (avoids circular import chain) */
interface OSVVulnForMapper {
  id: string;
  summary: string;
  details: string;
  aliases?: string[];
  references?: Array<{ type: string; url: string; }>;
  severity?: Array<{ type: string; score: string; }>;
  affected?: Array<{
    versions?: string[];
    ranges?: Array<{
      type: string;
      events: Array<{ introduced?: string; fixed?: string; }>;
    }>;
  }>;
  database_specific?: Record<string, unknown>;
  package: string;
}

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

function osvSeverityToStandard(
  severity: string
): Severity | undefined {
  const lower = severity.toLowerCase();
  if (lower === "moderate") {
    return "medium";
  }
  if (lower === "low" || lower === "medium" || lower === "high" || lower === "critical" || lower === "info") {
    return lower;
  }

  return undefined;
}

function mapFromOSV(
  vuln: OSVVulnForMapper
): StandardVulnerability {
  const advisoryRef = vuln.references?.find((r) => r.type === "ADVISORY") ?? vuln.references?.[0];
  const cves = vuln.aliases?.filter((a) => a.startsWith("CVE-")) ?? [];

  const affected = vuln.affected?.[0];
  const vulnerableVersions = affected?.versions ?? [];

  const semverRanges = affected?.ranges?.filter((r) => r.type === "SEMVER") ?? [];
  const vulnerableRanges: string[] = semverRanges.flatMap((range) => {
    const ranges: string[] = [];
    let intro: string | undefined;
    for (const event of range.events) {
      if (event.introduced !== undefined) {
        intro = event.introduced;
      }
      else if (event.fixed !== undefined && intro !== undefined) {
        ranges.push(`>=${intro} <${event.fixed}`);
        intro = undefined;
      }
    }

    return ranges;
  });

  const patchedVersions = semverRanges
    .flatMap((r) => r.events.filter((e) => e.fixed !== undefined).map((e) => e.fixed!))
    .join(" || ") || undefined;

  const cvssEntry = vuln.severity?.[0];
  const cvssVector = cvssEntry?.score;

  const dbSeverity = vuln.database_specific?.severity as string | undefined;
  const severity = dbSeverity ? osvSeverityToStandard(dbSeverity) : undefined;

  return {
    id: vuln.id,
    origin: VULN_MODE.OSV,
    package: vuln.package,
    title: vuln.summary,
    description: vuln.details,
    url: advisoryRef?.url,
    severity,
    cves: cves.length > 0 ? cves : undefined,
    cvssVector,
    vulnerableVersions,
    vulnerableRanges,
    patchedVersions
  };
}

export const STANDARD_VULN_MAPPERS = Object.freeze({
  [VULN_MODE.GITHUB_ADVISORY]: mapFromNPM,
  "github-advisory_pnpm": mapFromPnpm,
  [VULN_MODE.SNYK]: mapFromSnyk,
  [VULN_MODE.SONATYPE]: mapFromSonatype,
  [VULN_MODE.OSV]: mapFromOSV
});

