// Import Internal Dependencies
import { VULN_MODE } from "../../constants.ts";
import * as utils from "../../utils.ts";

import type {
  OSV,
  OSVRange
} from "./index.ts";
import type {
  SonatypeVulnerability,
  NpmAuditAdvisory,
  PnpmAuditAdvisory
} from "../../index.ts";

function extractGhsaId(
  url: string
): string {
  return url.match(/GHSA-[a-z0-9-]+/i)?.[0] ?? "";
}

function toPurl(
  packageName: string
): string {
  return `pkg:npm/${encodeURIComponent(packageName)}`;
}

function semverRangeToOsvEvents(
  range: string
): OSVRange["events"] {
  const parts = range
    .split(",")
    .map((part) => part.trim());
  const events: OSVRange["events"] = [];

  for (const part of parts) {
    const ltMatch = part.match(/^<([^\s=].*)$/);
    const lteMatch = part.match(/^<=(.+)$/);
    const gteMatch = part.match(/^>=(.+)$/);
    const gtMatch = part.match(/^>([^=].*)$/);

    if (lteMatch) {
      events.push({ last_affected: lteMatch[1].trim() });
    }
    else if (ltMatch) {
      events.push({ fixed: ltMatch[1].trim() });
    }
    else if (gteMatch) {
      events.push({ introduced: gteMatch[1].trim() });
    }
    else if (gtMatch) {
      events.push({ introduced: gtMatch[1].trim() });
    }
  }

  const hasIntroduced = events.some((e) => "introduced" in e);
  if (!hasIntroduced) {
    events.unshift({ introduced: "0" });
  }

  return events;
}

function mapFromNPM(
  vuln: NpmAuditAdvisory
): OSV {
  const id = extractGhsaId(vuln.url) || String(vuln.source);

  return {
    id,
    modified: new Date().toISOString(),
    published: new Date().toISOString(),
    aliases: vuln.cwe ?? [],
    upstream: [],
    summary: vuln.title,
    details: vuln.title,
    severity: vuln.cvss ?
      [{ type: "CVSS_V3", score: vuln.cvss.vectorString }] :
      [],
    affected: [
      {
        package: {
          ecosystem: "npm",
          name: vuln.name,
          purl: toPurl(vuln.name)
        },
        severity: [],
        ranges: [
          {
            type: "SEMVER",
            events: semverRangeToOsvEvents(vuln.range),
            database_specific: {}
          }
        ],
        versions: utils.fromMaybeStringToArray(vuln.vulnerableVersions),
        ecosystem_specific: {},
        database_specific: {}
      }
    ],
    references: [
      {
        type: "ADVISORY",
        url: vuln.url
      }
    ],
    credits: [],
    database_specific: {
      severity: vuln.severity
    }
  };
}

function mapFromPnpm(
  vuln: PnpmAuditAdvisory
): OSV {
  return {
    id: vuln.github_advisory_id,
    modified: new Date().toISOString(),
    published: new Date().toISOString(),
    aliases: utils.fromMaybeStringToArray(vuln.cwe),
    upstream: [],
    summary: vuln.title,
    details: vuln.overview ?? vuln.title,
    severity: vuln.cvss ?
      [{ type: "CVSS_V3", score: vuln.cvss.vectorString }] :
      [],
    affected: [
      {
        package: {
          ecosystem: "npm",
          name: vuln.module_name,
          purl: toPurl(vuln.module_name)
        },
        severity: [],
        ranges: [],
        versions: utils.fromMaybeStringToArray(vuln.vulnerable_versions),
        ecosystem_specific: { patched_versions: vuln.patched_versions },
        database_specific: {}
      }
    ],
    references: [{ type: "ADVISORY", url: vuln.url }],
    credits: [],
    database_specific: { severity: vuln.severity }
  };
}

function mapFromSonatype(
  vuln: SonatypeVulnerability
): OSV {
  return {
    id: vuln.id,
    modified: new Date().toISOString(),
    published: new Date().toISOString(),
    aliases: utils.fromMaybeStringToArray(vuln.cve),
    upstream: [],
    summary: vuln.title,
    details: vuln.description,
    severity: [
      { type: "CVSS_V3", score: vuln.cvssVector }
    ],
    affected: [
      {
        package: {
          ecosystem: "npm",
          name: vuln.package ?? "",
          purl: vuln.package ? toPurl(vuln.package) : ""
        },
        severity: [],
        ranges: (vuln.versionRanges ?? []).map((range) => {
          return {
            type: "SEMVER",
            events: semverRangeToOsvEvents(range),
            database_specific: {}
          };
        }),
        versions: vuln.versionRanges ?? [],
        ecosystem_specific: {},
        database_specific: {}
      }
    ],
    references: [
      { type: "ADVISORY", url: vuln.reference },
      ...vuln.externalReferences.map((url) => {
        return { type: "WEB" as const, url };
      })
    ],
    credits: [],
    database_specific: {
      cwe: vuln.cwe,
      cvssScore: vuln.cvssScore
    }
  };
}

export const OSV_VULN_MAPPERS = Object.freeze({
  [VULN_MODE.GITHUB_ADVISORY]: mapFromNPM,
  "github-advisory_pnpm": mapFromPnpm,
  [VULN_MODE.SONATYPE]: mapFromSonatype
});
