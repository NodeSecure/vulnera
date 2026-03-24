// Import Internal Dependencies
import {
  NPM_VULNERABILITY,
  PNPM_VULNERABILITY,
  SONATYPE_VULNERABILITY
} from "./vulns.ts";

export const NPM_VULNS_PAYLOADS = {
  inputVulnsPayload: {
    vulnerabilities: {
      "@npmcli/git": {
        via: [NPM_VULNERABILITY]
      }
    }
  },
  outputStandardizedPayload: {
    id: 1005085,
    origin: "github-advisory",
    package: NPM_VULNERABILITY.name,
    title: NPM_VULNERABILITY.title,
    url: NPM_VULNERABILITY.url,
    severity: "medium",
    vulnerableRanges: [NPM_VULNERABILITY.range],
    vulnerableVersions: []
  }
};

export const SONATYPE_VULNS_PAYLOADS = {
  inputVulnsPayload: {
    vulnerabilities: [
      SONATYPE_VULNERABILITY
    ]
  },
  outputStandardizedPayload: {
    id: SONATYPE_VULNERABILITY.id,
    origin: "sonatype",
    /**
     * Package name is harcoded because the input name is not directly available
     * from the input vulnerability but from an outer object. Outside of the
     * context of tests, the package name is provided from a High Order Function
    */
    package: "debug",
    title: SONATYPE_VULNERABILITY.title,
    url: SONATYPE_VULNERABILITY.reference,
    description: SONATYPE_VULNERABILITY.description,
    vulnerableRanges: [],
    vulnerableVersions: [],
    cves: [],
    cvssVector: SONATYPE_VULNERABILITY.cvssVector,
    cvssScore: SONATYPE_VULNERABILITY.cvssScore
  }
};

export const NPM_OSV_PAYLOAD = {
  inputVulnsPayload: {
    vulnerabilities: {
      "@npmcli/git": {
        via: [NPM_VULNERABILITY]
      }
    }
  },
  outputOSVPayload: {
    id: "GHSA-hxwm-x553-x359",
    aliases: [],
    upstream: [],
    summary: NPM_VULNERABILITY.title,
    details: NPM_VULNERABILITY.title,
    severity: [],
    affected: [
      {
        package: {
          ecosystem: "npm",
          name: NPM_VULNERABILITY.name,
          purl: `pkg:npm/${encodeURIComponent(NPM_VULNERABILITY.name)}`
        },
        severity: [],
        ranges: [
          {
            type: "SEMVER",
            events: [{ introduced: "0" }, { fixed: "2.0.8" }],
            database_specific: {}
          }
        ],
        versions: [],
        ecosystem_specific: {},
        database_specific: {}
      }
    ],
    references: [{ type: "ADVISORY", url: NPM_VULNERABILITY.url }],
    credits: [],
    database_specific: { severity: NPM_VULNERABILITY.severity }
  }
};

export const PNPM_OSV_PAYLOAD = {
  inputVulnsPayload: {
    vulnerabilities: [PNPM_VULNERABILITY]
  },
  outputOSVPayload: {
    id: PNPM_VULNERABILITY.github_advisory_id,
    aliases: PNPM_VULNERABILITY.cwe,
    upstream: [],
    summary: PNPM_VULNERABILITY.title,
    details: PNPM_VULNERABILITY.overview,
    severity: [{ type: "CVSS_V3", score: PNPM_VULNERABILITY.cvss.vectorString }],
    affected: [
      {
        package: {
          ecosystem: "npm",
          name: PNPM_VULNERABILITY.module_name,
          purl: `pkg:npm/${encodeURIComponent(PNPM_VULNERABILITY.module_name)}`
        },
        severity: [],
        ranges: [],
        versions: PNPM_VULNERABILITY.vulnerable_versions,
        ecosystem_specific: { patched_versions: PNPM_VULNERABILITY.patched_versions },
        database_specific: {}
      }
    ],
    references: [{ type: "ADVISORY", url: PNPM_VULNERABILITY.url }],
    credits: [],
    database_specific: { severity: PNPM_VULNERABILITY.severity }
  }
};

export const SONATYPE_OSV_PAYLOAD = {
  inputVulnsPayload: {
    vulnerabilities: [SONATYPE_VULNERABILITY]
  },
  outputOSVPayload: {
    id: SONATYPE_VULNERABILITY.id,
    aliases: [],
    upstream: [],
    summary: SONATYPE_VULNERABILITY.title,
    details: SONATYPE_VULNERABILITY.description,
    severity: [{ type: "CVSS_V3", score: SONATYPE_VULNERABILITY.cvssVector }],
    affected: [
      {
        package: {
          ecosystem: "npm",
          name: "",
          purl: ""
        },
        severity: [],
        ranges: [],
        versions: [],
        ecosystem_specific: {},
        database_specific: {}
      }
    ],
    references: [
      { type: "ADVISORY", url: SONATYPE_VULNERABILITY.reference },
      { type: "WEB", url: SONATYPE_VULNERABILITY.externalReferences[0] }
    ],
    credits: [],
    database_specific: { cwe: SONATYPE_VULNERABILITY.cwe, cvssScore: SONATYPE_VULNERABILITY.cvssScore }
  }
};
