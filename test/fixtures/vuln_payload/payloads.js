import { SNYK_VULNERABILITY, NPM_VULNERABILITY, SECURITYWG_VULNERABILITY, SONATYPE_VULNERABILITY } from "./vulns.js";

export const NPM_VULNS_PAYLOADS = {
  inputVulnsPayload: {
    vulnerabilities: {
      "@npmcli/git": {
        via: [NPM_VULNERABILITY]
      }
    }
  },
  outputStandardizedPayload: {
    id: undefined,
    origin: "npm",
    package: NPM_VULNERABILITY.name,
    title: NPM_VULNERABILITY.title,
    url: NPM_VULNERABILITY.url,
    severity: "medium",
    vulnerableRanges: [NPM_VULNERABILITY.range],
    vulnerableVersions: []
  }
};

export const SNYK_VULNS_PAYLOADS = {
  inputVulnsPayload: {
    vulnerabilities: [
      SNYK_VULNERABILITY
    ]
  },
  outputStandardizedPayload: {
    id: SNYK_VULNERABILITY.id,
    origin: "snyk",
    package: SNYK_VULNERABILITY.package,
    title: SNYK_VULNERABILITY.title,
    url: SNYK_VULNERABILITY.url,
    description: SNYK_VULNERABILITY.description,
    severity: SNYK_VULNERABILITY.severity,
    vulnerableRanges: SNYK_VULNERABILITY.semver.vulnerable,
    vulnerableVersions: [
      ...SNYK_VULNERABILITY.functions[0].version,
      ...SNYK_VULNERABILITY.functions[1].version
    ],
    cves: SNYK_VULNERABILITY.identifiers.CVE,
    cvssVector: SNYK_VULNERABILITY.CVSSv3,
    cvssScore: SNYK_VULNERABILITY.cvssScore,
    patches: SNYK_VULNERABILITY.patches
  }
};

export const SECURITYWG_VULNS_PAYLOADS = {
  inputVulnsPayload: {
    vulnerabilities: [
      SECURITYWG_VULNERABILITY
    ]
  },
  outputStandardizedPayload: {
    id: SECURITYWG_VULNERABILITY.id,
    origin: "node",
    package: SECURITYWG_VULNERABILITY.module_name,
    title: SECURITYWG_VULNERABILITY.title,
    description: SECURITYWG_VULNERABILITY.overview,
    vulnerableRanges: [SECURITYWG_VULNERABILITY.vulnerable_versions],
    vulnerableVersions: [],
    cves: SECURITYWG_VULNERABILITY.cves,
    cvssVector: SECURITYWG_VULNERABILITY.cvss_vector,
    cvssScore: SECURITYWG_VULNERABILITY.cvss_score,
    patchedVersions: SECURITYWG_VULNERABILITY.patched_versions
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
