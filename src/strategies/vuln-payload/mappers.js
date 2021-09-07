// Import Internal Dependencies
import { VULN_MODE } from "../../constants.js"

function mapToSecurityWG(vuln) {
    return {
        id: vuln.id,
        origin: VULN_MODE.SECURITY_WG,
        package: vuln.module_name,
        title: vuln.title,
        description: vuln.overview,
        cves: vuln.cves,
        cvssVector: vuln.cvss_vector,
        cvssScore: vuln.cvss_score,
        vulnerableVersions: [vuln.vulnerable_versions],
        patchedVersions: vuln.patched_versions,
    }
}

function mapToNPM(vuln) {
    return {
        id: vuln.id,
        origin: VULN_MODE.NPM_AUDIT,
        package: vuln.name,
        title: vuln.title,
        url: vuln.url,
        severity: vuln.severity,
        vulnerableVersions: [vuln.vulnerableVersions || vuln.range]
    }
}

function mapToSnyk(vuln) {
    return {
        id: vuln.id,
        origin: VULN_MODE.SNYK,
        package: vuln.package,
        title: vuln.title,
        url: vuln.url,
        description: vuln.description,
        severity: vuln.severity,
        vulnerableVersions: vuln.semver.vulnerable,
        cves: vuln.identifiers.CVE,
        cvssVector: vuln.CVSSv3,
        cvssScore: vuln.cvssScore,
        patches: vuln.patches
    }
}

export const VULN_MAPPERS = {
    [VULN_MODE.NPM_AUDIT]: mapToNPM,
    [VULN_MODE.SECURITY_WG]: mapToSecurityWG,
    [VULN_MODE.SNYK]: mapToSnyk
};