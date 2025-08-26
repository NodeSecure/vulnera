// Import Internal Dependencies
import { VULN_MODE } from "../../constants.js";

import type { OSV } from "./index.js";
import type {
  SonatypeVulnerability,
  SnykVulnerability,
  NpmAuditAdvisory,
  PnpmAuditAdvisory
} from "../../index.js";

function mapFromNPM(
  _vuln: NpmAuditAdvisory
): OSV {
  throw new Error("Not Implemented Yet");
}

function mapFromPnpm(
  _vuln: PnpmAuditAdvisory
): OSV {
  throw new Error("Not Implemented Yet");
}

function mapFromSnyk(
  _vuln: SnykVulnerability
): OSV {
  throw new Error("Not Implemented Yet");
}

function mapFromSonatype(
  _vuln: SonatypeVulnerability
): OSV {
  throw new Error("Not Implemented Yet");
}

export const OSV_VULN_MAPPERS = Object.freeze({
  [VULN_MODE.GITHUB_ADVISORY]: mapFromNPM,
  "github-advisory_pnpm": mapFromPnpm,
  [VULN_MODE.SNYK]: mapFromSnyk,
  [VULN_MODE.SONATYPE]: mapFromSonatype
});
