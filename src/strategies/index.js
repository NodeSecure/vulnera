// Import Strategies
import { GitHubAuditStrategy } from "./github-advisory.js";
import { SecurityWGStrategy } from "./security-wg.js";
import { SnykStrategy } from "./snyk.js";
import { SonatypeStrategy } from "./sonatype.js";
import { NoneStrategy } from "./none.js";

// CONSTANTS
import { VULN_MODE } from "../constants.js";

export { GitHubAuditStrategy, SecurityWGStrategy, SnykStrategy, SonatypeStrategy };

export async function initStrategy(strategy, options) {
  switch (strategy) {
    case VULN_MODE.SECURITY_WG:
      return Object.seal(await SecurityWGStrategy(options));

    case VULN_MODE.GITHUB_ADVISORY:
      return Object.seal(GitHubAuditStrategy());

    case VULN_MODE.SNYK:
      return Object.seal(SnykStrategy());

    case VULN_MODE.SONATYPE:
      return Object.seal(SonatypeStrategy());
  }

  return Object.seal(NoneStrategy());
}
