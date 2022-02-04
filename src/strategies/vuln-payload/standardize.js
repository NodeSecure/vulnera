// Import Internal Dependencies
import { VULN_MAPPERS } from "./mappers.js";

function useStrategyVulnerabilityMapper(strategy, vulns) {
  if (!VULN_MAPPERS[strategy]) {
    return [];
  }

  return vulns.map(VULN_MAPPERS[strategy]);
}

export function standardizeVulnsPayload(useStandardFormat) {
  return function formatVulnerabilities(strategy, vulnerabilities) {
    if (useStandardFormat) {
      return useStrategyVulnerabilityMapper(
        strategy, vulnerabilities
      );
    }

    // identity function
    return vulnerabilities;
  };
}

