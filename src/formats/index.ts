// Import Internal Dependencies
import type { BaseStrategyFormat } from "../strategies/types/api.js";

import {
  standardVulnerabilityMapper,
  type StandardizeKind
} from "./standard/index.js";
import {
  osvVulnerabilityMapper,
  type OSVKind
} from "./osv/index.js";

export function formatVulnsPayload(
  format: BaseStrategyFormat | null = null
) {
  return function formatVulnerabilities(
    strategy: StandardizeKind | OSVKind,
    vulnerabilities: any[]
  ) {
    if (format === "Standard") {
      return standardVulnerabilityMapper(
        strategy,
        vulnerabilities
      );
    }
    if (format === "OSV") {
      return osvVulnerabilityMapper(
        strategy,
        vulnerabilities
      );
    }

    // identity function
    return vulnerabilities;
  };
}
