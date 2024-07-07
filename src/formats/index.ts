// Import Internal Dependencies
import { BaseStrategyFormat } from "../strategies/types/api.js";

import {
  standardVulnerabilityMapper,
  StandardizeKind
} from "./standard/index.js";

import {
  osvVulnerabilityMapper,
  OSVKind
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
