// Import Internal Dependencies
import type { BaseStrategyFormat } from "../strategies/types/api.ts";

import {
  standardVulnerabilityMapper,
  type StandardizeKind
} from "./standard/index.ts";
import {
  osvVulnerabilityMapper,
  type OSVKind
} from "./osv/index.ts";

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
