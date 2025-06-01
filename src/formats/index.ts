// Import Internal Dependencies
import type { BaseStrategyFormat } from "../strategies/types/api.js";

import {
  standardVulnerabilityMapper,
  type StandardizeKind
} from "./standard/index.js";

export function formatVulnsPayload(
  format: BaseStrategyFormat | null = null
) {
  return function formatVulnerabilities(
    strategy: StandardizeKind,
    vulnerabilities: any[]
  ) {
    if (format === "Standard") {
      return standardVulnerabilityMapper(
        strategy,
        vulnerabilities
      );
    }

    // identity function
    return vulnerabilities;
  };
}
