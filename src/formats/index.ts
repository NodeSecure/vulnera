// Import Internal Dependencies
import type { BaseStrategyFormat } from "../strategies/types/api.ts";

import {
  standardVulnerabilityMapper,
  type StandardizeKind
} from "./standard/index.ts";

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
