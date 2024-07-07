// Import Internal Dependencies
import { BaseStrategyFormat } from "../strategies/types/api.js";

import {
  standardVulnerabilityMapper,
  StandardizeKind
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
    if (format === "OSV") {
      throw new Error("Not Implemented Yet");
    }

    // identity function
    return vulnerabilities;
  };
}
