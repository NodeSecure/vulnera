// Import Internal Dependencies
import { VULN_MODE } from "../constants.js";
import type { BaseStrategy } from "./types/api.js";

export type NoneStrategyDefinition = BaseStrategy<"none">;

export function NoneStrategy(): NoneStrategyDefinition {
  return {
    strategy: VULN_MODE.NONE,
    hydratePayloadDependencies
  };
}

async function hydratePayloadDependencies(dependencies: any) {
  // Do nothing
}
