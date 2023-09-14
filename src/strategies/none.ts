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

// eslint-disable-next-line @typescript-eslint/no-unused-vars
async function hydratePayloadDependencies(dependencies: any) {
  // Do nothing
}
