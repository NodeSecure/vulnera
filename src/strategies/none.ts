// Import Internal Dependencies
import { VULN_MODE } from "../constants.ts";
import type { BaseStrategy } from "./types/api.ts";

export type NoneStrategyDefinition = BaseStrategy<"none">;

export function NoneStrategy(): NoneStrategyDefinition {
  return {
    strategy: VULN_MODE.NONE,
    hydratePayloadDependencies
  };
}

async function hydratePayloadDependencies(_dependencies: any) {
  // Do nothing
}
