// Import Internal Dependencies
import { VULN_MODE } from "../constants.js";

export function NoneStrategy() {
  return {
    strategy: VULN_MODE.NONE,
    hydratePayloadDependencies
  };
}

async function hydratePayloadDependencies(dependencies) {
  // Do nothing
}
