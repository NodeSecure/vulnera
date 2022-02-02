import { VULN_MODE } from "../constants.js";

export function SonatypeStrategy() {
  return {
    strategy: VULN_MODE.SONATYPE,
    hydratePayloadDependencies
  };
}

export async function hydratePayloadDependencies(dependencies) {
  // Do nothing
}
