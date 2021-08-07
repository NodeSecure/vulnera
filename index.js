// Import Internal Dependencies
import { initStrategy } from "./src/strategies/index.js";
import { VULN_MODE, DEFAULT_VULN_MODE } from "./src/constants.js";

/** @type {Vuln.Strategy} **/
let localVulnerabilityStrategy;

export async function setStrategy(name = DEFAULT_VULN_MODE, options = {}) {
  localVulnerabilityStrategy = await initStrategy(name, options);

  return localVulnerabilityStrategy;
}

export async function getStrategy() {
  if (!localVulnerabilityStrategy) {
    // eslint-disable-next-line no-return-await
    return await setStrategy(DEFAULT_VULN_MODE);
  }

  return localVulnerabilityStrategy;
}

export { VULN_MODE };
