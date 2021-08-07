// Import Internal Dependencies
import { NPMAuditStrategy, SecurityWGStrategy } from "./src/strategies/index.js";
import { VULN_MODE } from "./src/constants.js";

// CONSTANTS
const kDefaultVulnModeStrategy = VULN_MODE.NPM_AUDIT;

// VARS
let strategy;

export async function setVulnerabilityStrategy(newStrategy = kDefaultVulnModeStrategy, options = {}) {
  strategy = await initVulnerabilityStrategy(newStrategy, options);

  return strategy;
}

export async function getVulnerabilityStrategy() {
  if (!strategy) {
    const initializedStrategy = await setVulnerabilityStrategy(kDefaultVulnModeStrategy);

    return initializedStrategy;
  }

  return strategy;
}

async function initVulnerabilityStrategy(strategy, options) {
  switch (strategy) {
    case VULN_MODE.SECURITY_WG:
      return Object.seal(await SecurityWGStrategy(options));

    case VULN_MODE.NPM_AUDIT:
      return Object.seal(NPMAuditStrategy());

    default:
      return Object.seal(await SecurityWGStrategy(options));
  }
}
