// Import Strategies
import { NPMAuditStrategy } from "./npm-audit.js";
import { SecurityWGStrategy } from "./security-wg.js";

// CONSTANTS
import { VULN_MODE } from "../constants.js";

export { NPMAuditStrategy, SecurityWGStrategy };

export async function initStrategy(strategy, options) {
  switch (strategy) {
    case VULN_MODE.SECURITY_WG:
      return Object.seal(await SecurityWGStrategy(options));

    case VULN_MODE.NPM_AUDIT:
      return Object.seal(NPMAuditStrategy());

    default:
      return Object.seal(NPMAuditStrategy());
  }
}
