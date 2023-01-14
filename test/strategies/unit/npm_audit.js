// Import Third-party Dependencies
import test from "tape";

// Import Internal Dependencies
import { NPMAuditStrategy } from "../../../src/strategies/npm-audit.js";

test("NPMAuditStrategy definition must return only three keys.", (tape) => {
  const definition = NPMAuditStrategy();

  tape.strictEqual(definition.strategy, "npm", "strategy property must equal 'npm'");
  tape.deepEqual(Object.keys(definition).sort(), ["strategy", "hydratePayloadDependencies", "getVulnerabilities"].sort());

  tape.end();
});

