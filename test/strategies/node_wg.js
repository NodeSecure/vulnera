// Import Third-party Dependencies
import test from "tape";

// Import Internal Dependencies
import { SecurityWGStrategy } from "../../src/strategies/security-wg.js";

test("SecurityWGStrategy definition must return only two keys.", async(tape) => {
  const definition = await SecurityWGStrategy();

  tape.strictEqual(definition.strategy, "node", "strategy property must equal 'node'");
  tape.true(Object.keys(definition).includes("hydratePayloadDependencies"));

  tape.end();
});

