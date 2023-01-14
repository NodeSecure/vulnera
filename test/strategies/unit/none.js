// Import Third-party Dependencies
import test from "tape";

import * as none from "../../../src/strategies/none.js";

test("NoneStrategy definition must return only two keys.", (tape) => {
  const definition = none.NoneStrategy();

  tape.strictEqual(definition.strategy, "none", "strategy property must equal 'none'");
  tape.deepEqual(Object.keys(definition).sort(), ["strategy", "hydratePayloadDependencies"].sort());

  tape.end();
});

test("none: hydratePayloadDependencies should not hydrate dependencies Map", async(tape) => {
  const { hydratePayloadDependencies } = none.NoneStrategy();
  const dependencies = new Map();

  await hydratePayloadDependencies(dependencies);
  tape.strictEqual(dependencies.size, 0, "dependencies must be always empty with none strategy");

  tape.end();
});
