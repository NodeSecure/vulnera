// Import Node.js Dependencies
import { test } from "node:test";
import assert from "node:assert";

// Import Internal Dependencies
import * as none from "../../../src/strategies/none.js";

test("NoneStrategy definition must return only two keys.", () => {
  const definition = none.NoneStrategy();

  assert.strictEqual(definition.strategy, "none", "strategy property must equal 'none'");
  assert.deepEqual(Object.keys(definition).sort(), ["strategy", "hydratePayloadDependencies"].sort());
});

test("none: hydratePayloadDependencies should not hydrate dependencies Map", async() => {
  const { hydratePayloadDependencies } = none.NoneStrategy();
  const dependencies = new Map();

  await hydratePayloadDependencies(dependencies);
  assert.strictEqual(dependencies.size, 0, "dependencies must be always empty with none strategy");
});
