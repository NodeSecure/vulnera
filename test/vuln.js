// Import Node.js Dependencies
import { existsSync, rmSync, writeFileSync } from "fs";

// Import Third-party Dependencies
import test from "tape";
import is from "@slimio/is";

// Import Internal Dependencies
import { setStrategy, getStrategy, mode } from "../index.js";
import { initStrategy } from "../src/strategies/index.js";
import { VULN_FILE_PATH, TMP_CACHE, CACHE_DELAY } from "../src/constants.js";

/**
 * @param {test.Test} tape
 * @param {any} definition
 */
function isStrategyDefinition(tape, definition) {
  tape.true("type" in definition, "definition should have a 'type' property");
  tape.true(typeof definition.type === "string", "definition type property should be a string");

  tape.true("hydratePayloadDependencies" in definition, "definition should have a 'type' property");
  tape.true(
    is.func(definition.hydratePayloadDependencies), "definition hydratePayloadDependencies should be a function"
  );

  if ("hydrateDatabase" in definition) {
    tape.true(is.asyncFunction(definition.hydrateDatabase), "definition hydrateDatabase should be a function");
  }

  if ("deleteDatabase" in definition) {
    tape.true(is.func(definition.deleteDatabase), "definition deleteDatabase should be a function");
  }
}

test("get default strategy", async(tape) => {
  const definition = await getStrategy();
  isStrategyDefinition(tape, definition);
  tape.strictEqual(definition.type, mode.NPM_AUDIT);
});

test("expect initStrategy to return npm strategy as default case", async(tape) => {
  const definition = await initStrategy();
  isStrategyDefinition(tape, definition);
  tape.strictEqual(definition.type, mode.NPM_AUDIT);
});

test("initialize Node.js strategy (with no database hydration)", async(tape) => {
  rmSync(VULN_FILE_PATH, { force: true });

  const definition = await setStrategy(mode.SECURITY_WG);
  isStrategyDefinition(tape, definition);
  tape.strictEqual(definition.type, mode.SECURITY_WG);
  tape.false(existsSync(VULN_FILE_PATH));

  // Fetch current definition
  const currentDefinition = await getStrategy();
  isStrategyDefinition(tape, currentDefinition);
  tape.strictEqual(currentDefinition.type, mode.SECURITY_WG);

  tape.strictEqual(definition, currentDefinition);
  tape.end();
});

test("initialize Node.js strategy (with database hydration)", async(tape) => {
  rmSync(VULN_FILE_PATH, { force: true });
  writeFileSync(TMP_CACHE, JSON.stringify({ lastUpdated: Date.now() - (CACHE_DELAY * 4) }));

  const definition = await setStrategy(mode.SECURITY_WG, { hydrateDatabase: true });
  isStrategyDefinition(tape, definition);
  tape.strictEqual(definition.type, mode.SECURITY_WG);
  tape.true(existsSync(VULN_FILE_PATH));

  tape.end();
});
