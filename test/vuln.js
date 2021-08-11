// Import Node.js Dependencies
import { existsSync, rmSync, writeFileSync } from "fs";

// Import Third-party Dependencies
import test from "tape";
import is from "@slimio/is";

// Import Internal Dependencies
import { setStrategy, getStrategy, strategies, defaultStrategyName } from "../index.js";
import { initStrategy } from "../src/strategies/index.js";
import { VULN_FILE_PATH, TMP_CACHE, CACHE_DELAY } from "../src/constants.js";

/**
 * @param {test.Test} tape
 * @param {any} definition
 */
function isStrategyDefinition(tape, definition) {
  tape.true("strategy" in definition, "definition should have a 'strategy' property");
  tape.true(typeof definition.strategy === "string", "definition strategy property should be a string");

  tape.true("hydratePayloadDependencies" in definition, "definition should have a 'hydratePayloadDependencies' property");
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

test("expect getStrategy() to return the default strategy", async(tape) => {
  const definition = await getStrategy();

  isStrategyDefinition(tape, definition);
  tape.strictEqual(definition.strategy, defaultStrategyName);

  tape.end();
});

test("expect initStrategy() to return npm strategy as default case", async(tape) => {
  const definition = await initStrategy();

  isStrategyDefinition(tape, definition);
  tape.strictEqual(definition.strategy, strategies.NPM_AUDIT);

  tape.end();
});

test("initialize Node.js strategy (with no database hydration)", async(tape) => {
  rmSync(VULN_FILE_PATH, { force: true });

  const definition = await setStrategy(strategies.SECURITY_WG);
  isStrategyDefinition(tape, definition);

  tape.strictEqual(definition.strategy, strategies.SECURITY_WG);
  tape.false(existsSync(VULN_FILE_PATH));

  // Fetch current definition
  const currentDefinition = await getStrategy();
  isStrategyDefinition(tape, currentDefinition);

  tape.strictEqual(currentDefinition.strategy, strategies.SECURITY_WG);
  tape.strictEqual(definition, currentDefinition);

  tape.end();
});

test("initialize Node.js strategy (with database hydration)", async(tape) => {
  rmSync(VULN_FILE_PATH, { force: true });
  writeFileSync(TMP_CACHE, JSON.stringify({ lastUpdated: Date.now() - (CACHE_DELAY * 4) }));

  const definition = await setStrategy(strategies.SECURITY_WG, { hydrateDatabase: true });
  isStrategyDefinition(tape, definition);

  tape.strictEqual(definition.strategy, strategies.SECURITY_WG);
  tape.true(existsSync(VULN_FILE_PATH));

  tape.end();
});
