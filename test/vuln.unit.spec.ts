// Import Node.js Dependencies
import assert from "node:assert";
import { test } from "node:test";

// Import Third-party Dependencies
import is from "@slimio/is";

// Import Internal Dependencies
import {
  setStrategy,
  getStrategy,
  strategies,
  defaultStrategyName,
  AnyStrategy
} from "../src/index.js";

function isStrategyDefinition(definition: AnyStrategy) {
  assert.ok("strategy" in definition, "definition should have a 'strategy' property");
  assert.ok(typeof definition.strategy === "string", "definition strategy property should be a string");

  assert.ok("hydratePayloadDependencies" in definition, "definition should have a 'hydratePayloadDependencies' property");
  assert.ok(
    is.func(definition.hydratePayloadDependencies), "definition hydratePayloadDependencies should be a function"
  );

  if ("hydrateDatabase" in definition) {
    assert.ok(is.asyncFunction(definition.hydrateDatabase), "definition hydrateDatabase should be a function");
  }

  if ("deleteDatabase" in definition) {
    assert.ok(is.func(definition.deleteDatabase), "definition deleteDatabase should be a function");
  }
}

test("expect setStrategy to throw if strategy name is unknown", () => {
  assert.throws(
    () => setStrategy("foobar" as any),
    /^Error: Unknown strategy with name 'foobar'./g
  );
});

test("expect getStrategy() to return the default strategy", () => {
  const definition = getStrategy();

  isStrategyDefinition(definition);
  assert.strictEqual(definition.strategy, defaultStrategyName);
});

test("initialize GithubAdvisory Strategy", () => {
  const definition = setStrategy(strategies.GITHUB_ADVISORY);

  isStrategyDefinition(definition);
  assert.strictEqual(definition.strategy, strategies.GITHUB_ADVISORY);
});
