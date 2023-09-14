// Import Node.js Dependencies
import { test } from "node:test";
import assert from "node:assert";

// Import Internal Dependencies
import { GitHubAdvisoryStrategy } from "../../../src/strategies/github-advisory.js";

test("GitHubAdvisoryStrategy definition must return only three keys.", () => {
  const definition = GitHubAdvisoryStrategy();

  assert.strictEqual(definition.strategy, "github-advisory", "strategy property must equal 'github-advisory'");
  assert.deepEqual(Object.keys(definition).sort(), ["strategy", "hydratePayloadDependencies", "getVulnerabilities"].sort());
});

