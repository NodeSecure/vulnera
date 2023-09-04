// Import Third-party Dependencies
import test from "tape";

// Import Internal Dependencies
import { GitHubAuditStrategy } from "../../../src/strategies/github-advisory.js";

test("GitHubAuditStrategy definition must return only three keys.", (tape) => {
  const definition = GitHubAuditStrategy();

  tape.strictEqual(definition.strategy, "github-advisory", "strategy property must equal 'github-advisory'");
  tape.deepEqual(Object.keys(definition).sort(), ["strategy", "hydratePayloadDependencies", "getVulnerabilities"].sort());

  tape.end();
});

