// Import Third-party Dependencies
import test from "tape";

// Import Internal Dependencies
import { SnykStrategy } from "../../../src/strategies/snyk.js";
import { isNodeSecureStandardVulnerabilityPayload } from "../utils.js";

// When a test environment will be available for skip, unskip this test.
test.skip("snyk strategy: hydratePayloadDependencies when using the API", async(tape) => {
  const { hydratePayloadDependencies } = SnykStrategy();
  const dependencies = new Map();

  dependencies.set("node-uuid", { vulnerabilities: [] });

  await hydratePayloadDependencies(dependencies, {
    path: path.join(kFixturesDir, "snyk"),
    useStandardFormat: true
  });

  tape.strictEqual(
    dependencies.size,
    1,
    "hydratePayloadDependencies must not add new dependencies by itself"
  );

  const { vulnerabilities } = dependencies.get("node-uuid");
  tape.strictEqual(vulnerabilities.length, 1);
  isNodeSecureStandardVulnerabilityPayload(tape, vulnerabilities[0]);

  tape.end();
});

test("snyk strategy: getVulnerabilities", async(tape) => {
  const { getVulnerabilities } = SnykStrategy();

  try {
    await getVulnerabilities();
  }
  catch (error) {
    tape.strictEqual(error.message, "Not Yet Implemented");
  }

  tape.end();
});
