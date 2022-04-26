// Import Third-party Dependencies
import test from "tape";

// Import Internal Dependencies
import { SonatypeStrategy } from "../../src/strategies/sonatype.js";

// CONSTANTS
/**
 * This package is arbitrary chosen and hardcoded as there is no way to fetch
 * a list of librairies with versions containing vulnerabilities from Sonatype API.
 * This might break the test at some point if Sonatype databases changes.
 */
const kPackageURLWithVulnerability = {
  package: "debug",
  version: "3.0.1"
};

test("sonatype strategy: hydrating the payload dependencies using the API", async(tape) => {
  const { hydratePayloadDependencies } = SonatypeStrategy();
  const dependencies = new Map();

  dependencies.set(kPackageURLWithVulnerability.package, {
    vulnerabilities: [],
    versions: {
      [kPackageURLWithVulnerability.version]: {}
    }
  });

  await hydratePayloadDependencies(dependencies);

  tape.strictEqual(
    dependencies.size,
    1,
    "hydratePayloadDependencies must not add new dependencies by itself"
  );

  const { vulnerabilities } = dependencies.get(
    kPackageURLWithVulnerability.package
  );
  tape.strictEqual(vulnerabilities.length, 1);

  const [vulnerability] = vulnerabilities;

  tape.true("id" in vulnerability);
  tape.true("package" in vulnerability);
  tape.true("cvssScore" in vulnerability);

  tape.end();
});
