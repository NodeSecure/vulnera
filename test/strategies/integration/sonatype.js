// Import Third-party Dependencies
import test from "tape";

// Import Internal Dependencies
import { SonatypeStrategy } from "../../../src/strategies/sonatype.js";
import { isNodeSecureStandardVulnerabilityPayload } from "../utils.js";


test("sonatype strategy: fetching a package with a vulnerability using the API", async(tape) => {
  const { hydratePayloadDependencies } = SonatypeStrategy();
  const dependencies = new Map();
  /**
 * This package is arbitrary chosen and hardcoded as there is no way to fetch
 * a list of librairies with versions containing vulnerabilities from Sonatype API.
 * This might break the test at some point if Sonatype databases changes.
 */
  const packageWithVulnerability = {
    package: "debug",
    version: "3.0.1"
  };

  dependencies.set(packageWithVulnerability.package, {
    vulnerabilities: [],
    versions: {
      [packageWithVulnerability.version]: {}
    }
  });

  await hydratePayloadDependencies(dependencies, { useStandardFormat: true });

  tape.strictEqual(
    dependencies.size,
    1,
    "hydratePayloadDependencies must not add new dependencies by itself"
  );

  const { vulnerabilities } = dependencies.get(
    packageWithVulnerability.package
  );
  tape.strictEqual(vulnerabilities.length, 1);

  const [vulnerability] = vulnerabilities;

  isNodeSecureStandardVulnerabilityPayload(tape, vulnerability);

  tape.end();
});

test("sonatype strategy: fetching a package with a name that should be percent-encoded/decoded, using the API", async(tape) => {
  const { hydratePayloadDependencies } = SonatypeStrategy();
  const dependencies = new Map();
  const packageWithScopeThatShouldBePercentEncoded = {
    /**
     * To be compliant with the Package URL spec, the scope from a package name
     * must be percent-encoded.
     * In this case, "@npmcli" is the scope from the full package name "@npmcli/move-file".
     * See: https://github.com/package-url/purl-spec/blob/master/PURL-SPECIFICATION.rst
     */
    package: "@npmcli/move-file",
    version: "1.0.0"
  };

  dependencies.set(
    packageWithScopeThatShouldBePercentEncoded.package,
    {
      vulnerabilities: [],
      versions: {
        [packageWithScopeThatShouldBePercentEncoded.version]: {}
      }
    }
  );

  await hydratePayloadDependencies(dependencies, { useStandardFormat: true });

  tape.strictEqual(
    dependencies.size,
    1,
    "hydratePayloadDependencies must not add new dependencies by itself"
  );

  const { vulnerabilities } = dependencies.get(
    packageWithScopeThatShouldBePercentEncoded.package
  );

  /**
   * We are only interested here in the fact that we were effectively able to reach
   * the API and get back some payload. If the API is not reachable, the vulnerabilities
   * object would not be available and the test would fail.
   */
  tape.strictEqual(vulnerabilities.length, 0);

  tape.end();
});
