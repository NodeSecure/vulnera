// Import Third-party Dependencies
import test from "tape";

// Import Internal Dependencies
import { SonatypeStrategy } from "../../src/strategies/sonatype.js";
import { SONATYPE_VULNS_PAYLOADS } from "../fixtures/vuln-payload/payloads.js";

// CONSTANTS

test("SonatypeStrategy definition must return only two keys.", (tape) => {
  const definition = SonatypeStrategy();

  tape.strictEqual(definition.strategy, "sonatype", "strategy property must equal 'sonatype'");
  tape.deepEqual(Object.keys(definition).sort(), ["strategy", "hydratePayloadDependencies"].sort());

  tape.end();
});

test("sonatype strategy: hydratePayloadDependencies using NodeSecure standard format", async(tape) => {
  const { hydratePayloadDependencies } = SonatypeStrategy();
  const dependencies = new Map();

  dependencies.set("debug", {
    vulnerabilities: [],
    versions: ["3.0.1"]
  });

  await hydratePayloadDependencies(dependencies, {
  });

  tape.strictEqual(dependencies.size, 1, "hydratePayloadDependencies must not add new dependencies by itself");
  const { vulnerabilities } = dependencies.get("debug");
  tape.strictEqual(vulnerabilities.length, 1);

  tape.end();
});

test("sonatype strategy: hydratePayloadDependencies using NodeSecure standard format", async(tape) => {
  const { hydratePayloadDependencies } = SonatypeStrategy();
  const dependencies = new Map();

  dependencies.set("debug", {
    vulnerabilities: [],
    versions: ["3.0.1"]
  });

  await hydratePayloadDependencies(dependencies, { useStandardFormat: true });

  tape.strictEqual(dependencies.size, 1, "hydratePayloadDependencies must not add new dependencies by itself");
  const { vulnerabilities } = dependencies.get("debug");
  tape.strictEqual(vulnerabilities.length, 1);

  const [standardizedVulnFromSonatype] = vulnerabilities;

  tape.deepEqual(standardizedVulnFromSonatype, SONATYPE_VULNS_PAYLOADS.outputStandardizedPayload);

  tape.end();
});
