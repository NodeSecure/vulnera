// Import Node.js Dependencies
import path from "path";
import { fileURLToPath } from "url";

// Import Third-party Dependencies
import test from "tape";

// Import Internal Dependencies
import { NPMAuditStrategy } from "../../../src/strategies/npm-audit.js";
import { isNodeSecureStandardVulnerabilityPayload } from "../utils.js";

// CONSTANTS
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const kFixturesDir = path.join(__dirname, "..", "..", "fixtures");


/**
 * @param {test.Test} tape
 * @param {any} data
 */
function isAdvisory(tape, data) {
  // Assert property
  tape.true("source" in data, "advisory must have a 'source' property");
  tape.true("name" in data, "advisory must have a 'name' property");
  tape.true("dependency" in data, "advisory must have a 'dependency' property");
  tape.true("title" in data, "advisory must have a 'title' property");
  tape.true("url" in data, "advisory must have a 'url' property");
  tape.true("severity" in data, "advisory must have a 'severity' property");
  tape.true("range" in data, "advisory must have a 'range' property");
}

test("NPMAuditStrategy definition must return only three keys.", (tape) => {
  const definition = NPMAuditStrategy();

  tape.strictEqual(definition.strategy, "npm", "strategy property must equal 'npm'");
  tape.deepEqual(Object.keys(definition).sort(), ["strategy", "hydratePayloadDependencies", "getVulnerabilities"].sort());

  tape.end();
});

test("npm strategy: hydratePayloadDependencies", async(tape) => {
  const { hydratePayloadDependencies } = NPMAuditStrategy();
  const dependencies = new Map();
  dependencies.set("@npmcli/git", { vulnerabilities: [] });

  await hydratePayloadDependencies(dependencies, {
    path: path.join(kFixturesDir, "audit")
  });

  tape.strictEqual(dependencies.size, 1, "hydratePayloadDependencies must not add new dependencies by itself");
  const { vulnerabilities } = dependencies.get("@npmcli/git");
  tape.strictEqual(vulnerabilities.length, 1);

  isAdvisory(tape, vulnerabilities[0]);

  tape.end();
});

test("npm strategy: hydratePayloadDependencies using NodeSecure standard format", async(tape) => {
  const { hydratePayloadDependencies } = NPMAuditStrategy();
  const dependencies = new Map();
  dependencies.set("@npmcli/git", { vulnerabilities: [] });

  await hydratePayloadDependencies(dependencies, {
    path: path.join(kFixturesDir, "audit"),
    useStandardFormat: true
  });

  tape.strictEqual(dependencies.size, 1, "hydratePayloadDependencies must not add new dependencies by itself");
  const { vulnerabilities } = dependencies.get("@npmcli/git");
  tape.strictEqual(vulnerabilities.length, 1);

  isNodeSecureStandardVulnerabilityPayload(tape, vulnerabilities[0]);

  tape.end();
});

test("npm strategy: getVulnerabilities in NPM format", async(tape) => {
  const { getVulnerabilities } = NPMAuditStrategy();
  const vulnerabilities = await getVulnerabilities(path.join(kFixturesDir, "audit"));
  tape.equal(Object.values(vulnerabilities).length, 21);

  tape.end();
});

test("npm strategy: getVulnerabilities in the standard NodeSecure format", async(tape) => {
  const { getVulnerabilities } = NPMAuditStrategy();
  const vulnerabilities = await getVulnerabilities(path.join(kFixturesDir, "audit"), { useStandardFormat: true });

  tape.equal(vulnerabilities.length, 21);
  tape.deepEqual(vulnerabilities[0], {
    id: undefined,
    origin: "npm",
    package: "@npmcli/arborist",
    title: undefined,
    url: undefined,
    severity: "high",
    vulnerableRanges: ["<=2.8.1"],
    vulnerableVersions: []
  });

  tape.end();
});
