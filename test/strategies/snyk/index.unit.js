// Import Node.js Dependencies
import path from "path";
import { fileURLToPath } from "url";

// Import Third-party Dependencies
import test from "tape";

// Import Internal Dependencies
import { SnykStrategy } from "../../../src/strategies/snyk.js";
import { readJsonFile } from "../../../src/utils.js";
import {
  expectVulnToBeNodeSecureStandardCompliant,
  kHttpClientHeaders,
  setupHttpAgentMock
} from "../utils.js";

// CONSTANTS
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const kFixturesDir = path.join(__dirname, "..", "..", "fixtures");
const kSnykOrigin = "https://snyk.io";
const kSnykApiPath = "/api/v1/test/npm?org=undefined";

/**
 * @param {test.Test} tape
 * @param {any} data
 */
function isAdvisory(tape, data) {
  // Assert property
  tape.true("id" in data, "advisory must have a 'id' property");
  tape.true("url" in data, "advisory must have a 'url' property");
  tape.true("title" in data, "advisory must have a 'title' property");
  tape.true("package" in data, "advisory must have a 'package' property");
  tape.true(
    "isPatchable" in data,
    "advisory must have a 'isPatchable' property"
  );
  tape.true("patches" in data, "advisory must have a 'patches' property");
  tape.true(
    "upgradePath" in data,
    "advisory must have a 'upgradePath' property"
  );
  tape.true("severity" in data, "advisory must have a 'severity' property");
}

test("SnykStrategy definition must return only three keys.", (tape) => {
  const definition = SnykStrategy();

  tape.strictEqual(
    definition.strategy,
    "snyk",
    "strategy property must equal 'snyk'"
  );
  tape.deepEqual(
    Object.keys(definition).sort(),
    ["strategy", "hydratePayloadDependencies", "getVulnerabilities"].sort()
  );

  tape.end();
});

test("snyk strategy: hydratePayloadDependencies", async(tape) => {
  const { hydratePayloadDependencies } = SnykStrategy();
  const dependencies = new Map();
  const [mockedHttpAgent, restoreHttpAgent] = setupHttpAgentMock();
  const mockedHttpClient = mockedHttpAgent.get(kSnykOrigin);
  const responseBody = await readJsonFile(
    path.join(kFixturesDir, "snyk/responseBody.json")
  );

  mockedHttpClient
    .intercept({
      path: kSnykApiPath,
      method: "POST"
    })
    .reply(200, responseBody, kHttpClientHeaders);

  dependencies.set("node-uuid", { vulnerabilities: [] });

  await hydratePayloadDependencies(dependencies, {
    path: path.join(kFixturesDir, "snyk")
  });

  tape.strictEqual(
    dependencies.size,
    1,
    "hydratePayloadDependencies must not add new dependencies by itself"
  );
  const { vulnerabilities } = dependencies.get("node-uuid");
  tape.strictEqual(vulnerabilities.length, 1);

  const nodeUUIDVulnerability = vulnerabilities[0];
  isAdvisory(tape, nodeUUIDVulnerability);
  tape.deepEqual(nodeUUIDVulnerability, responseBody.issues.vulnerabilities[0]);

  restoreHttpAgent();
  tape.end();
});

test("snyk strategy: hydratePayloadDependencies using NodeSecure standard format", async(tape) => {
  const { hydratePayloadDependencies } = SnykStrategy();
  const dependencies = new Map();
  const [mockedHttpAgent, restoreHttpAgent] = setupHttpAgentMock();
  const mockedHttpClient = mockedHttpAgent.get(kSnykOrigin);
  const responseBody = await readJsonFile(
    path.join(kFixturesDir, "snyk/responseBody.json")
  );

  mockedHttpClient
    .intercept({
      path: kSnykApiPath,
      method: "POST"
    })
    .reply(200, responseBody, kHttpClientHeaders);

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
  expectVulnToBeNodeSecureStandardCompliant(tape, vulnerabilities[0]);

  restoreHttpAgent();
  tape.end();
});
