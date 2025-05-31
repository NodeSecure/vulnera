// Import Node.js Dependencies
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import assert from "node:assert";
import path from "node:path";
import fs from "node:fs/promises";

// Import Internal Dependencies
import { SnykStrategy } from "../../../src/strategies/snyk.js";
import {
  expectVulnToBeNodeSecureStandardCompliant,
  HTTP_CLIENT_HEADERS,
  setupHttpAgentMock
} from "../utils.js";

// CONSTANTS
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const kFixturesDir = path.join(__dirname, "..", "..", "fixtures");
const kSnykOrigin = "https://snyk.io";
const kSnykApiPath = "/api/v1/test/npm?org=undefined";

async function readFileJSON<T>(location: string): Promise<T> {
  const rawText = await fs.readFile(location, "utf-8");

  return JSON.parse(rawText) as T;
}

function isAdvisory(data: any) {
  // Assert property
  assert.ok("id" in data, "advisory must have a 'id' property");
  assert.ok("url" in data, "advisory must have a 'url' property");
  assert.ok("title" in data, "advisory must have a 'title' property");
  assert.ok("package" in data, "advisory must have a 'package' property");
  assert.ok(
    "isPatchable" in data,
    "advisory must have a 'isPatchable' property"
  );
  assert.ok("patches" in data, "advisory must have a 'patches' property");
  assert.ok(
    "upgradePath" in data,
    "advisory must have a 'upgradePath' property"
  );
  assert.ok("severity" in data, "advisory must have a 'severity' property");
}

test("SnykStrategy definition must return only two keys.", () => {
  const definition = SnykStrategy();

  assert.strictEqual(
    definition.strategy,
    "snyk",
    "strategy property must equal 'snyk'"
  );
  assert.deepEqual(
    Object.keys(definition).sort(),
    ["strategy", "hydratePayloadDependencies"].sort()
  );
});

test("snyk strategy: hydratePayloadDependencies", async() => {
  const { hydratePayloadDependencies } = SnykStrategy();
  const dependencies = new Map();
  const [mockedHttpAgent, restoreHttpAgent] = setupHttpAgentMock();
  const mockedHttpClient = mockedHttpAgent.get(kSnykOrigin);
  const responseBody = await readFileJSON<any>(
    path.join(kFixturesDir, "snyk/responseBody.json")
  );

  mockedHttpClient
    .intercept({
      path: kSnykApiPath,
      method: "POST"
    })
    .reply(200, responseBody, HTTP_CLIENT_HEADERS);

  dependencies.set("node-uuid", { vulnerabilities: [] });

  await hydratePayloadDependencies(dependencies, {
    path: path.join(kFixturesDir, "snyk")
  });

  assert.strictEqual(
    dependencies.size,
    1,
    "hydratePayloadDependencies must not add new dependencies by itself"
  );
  const { vulnerabilities } = dependencies.get("node-uuid");
  assert.strictEqual(vulnerabilities.length, 1);

  const nodeUUIDVulnerability = vulnerabilities[0];
  isAdvisory(nodeUUIDVulnerability);
  assert.deepEqual(nodeUUIDVulnerability, responseBody.issues.vulnerabilities[0]);

  restoreHttpAgent();
});

test("snyk strategy: hydratePayloadDependencies using NodeSecure standard format", async() => {
  const { hydratePayloadDependencies } = SnykStrategy();
  const dependencies = new Map();
  const [mockedHttpAgent, restoreHttpAgent] = setupHttpAgentMock();
  const mockedHttpClient = mockedHttpAgent.get(kSnykOrigin);
  const responseBody = await readFileJSON<any>(
    path.join(kFixturesDir, "snyk/responseBody.json")
  );

  mockedHttpClient
    .intercept({
      path: kSnykApiPath,
      method: "POST"
    })
    .reply(200, responseBody, HTTP_CLIENT_HEADERS);

  dependencies.set("node-uuid", { vulnerabilities: [] });

  await hydratePayloadDependencies(dependencies, {
    path: path.join(kFixturesDir, "snyk"),
    useFormat: "Standard"
  });

  assert.strictEqual(
    dependencies.size,
    1,
    "hydratePayloadDependencies must not add new dependencies by itself"
  );

  const { vulnerabilities } = dependencies.get("node-uuid");
  assert.strictEqual(vulnerabilities.length, 1);
  expectVulnToBeNodeSecureStandardCompliant(vulnerabilities[0]);

  restoreHttpAgent();
});
