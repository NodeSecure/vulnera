// Import Node.js Dependencies
import { test } from "node:test";
import assert from "node:assert";

// Import Internal Dependencies
import { OSVStrategy } from "../../../src/strategies/osv.ts";
import { OSV } from "../../../src/database/index.ts";
import {
  expectVulnToBeNodeSecureStandardCompliant,
  HTTP_CLIENT_HEADERS,
  setupHttpAgentMock
} from "../utils.ts";

// CONSTANTS
const kOSVApiOrigin = OSV.ROOT_API;
const kQueryBatchPath = new URL("/v1/querybatch", kOSVApiOrigin).href;

const kFakeOSVVuln = {
  id: "OSV-2021-1234",
  modified: "2021-01-01T00:00:00Z",
  published: "2021-01-01T00:00:00Z",
  aliases: ["CVE-2021-1234"],
  upstream: [],
  summary: "Fake vulnerability for testing",
  details: "This is a fake vulnerability for testing purposes",
  severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
  affected: [
    {
      package: { ecosystem: "npm", name: "fake-pkg", purl: "pkg:npm/fake-pkg" },
      severity: [],
      ranges: [
        {
          type: "SEMVER",
          events: [{ introduced: "1.0.0" }, { fixed: "1.0.1" }],
          database_specific: {}
        }
      ],
      versions: ["1.0.0"],
      ecosystem_specific: {},
      database_specific: {}
    }
  ],
  references: [{ type: "ADVISORY", url: "https://example.com/vuln/OSV-2021-1234" }],
  credits: [],
  database_specific: { severity: "high" }
};

test("OSVStrategy definition must return three keys", () => {
  const definition = OSVStrategy();

  assert.strictEqual(
    definition.strategy,
    "osv",
    "strategy property must equal 'osv'"
  );
  assert.deepEqual(
    Object.keys(definition).sort(),
    ["getVulnerabilities", "hydratePayloadDependencies", "strategy"].sort()
  );
});

test("osv strategy: hydratePayloadDependencies", async() => {
  const { hydratePayloadDependencies } = OSVStrategy();
  const [mockedHttpAgent, restoreHttpAgent] = setupHttpAgentMock();
  const mockedHttpClient = mockedHttpAgent.get(kOSVApiOrigin);

  const dependencies = new Map();
  dependencies.set("fake-pkg", {
    vulnerabilities: [],
    versions: { "1.0.0": { id: 1, description: "package description" } }
  });

  mockedHttpClient
    .intercept({
      path: kQueryBatchPath,
      method: "POST"
    })
    .reply(
      200,
      { results: [{ vulns: [kFakeOSVVuln] }] },
      HTTP_CLIENT_HEADERS
    );

  await hydratePayloadDependencies(dependencies, {});

  assert.strictEqual(
    dependencies.size,
    1,
    "hydratePayloadDependencies must not add new dependencies by itself"
  );

  const { vulnerabilities } = dependencies.get("fake-pkg");
  assert.strictEqual(vulnerabilities.length, 1);

  const [vuln] = vulnerabilities;
  assert.strictEqual(vuln.id, kFakeOSVVuln.id);
  assert.strictEqual(vuln.package, "fake-pkg");

  restoreHttpAgent();
});

test("osv strategy: hydratePayloadDependencies when using NodeSecure standard format", async() => {
  const { hydratePayloadDependencies } = OSVStrategy();
  const [mockedHttpAgent, restoreHttpAgent] = setupHttpAgentMock();
  const mockedHttpClient = mockedHttpAgent.get(kOSVApiOrigin);

  const dependencies = new Map();
  dependencies.set("fake-pkg", {
    vulnerabilities: [],
    versions: { "1.0.0": { id: 1, description: "package description" } }
  });

  mockedHttpClient
    .intercept({
      path: kQueryBatchPath,
      method: "POST"
    })
    .reply(
      200,
      { results: [{ vulns: [kFakeOSVVuln] }] },
      HTTP_CLIENT_HEADERS
    );

  await hydratePayloadDependencies(dependencies, { useFormat: "Standard" });

  assert.strictEqual(
    dependencies.size,
    1,
    "hydratePayloadDependencies must not add new dependencies by itself"
  );

  const { vulnerabilities } = dependencies.get("fake-pkg");
  assert.strictEqual(vulnerabilities.length, 1);

  const [vulnerability] = vulnerabilities;
  expectVulnToBeNodeSecureStandardCompliant(vulnerability);
  assert.strictEqual(vulnerability.origin, "osv");
  assert.strictEqual(vulnerability.package, "fake-pkg");

  restoreHttpAgent();
});

test("osv strategy: hydratePayloadDependencies with > 1000 packages sends two batches", async() => {
  const { hydratePayloadDependencies } = OSVStrategy();
  const [mockedHttpAgent, restoreHttpAgent] = setupHttpAgentMock();
  const mockedHttpClient = mockedHttpAgent.get(kOSVApiOrigin);

  const fakeDependencyPayload = {
    vulnerabilities: [],
    versions: { "1.0.0": { id: 1, description: "package description" } }
  };
  const dependencies = new Map();

  // 1001 packages => two batches (1000 + 1)
  Array.from({ length: 1001 }, (_, i) => dependencies.set(`fake-pkg-${i}`, fakeDependencyPayload));

  mockedHttpClient
    .intercept({
      path: kQueryBatchPath,
      method: "POST"
    })
    .reply(200, { results: Array.from({ length: 1000 }, () => {
      return {};
    }) }, HTTP_CLIENT_HEADERS);

  mockedHttpClient
    .intercept({
      path: kQueryBatchPath,
      method: "POST"
    })
    .reply(200, { results: [{}] }, HTTP_CLIENT_HEADERS);

  await hydratePayloadDependencies(dependencies, {});

  mockedHttpAgent.assertNoPendingInterceptors();

  restoreHttpAgent();
});
