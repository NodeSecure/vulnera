// Import Node.js Dependencies
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import assert from "node:assert";

// Import Internal Dependencies
import { GitHubAdvisoryStrategy, NpmAuditAdvisory } from "../../../src/strategies/github-advisory.js";
import { expectVulnToBeNodeSecureStandardCompliant } from "../utils.js";

// CONSTANTS
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const kFixturesDir = path.join(__dirname, "..", "..", "fixtures");

function expectNpmAuditVulnToBeGithubAdvisory(vuln: NpmAuditAdvisory) {
  // Assert property
  assert.ok("source" in vuln, "advisory must have a 'source' property");
  assert.ok("name" in vuln, "advisory must have a 'name' property");
  assert.ok("dependency" in vuln, "advisory must have a 'dependency' property");
  assert.ok("title" in vuln, "advisory must have a 'title' property");
  assert.ok("url" in vuln, "advisory must have a 'url' property");
  assert.ok("severity" in vuln, "advisory must have a 'severity' property");
  assert.ok("range" in vuln, "advisory must have a 'range' property");
}

test("GitHubAdvisoryStrategy definition must return only three keys.", () => {
  const definition = GitHubAdvisoryStrategy();

  assert.strictEqual(definition.strategy, "github-advisory", "strategy property must equal 'github-advisory'");
  assert.deepEqual(Object.keys(definition).sort(), ["strategy", "hydratePayloadDependencies", "getVulnerabilities"].sort());
});

test("GitHubAdvisoryStrategy (npm): hydratePayloadDependencies", async() => {
  const { hydratePayloadDependencies } = GitHubAdvisoryStrategy();
  const dependencies = new Map();
  dependencies.set("@npmcli/git", { vulnerabilities: [] });

  await hydratePayloadDependencies(dependencies, {
    path: path.join(kFixturesDir, "audit")
  });

  assert.strictEqual(dependencies.size, 1, "hydratePayloadDependencies must not add new dependencies by itself");
  const { vulnerabilities } = dependencies.get("@npmcli/git");
  assert.strictEqual(vulnerabilities.length, 1);
  expectNpmAuditVulnToBeGithubAdvisory(vulnerabilities[0]);
});

test("GitHubAdvisoryStrategy (npm): hydratePayloadDependencies using NodeSecure standard format", async() => {
  const { hydratePayloadDependencies } = GitHubAdvisoryStrategy();
  const dependencies = new Map();
  dependencies.set("@npmcli/git", { vulnerabilities: [] });

  await hydratePayloadDependencies(dependencies, {
    path: path.join(kFixturesDir, "audit"),
    useStandardFormat: true
  });

  assert.strictEqual(dependencies.size, 1, "hydratePayloadDependencies must not add new dependencies by itself");
  const { vulnerabilities } = dependencies.get("@npmcli/git");
  assert.strictEqual(vulnerabilities.length, 1);
  expectVulnToBeNodeSecureStandardCompliant(vulnerabilities[0]);
});

test("GitHubAdvisoryStrategy (npm): getVulnerabilities in NPM format", async() => {
  const { getVulnerabilities } = GitHubAdvisoryStrategy();
  const vulnerabilities = await getVulnerabilities(path.join(kFixturesDir, "audit"));
  const vulnerabilitiesAsIterable = Object.values(
    vulnerabilities
  );

  assert.equal(vulnerabilitiesAsIterable.length > 0, true);
});

test("GitHubAdvisoryStrategy (npm): getVulnerabilities in the standard NodeSecure format", async() => {
  const { getVulnerabilities } = GitHubAdvisoryStrategy();
  const vulnerabilities = await getVulnerabilities(
    path.join(kFixturesDir, "audit"),
    { useStandardFormat: true }
  );

  assert.equal(vulnerabilities.length > 0, true);
  vulnerabilities.forEach((vuln) => expectVulnToBeNodeSecureStandardCompliant(vuln));
});
