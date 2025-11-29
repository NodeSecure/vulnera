// Import Node.js Dependencies
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import assert from "node:assert";

// Import Internal Dependencies
import {
  GitHubAdvisoryStrategy,
  type PnpmAuditAdvisory
} from "../../../src/strategies/github-advisory.ts";
import { expectVulnToBeNodeSecureStandardCompliant } from "../utils.ts";

// CONSTANTS
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const kFixturesDir = path.join(__dirname, "..", "..", "fixtures");

function expectNpmVulnToBePnpmAdvisory(vuln: PnpmAuditAdvisory) {
  // Assert property
  assert.ok("created" in vuln, "pnpm advisory must have a 'created' property");
  assert.ok("module_name" in vuln, "pnpm advisory must have a 'module_name' property");
  assert.ok("cwe" in vuln, "pnpm advisory must have a 'cwe' property");
  assert.ok("title" in vuln, "pnpmadvisory must have a 'title' property");
  assert.ok("url" in vuln, "pnpm advisory must have a 'url' property");
  assert.ok("severity" in vuln, "pnpm advisory must have a 'severity' property");
}

test("GitHubAdvisoryStrategy (pnpm): hydratePayloadDependencies", async() => {
  const { hydratePayloadDependencies } = GitHubAdvisoryStrategy();
  const dependencies = new Map();
  dependencies.set("semver", { vulnerabilities: [] });

  await hydratePayloadDependencies(dependencies, {
    path: path.join(kFixturesDir, "audit_pnpm")
  });

  assert.strictEqual(dependencies.size, 1, "hydratePayloadDependencies must not add new dependencies by itself");
  const { vulnerabilities } = dependencies.get("semver");
  assert.strictEqual(vulnerabilities.length, 2);
  for (const subVulnerability of vulnerabilities) {
    expectNpmVulnToBePnpmAdvisory(subVulnerability);
  }
});

test("GitHubAdvisoryStrategy (pnpm): hydratePayloadDependencies using NodeSecure standard format", async() => {
  const { hydratePayloadDependencies } = GitHubAdvisoryStrategy();
  const dependencies = new Map();
  dependencies.set("semver", { vulnerabilities: [] });

  await hydratePayloadDependencies(dependencies, {
    path: path.join(kFixturesDir, "audit_pnpm"),
    useFormat: "Standard"
  });

  assert.strictEqual(dependencies.size, 1, "hydratePayloadDependencies must not add new dependencies by itself");
  const { vulnerabilities } = dependencies.get("semver");
  assert.strictEqual(vulnerabilities.length, 2);
  for (const subVulnerability of vulnerabilities) {
    expectVulnToBeNodeSecureStandardCompliant(subVulnerability);
  }
});

test("GitHubAdvisoryStrategy (pnpm): getVulnerabilities in PNPM format", async() => {
  const { getVulnerabilities } = GitHubAdvisoryStrategy();
  const vulnerabilities = await getVulnerabilities(path.join(kFixturesDir, "audit_pnpm"));
  const vulnerabilitiesAsIterable = Object.values(
    vulnerabilities
  );

  assert.equal(vulnerabilitiesAsIterable.length > 0, true);
});

test("GitHubAdvisoryStrategy (pnpm): getVulnerabilities in the standard NodeSecure format", async() => {
  const { getVulnerabilities } = GitHubAdvisoryStrategy();
  const vulnerabilities = await getVulnerabilities(
    path.join(kFixturesDir, "audit_pnpm"),
    { useFormat: "Standard" }
  );

  assert.equal(vulnerabilities.length > 0, true);
  vulnerabilities.forEach((vuln) => expectVulnToBeNodeSecureStandardCompliant(vuln));
});

test("GitHubAdvisoryStrategy (pnpm): getVulnerabilities should work even if we provide a path to a package.json", async() => {
  const { getVulnerabilities } = GitHubAdvisoryStrategy();
  const vulnerabilities = await getVulnerabilities(
    path.join(kFixturesDir, "audit_pnpm", "package.json"),
    { useFormat: "Standard" }
  );

  assert.equal(vulnerabilities.length > 0, true);
});
