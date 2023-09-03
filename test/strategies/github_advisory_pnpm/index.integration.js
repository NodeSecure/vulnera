// Import Node.js Dependencies
import path from "node:path";
import { fileURLToPath } from "node:url";

// Import Third-party Dependencies
import test from "tape";

// Import Internal Dependencies
import { GitHubAuditStrategy } from "../../../src/strategies/github-advisory.js";
import { expectVulnToBeNodeSecureStandardCompliant } from "../utils.js";

// CONSTANTS
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const kFixturesDir = path.join(__dirname, "..", "..", "fixtures");

/**
 * @param {test.Test} tape
 * @param {any} data
 */
function expectNpmVulnToBePnpmAdvisory(tape, vuln) {
  // Assert property
  tape.true("created" in vuln, "pnpm advisory must have a 'created' property");
  tape.true("module_name" in vuln, "pnpm advisory must have a 'module_name' property");
  tape.true("cwe" in vuln, "pnpm advisory must have a 'cwe' property");
  tape.true("title" in vuln, "pnpmadvisory must have a 'title' property");
  tape.true("url" in vuln, "pnpm advisory must have a 'url' property");
  tape.true("severity" in vuln, "pnpm advisory must have a 'severity' property");
}

test("github (pnpm) strategy: hydratePayloadDependencies", async(tape) => {
  const { hydratePayloadDependencies } = GitHubAuditStrategy();
  const dependencies = new Map();
  dependencies.set("semver", { vulnerabilities: [] });

  await hydratePayloadDependencies(dependencies, {
    path: path.join(kFixturesDir, "audit_pnpm")
  });

  tape.strictEqual(dependencies.size, 1, "hydratePayloadDependencies must not add new dependencies by itself");
  const { vulnerabilities } = dependencies.get("semver");
  tape.strictEqual(vulnerabilities.length, 2);
  for (const subVulnerability of vulnerabilities) {
    expectNpmVulnToBePnpmAdvisory(tape, subVulnerability);
  }

  tape.end();
});

test("github (pnpm) strategy: hydratePayloadDependencies using NodeSecure standard format", async(tape) => {
  const { hydratePayloadDependencies } = GitHubAuditStrategy();
  const dependencies = new Map();
  dependencies.set("semver", { vulnerabilities: [] });

  await hydratePayloadDependencies(dependencies, {
    path: path.join(kFixturesDir, "audit_pnpm"),
    useStandardFormat: true
  });

  tape.strictEqual(dependencies.size, 1, "hydratePayloadDependencies must not add new dependencies by itself");
  const { vulnerabilities } = dependencies.get("semver");
  tape.strictEqual(vulnerabilities.length, 2);
  for (const subVulnerability of vulnerabilities) {
    expectVulnToBeNodeSecureStandardCompliant(tape, subVulnerability);
  }

  tape.end();
});

test("github (pnpm) strategy: getVulnerabilities in PNPM format", async(tape) => {
  const { getVulnerabilities } = GitHubAuditStrategy();
  const vulnerabilities = await getVulnerabilities(path.join(kFixturesDir, "audit_pnpm"));
  const vulnerabilitiesAsIterable = Object.values(
    vulnerabilities
  );

  tape.equal(vulnerabilitiesAsIterable.length > 0, true);

  tape.end();
});

test("github (pnpm) strategy: getVulnerabilities in the standard NodeSecure format", async(tape) => {
  const { getVulnerabilities } = GitHubAuditStrategy();
  const vulnerabilities = await getVulnerabilities(
    path.join(kFixturesDir, "audit_pnpm"),
    { useStandardFormat: true }
  );

  tape.equal(vulnerabilities.length > 0, true);
  vulnerabilities.forEach((vuln) => expectVulnToBeNodeSecureStandardCompliant(tape, vuln));

  tape.end();
});

test("github (pnpm) strategy: getVulnerabilities should work even if we provide a path to a package.json", async(tape) => {
  const { getVulnerabilities } = GitHubAuditStrategy();
  const vulnerabilities = await getVulnerabilities(
    path.join(kFixturesDir, "audit_pnpm", "package.json"),
    { useStandardFormat: true }
  );

  tape.equal(vulnerabilities.length > 0, true);

  tape.end();
});


