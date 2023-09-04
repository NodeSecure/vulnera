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
function expectNpmAuditVulnToBeGithubAdvisory(tape, vuln) {
  // Assert property
  tape.true("source" in vuln, "advisory must have a 'source' property");
  tape.true("name" in vuln, "advisory must have a 'name' property");
  tape.true("dependency" in vuln, "advisory must have a 'dependency' property");
  tape.true("title" in vuln, "advisory must have a 'title' property");
  tape.true("url" in vuln, "advisory must have a 'url' property");
  tape.true("severity" in vuln, "advisory must have a 'severity' property");
  tape.true("range" in vuln, "advisory must have a 'range' property");
}

test("GitHubAuditStrategy definition must return only three keys.", (tape) => {
  const definition = GitHubAuditStrategy();

  tape.strictEqual(definition.strategy, "github-advisory", "strategy property must equal 'github-advisory'");
  tape.deepEqual(Object.keys(definition).sort(), ["strategy", "hydratePayloadDependencies", "getVulnerabilities"].sort());

  tape.end();
});

test("npm strategy: hydratePayloadDependencies", async(tape) => {
  const { hydratePayloadDependencies } = GitHubAuditStrategy();
  const dependencies = new Map();
  dependencies.set("@npmcli/git", { vulnerabilities: [] });

  await hydratePayloadDependencies(dependencies, {
    path: path.join(kFixturesDir, "audit")
  });

  tape.strictEqual(dependencies.size, 1, "hydratePayloadDependencies must not add new dependencies by itself");
  const { vulnerabilities } = dependencies.get("@npmcli/git");
  tape.strictEqual(vulnerabilities.length, 1);
  expectNpmAuditVulnToBeGithubAdvisory(tape, vulnerabilities[0]);

  tape.end();
});

test("npm strategy: hydratePayloadDependencies using NodeSecure standard format", async(tape) => {
  const { hydratePayloadDependencies } = GitHubAuditStrategy();
  const dependencies = new Map();
  dependencies.set("@npmcli/git", { vulnerabilities: [] });

  await hydratePayloadDependencies(dependencies, {
    path: path.join(kFixturesDir, "audit"),
    useStandardFormat: true
  });

  tape.strictEqual(dependencies.size, 1, "hydratePayloadDependencies must not add new dependencies by itself");
  const { vulnerabilities } = dependencies.get("@npmcli/git");
  tape.strictEqual(vulnerabilities.length, 1);
  expectVulnToBeNodeSecureStandardCompliant(tape, vulnerabilities[0]);

  tape.end();
});

test("npm strategy: getVulnerabilities in NPM format", async(tape) => {
  const { getVulnerabilities } = GitHubAuditStrategy();
  const vulnerabilities = await getVulnerabilities(path.join(kFixturesDir, "audit"));
  const vulnerabilitiesAsIterable = Object.values(
    vulnerabilities
  );

  tape.equal(vulnerabilitiesAsIterable.length > 0, true);

  tape.end();
});

test("npm strategy: getVulnerabilities in the standard NodeSecure format", async(tape) => {
  const { getVulnerabilities } = GitHubAuditStrategy();
  const vulnerabilities = await getVulnerabilities(
    path.join(kFixturesDir, "audit"),
    { useStandardFormat: true }
  );

  tape.equal(vulnerabilities.length > 0, true);
  vulnerabilities.forEach((vuln) => expectVulnToBeNodeSecureStandardCompliant(tape, vuln));

  tape.end();
});
