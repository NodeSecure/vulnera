// Import Node.js Dependencies
import path from "path";
import { fileURLToPath } from "url";

// Import Third-party Dependencies
import test from "tape";

// Import Internal Dependencies
import { SnykStrategy } from "../../src/strategies/snyk.js";
import { readJsonFile } from "../../src/utils.js";
import { standardizeVulnsPayload } from "../../src/strategies/vuln-payload/standardize.js";

// CONSTANTS
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const kFixturesDir = path.join(__dirname, "..", "fixtures");

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
  tape.true("isPatchable" in data, "advisory must have a 'isPatchable' property");
  tape.true("patches" in data, "advisory must have a 'patches' property");
  tape.true("upgradePath" in data, "advisory must have a 'upgradePath' property");
  tape.true("severity" in data, "advisory must have a 'severity' property");
}

test("SnykStrategy definition must return only two keys.", (tape) => {
  const definition = SnykStrategy();

  tape.strictEqual(definition.strategy, "snyk", "strategy property must equal 'snyk'");
  tape.deepEqual(Object.keys(definition).sort(), ["strategy", "hydratePayloadDependencies"].sort());

  tape.end();
});

// test("snyk strategy: hydratePayloadDependencies", async (tape) => {
//   const dependencies = new Map();
//   dependencies.set("node-uuid", { vulnerabilities: [] });

//   await hydratePayloadDependencies(dependencies, {
//     path: path.join(kFixturesDir, "snyk")
//   });

//   tape.strictEqual(dependencies.size, 1, "hydratePayloadDependencies must not add new dependencies by itself");
//   const { vulnerabilities } = dependencies.get("node-uuid");
//   tape.strictEqual(vulnerabilities.length, 1);

//   isAdvisory(tape, vulnerabilities[0]);

//   const responseBody = await readJsonFile(path.join(kFixturesDir, "snyk/responseBody.json"));
//   tape.deepEqual(vulnerabilities[0], responseBody.issues.vulnerabilities[0]);

//   tape.end();
// });

// test("snyk strategy: hydratePayloadDependencies using NodeSecure standard format", async (tape) => {
//   const dependencies = new Map();
//   dependencies.set("node-uuid", { vulnerabilities: [] });

//   await hydratePayloadDependencies(dependencies, {
//     path: path.join(kFixturesDir, "snyk"),
//     useStandardFormat: true
//   });

//   const { vulnerabilities } = dependencies.get("node-uuid");
//   const { issues } = await readJsonFile(path.join(kFixturesDir, "snyk/responseBody.json"));

//   // when Snyk API can be reached, uncomment line below
//   // tape.deepEqual(vulnerabilities[0], standardizeVulnsPayload(issues.vulnerabilities));

//   tape.end();
// });
