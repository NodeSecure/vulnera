// Import Node.js Dependencies
// import { test } from "node:test";
// import assert from "node:assert";
// import { fileURLToPath } from "node:url";
// import path from "node:path";

// Import Internal Dependencies
// import { SnykStrategy } from "../../../src/strategies/snyk.js";
// import { expectVulnToBeNodeSecureStandardCompliant } from "../utils.js";

// CONSTANTS
// const __dirname = path.dirname(fileURLToPath(import.meta.url));
// const kFixturesDir = path.join(__dirname, "..", "..", "fixtures");

// When a test environment will be available for skip, unskip this test.
// test("snyk strategy: hydratePayloadDependencies when using the API", async() => {
//   const { hydratePayloadDependencies } = SnykStrategy();
//   const dependencies = new Map();

//   dependencies.set("node-uuid", { vulnerabilities: [] });

//   await hydratePayloadDependencies(dependencies, {
//     path: path.join(kFixturesDir, "snyk"),
//     useStandardFormat: true
//   });

//   assert.strictEqual(
//     dependencies.size,
//     1,
//     "hydratePayloadDependencies must not add new dependencies by itself"
//   );

//   const { vulnerabilities } = dependencies.get("node-uuid");
//   assert.strictEqual(vulnerabilities.length, 1);
//   expectVulnToBeNodeSecureStandardCompliant(vulnerabilities[0]);
// });
