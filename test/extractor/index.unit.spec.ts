// Import Node.js Dependencies
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert";

// Import Internal Dependencies
import {
  NodeDependencyExtractor,
  type PackageSpec
} from "../../src/extractor/index.ts";

// CONSTANTS
const __dirname = import.meta.dirname;
const kFixturesDir = path.join(__dirname, "..", "fixtures");
const kExtractorFixture = path.join(kFixturesDir, "extractor");

// The fixture has exactly two packages: once@1.4.0 and its dep wrappy@1.0.2
const kExpectedPackages: PackageSpec[] = [
  { name: "once", version: "1.4.0" },
  { name: "wrappy", version: "1.0.2" }
];

test("NodeDependencyExtractor: extract() returns one PackageSpec per lockfile entry", async() => {
  const extractor = new NodeDependencyExtractor();
  const packages = await extractor.extract(kExtractorFixture);

  assert.strictEqual(packages.length, kExpectedPackages.length);
  assert.deepEqual(
    packages.slice().sort((a, b) => a.name.localeCompare(b.name)),
    kExpectedPackages.slice().sort((a, b) => a.name.localeCompare(b.name))
  );
});

test("NodeDependencyExtractor: extract() does not include the root package", async() => {
  const extractor = new NodeDependencyExtractor();
  const packages = await extractor.extract(kExtractorFixture);

  const rootEntry = packages.find(
    (pkg) => pkg.name === "test-extractor-project"
  );
  assert.strictEqual(
    rootEntry,
    undefined,
    "the root package must not appear in results"
  );
});

test("NodeDependencyExtractor: extract() returns no duplicate name@version pairs", async() => {
  const extractor = new NodeDependencyExtractor();
  const packages = await extractor.extract(kExtractorFixture);

  const specs = new Set(packages.map((pkg) => `${pkg.name}@${pkg.version}`));
  assert.strictEqual(
    specs.size,
    packages.length,
    "must not contain duplicate name@version entries"
  );
});
