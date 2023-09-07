// Import Third-party Dependencies
import test from "tape";

// Import Internal Dependencies
import {
  SonatypeStrategy
} from "../../../src/strategies/sonatype.js";
import {
  expectVulnToBeNodeSecureStandardCompliant,
  kHttpClientHeaders,
  setupHttpAgentMock
} from "../utils.js";

// CONSTANTS
const kSonatypeOrigin = "https://ossindex.sonatype.org";
const kSonatypeApiPath = "/api/v3/component-report";
const kSonatypeVulnComponent = {
  coordinates: "pkg:npm/fake-npm-package@3.0.1",
  vulnerabilities: [{ id: "1617", cvssScore: 7.5 }]
};
const kFakePackageURL = "pkg:npm/fake-npm-package@3.0.1";

test("SonatypeStrategy definition must return only three keys.", (tape) => {
  const definition = SonatypeStrategy();

  tape.strictEqual(
    definition.strategy,
    "sonatype",
    "strategy property must equal 'sonatype'"
  );
  tape.deepEqual(
    Object.keys(definition).sort(),
    ["strategy", "hydratePayloadDependencies", "getVulnerabilities"].sort()
  );

  tape.end();
});

test("sonatype strategy: hydratePayloadDependencies", async(tape) => {
  const { hydratePayloadDependencies } = SonatypeStrategy();
  const dependencies = new Map();
  const [mockedHttpAgent, restoreHttpAgent] = setupHttpAgentMock();
  const mockedHttpClient = mockedHttpAgent.get(kSonatypeOrigin);

  mockedHttpClient
    .intercept({
      path: kSonatypeApiPath,
      method: "POST",
      body: JSON.stringify({ coordinates: [kFakePackageURL] })
    })
    .reply(200, [kSonatypeVulnComponent], kHttpClientHeaders);

  dependencies.set("fake-npm-package", {
    vulnerabilities: [],
    versions: {
      "3.0.1": {
        id: 10,
        description: "package description"
      }
    }
  });

  await hydratePayloadDependencies(dependencies);

  tape.strictEqual(
    dependencies.size,
    1,
    "hydratePayloadDependencies must not add new dependencies by itself"
  );

  const { vulnerabilities } = dependencies.get("fake-npm-package");
  tape.strictEqual(vulnerabilities.length, 1);

  const [fakeNpmPackageVulnerability] = vulnerabilities;
  tape.deepEqual(fakeNpmPackageVulnerability, {
    package: "fake-npm-package",
    id: "1617",
    cvssScore: 7.5
  });

  restoreHttpAgent();
  tape.end();
});

test("sonatype strategy: hydratePayloadDependencies when using NodeSecure standard format", async(tape) => {
  const { hydratePayloadDependencies } = SonatypeStrategy();
  const dependencies = new Map();
  const [mockedHttpAgent, restoreHttpAgent] = setupHttpAgentMock();
  const mockedHttpClient = mockedHttpAgent.get(kSonatypeOrigin);

  mockedHttpClient
    .intercept({
      path: kSonatypeApiPath,
      method: "POST",
      body: JSON.stringify({ coordinates: [kFakePackageURL] })
    })
    .reply(200, [kSonatypeVulnComponent], kHttpClientHeaders);

  dependencies.set("fake-npm-package", {
    vulnerabilities: [],
    versions: {
      "3.0.1": {
        id: 10,
        description: "package description"
      }
    }
  });

  await hydratePayloadDependencies(dependencies, { useStandardFormat: true });

  tape.strictEqual(
    dependencies.size,
    1,
    "hydratePayloadDependencies must not add new dependencies by itself"
  );

  const { vulnerabilities } = dependencies.get("fake-npm-package");
  tape.strictEqual(vulnerabilities.length, 1);

  const [vulnerability] = vulnerabilities;
  const { id, package: packageName, origin, cvssScore } = vulnerability;
  const partialPackageData = {
    id,
    package: packageName,
    origin,
    cvssScore
  };

  expectVulnToBeNodeSecureStandardCompliant(tape, vulnerability);
  tape.deepEqual(partialPackageData, {
    package: "fake-npm-package",
    origin: "sonatype",
    id: "1617",
    cvssScore: 7.5
  });

  restoreHttpAgent();
  tape.end();
});

test("sonatype strategy: fetchDataForPackageURLs with coordinates exceeding the ratelimit", async(tape) => {
  const { hydratePayloadDependencies } = SonatypeStrategy();
  const chunkSizeApiLimit = 128;
  const [mockedHttpAgent, restoreHttpAgent] = setupHttpAgentMock();
  const mockedHttpClient = mockedHttpAgent.get(kSonatypeOrigin);
  const fakeDependencyPayload = {
    vulnerabilities: [],
    versions: {
      "3.0.1": {
        id: 10,
        description: "package description"
      }
    }
  };
  const dependencies = new Map();

  mockedHttpClient
    .intercept({
      path: kSonatypeApiPath,
      method: "POST"
    })
    .reply(200, [kSonatypeVulnComponent], kHttpClientHeaders)
    .times(2);

  dependencies.set("fake-npm-package", fakeDependencyPayload);

  Array.from({ length: chunkSizeApiLimit + 1 }, (_, index) => dependencies.set(`fake-npm-${index}`, fakeDependencyPayload));

  await hydratePayloadDependencies(dependencies);

  mockedHttpAgent.assertNoPendingInterceptors();

  restoreHttpAgent();
  tape.end();
});
