// Import Third-party Dependencies
import test from "tape";
import * as httpie from "@myunisoft/httpie";

// Import Internal Dependencies
import { SonatypeStrategy } from "../../src/strategies/sonatype.js";

// CONSTANTS
const kSonatypeOrigin = "https://ossindex.sonatype.org";
const kSonatypeApiPath = "/api/v3/component-report";
const kHttpClientHeaders = { headers: { "content-type": "application/json" } };
const kSonatypeVulnComponent = {
  coordinates: "pkg:npm/fake-npm-package@3.0.1",
  vulnerabilities: [{ id: "1617", cvssScore: 7.5 }]
};
const kFakePackageURL = "pkg:npm/fake-npm-package@3.0.1";

test("SonatypeStrategy definition must return only two keys.", (tape) => {
  const definition = SonatypeStrategy();

  tape.strictEqual(
    definition.strategy,
    "sonatype",
    "strategy property must equal 'sonatype'"
  );
  tape.deepEqual(
    Object.keys(definition).sort(),
    ["strategy", "hydratePayloadDependencies"].sort()
  );

  tape.end();
});

function setupHttpAgentMock() {
  const httpDispatcher = httpie.getGlobalDispatcher();
  const mockedHttpAgent = new httpie.MockAgent();

  mockedHttpAgent.disableNetConnect();
  httpie.setGlobalDispatcher(mockedHttpAgent);

  return [
    mockedHttpAgent,
    () => {
      mockedHttpAgent.enableNetConnect();
      httpie.setGlobalDispatcher(httpDispatcher);
    }
  ];
}

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

  const [{ id, package: packageName, origin, cvssScore }] = vulnerabilities;

  const partialPackageData = {
    id,
    package: packageName,
    origin,
    cvssScore
  };

  tape.isEquivalent(partialPackageData, {
    package: "fake-npm-package",
    origin: "sonatype",
    id: "1617",
    cvssScore: 7.5
  });

  restoreHttpAgent();
  tape.end();
});
