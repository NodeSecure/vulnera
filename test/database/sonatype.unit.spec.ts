// Import Node.js Dependencies
import { describe, test, after } from "node:test";
import assert from "node:assert";

// Import Internal Dependencies
import {
  HTTP_CLIENT_HEADERS,
  setupHttpAgentMock
} from "../strategies/utils";
import { sonatype } from "../../src/database/index";

describe("sonatype", () => {
  const [mockedHttpAgent, restoreHttpAgent] = setupHttpAgentMock();
  const mockedHttpClient = mockedHttpAgent.get(sonatype.ROOT_API);

  after(() => {
    restoreHttpAgent();
  });

  const kSonatypeVulnComponent = {
    coordinates: "pkg:npm/fake-npm-package@3.0.1",
    vulnerabilities: [{ id: "1617", cvssScore: 7.5 }]
  };

  test(`should send a POST http request to the SONATYPE API using findOne
  and then return the SonatypeHttpResponse`, async() => {
    const expectedResponse = [kSonatypeVulnComponent];
    const coordinates = ["coord1", "coord2"];
    mockedHttpClient
      .intercept({
        path: new URL("/api/v3/component-report", sonatype.ROOT_API).href,
        method: "POST",
        body: JSON.stringify({ coordinates }),
        headers: {
          accept: "application/json"
        }
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const vulns = await sonatype.findOne({
      coordinates
    });
    assert.deepStrictEqual(vulns, expectedResponse);
  });

  test("should send multiple POST http requests to the SONATYPE API using findMany", async() => {
    const expectedResponse = [kSonatypeVulnComponent];

    mockedHttpClient
      .intercept({
        path: new URL("/api/v3/component-report", sonatype.ROOT_API).href,
        method: "POST",
        headers: {
          accept: "application/json"
        },
        body: JSON.stringify({ coordinates: ["coord1", "coord2"] })
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS)
      .times(2);

    const result = await sonatype.findMany(
      {
        coordinates: [["coord1", "coord2"], ["coord1", "coord2"]]
      }
    );
    assert.deepEqual(result, [kSonatypeVulnComponent, kSonatypeVulnComponent]);
  });
});
