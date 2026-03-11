// Import Node.js Dependencies
import { describe, test, after } from "node:test";
import assert from "node:assert";

// Import Internal Dependencies
import {
  HTTP_CLIENT_HEADERS,
  setupHttpAgentMock
} from "../strategies/utils.ts";
import { OSV } from "../../src/database/index.ts";

describe("Database.OSV", () => {
  const db = new OSV();
  const [mockedHttpAgent, restoreHttpAgent] = setupHttpAgentMock();
  const mockedHttpClient = mockedHttpAgent.get(OSV.ROOT_API);

  after(() => {
    restoreHttpAgent();
  });

  test(`should send a POST http request to the OSV API using query
  and then return the 'vulns' property from the JSON response`, async() => {
    const expectedResponse = { vulns: "hello world" };
    mockedHttpClient
      .intercept({
        path: new URL("/v1/query", OSV.ROOT_API).href,
        method: "POST",
        body: JSON.stringify({ package: { name: "foobar", ecosystem: "npm" } })
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const vulns = await db.query({
      package: {
        name: "foobar",
        ecosystem: "npm"
      }
    });
    assert.strictEqual(vulns, expectedResponse.vulns);
  });

  test(`should send a POST http request to the OSV API using queryBySpec
  and then return the 'vulns' property from the JSON response`, async() => {
    const expectedResponse = { vulns: "hello world" };
    const packageName = "@nodesecure/js-x-ray";

    mockedHttpClient
      .intercept({
        path: new URL("/v1/query", OSV.ROOT_API).href,
        method: "POST",
        body: JSON.stringify({
          version: "2.0.0",
          package: { name: packageName, ecosystem: "npm" }
        })
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const vulns = await db.queryBySpec(`${packageName}@2.0.0`);
    assert.strictEqual(vulns, expectedResponse.vulns);
  });

  test("should send a POST http request to /v1/querybatch and return the 'results' array", async() => {
    const expectedResults = [
      { vulns: [{ id: "OSV-2021-1" }] },
      {}
    ];
    const queries = [
      { package: { name: "foo", ecosystem: "npm" }, version: "1.0.0" },
      { package: { name: "bar", ecosystem: "npm" }, version: "2.0.0" }
    ];

    mockedHttpClient
      .intercept({
        path: new URL("/v1/querybatch", OSV.ROOT_API).href,
        method: "POST",
        body: JSON.stringify({ queries })
      })
      .reply(200, { results: expectedResults }, HTTP_CLIENT_HEADERS);

    const results = await db.queryBatch(queries);
    assert.deepEqual(results, expectedResults);
  });

  test("should send a GET http request to /v1/vulns/{id} and return the full OSV object", async() => {
    const vulnId = "OSV-2021-1234";
    const expectedVuln = {
      id: vulnId,
      summary: "Fake vulnerability",
      modified: "2021-01-01T00:00:00Z"
    };

    mockedHttpClient
      .intercept({
        path: new URL(`/v1/vulns/${vulnId}`, OSV.ROOT_API).href,
        method: "GET"
      })
      .reply(200, expectedVuln, HTTP_CLIENT_HEADERS);

    const vuln = await db.findVulnById(vulnId);
    assert.deepEqual(vuln, expectedVuln);
  });
});
