// Import Node.js Dependencies
import { describe, test, after } from "node:test";
import assert from "node:assert";

// Import Internal Dependencies
import {
  HTTP_CLIENT_HEADERS,
  setupHttpAgentMock
} from "../strategies/utils.ts";
import { osv } from "../../src/database/index.ts";

describe("osv", () => {
  const [mockedHttpAgent, restoreHttpAgent] = setupHttpAgentMock();
  const mockedHttpClient = mockedHttpAgent.get(osv.ROOT_API);

  after(() => {
    restoreHttpAgent();
  });

  test(`should send a POST http request to the OSV API using findOne
  and then return the 'vulns' property from the JSON response`, async() => {
    const expectedResponse = { vulns: "hello world" };
    mockedHttpClient
      .intercept({
        path: new URL("/v1/query", osv.ROOT_API).href,
        method: "POST",
        body: JSON.stringify({ package: { name: "foobar", ecosystem: "npm" } })
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const vulns = await osv.findOne({
      package: {
        name: "foobar",
        ecosystem: "npm"
      }
    });
    assert.strictEqual(vulns, expectedResponse.vulns);
  });

  test(`should send a POST http request to the OSV API using findOneBySpec
  and then return the 'vulns' property from the JSON response`, async() => {
    const expectedResponse = { vulns: "hello world" };
    const packageName = "@nodesecure/js-x-ray";

    mockedHttpClient
      .intercept({
        path: new URL("/v1/query", osv.ROOT_API).href,
        method: "POST",
        body: JSON.stringify({
          version: "2.0.0",
          package: { name: packageName, ecosystem: "npm" }
        })
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const vulns = await osv.findOneBySpec(`${packageName}@2.0.0`);
    assert.strictEqual(vulns, expectedResponse.vulns);
  });

  test("should send multiple POST http requests to the OSV API using findMany", async() => {
    const expectedResponse = { vulns: [1, 2, 3] };

    mockedHttpClient
      .intercept({
        path: new URL("/v1/query", osv.ROOT_API).href,
        method: "POST"
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS)
      .times(2);

    const result = await osv.findMany(
      ["foobar", "yoobar"]
    );
    assert.deepEqual(result, {
      foobar: expectedResponse.vulns,
      yoobar: expectedResponse.vulns
    });
  });
});
