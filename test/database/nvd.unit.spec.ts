// Import Node.js Dependencies
import { describe, test, after } from "node:test";
import assert from "node:assert";

// Import Internal Dependencies
import {
  HTTP_CLIENT_HEADERS,
  setupHttpAgentMock
} from "../strategies/utils.ts";
import { NVD, ApiCredential } from "../../src/database/index.ts";

// CONSTANTS
const kTestApiKey = "test-api-key";
const kTestCredential = new ApiCredential({ type: "querystring", name: "apiKey", value: kTestApiKey });
const kNvdPathname = new URL(NVD.ROOT_API).pathname;

describe("Database.NVD", () => {
  const db = new NVD({ credential: kTestCredential });
  const [mockedHttpAgent, restoreHttpAgent] = setupHttpAgentMock();
  const mockedHttpClient = mockedHttpAgent.get(new URL(NVD.ROOT_API).origin);

  after(() => {
    restoreHttpAgent();
  });

  test(`should send a GET http request to the NVD API using findOne
  and then return the 'vulnerabilities' property from the JSON response`, async() => {
    const expectedResponse = { vulnerabilities: ["cve-data-1", "cve-data-2"] };
    const params = new URLSearchParams();
    params.append("keywordSearch", "express");
    params.append("apiKey", kTestApiKey);
    const queryString = params.toString();

    mockedHttpClient
      .intercept({
        path: `${kNvdPathname}?${queryString}`,
        method: "GET"
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const vulns = await db.findOne({
      packageName: "express",
      ecosystem: "npm"
    });

    assert.deepStrictEqual(vulns, expectedResponse.vulnerabilities);
  });

  test("should send a GET http request with severity parameter", async() => {
    const expectedResponse = { vulnerabilities: ["cve-data-1"] };
    const params = new URLSearchParams();
    params.append("keywordSearch", "express");
    params.append("cvssV3Severity", "HIGH");
    params.append("apiKey", kTestApiKey);
    const queryString = params.toString();

    mockedHttpClient
      .intercept({
        path: `${kNvdPathname}?${queryString}`,
        method: "GET"
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const vulns = await db.findOne({
      packageName: "express",
      ecosystem: "npm",
      cvssV3Severity: "HIGH"
    });

    assert.deepStrictEqual(vulns, expectedResponse.vulnerabilities);
  });

  test("should send a GET http request to the NVD API using findOneBySpec", async() => {
    const expectedResponse = { vulnerabilities: ["cve-data-1", "cve-data-2"] };
    const packageName = "express";
    const params = new URLSearchParams();
    params.append("keywordSearch", packageName);
    params.append("apiKey", kTestApiKey);
    const queryString = params.toString();

    mockedHttpClient
      .intercept({
        path: `${kNvdPathname}?${queryString}`,
        method: "GET"
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const vulns = await db.findOneBySpec(`${packageName}@1.0.0`);
    assert.deepStrictEqual(vulns, expectedResponse.vulnerabilities);
  });

  test("should send multiple GET http requests to the NVD API using findMany", async() => {
    const expectedResponse = { vulnerabilities: ["cve-data-1", "cve-data-2"] };

    const paramsFirst = new URLSearchParams();
    paramsFirst.append("keywordSearch", "foobar");
    paramsFirst.append("apiKey", kTestApiKey);
    const queryStringFirst = paramsFirst.toString();

    const paramsSecond = new URLSearchParams();
    paramsSecond.append("keywordSearch", "yoobar");
    paramsSecond.append("apiKey", kTestApiKey);
    const queryStringSecond = paramsSecond.toString();

    mockedHttpClient
      .intercept({
        path: `${kNvdPathname}?${queryStringFirst}`,
        method: "GET"
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    mockedHttpClient
      .intercept({
        path: `${kNvdPathname}?${queryStringSecond}`,
        method: "GET"
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const result = await db.findMany(
      ["foobar", "yoobar"]
    );

    assert.deepEqual(result, {
      foobar: expectedResponse.vulnerabilities,
      yoobar: expectedResponse.vulnerabilities
    });
  });

  test("should handle empty response from NVD API", async() => {
    const emptyResponse = {};

    const params = new URLSearchParams();
    params.append("keywordSearch", "nonexistent");
    params.append("apiKey", kTestApiKey);
    const queryString = params.toString();

    mockedHttpClient
      .intercept({
        path: `${kNvdPathname}?${queryString}`,
        method: "GET"
      })
      .reply(200, emptyResponse, HTTP_CLIENT_HEADERS);

    const vulns = await db.findOne({
      packageName: "nonexistent",
      ecosystem: "npm"
    });

    assert.deepStrictEqual(vulns, []);
  });
});
