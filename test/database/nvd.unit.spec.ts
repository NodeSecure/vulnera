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
  const db = new NVD({ credential: kTestCredential, requestDelay: 0 });
  const [mockedHttpAgent, restoreHttpAgent] = setupHttpAgentMock();
  const mockedHttpClient = mockedHttpAgent.get(new URL(NVD.ROOT_API).origin);

  after(() => {
    restoreHttpAgent();
  });

  test(`should send a GET http request to the NVD API using find
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

    const vulns = await db.find({
      packageName: "express",
      ecosystem: "npm"
    });

    assert.deepStrictEqual(vulns, expectedResponse.vulnerabilities);
  });

  test("should send a GET http request with keywordSearch directly", async() => {
    const expectedResponse = { vulnerabilities: ["cve-data-1"] };
    const params = new URLSearchParams();
    params.append("keywordSearch", "log4j");
    params.append("apiKey", kTestApiKey);
    const queryString = params.toString();

    mockedHttpClient
      .intercept({
        path: `${kNvdPathname}?${queryString}`,
        method: "GET"
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const vulns = await db.find({ keywordSearch: "log4j" });

    assert.deepStrictEqual(vulns, expectedResponse.vulnerabilities);
  });

  test("should send a GET http request with keywordExactMatch flag", async() => {
    const expectedResponse = { vulnerabilities: ["cve-data-1"] };
    const params = new URLSearchParams();
    params.append("keywordSearch", "express framework");
    params.append("keywordExactMatch", "");
    params.append("apiKey", kTestApiKey);
    const queryString = params.toString();

    mockedHttpClient
      .intercept({
        path: `${kNvdPathname}?${queryString}`,
        method: "GET"
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const vulns = await db.find({
      keywordSearch: "express framework",
      keywordExactMatch: true
    });

    assert.deepStrictEqual(vulns, expectedResponse.vulnerabilities);
  });

  test("should send a GET http request with cvssV3Severity parameter", async() => {
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

    const vulns = await db.find({
      packageName: "express",
      ecosystem: "npm",
      cvssV3Severity: "HIGH"
    });

    assert.deepStrictEqual(vulns, expectedResponse.vulnerabilities);
  });

  test("should send a GET http request with cvssV2Severity parameter", async() => {
    const expectedResponse = { vulnerabilities: ["cve-data-1"] };
    const params = new URLSearchParams();
    params.append("keywordSearch", "express");
    params.append("cvssV2Severity", "MEDIUM");
    params.append("apiKey", kTestApiKey);
    const queryString = params.toString();

    mockedHttpClient
      .intercept({
        path: `${kNvdPathname}?${queryString}`,
        method: "GET"
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const vulns = await db.find({
      packageName: "express",
      cvssV2Severity: "MEDIUM"
    });

    assert.deepStrictEqual(vulns, expectedResponse.vulnerabilities);
  });

  test("should send a GET http request with cvssV4Severity parameter", async() => {
    const expectedResponse = { vulnerabilities: ["cve-data-1"] };
    const params = new URLSearchParams();
    params.append("keywordSearch", "express");
    params.append("cvssV4Severity", "CRITICAL");
    params.append("apiKey", kTestApiKey);
    const queryString = params.toString();

    mockedHttpClient
      .intercept({
        path: `${kNvdPathname}?${queryString}`,
        method: "GET"
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const vulns = await db.find({
      packageName: "express",
      cvssV4Severity: "CRITICAL"
    });

    assert.deepStrictEqual(vulns, expectedResponse.vulnerabilities);
  });

  test("should send a GET http request with cvssV3Metrics vector string", async() => {
    const expectedResponse = { vulnerabilities: ["cve-data-1"] };
    const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    const params = new URLSearchParams();
    params.append("cvssV3Metrics", vector);
    params.append("apiKey", kTestApiKey);
    const queryString = params.toString();

    mockedHttpClient
      .intercept({
        path: `${kNvdPathname}?${queryString}`,
        method: "GET"
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const vulns = await db.find({ cvssV3Metrics: vector });

    assert.deepStrictEqual(vulns, expectedResponse.vulnerabilities);
  });

  test("should send a GET http request with cveId parameter", async() => {
    const expectedResponse = { vulnerabilities: ["cve-data-1"] };
    const params = new URLSearchParams();
    params.append("cveId", "CVE-2021-44228");
    params.append("apiKey", kTestApiKey);
    const queryString = params.toString();

    mockedHttpClient
      .intercept({
        path: `${kNvdPathname}?${queryString}`,
        method: "GET"
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const vulns = await db.find({ cveId: "CVE-2021-44228" });

    assert.deepStrictEqual(vulns, expectedResponse.vulnerabilities);
  });

  test("should send a GET http request using findByCveId", async() => {
    const expectedResponse = { vulnerabilities: ["cve-data-1"] };
    const params = new URLSearchParams();
    params.append("cveId", "CVE-2021-44228");
    params.append("apiKey", kTestApiKey);
    const queryString = params.toString();

    mockedHttpClient
      .intercept({
        path: `${kNvdPathname}?${queryString}`,
        method: "GET"
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const vulns = await db.findByCveId("CVE-2021-44228");

    assert.deepStrictEqual(vulns, expectedResponse.vulnerabilities);
  });

  test("should send a GET http request with cveTag parameter", async() => {
    const expectedResponse = { vulnerabilities: ["cve-data-1"] };
    const params = new URLSearchParams();
    params.append("keywordSearch", "express");
    params.append("cveTag", "disputed");
    params.append("apiKey", kTestApiKey);
    const queryString = params.toString();

    mockedHttpClient
      .intercept({
        path: `${kNvdPathname}?${queryString}`,
        method: "GET"
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const vulns = await db.find({ packageName: "express", cveTag: "disputed" });

    assert.deepStrictEqual(vulns, expectedResponse.vulnerabilities);
  });

  test("should send a GET http request with noRejected flag", async() => {
    const expectedResponse = { vulnerabilities: ["cve-data-1"] };
    const params = new URLSearchParams();
    params.append("keywordSearch", "express");
    params.append("noRejected", "");
    params.append("apiKey", kTestApiKey);
    const queryString = params.toString();

    mockedHttpClient
      .intercept({
        path: `${kNvdPathname}?${queryString}`,
        method: "GET"
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const vulns = await db.find({ packageName: "express", noRejected: true });

    assert.deepStrictEqual(vulns, expectedResponse.vulnerabilities);
  });

  test("should send a GET http request with hasKev flag", async() => {
    const expectedResponse = { vulnerabilities: ["cve-data-1"] };
    const params = new URLSearchParams();
    params.append("keywordSearch", "log4j");
    params.append("hasKev", "");
    params.append("apiKey", kTestApiKey);
    const queryString = params.toString();

    mockedHttpClient
      .intercept({
        path: `${kNvdPathname}?${queryString}`,
        method: "GET"
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const vulns = await db.find({ keywordSearch: "log4j", hasKev: true });

    assert.deepStrictEqual(vulns, expectedResponse.vulnerabilities);
  });

  test("should send a GET http request with hasCertAlerts flag", async() => {
    const expectedResponse = { vulnerabilities: ["cve-data-1"] };
    const params = new URLSearchParams();
    params.append("hasCertAlerts", "");
    params.append("apiKey", kTestApiKey);
    const queryString = params.toString();

    mockedHttpClient
      .intercept({
        path: `${kNvdPathname}?${queryString}`,
        method: "GET"
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const vulns = await db.find({ hasCertAlerts: true });

    assert.deepStrictEqual(vulns, expectedResponse.vulnerabilities);
  });

  test("should send a GET http request with hasCertNotes flag", async() => {
    const expectedResponse = { vulnerabilities: ["cve-data-1"] };
    const params = new URLSearchParams();
    params.append("hasCertNotes", "");
    params.append("apiKey", kTestApiKey);
    const queryString = params.toString();

    mockedHttpClient
      .intercept({
        path: `${kNvdPathname}?${queryString}`,
        method: "GET"
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const vulns = await db.find({ hasCertNotes: true });

    assert.deepStrictEqual(vulns, expectedResponse.vulnerabilities);
  });

  test("should send a GET http request with hasOval flag", async() => {
    const expectedResponse = { vulnerabilities: ["cve-data-1"] };
    const params = new URLSearchParams();
    params.append("hasOval", "");
    params.append("apiKey", kTestApiKey);
    const queryString = params.toString();

    mockedHttpClient
      .intercept({
        path: `${kNvdPathname}?${queryString}`,
        method: "GET"
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const vulns = await db.find({ hasOval: true });

    assert.deepStrictEqual(vulns, expectedResponse.vulnerabilities);
  });

  test("should send a GET http request with publication date range", async() => {
    const expectedResponse = { vulnerabilities: ["cve-data-1"] };
    const params = new URLSearchParams();
    params.append("pubStartDate", "2024-01-01T00:00:00.000Z");
    params.append("pubEndDate", "2024-04-30T23:59:59.000Z");
    params.append("apiKey", kTestApiKey);
    const queryString = params.toString();

    mockedHttpClient
      .intercept({
        path: `${kNvdPathname}?${queryString}`,
        method: "GET"
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const vulns = await db.find({
      pubStartDate: "2024-01-01T00:00:00.000Z",
      pubEndDate: "2024-04-30T23:59:59.000Z"
    });

    assert.deepStrictEqual(vulns, expectedResponse.vulnerabilities);
  });

  test("should send a GET http request with last-modified date range", async() => {
    const expectedResponse = { vulnerabilities: ["cve-data-1"] };
    const params = new URLSearchParams();
    params.append("lastModStartDate", "2024-01-01T00:00:00.000Z");
    params.append("lastModEndDate", "2024-04-30T23:59:59.000Z");
    params.append("apiKey", kTestApiKey);
    const queryString = params.toString();

    mockedHttpClient
      .intercept({
        path: `${kNvdPathname}?${queryString}`,
        method: "GET"
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const vulns = await db.find({
      lastModStartDate: "2024-01-01T00:00:00.000Z",
      lastModEndDate: "2024-04-30T23:59:59.000Z"
    });

    assert.deepStrictEqual(vulns, expectedResponse.vulnerabilities);
  });

  test("should send a GET http request with sourceIdentifier parameter", async() => {
    const expectedResponse = { vulnerabilities: ["cve-data-1"] };
    const params = new URLSearchParams();
    params.append("sourceIdentifier", "cve@mitre.org");
    params.append("apiKey", kTestApiKey);
    const queryString = params.toString();

    mockedHttpClient
      .intercept({
        path: `${kNvdPathname}?${queryString}`,
        method: "GET"
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const vulns = await db.find({ sourceIdentifier: "cve@mitre.org" });

    assert.deepStrictEqual(vulns, expectedResponse.vulnerabilities);
  });

  test("should send a GET http request with pagination parameters", async() => {
    const expectedResponse = { vulnerabilities: ["cve-data-1"] };
    const params = new URLSearchParams();
    params.append("keywordSearch", "express");
    params.append("resultsPerPage", "100");
    params.append("startIndex", "200");
    params.append("apiKey", kTestApiKey);
    const queryString = params.toString();

    mockedHttpClient
      .intercept({
        path: `${kNvdPathname}?${queryString}`,
        method: "GET"
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const vulns = await db.find({
      packageName: "express",
      resultsPerPage: 100,
      startIndex: 200
    });

    assert.deepStrictEqual(vulns, expectedResponse.vulnerabilities);
  });

  test("should send a GET http request to the NVD API using findBySpec", async() => {
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

    const vulns = await db.findBySpec(`${packageName}@1.0.0`);
    assert.deepStrictEqual(vulns, expectedResponse.vulnerabilities);
  });

  test("should send sequential GET http requests to the NVD API using findMany", async() => {
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

  test("findMany should respect requestDelay between requests", async() => {
    const expectedResponse = { vulnerabilities: ["cve-data-1"] };
    const delayMs = 50;
    const dbWithDelay = new NVD({ credential: kTestCredential, requestDelay: delayMs });

    for (const pkg of ["pkg-a", "pkg-b", "pkg-c"]) {
      const params = new URLSearchParams();
      params.append("keywordSearch", pkg);
      params.append("apiKey", kTestApiKey);
      mockedHttpClient
        .intercept({ path: `${kNvdPathname}?${params.toString()}`, method: "GET" })
        .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);
    }

    const start = Date.now();
    await dbWithDelay.findMany(["pkg-a", "pkg-b", "pkg-c"]);
    const elapsed = Date.now() - start;

    // 3 packages → 2 delays of delayMs each (no delay after the last request)
    assert.ok(elapsed >= delayMs * 2, `Expected at least ${delayMs * 2}ms, got ${elapsed}ms`);
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

    const vulns = await db.find({
      packageName: "nonexistent",
      ecosystem: "npm"
    });

    assert.deepStrictEqual(vulns, []);
  });
});
