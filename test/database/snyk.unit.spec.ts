// Import Node.js Dependencies
import { describe, test, after } from "node:test";
import assert from "node:assert";

// Import Internal Dependencies
import { HTTP_CLIENT_HEADERS, setupHttpAgentMock } from "../strategies/utils.ts";
import { Snyk, ApiCredential } from "../../src/database/index.ts";

describe("Database.Snyk", () => {
  const org = process.env.SNYK_ORG ?? "test-org";
  const token = process.env.SNYK_TOKEN ?? "test-token";
  const db = new Snyk({
    org,
    credential: new ApiCredential({ type: "token", token })
  });
  const [mockedHttpAgent, restoreHttpAgent] = setupHttpAgentMock();
  const mockedHttpClient = mockedHttpAgent.get(Snyk.ROOT_API);

  after(() => {
    restoreHttpAgent();
  });

  test("should send a POST http request to the Snyk API using findOne and then return the SnykAuditResponse", async() => {
    const expectedResponse = { issues: "some issues data" };
    const targetFile = "some target file content";
    const additionalFile = "some additional file content";

    mockedHttpClient
      .intercept({
        path: new URL(`/api/v1/test/npm?org=${org}`, Snyk.ROOT_API).href,
        method: "POST",
        body: JSON.stringify({
          files: {
            target: { contents: targetFile },
            additional: [{ contents: additionalFile }]
          }
        })
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const data = await db.findOne({
      files: {
        target: { contents: targetFile },
        additional: [{ contents: additionalFile }]
      }
    });

    assert.deepStrictEqual(data, expectedResponse);
  });

  test("should send a POST http request to the Snyk API using findOne without additional files", async() => {
    const expectedResponse = { issues: "some issues data" };
    const targetFile = "some target file content";

    mockedHttpClient
      .intercept({
        path: new URL(`/api/v1/test/npm?org=${org}`, Snyk.ROOT_API).href,
        method: "POST",
        body: JSON.stringify({
          files: {
            target: { contents: targetFile }
          }
        })
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const data = await db.findOne({
      files: { target: { contents: targetFile } }
    });

    assert.deepStrictEqual(data, expectedResponse);
  });
});
