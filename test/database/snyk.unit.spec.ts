// Import Node.js Dependencies
import { describe, test, after } from "node:test";
import assert from "node:assert";

// Import Internal Dependencies
import { HTTP_CLIENT_HEADERS, setupHttpAgentMock } from "../strategies/utils.ts";
import { snyk } from "../../src/database/index.ts";
import { SNYK_ORG } from "../../src/constants.ts";

describe("snyk", () => {
  const [mockedHttpAgent, restoreHttpAgent] = setupHttpAgentMock();
  const mockedHttpClient = mockedHttpAgent.get(snyk.ROOT_API);

  after(() => {
    restoreHttpAgent();
  });

  test("should send a POST http request to the Snyk API using findOne and then return the SnykAuditResponse", async() => {
    const expectedResponse = { issues: "some issues data" };
    const targetFile = "some target file content";
    const additionalFile = "some additional file content";

    mockedHttpClient
      .intercept({
        path: new URL(`/api/v1/test/npm?org=${SNYK_ORG}`, snyk.ROOT_API).href,
        method: "POST",
        body: JSON.stringify({
          files: {
            target: { contents: targetFile },
            additional: [{ contents: additionalFile }]
          }
        })
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const data = await snyk.findOne({
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
        path: new URL(`/api/v1/test/npm?org=${SNYK_ORG}`, snyk.ROOT_API).href,
        method: "POST",
        body: JSON.stringify({
          files: {
            target: { contents: targetFile }
          }
        })
      })
      .reply(200, expectedResponse, HTTP_CLIENT_HEADERS);

    const data = await snyk.findOne({
      files: { target: { contents: targetFile } }
    });

    assert.deepStrictEqual(data, expectedResponse);
  });
});
