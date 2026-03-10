// Import Node.js Dependencies
import { describe, test } from "node:test";
import assert from "node:assert";

// Import Internal Dependencies
import { ApiCredential } from "../../src/credential.ts";

describe("ApiCredential", () => {
  test("string token produces Authorization: Bearer header", () => {
    const cred = new ApiCredential("mytoken");

    assert.deepStrictEqual(cred.headers, { Authorization: "Bearer mytoken" });
    assert.deepStrictEqual(cred.queryParams, {});
  });

  test("bearer type produces Authorization: Bearer header", () => {
    const cred = new ApiCredential({ type: "bearer", token: "mytoken" });

    assert.deepStrictEqual(cred.headers, { Authorization: "Bearer mytoken" });
    assert.deepStrictEqual(cred.queryParams, {});
  });

  test("token type produces Authorization: token header", () => {
    const cred = new ApiCredential({ type: "token", token: "mytoken" });

    assert.deepStrictEqual(cred.headers, { Authorization: "token mytoken" });
    assert.deepStrictEqual(cred.queryParams, {});
  });

  test("basic type produces Authorization: Basic header with base64-encoded credentials", () => {
    const cred = new ApiCredential({ type: "basic", username: "user", password: "pass" });
    const expected = Buffer.from("user:pass").toString("base64");

    assert.deepStrictEqual(cred.headers, { Authorization: `Basic ${expected}` });
    assert.deepStrictEqual(cred.queryParams, {});
  });

  test("querystring type produces a query param and no headers", () => {
    const cred = new ApiCredential({ type: "querystring", name: "apiKey", value: "secret" });

    assert.deepStrictEqual(cred.headers, {});
    assert.deepStrictEqual(cred.queryParams, { apiKey: "secret" });
  });

  test("custom type produces Authorization header with the raw value", () => {
    const cred = new ApiCredential({ type: "custom", authorization: "SharedAccessSignature sv=..." });

    assert.deepStrictEqual(cred.headers, { Authorization: "SharedAccessSignature sv=..." });
    assert.deepStrictEqual(cred.queryParams, {});
  });

  test("no options produces empty headers and queryParams", () => {
    const cred = new ApiCredential();

    assert.deepStrictEqual(cred.headers, {});
    assert.deepStrictEqual(cred.queryParams, {});
  });
});
