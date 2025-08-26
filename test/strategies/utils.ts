// Import Node.js Dependencies
import assert from "node:assert";

// Import Third-party Dependencies
import * as httpie from "@openally/httpie";

// CONSTANTS
export const HTTP_CLIENT_HEADERS = {
  headers: { "content-type": "application/json" }
};

export function setupHttpAgentMock(): [httpie.MockAgent, () => void] {
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

export function expectVulnToBeNodeSecureStandardCompliant(vuln) {
  const mandatoryStandardFormatKeys = [
    "origin",
    "package",
    "title",
    "vulnerableVersions",
    "vulnerableRanges"
  ];

  // Check that the mandatory properties are present in the payload
  mandatoryStandardFormatKeys.forEach((standardProperty) => {
    assert.ok(
      standardProperty in vuln,
      `the payload is missing the '${standardProperty}' standard property`
    );
  });

  const optionalStandardFormatKeys = [
    "id",
    "url",
    "description",
    "severity",
    "cves",
    "cvssVector",
    "cvssScore",
    "patches",
    "patchedVersions"
  ];

  // Check that every other property of the payload is part of the optional
  // properties (sort of schema validation) or part of the standard format
  Object.keys(vuln).forEach((payloadProperty) => {
    // Mandatory properties were already verified so we don't want to check it again
    if (!mandatoryStandardFormatKeys.includes(payloadProperty)) {
      assert.ok(
        optionalStandardFormatKeys.includes(payloadProperty),
        `the payload contains '${payloadProperty}' property which is not standard compliant`
      );
    }
  });
}
