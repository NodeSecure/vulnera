// Import Node.js Dependencies
import { rmSync } from "fs";

// Import Third-party Dependencies
import test from "tape";

// Import Internal Dependencies
import { VULN_FILE_PATH, TMP_CACHE, VULN_MODE } from "../../src/constants.js";
import { hydrateDatabase, hydratePayloadDependencies } from "../../src/strategies/security-wg.js";
import { standardizeVulnsPayload } from "../../src/strategies/vuln-payload/standardize.js";

function cleanupCache() {
  rmSync(TMP_CACHE, { force: true });
  rmSync(VULN_FILE_PATH, { force: true });
}

function getSecurityWGExpectedPayload() {
  return {
    id: 100,
    created_at: "2016-04-15",
    updated_at: "2017-04-14",
    title: "Regular Expression Denial Of Service",
    author: {
      name: "Peter Dotchev",
      website: null,
      username: null
    },
    module_name: "uri-js",
    publish_date: "2017-04-14",
    cves: [],
    vulnerable_versions: "<=2.1.1",
    patched_versions: ">=3.0.0",
    // eslint-disable-next-line max-len
    overview: "uri-js is a module that tries to fully implement RFC 3986. One of these features is validating whether or not a supplied URL is valid or not. To do this, uri-js uses a regular expression, This regular expression is vulnerable to redos. This causes the program to hang and the CPU to idle at 100% usage while uri-js is trying to validate if the supplied URL is valid or not. \nTo check if you're vulnerable, look for a call to `require(\"uri-js\").parse()` where a user is able to send their own input.",
    recommendation: "Upgrade to v3.0.0",
    references: [
      "https://github.com/garycourt/uri-js/issues/12",
      "https://www.owasp.org/index.php/Regular_expression_Denial_of_Service_-_ReDoS"
    ],
    cvss_vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    cvss_score: 7.5,
    coordinating_vendor: "^Lift Security"
  };
}

test("node.js strategy: hydratePayloadDependencies", async(tape) => {
  cleanupCache();

  // Re-download database!
  await hydrateDatabase();

  try {
    const dependencies = new Map();
    // see: https://github.com/nodejs/security-wg/blob/main/vuln/npm/100.json
    dependencies.set("uri-js", {
      vulnerabilities: [],
      versions: ["2.0.0"]
    });

    await hydratePayloadDependencies(dependencies);

    const [vuln] = dependencies.get("uri-js").vulnerabilities;
    tape.deepEqual(vuln, getSecurityWGExpectedPayload());
  }
  finally {
    cleanupCache();
    tape.end();
  }
});

test("node.js strategy: hydratePayloadDependencies using standard format", async(tape) => {
  cleanupCache();

  // Re-download database!
  await hydrateDatabase();

  try {
    const dependencies = new Map();
    // see: https://github.com/nodejs/security-wg/blob/main/vuln/npm/100.json
    dependencies.set("uri-js", {
      vulnerabilities: [],
      versions: ["2.0.0"]
    });

    await hydratePayloadDependencies(dependencies, { useStandardFormat: true });

    const vulns = dependencies.get("uri-js").vulnerabilities;
    tape.deepEqual(vulns, standardizeVulnsPayload(VULN_MODE.SECURITY_WG, [getSecurityWGExpectedPayload()]));
  }
  finally {
    cleanupCache();
    tape.end();
  }
});
