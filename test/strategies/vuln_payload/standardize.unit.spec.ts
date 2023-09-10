// Import Node.js Dependencies
import { test } from "node:test";
import assert from "node:assert";

// Import Internal Dependencies
import { VULN_MODE } from "../../../src/constants.js";
import { standardizeVulnsPayload } from "../../../src/formats/standard/index.js";
import {
  NPM_VULNS_PAYLOADS,
  SNYK_VULNS_PAYLOADS,
  SONATYPE_VULNS_PAYLOADS
} from "../../fixtures/vuln_payload/payloads.js";

const formatVulnerabilities = standardizeVulnsPayload(true);

test("should convert NONE or unknown strategy into blank payload", () => {
  let notStandardized = formatVulnerabilities(VULN_MODE.NONE as any, [{}, {}]);
  assert.ok(notStandardized.length === 0);

  notStandardized = formatVulnerabilities("exploit" as any, []);
  assert.ok(notStandardized.length === 0);
});

test("should convert NPM strategy vulns payload into NodeSecure standard payload", () => {
  const { vulnerabilities } = NPM_VULNS_PAYLOADS.inputVulnsPayload;
  const [fromNPMToStandardFormat] = formatVulnerabilities(
    VULN_MODE.GITHUB_ADVISORY,
    vulnerabilities["@npmcli/git"].via
  );

  assert.deepEqual(
    fromNPMToStandardFormat,
    NPM_VULNS_PAYLOADS.outputStandardizedPayload
  );
});

test("should convert Snyk strategy payload into NodeSecure standard payload", () => {
  const [fromSnykToStandardFormat] = formatVulnerabilities(
    VULN_MODE.SNYK,
    SNYK_VULNS_PAYLOADS.inputVulnsPayload.vulnerabilities
  );

  assert.deepEqual(
    fromSnykToStandardFormat,
    SNYK_VULNS_PAYLOADS.outputStandardizedPayload
  );
});

test("should convert Sonatype strategy payload into NodeSecure standard payload", () => {
  const [sonatypeToStandardFormat] = formatVulnerabilities(
    VULN_MODE.SONATYPE,
    SONATYPE_VULNS_PAYLOADS.inputVulnsPayload.vulnerabilities
  );

  /**
   * Package's name is not part of the vuln payload. It is provided from another
   * part of the sonatype payload. To avoid any confusion, it is spreaded here
   * in addition to the vuln payload.
   */
  const packageName = "debug";
  assert.deepEqual(
    { ...sonatypeToStandardFormat, package: packageName },
    SONATYPE_VULNS_PAYLOADS.outputStandardizedPayload
  );
});
