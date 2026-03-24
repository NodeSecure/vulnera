// Import Node.js Dependencies
import { test } from "node:test";
import assert from "node:assert";

// Import Internal Dependencies
import { VULN_MODE } from "../../../src/constants.ts";
import { formatVulnsPayload } from "../../../src/formats/index.ts";
import {
  NPM_OSV_PAYLOAD,
  PNPM_OSV_PAYLOAD,
  SONATYPE_OSV_PAYLOAD
} from "../../fixtures/vuln_payload/payloads.ts";

const formatVulnerabilities = formatVulnsPayload("OSV");

test("should convert NONE or unknown strategy into blank payload", () => {
  let notFormatted = formatVulnerabilities(VULN_MODE.NONE as any, [{}, {}]);
  assert.ok(notFormatted.length === 0);

  notFormatted = formatVulnerabilities("exploit" as any, []);
  assert.ok(notFormatted.length === 0);
});

test("should convert NPM strategy vulns payload into OSV format", () => {
  const { vulnerabilities } = NPM_OSV_PAYLOAD.inputVulnsPayload;
  const [result] = formatVulnerabilities(
    VULN_MODE.GITHUB_ADVISORY,
    vulnerabilities["@npmcli/git"].via
  );

  assert.ok(typeof result.modified === "string" && !isNaN(Date.parse(result.modified)));
  assert.ok(typeof result.published === "string" && !isNaN(Date.parse(result.published)));

  const { modified, published, ...rest } = result as any;
  const { outputOSVPayload } = NPM_OSV_PAYLOAD;
  assert.deepEqual(rest, outputOSVPayload);
});

test("should convert Pnpm strategy vulns payload into OSV format", () => {
  const [result] = formatVulnerabilities(
    "github-advisory_pnpm" as any,
    PNPM_OSV_PAYLOAD.inputVulnsPayload.vulnerabilities
  );

  assert.ok(typeof result.modified === "string" && !isNaN(Date.parse(result.modified)));
  assert.ok(typeof result.published === "string" && !isNaN(Date.parse(result.published)));

  const { modified, published, ...rest } = result as any;
  const { outputOSVPayload } = PNPM_OSV_PAYLOAD;
  assert.deepEqual(rest, outputOSVPayload);
});

test("should convert Sonatype strategy payload into OSV format", () => {
  const [result] = formatVulnerabilities(
    VULN_MODE.SONATYPE,
    SONATYPE_OSV_PAYLOAD.inputVulnsPayload.vulnerabilities
  );

  assert.ok(typeof result.modified === "string" && !isNaN(Date.parse(result.modified)));
  assert.ok(typeof result.published === "string" && !isNaN(Date.parse(result.published)));

  const { modified, published, ...rest } = result as any;
  const { outputOSVPayload } = SONATYPE_OSV_PAYLOAD;
  assert.deepEqual(rest, outputOSVPayload);
});
