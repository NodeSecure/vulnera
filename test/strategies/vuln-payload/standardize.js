import test from "tape";
import { VULN_MODE } from "../../../src/constants.js";
import { standardizeVulnsPayload } from "../../../src/strategies/vuln-payload/standardize.js";
import {
  NPM_VULNS_PAYLOADS,
  SECURITYWG_VULNS_PAYLOADS,
  SNYK_VULNS_PAYLOADS,
  SONATYPE_VULNS_PAYLOADS
} from "../../fixtures/vuln-payload/payloads.js";

test("should convert NONE or unknown strategy into blank payload", (tape) => {
  let notStandardized = standardizeVulnsPayload(VULN_MODE.NONE, [{}, {}]);
  tape.isEquivalent(notStandardized, []);
  notStandardized = standardizeVulnsPayload("exploit", {});
  tape.isEquivalent(notStandardized, []);
  tape.end();
});

test("should convert NPM strategy vulns payload into NodeSecure standard payload", (tape) => {
  const { vulnerabilities } = NPM_VULNS_PAYLOADS.inputVulnsPayload;
  const [fromNPMToStandardFormat] = standardizeVulnsPayload(
    VULN_MODE.NPM_AUDIT, vulnerabilities.slashify.via
  );
  tape.deepEqual(fromNPMToStandardFormat, NPM_VULNS_PAYLOADS.outputStandardizedPayload);
  tape.end();
});

test("should convert Snyk strategy payload into NodeSecure standard payload", (tape) => {
  const [fromSnykToStandardFormat] = standardizeVulnsPayload(
    VULN_MODE.SNYK, SNYK_VULNS_PAYLOADS.inputVulnsPayload.vulnerabilities
  );
  tape.deepEqual(fromSnykToStandardFormat, SNYK_VULNS_PAYLOADS.outputStandardizedPayload);
  tape.end();
});

test("should convert NodeWG strategy payload into NodeSecure standard payload", (tape) => {
  const [nodeWGToStandardFormat] = standardizeVulnsPayload(
    VULN_MODE.SECURITY_WG, SECURITYWG_VULNS_PAYLOADS.inputVulnsPayload.vulnerabilities
  );
  tape.deepEqual(nodeWGToStandardFormat, SECURITYWG_VULNS_PAYLOADS.outputStandardizedPayload);
  tape.end();
});

test("should convert Sonatype strategy payload into NodeSecure standard payload", (tape) => {
  const [sonatypeToStandardFormat] = standardizeVulnsPayload(
    VULN_MODE.SONATYPE, SONATYPE_VULNS_PAYLOADS.inputVulnsPayload.vulnerabilities
  );
  tape.deepEqual(sonatypeToStandardFormat, SONATYPE_VULNS_PAYLOADS.outputStandardizedPayload);
  tape.end();
});
