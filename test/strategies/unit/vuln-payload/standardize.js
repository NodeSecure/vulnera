import test from "tape";
import { VULN_MODE } from "../../../../src/constants.js";
import { standardizeVulnsPayload } from "../../../../src/strategies/vuln-payload/standardize.js";
import {
  NPM_VULNS_PAYLOADS,
  SECURITYWG_VULNS_PAYLOADS,
  SNYK_VULNS_PAYLOADS,
  SONATYPE_VULNS_PAYLOADS
} from "../../../fixtures/vuln-payload/payloads.js";

const formatVulnerabilities = standardizeVulnsPayload(true);

test("should convert NONE or unknown strategy into blank payload", (tape) => {
  let notStandardized = formatVulnerabilities(VULN_MODE.NONE, [{}, {}]);
  tape.isEquivalent(notStandardized, []);
  notStandardized = formatVulnerabilities("exploit", {});
  tape.isEquivalent(notStandardized, []);
  tape.end();
});

test("should convert NPM strategy vulns payload into NodeSecure standard payload", (tape) => {
  const { vulnerabilities } = NPM_VULNS_PAYLOADS.inputVulnsPayload;
  const [fromNPMToStandardFormat] = formatVulnerabilities(
    VULN_MODE.NPM_AUDIT, vulnerabilities["@npmcli/git"].via
  );
  tape.deepEqual(fromNPMToStandardFormat, NPM_VULNS_PAYLOADS.outputStandardizedPayload);
  tape.end();
});

test("should convert Snyk strategy payload into NodeSecure standard payload", (tape) => {
  const [fromSnykToStandardFormat] = formatVulnerabilities(
    VULN_MODE.SNYK, SNYK_VULNS_PAYLOADS.inputVulnsPayload.vulnerabilities
  );
  tape.deepEqual(fromSnykToStandardFormat, SNYK_VULNS_PAYLOADS.outputStandardizedPayload);
  tape.end();
});

test("should convert NodeWG strategy payload into NodeSecure standard payload", (tape) => {
  const [nodeWGToStandardFormat] = formatVulnerabilities(
    VULN_MODE.SECURITY_WG, SECURITYWG_VULNS_PAYLOADS.inputVulnsPayload.vulnerabilities
  );
  tape.deepEqual(nodeWGToStandardFormat, SECURITYWG_VULNS_PAYLOADS.outputStandardizedPayload);
  tape.end();
});

test("should convert Sonatype strategy payload into NodeSecure standard payload", (tape) => {
  const [sonatypeToStandardFormat] = formatVulnerabilities(
    VULN_MODE.SONATYPE, SONATYPE_VULNS_PAYLOADS.inputVulnsPayload.vulnerabilities
  );
  /**
   * Package's name is not part of the vuln payload. It is provided from another
   * part of the sonatype payload. To avoid any confusion, it is spreaded here
   * in addition to the vuln payload.
  */
  const packageName = "debug";
  tape.deepEqual(
    { ...sonatypeToStandardFormat, package: packageName },
    SONATYPE_VULNS_PAYLOADS.outputStandardizedPayload
  );
  tape.end();
});
