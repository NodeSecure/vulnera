/* eslint-disable @stylistic/max-len */

export const NPM_VULNERABILITY = {
  title: "Arbitrary Command Injection due to Improper Command Sanitization",
  name: "@npmcli/git",
  source: 1005085,
  url: "https://github.com/advisories/GHSA-hxwm-x553-x359",
  dependency: "@npmcli/git",
  severity: "moderate",
  version: undefined,
  vulnerableVersions: undefined,
  range: "<2.0.8",
  id: undefined
};

export const PNPM_VULNERABILITY = {
  id: 1005085,
  github_advisory_id: "GHSA-hxwm-x553-x359",
  npm_advisory_id: 1005085,
  module_name: "@npmcli/git",
  title: "Arbitrary Command Injection due to Improper Command Sanitization",
  overview: "A vulnerability in @npmcli/git allows arbitrary command injection.",
  url: "https://github.com/advisories/GHSA-hxwm-x553-x359",
  severity: "moderate",
  cwe: ["CWE-77"],
  cves: ["CVE-2021-3807"],
  patched_versions: ">=2.0.8",
  vulnerable_versions: ["<2.0.8"],
  cvss: { score: 7.5, vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" }
};

export const SONATYPE_VULNERABILITY = {
  id: "a917ab55-851f-4c8b-ac82-6f988881c329",
  displayName: "OSSINDEX-6f98-8881-c329",
  title: "CWE-400: Uncontrolled Resource Consumption ('Resource Exhaustion')",
  description: "The software does not properly restrict the size or amount of resources that are requested or influenced by an actor, which can be used to consume more resources than intended.",
  cvssScore: 7.5,
  cvssVector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
  cwe: "CWE-400",
  reference: "https://ossindex.sonatype.org/vulnerability/a917ab55-851f-4c8b-ac82-6f988881c329?component-type=npm&component-name=debug&utm_source=httpie&utm_medium=integration",
  externalReferences: [
    "https://www.npmjs.com/advisories/534"
  ]
};
