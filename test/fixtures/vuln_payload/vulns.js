/* eslint-disable max-len */
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

export const SNYK_VULNERABILITY = {
  id: "npm:ms:20151024",
  url: "https://snyk.io/vuln/npm:ms:20151024",
  title: "Regular Expression Denial of Service (ReDoS)",
  type: "vuln",
  description: "## Overview",
  functions: [
    {
      functionId: {
        filePath: "ms.js",
        functionName: "parse"
      },
      version: [">0.1.0 <=0.3.0"]
    },
    {
      functionId: {
        filePath: "index.js",
        functionName: "parse"
      },
      version: [">0.3.0 <0.7.1"]
    }
  ],
  from: ["ms@0.7.0"],
  package: "ms",
  version: "0.7.0",
  severity: "medium",
  exploitMaturity: "no-known-exploit",
  language: "js",
  packageManager: "npm",
  semver: {
    vulnerable: ["<0.5.0, >=0.4.0", "<0.3.8, >=0.3.6"]
  },
  publicationTime: "2015-11-06T02:09:36Z",
  disclosureTime: "2015-10-24T20:39:59Z",
  isUpgradable: true,
  isPatchable: true,
  isPinnable: false,
  identifiers: {
    ALTERNATIVE: ["SNYK-JS-MS-10064"],
    CVE: ["CVE-2015-8315"],
    CWE: ["CWE-400"],
    NSP: [46]
  },
  credit: ["Adam Baldwin"],
  CVSSv3: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
  cvssScore: 5.3,
  patches: [
    {
      comments: [],
      id: "patch:npm:ms:20151024:5",
      modificationTime: "2019-12-03T11:40:45.777474Z",
      urls: [
        "https://snyk-patches.s3.amazonaws.com/npm/ms/20151024/ms_20151024_5_0_48701f029417faf65e6f5e0b61a3cebe5436b07b_snyk5.patch"
      ],
      version: "=0.1.0"
    },
    {
      comments: [],
      id: "patch:npm:ms:20151024:4",
      modificationTime: "2019-12-03T11:40:45.776329Z",
      urls: [
        "https://snyk-patches.s3.amazonaws.com/npm/ms/20151024/ms_20151024_4_0_48701f029417faf65e6f5e0b61a3cebe5436b07b_snyk4.patch"
      ],
      version: "=0.2.0"
    },
    {
      comments: [],
      id: "patch:npm:ms:20151024:3",
      modificationTime: "2019-12-03T11:40:45.775292Z",
      urls: [
        "https://snyk-patches.s3.amazonaws.com/npm/ms/20151024/ms_20151024_3_0_48701f029417faf65e6f5e0b61a3cebe5436b07b_snyk3.patch"
      ],
      version: "=0.3.0"
    },
    {
      comments: [],
      id: "patch:npm:ms:20151024:2",
      modificationTime: "2019-12-03T11:40:45.774221Z",
      urls: [
        "https://snyk-patches.s3.amazonaws.com/npm/ms/20151024/ms_20151024_2_0_48701f029417faf65e6f5e0b61a3cebe5436b07b_snyk2.patch"
      ],
      version: "<0.6.0 >0.3.0"
    },
    {
      comments: [],
      id: "patch:npm:ms:20151024:1",
      modificationTime: "2019-12-03T11:40:45.773094Z",
      urls: [
        "https://snyk-patches.s3.amazonaws.com/npm/ms/20151024/ms_20151024_1_0_48701f029417faf65e6f5e0b61a3cebe5436b07b_snyk.patch"
      ],
      version: "<0.7.0 >=0.6.0"
    },
    {
      comments: [],
      id: "patch:npm:ms:20151024:0",
      modificationTime: "2019-12-03T11:40:45.772009Z",
      urls: [
        "https://snyk-patches.s3.amazonaws.com/npm/ms/20151024/ms_20151024_0_0_48701f029417faf65e6f5e0b61a3cebe5436b07b.patch"
      ],
      version: "=0.7.0"
    }
  ],
  upgradePath: ["ms@0.7.1"]
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
