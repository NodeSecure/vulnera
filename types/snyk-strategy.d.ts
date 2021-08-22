export = SnykStrategy;

declare namespace SnykStrategy {
  export interface Issue {
    /** The issue ID **/
    id: string;
    /** A link to the issue details on snyk.io **/
    url: string;
    /** The issue title **/
    title: string;
    /** The issue type **/
    type: "vulnerability" | "license";
    /** The paths to the dependencies which have an issue, and their corresponding upgrade path (if an upgrade is available) **/
    paths?: Array<{
      "from": Array<string>,
      "upgrade": Array<string | boolean>
    }>;
    /** The package identifier according to its package manager **/
    package: string;
    /** The package version this issue is applicable to. **/
    version: string;
    /** The Snyk defined severity level **/
    severity: "critical" | "high" | "medium" | "low";
    /** The package's programming language **/
    language: string;
    /** The package manager **/
    packageManager: string;
    /** One or more semver ranges this issue is applicable to. **/
    semver: string[] | Map<string, string[]>;
  }

  export interface Patch {
    id: string;
    urls: string[];
    version: string;
    modificationTime: string;
    comments: string[];
  }

  export interface Vulnerability extends Issue {
    /** The vulnerability publication time **/
    publicationTime: string;
    /** The time this vulnerability was originally disclosed to the package maintainers **/
    disclosureTime: string;
    /** Is this vulnerability fixable by upgrading a dependency? **/
    isUpgradable: boolean;
    /** The detailed description of the vulnerability, why and how it is exploitable. **/
    description: string;
    /** Is this vulnerability fixable by using a Snyk supplied patch? **/
    isPatchable: boolean;
    /** Is this vulnerability fixable by pinning a transitive dependency **/
    isPinnable: boolean;
    /** Additional vulnerability identifiers **/
    identifiers: Map<string, string[]>;
    /** The reporter of the vulnerability **/
    credit: string;
    /** Common Vulnerability Scoring System (CVSS) provides a way to capture the principal characteristics of a vulnerability, and produce a numerical score reflecting its severity, as well as a textual representation of that score. **/
    CVSSv3: string;
    /** CVSS Score **/
    cvssScore: number;
    /** Patches to fix this issue, by snyk **/
    patches: Patch[];
    /** The path to upgrade this issue, if applicable **/
    upgradePath: string[];
    /** Is this vulnerability patched? **/
    isPatched: boolean;
    /** The snyk exploit maturity level **/
    exploitMaturity: string;
  }

  export interface TestRequest {
    /** the encoding for the manifest files sent. Default: base64 **/
    encoding?: "plain" | "base64"
    /** The manifest files **/
    files: {
      /** the package.json file, encoded according the the "encoding" field. **/
      target: {
        /** the contents of package.json as a string. **/
        contents: string;
      }
      /** a lockfile can be sent (if needed), encoded according the the "encoding" field. **/
      additional?: Array<{
        /** The contents of the file, encoded according to the encoding field. **/
        contents: string;
      }>
    }
  }

  export interface TestResult {
    /** Does this package have one or more issues? **/
    ok: boolean;
    /** The issues found. **/
    issues: {
      vulnerabilities: Vulnerability[];
      licenses: Vulnerability[];
    };
    /** The number of dependencies the package has. **/
    dependencyCount: number;
    /** The organization this test was carried out for. **/
    org: {
      id: string;
      name: string;
    };
    /** The organization's licenses policy used for this test **/
    licensesPolicy: null | object;
    /** The package manager for this package **/
    packageManager: string;
  }
}
