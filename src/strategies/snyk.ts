// Import Node.js Dependencies
import path from "node:path";
import { readFile } from "node:fs/promises";

// Import Third-Party Dependencies
import * as httpie from "@myunisoft/httpie";

// Import Internal Dependencies
import { VULN_MODE, SNYK_ORG, SNYK_TOKEN } from "../constants.js";
import { standardizeVulnsPayload } from "../formats/standard/index.js";
import type { Dependencies } from "./types/scanner.js";
import type {
  HydratePayloadDepsOptions,
  BaseStrategy
} from "./types/api.js";

// CONSTANTS
const kSnykApiUrl = `https://snyk.io/api/v1/test/npm?org=${SNYK_ORG}`;

export interface SnykPatch {
  id: string;
  urls: string[];
  version: string;
  modificationTime: string;
  comments: string[];
}

export interface SnykVulnerability {
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
  semver: Record<string, string[]>;
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
  identifiers: Record<string, string[]>;
  /** The reporter of the vulnerability **/
  credit: string;
  /**
   * Common Vulnerability Scoring System (CVSS) provides a way to capture the principal characteristics
   * of a vulnerability, and produce a numerical score reflecting its severity,
   * as well as a textual representation of that score.
   * **/
  CVSSv3: string;
  /** CVSS Score **/
  cvssScore: number;
  /** Patches to fix this issue, by snyk **/
  patches: SnykPatch[];
  /** The path to upgrade this issue, if applicable **/
  upgradePath: string[];
  /** Is this vulnerability patched? **/
  isPatched: boolean;
  /** The snyk exploit maturity level **/
  exploitMaturity: string;
  functions: any;
}

export interface SnykAuditResponse {
  /** Does this package have one or more issues? **/
  ok: boolean;
  /** The issues found. **/
  issues: {
    vulnerabilities: SnykVulnerability[];
    licenses: SnykVulnerability[];
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

export type SnykStrategyDefinition = BaseStrategy<"snyk">;

export function SnykStrategy(): SnykStrategyDefinition {
  return {
    strategy: VULN_MODE.SNYK,
    hydratePayloadDependencies
  };
}

async function hydratePayloadDependencies(
  dependencies: Dependencies,
  options: HydratePayloadDepsOptions
) {
  const { path } = options;
  if (!path) {
    throw new Error("path argument is required for <snyk> strategy");
  }

  try {
    const { targetFile, additionalFile } = await getNpmManifestFiles(path);

    const body = {
      files: {
        ...(additionalFile ? { additional: [{ contents: additionalFile }] } : {}),
        target: {
          contents: targetFile
        }
      }
    };

    const { data } = await httpie.post<SnykAuditResponse>(
      kSnykApiUrl,
      {
        headers: {
          Authorization: `token ${SNYK_TOKEN}`
        },
        body
      }
    );
    extractSnykVulnerabilities(dependencies, data, options);
  }
  catch { }
}

async function getNpmManifestFiles(
  projectPath: string
) {
  const targetFile = await readFile(
    path.join(projectPath, "package.json"),
    { encoding: "base64" }
  );
  let additionalFile: string | undefined;

  try {
    additionalFile = await readFile(
      path.join(projectPath, "package-lock.json"),
      { encoding: "base64" }
    );
  }
  catch { }

  return {
    targetFile,
    additionalFile
  };
}

function extractSnykVulnerabilities(
  dependencies: Dependencies,
  snykAudit: SnykAuditResponse,
  options: HydratePayloadDepsOptions
) {
  const { ok, issues } = snykAudit;
  const { useStandardFormat } = options;
  const formatVulnerabilities = standardizeVulnsPayload(useStandardFormat);

  if (!ok) {
    const vulnerabilities = formatVulnerabilities(VULN_MODE.SNYK, issues.vulnerabilities);
    for (const vuln of vulnerabilities) {
      const dependency = dependencies.get(vuln.package);
      if (dependency) {
        dependency.vulnerabilities.push(vuln);
      }
    }
  }
}
