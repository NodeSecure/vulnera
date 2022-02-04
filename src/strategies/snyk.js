// Import Node.js Dependencies
import path from "path";
import { readFile } from "fs/promises";

// Import Third-Party Dependencies
import * as httpie from "@myunisoft/httpie";

// Import Internal Dependencies
import { VULN_MODE, SNYK_ORG, SNYK_TOKEN } from "../constants.js";
import { standardizeVulnsPayload } from "./vuln-payload/standardize.js";

// Constants
const kTargetFileName = "package.json";
const kAdditionalFileName = "package-lock.json";
const kSnykApiUrl = `https://snyk.io/api/v1/test/npm?org=${SNYK_ORG}`;
const kAuthHeader = `token ${SNYK_TOKEN}`;
const kEncoding = "base64";

export function SnykStrategy() {
  return {
    strategy: VULN_MODE.SNYK,
    hydratePayloadDependencies
  };
}

async function hydratePayloadDependencies(dependencies, options = {}) {
  try {
    const { targetFile, additionalFile } = await getDependenciesFiles(options.path);
    const { data } = await httpie.post(kSnykApiUrl, getRequestOptions(targetFile, additionalFile));
    extractSnykVulnerabilities(dependencies, data, options);
  }
  catch { }
}

async function getDependenciesFiles(projectPath) {
  const targetFile = await readFile(path.join(projectPath, kTargetFileName), kEncoding);
  let additionalFile;

  try {
    additionalFile = await readFile(path.join(projectPath, kAdditionalFileName), kEncoding);
  }
  catch { }

  return {
    targetFile,
    additionalFile
  };
}

function getRequestOptions(targetFile, additionalFile) {
  const additional = additionalFile ? {
    additional: [{
      contents: additionalFile
    }]
  } : {};
  const body = {
    files: {
      ...additional,
      target: {
        contents: targetFile
      }
    }
  };

  return {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      Authorization: kAuthHeader
    },
    body: JSON.stringify(body)
  };
}

function extractSnykVulnerabilities(dependencies, snykAudit, options) {
  const { ok, issues } = snykAudit;
  const { useStandardFormat } = options;
  const formatVulnerabilities = standardizeVulnsPayload(useStandardFormat);

  if (!ok) {
    const vulnerabilities = formatVulnerabilities(issues.vulnerabilities);
    for (const vuln of vulnerabilities) {
      const dependency = dependencies.get(vuln.package);
      if (dependency) {
        dependency.vulnerabilities.push(vuln);
      }
    }
  }
}
