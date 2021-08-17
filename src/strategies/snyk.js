// Import Node.js Dependencies
import path from "path";
import { readFile } from "fs/promises";

// Import Third-Party Dependencies
import fetch from "node-fetch";

// Import Internal Dependencies
import { VULN_MODE, SNYK_ORG, SNYK_TOKEN } from "../constants.js";

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

export async function hydratePayloadDependencies(dependencies, options = {}) {
  try {
    const targetFilePath = path.join(options.path, kTargetFileName);
    const additionalFilePath = path.join(options.path, kAdditionalFileName);

    const targetFile = await readFile(targetFilePath, kEncoding);
    let additionalFile;

    try {
      additionalFile = await readFile(additionalFilePath, kEncoding);
    }
    catch {}

    const res = await fetch(kSnykApiUrl, getRequestOptions(targetFile, additionalFile));
    const data = await res.json();
    // TODO: add extractPackageVulnsFromSource fn
    console.dir(data);
  }
  catch {}
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
    method: "post",
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      Authorization: kAuthHeader
    },
    body: JSON.stringify(body)
  };
}
