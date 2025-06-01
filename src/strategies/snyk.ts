/* eslint-disable no-empty */
// Import Node.js Dependencies
import path from "node:path";
import { readFile } from "node:fs/promises";

// Import Internal Dependencies
import { VULN_MODE } from "../constants.js";
import type { Dependencies } from "./types/scanner.js";
import type {
  HydratePayloadDepsOptions,
  BaseStrategy
} from "./types/api.js";
import { type SnykAuditResponse } from "../formats/snyk/index.js";
import { snyk } from "../database/index.js";
import { formatVulnsPayload } from "../formats/index.js";

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

    const data = await snyk.findOne({
      files: {
        ...(additionalFile ? { additional: [{ contents: additionalFile }] } : {}),
        target: {
          contents: targetFile
        }
      }
    });

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
  const { useFormat } = options;
  const formatVulnerabilities = formatVulnsPayload(useFormat);

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
