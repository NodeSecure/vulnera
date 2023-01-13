/* eslint-disable no-trailing-spaces */
/* eslint-disable no-multiple-empty-lines */
/* eslint-disable brace-style */
/* eslint-disable comma-dangle */
// Import Third-party Dependencies
import Arborist from "@npmcli/arborist";
import { audit } from "@pnpm/audit";
import { getLocalRegistryURL } from "@nodesecure/npm-registry-sdk";
import fs from "fs";

// Import Internal Dependencies
import { VULN_MODE, NPM_TOKEN } from "../constants.js";
import { standardizeVulnsPayload } from "./vuln-payload/standardize.js";

export function NPMAuditStrategy() {
  return {
    strategy: VULN_MODE.NPM_AUDIT,
    hydratePayloadDependencies,
    getVulnerabilities
  };
}

async function checkIfProjectUsePnpm(path) {
  return new Promise((resolve) => {
    fs.access(`${path}/pnpm-lock.yaml`, fs.constants.F_OK, (err) => {
      if (err) {
        resolve(false);
      } else {
        console.log("Project use pnpm");
        console.log("path", path);
        resolve(true);
      }
    });
  });
}

async function launchPnpmAudit(path, includeToAudit) {
  console.log("launch Pnpm Audit");

  const options = {
    include: { dependancies: true, devDependancies: true, optionDependancies: false },
  };
  const lockFile = `${path}/pnpm-lock.yaml`;
  let auditReport;
  try {
    auditReport = await audit(lockFile, {}, options);
    console.log("Audit report : ", auditReport);
  } catch (error) {
    console.log("error pnpm -> ", error);
  }

  return auditReport.vulnerabilities;
}



async function getVulnerabilities(path, options = {}) {
  const { useStandardFormat } = options;
  const isPnpmProject = await checkIfProjectUsePnpm(path);
  const formatVulnerabilities = standardizeVulnsPayload(useStandardFormat);
  const arborist = new Arborist({ ...NPM_TOKEN, path });
  const { vulnerabilities } = isPnpmProject
    ? await launchPnpmAudit(path, ["dependencies", "devDependencies"])
    : (await arborist.audit()).toJSON();

  if (useStandardFormat) {
    return formatVulnerabilities(
      VULN_MODE.NPM_AUDIT,
      Object.values(vulnerabilities)
    );
  }

  return vulnerabilities;
}

async function hydratePayloadDependencies(dependencies, options = {}) {
  const { path, useStandardFormat } = options;

  const formatVulnerabilities = standardizeVulnsPayload(useStandardFormat);
  const registry = getLocalRegistryURL();
  const arborist = new Arborist({ ...NPM_TOKEN, registry, path });

  try {
    const { vulnerabilities } = (await arborist.audit()).toJSON();

    for (const [packageName, packageVulns] of Object.entries(vulnerabilities)) {
      if (!dependencies.has(packageName)) {
        continue;
      }

      const dependenciesVulnerabilities =
        dependencies.get(packageName).vulnerabilities;
      dependenciesVulnerabilities.push(
        ...formatVulnerabilities(VULN_MODE.NPM_AUDIT, [
          ...extractPackageVulnsFromSource(packageVulns),
        ])
      );
    }
  } catch {}
}

function* extractPackageVulnsFromSource(packageVulnerabilities) {
  for (const vulnSource of packageVulnerabilities.via) {
    const {
      title,
      range,
      id,
      name,
      source,
      url,
      dependency,
      severity,
      version,
      vulnerableVersions,
    } = vulnSource;

    yield {
      title,
      name,
      source,
      url,
      dependency,
      severity,
      version,
      vulnerableVersions,
      range,
      id,
    };
  }
}
