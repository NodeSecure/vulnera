/* eslint-disable consistent-return */
/* eslint-disable no-trailing-spaces */
/* eslint-disable no-multiple-empty-lines */
/* eslint-disable brace-style */
/* eslint-disable comma-dangle */
// Import Third-party Dependencies
import Arborist from "@npmcli/arborist";
import { readWantedLockfile } from "@pnpm/lockfile-file";
import { getLocalRegistryURL } from "@nodesecure/npm-registry-sdk";
import { audit } from "@pnpm/audit";
import fs from "fs";

// Import Internal Dependencies
import { VULN_MODE, NPM_TOKEN } from "../constants.js";
import { standardizeVulnsPayload } from "./vuln-payload/standardize.js";
import { throws } from "assert";

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
        resolve(true);
      }
    });
  });
}

async function launchPnpmAudit(path) {
  console.log("launch Pnpm Audit");
  const opts = { 
    include: { dependencies: true, devDependencies: true, optionalDependencies: false },
    lockfileDir: path,
    registry: "https://registry.npmjs.org",
  };
  
  readWantedLockfile(path, {})
    .then((lockfile) => { 
      console.log("Lockfile ok");
      audit(lockfile, { registry: "https://registry.npmjs.org" }, opts); })
    .then((auditResult) => {
      console.log("Audit result -> ", JSON.stringify(auditResult, null, 2));

      return auditResult; 
    })
    .catch((err) => {
      console.log("Error -> ", err);
      throw err;
    });
}

async function getVulnerabilities(path, options = {}) {
  const { useStandardFormat } = options;
  const isPnpmProject = await checkIfProjectUsePnpm(path);
  const formatVulnerabilities = standardizeVulnsPayload(useStandardFormat);
  const arborist = new Arborist({ ...NPM_TOKEN, path });
  const { vulnerabilities } = isPnpmProject
    ? await launchPnpmAudit(path)
    : (await arborist.audit()).toJSON();

  if (useStandardFormat) {
    return formatVulnerabilities(
      VULN_MODE.NPM_AUDIT,
      Object.values(vulnerabilities)
    );
  }

  console.log("Vulnerabilities -> ", vulnerabilities);

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
