// Import Node.js Dependencies
import fs from "node:fs/promises";
import path from "node:path";

// Import Third-party Dependencies
import Arborist from "@npmcli/arborist";
import { getLocalRegistryURL } from "@nodesecure/npm-registry-sdk";
import { readWantedLockfile } from "@pnpm/lockfile-file";
import { audit } from "@pnpm/audit";

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

async function getVulnerabilities(path, options = {}) {
  const { useStandardFormat } = options;

  const formatVulnerabilities = standardizeVulnsPayload(useStandardFormat);
  const registry = getLocalRegistryURL();
  const isPnpm = await hasPnpmLockFile(path);

  const vulnerabilities = isPnpm ?
    await pnpmAudit(path, registry) :
    await npmAudit(path, registry);

  if (useStandardFormat) {
    return formatVulnerabilities(
      isPnpm ? VULN_MODE.NPM_AUDIT + "_pnpm" : VULN_MODE.NPM_AUDIT,
      vulnerabilities
    );
  }

  return vulnerabilities;
}

async function hydratePayloadDependencies(dependencies, options = {}) {
  const { path, useStandardFormat } = options;

  const formatVulnerabilities = standardizeVulnsPayload(useStandardFormat);
  const registry = getLocalRegistryURL();

  try {
    const isPnpm = await hasPnpmLockFile(path);

    const vulnerabilities = isPnpm ?
      await pnpmAudit(path, registry) :
      await npmAudit(path, registry);

    for (const packageVulns of vulnerabilities) {
      const packageName = packageVulns.name || packageVulns.module_name;
      if (!dependencies.has(packageName)) {
        continue;
      }

      const dependenciesVulnerabilities = dependencies.get(packageName).vulnerabilities;
      dependenciesVulnerabilities.push(
        ...formatVulnerabilities(
          isPnpm ? VULN_MODE.NPM_AUDIT + "_pnpm" : VULN_MODE.NPM_AUDIT,
          [packageVulns]
        )
      );
    }
  }
  catch { }
}

async function npmAudit(path, registry) {
  const arborist = new Arborist({ ...NPM_TOKEN, registry, path });
  const { vulnerabilities } = (await arborist.audit()).toJSON();

  return Object.values(vulnerabilities)
    .flatMap((vuln) => (Array.isArray(vuln.via) && typeof vuln.via[0] === "object" ? vuln.via : []));
}

async function pnpmAudit(lockfileDir, registry) {
  const auditOptions = {
    include: { dependencies: true, devDependencies: true, optionalDependencies: false },
    lockfileDir,
    registry
  };

  const lockfile = await readWantedLockfile(lockfileDir, {});

  // eslint-disable-next-line
  const getAuthHeader = () => ({});
  const { advisories } = await audit(
    lockfile, getAuthHeader, auditOptions
  );

  return Object.values(advisories);
}

async function hasPnpmLockFile(lockfileDir) {
  try {
    await fs.access(
      path.join(lockfileDir, "pnpm-lock.yaml"),
      fs.constants.F_OK
    );

    return true;
  }
  catch {
    return false;
  }
}
