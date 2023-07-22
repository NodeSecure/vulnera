// Import Third-party Dependencies
import Arborist from "@npmcli/arborist";
import { getLocalRegistryURL } from "@nodesecure/npm-registry-sdk";

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
  const arborist = new Arborist({ ...NPM_TOKEN, path });

  const { vulnerabilities } = (await arborist.audit()).toJSON();
  const advisories = Object.values(vulnerabilities)
    .flatMap((vuln) => (Array.isArray(vuln.via) && typeof vuln.via[0] === "object" ? vuln.via : []));

  if (useStandardFormat) {
    return formatVulnerabilities(VULN_MODE.NPM_AUDIT, advisories);
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

      const dependenciesVulnerabilities = dependencies.get(packageName).vulnerabilities;
      dependenciesVulnerabilities.push(
        ...formatVulnerabilities(
          VULN_MODE.NPM_AUDIT,
          [...extractPackageVulnsFromSource(packageVulns)]
        )
      );
    }
  }
  catch { }
}

function* extractPackageVulnsFromSource(packageVulnerabilities) {
  for (const vulnSource of packageVulnerabilities.via) {
    const { title, range, id, name, source, url, dependency, severity, version, vulnerableVersions } = vulnSource;

    yield {
      title, name, source, url, dependency, severity, version, vulnerableVersions, range, id
    };
  }
}
