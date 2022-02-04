// Import Third-party Dependencies
import Arborist from "@npmcli/arborist";
import { getLocalRegistryURL } from "@nodesecure/npm-registry-sdk";

// Import Internal Dependencies
import { VULN_MODE, NPM_TOKEN } from "../constants.js";
import { standardizeVulnsPayload } from "./vuln-payload/standardize.js";

export function NPMAuditStrategy() {
  return {
    strategy: VULN_MODE.NPM_AUDIT,
    hydratePayloadDependencies
  };
}

async function hydratePayloadDependencies(dependencies, options = {}) {
  const { path } = options;

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
        ...options.useStandardFormat
          ? standardizeVulnsPayload(VULN_MODE.NPM_AUDIT, packageVulns.via)
          : extractPackageVulnsFromSource(packageVulns)
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
