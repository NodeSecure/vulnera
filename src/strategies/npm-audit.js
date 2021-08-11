// Import Third-party Dependencies
import Arborist from "@npmcli/arborist";
import { getLocalRegistryURL } from "@nodesecure/npm-registry-sdk";

// Import Internal Dependencies
import { VULN_MODE } from "../constants.js";

export function NPMAuditStrategy() {
  return {
    strategy: VULN_MODE.NPM_AUDIT,
    hydratePayloadDependencies
  };
}

export async function hydratePayloadDependencies(dependencies) {
  const registry = getLocalRegistryURL();
  const arborist = new Arborist({ ...constants.NPM_TOKEN, registry });

  try {
    const { vulnerabilities } = (await arborist.audit()).toJSON();

    for (const [packageName, packageVulns] of Object.entries(vulnerabilities)) {
      const dependenciesVulnerabilities = dependencies.get(packageName).vulnerabilities;

      dependenciesVulnerabilities.push(...extractPackageVulnsFromSource(packageVulns));
    }
  }
  catch {}
}

export function* extractPackageVulnsFromSource(packageVulnerabilities) {
  for (const vulnSource of packageVulnerabilities.via) {
    const { title, range, id, module_name, severity, version, vulnerableVersions } = vulnSource;

    yield {
      title, module_name, severity, version, vulnerableVersions, range, id
    };
  }
}
