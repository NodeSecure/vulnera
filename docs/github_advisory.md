# GitHub Advisory strategy

> [!IMPORTANT] 
> This strategy was previously known as NPM

[NPM Audit](https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities) is a feature provided by the npm team. This allows to identify anomalies in a package.json/package-lock.json.

Under the hood we use [@npmcli/arborist](https://github.com/npm/arborist#readme) to fetch vulnerabilities (directly as JSON).

```js
const { vulnerabilities } = (await arborist.audit()).toJSON();
```

This strategy doesn't require the synchronization of a local database.

> [!IMPORTANT] 
> This strategy currently only work with a local project analysis (with a package.json/package-lock.json)

```js
import * as vulnera from "@nodesecure/vulnera";
import { loadRegistryURLFromLocalSystem } from "@nodesecure/npm-registry-sdk";

// Before walking the dependency tree (at runtime)
loadRegistryURLFromLocalSystem();

const dependencies = new Map();
// ...do work on dependencies...

const definition = await vulnera.setStrategy(vulnera.strategies.GITHUB_ADVISORY);
await definition.hydratePayloadDependencies(dependencies, {
  // path where we have to run npm audit (default equal to process.cwd())
  path: process.cwd()
});
```

Note that it is important to call `loadRegistryURLFromLocalSystem` before running `hydratePayloadDependencies` method. The internal method will retrieve the correct URL for the registry (could be useful if the developer use a private registry for example).

## Audit a specific manifest 

For audit a specific manifest (package.json, lock-file or nodes_modules), there is the getVulnerabilities function that takes the path of the manifest and returns the vulnerabilities.

```js
async function getVulnerabilities(path, options = {}) {
  const { useFormat } = options;

  const formatVulnerabilities = formatVulnsPayload(useFormat);
  const registry = getLocalRegistryURL();
  const isPnpm = await hasPnpmLockFile(path);

  const vulnerabilities = isPnpm ?
    await pnpmAudit(path, registry) :
    await npmAudit(path, registry);

  if (useFormat) {
    return formatVulnerabilities(
      isPnpm ? VULN_MODE.GITHUB_ADVISORY + "_pnpm" : VULN_MODE.GITHUB_ADVISORY,
      vulnerabilities
    );
  }

  return vulnerabilities;
}
```

Example with Standard NodeSecure format:
```js
import * as vulnera from "@nodesecure/vulnera";

const definition = await vulnera.setStrategy(vulnera.strategies.GITHUB_ADVISORY);
const vulnerabilites = await definition.getVulnerabilities(
  './package.json',
  { useFormat: "Standard" }
);
```

## Work natively with pnpm

Vulnera use `@pnpm/audit` to support the package manager pnpm and his lock file `pnpm-lock`.
