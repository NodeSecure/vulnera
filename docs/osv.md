# OSV strategy

The OSV strategy queries the [OSV (Open Source Vulnerability)](https://osv.dev/) public API directly. It uses the `/v1/querybatch` endpoint for efficient batch lookups, resolving vulnerabilities for all dependencies at once.

No credentials or local database synchronization are required.

## How it works

1. Dependencies are extracted from the local project using `NodeDependencyExtractor` (via Arborist), which reads from `node_modules` or falls back to the lockfile.
2. All `name@version` pairs are batched into chunks of up to **1000** entries and sent to the OSV batch API.
3. Results are mapped back to each package and optionally converted to the [Standard](./formats/standard.md) or [OSV](./formats/osv.md) format.

## Usage

### `getVulnerabilities(path, options?)`

Scans a local project directory and returns all found vulnerabilities.

```js
import * as vulnera from "@nodesecure/vulnera";

const definition = vulnera.setStrategy(vulnera.strategies.OSV);

const vulnerabilities = await definition.getVulnerabilities(process.cwd());
console.log(vulnerabilities);
```

With the Standard NodeSecure format:

```js
import * as vulnera from "@nodesecure/vulnera";

const definition = vulnera.setStrategy(vulnera.strategies.OSV);

const vulnerabilities = await definition.getVulnerabilities(process.cwd(), {
  useFormat: "Standard"
});
console.log(vulnerabilities);
```

### `hydratePayloadDependencies(dependencies, options?)`

Hydrates a Scanner dependencies `Map` in-place with vulnerability data.

```js
import * as vulnera from "@nodesecure/vulnera";

const dependencies = new Map();
// ...populate dependencies from Scanner...

const definition = vulnera.setStrategy(vulnera.strategies.OSV);
await definition.hydratePayloadDependencies(dependencies);
```

With the Standard NodeSecure format:

```js
await definition.hydratePayloadDependencies(dependencies, {
  useFormat: "Standard"
});
```

## OSV Database

The strategy uses the [`OSV` database class](./database/osv.md) internally. You can also use it directly for lower-level access to the OSV API (single queries, batch queries, lookup by ID).
