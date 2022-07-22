# Node.js strategy (deprecated)

> **Warning**: Node.js Security WG DB is deprecated. [Here is why](nodejs.medium.com/node-js-ecosystem-vulnerability-reporting-program-winding-down-591d9a8cd2c7).

Using the open database of the Node.js security WG github repository to hydrate NodeSecure dependencies payloads. This database is accessible [here](https://github.com/nodejs/security-wg/tree/main/vuln).

To exploit this database we clone it (extract the .tar.gz) locally, read and bundle all JSON files into one .JSON database.

```js
import * as vulnera from "@nodesecure/vulnera";

const definition = await vulnera.setStrategy(vulnera.strategies.SECURITY_WG, {
  // Force the update of the local database
  hydrateDatabase: true
});

// DO WORK

// Then delete the local database
await definition.deleteDatabase();
```

The database should be updated before the scanner is run. When required the method `hydratePayloadDependencies` will be called at the end of the scanner to hydrate vulnerabilities into the Dependencies Map.

```ts
const dependencies = new Map();
// ...do work on dependencies...

const definition = await vulnera.getStrategy();
await definition.hydratePayloadDependencies(dependencies);
```
