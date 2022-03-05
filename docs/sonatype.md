# Sonatype strategy
[Sonatype OSS Index](https://ossindex.sonatype.org/) is a free catalogue of open source components and scanning tools to help developers identify vulnerabilities, understand risk, and keep their software safe.

This strategy doesn't require the synchronization of a local database, all 
vulnerabilities are retrieved on the fly. We use the REST API linked to the open 
source database of the Sonatype OSS Index to hydrate NodeSecure dependencies payloads. 
The database for **npm** is accessible [here](https://ossindex.sonatype.org/browse/npm?page=0)

```js
import * as vuln from "@nodesecure/vuln";

const dependencies = new Map();
// ...retrieve all dependencies using shrinkwraps

const definition = await vuln.setStrategy(vuln.strategies.SONATYPE);
await definition.hydratePayloadDependencies(dependencies);
```