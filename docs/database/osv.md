# OSV

OSV stands for <kbd>Open Source Vulnerability</kbd> database. This project is an open, precise, and distributed approach to producing and consuming vulnerability information for open source.

All advisories in this database use the [OpenSSF OSV format](https://ossf.github.io/osv-schema/), which was developed in collaboration with open source communities.

Learn more at [osv.dev](https://osv.dev/)

## Format

See the [OSV format](../formats/osv.md) documentation.

## API

### Constructor

```ts
import * as vulnera from "@nodesecure/vulnera";

const db = new vulnera.Database.OSV();
```

```ts
export interface OSVOptions {
  credential?: ApiCredential;
}
```

No credentials are required to use the OSV public API. The optional `credential` can be used to attach API key headers if needed.

### `query(parameters: OSVQueryBatchEntry): Promise<OSV[]>`

Find the vulnerabilities of a given package using available OSV API parameters. Defaults the ecosystem to `npm` if not specified.

```ts
export type OSVQueryBatchEntry = {
  version?: string;
  package: {
    name: string;
    /**
     * @default "npm"
     */
    ecosystem?: string;
  };
};
```

Example:

```ts
import * as vulnera from "@nodesecure/vulnera";

const db = new vulnera.Database.OSV();

const vulns = await db.query({
  version: "1.0.0",
  package: { name: "lodash" }
});
console.log(vulns);
```

### `queryBySpec(spec: string): Promise<OSV[]>`

Find the vulnerabilities of a given package using the npm spec format `packageName@version`.

```ts
import * as vulnera from "@nodesecure/vulnera";

const db = new vulnera.Database.OSV();

const vulns = await db.queryBySpec("lodash@4.17.20");
console.log(vulns);
```

### `queryBatch(queries: OSVQueryBatchEntry[]): Promise<OSVQueryBatchResult[]>`

Query multiple packages at once using the `/v1/querybatch` OSV endpoint. Results are returned in the same order as the input queries.

```ts
export interface OSVQueryBatchResult {
  vulns?: OSV[];
}
```

Example:

```ts
import * as vulnera from "@nodesecure/vulnera";

const db = new vulnera.Database.OSV();

const results = await db.queryBatch([
  { version: "4.17.20", package: { name: "lodash" } },
  { version: "1.0.0", package: { name: "minimist" } }
]);

for (const result of results) {
  console.log(result.vulns ?? []);
}
```

### `findVulnById(id: string): Promise<OSV>`

Fetch a single vulnerability entry by its OSV identifier (e.g. `GHSA-xxxx-xxxx-xxxx` or `RUSTSEC-xxxx-xxxx`).

```ts
import * as vulnera from "@nodesecure/vulnera";

const db = new vulnera.Database.OSV();

const vuln = await db.findVulnById("GHSA-p6mc-m468-83gw");
console.log(vuln);
```
