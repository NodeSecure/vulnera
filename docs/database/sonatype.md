# Sonatype

Sonatype provides software supply chain security and repository management tools to help organizations manage risks in their open source dependencies.

## Implementation Notes

The Sonatype integration uses the REST API (v3) available at [ossindex.sonatype.org](https://ossindex.sonatype.org/api/v3/component-report).

### Authentication

`Sonatype` supports optional basic auth credentials for higher rate limits. Without credentials, the API is still accessible at reduced rate limits.

### Format

The Sonatype interface is exported as root like `SonatypeResponse`.

```ts
export type SonatypeResponse = {
  coordinates: string;
  vulnerabilities: SonatypeVulnerability[];
};
```

## API

### Constructor

```ts
import * as vulnera from "@nodesecure/vulnera";

const db = new vulnera.Database.Sonatype({
  credential: new vulnera.ApiCredential({
    type: "basic",
    username: process.env.SONATYPE_USERNAME,
    password: process.env.SONATYPE_PASSWORD
  })
});
```

```ts
export interface SonatypeOptions {
  credential?: ApiCredential;
}
```

### `findOne(parameters: SonaTypeFindOneParameters): Promise<SonatypeResponse[]>`

Find the vulnerabilities of a given package using available Sonatype API parameters.

```ts
export type SonaTypeFindOneParameters = {
  coordinates: string[];
};
```

```ts
import * as vulnera from "@nodesecure/vulnera";

const db = new vulnera.Database.Sonatype();
const vulns = await db.findOne({ coordinates: ["pkg:npm/express@4.0.0"] });
console.log(vulns);
```

### `findMany(parameters: SonaTypeFindManyParameters): Promise<SonatypeResponse[]>`

Find the vulnerabilities of many packages.

```ts
export type SonaTypeFindManyParameters = {
  coordinates: string[][];
};
```

```ts
import * as vulnera from "@nodesecure/vulnera";

const db = new vulnera.Database.Sonatype();
const vulns = await db.findMany({
  coordinates: [
    ["pkg:npm/express@4.0.0"],
    ["pkg:npm/lodash@4.17.0"]
  ]
});
console.log(vulns);
```
