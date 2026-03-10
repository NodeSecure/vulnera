# Snyk

[Snyk](https://snyk.io/fr) Snyk Limited is a developer-oriented cybersecurity company, specializing in securing custom developed code, open-source dependencies and cloud infrastructure.

## Implementation Notes

The Snyk integration uses the REST API (v1) available at [snyk.io](https://snyk.io/api/v1/test/npm) to perform security audit.

### Authentication

The `Snyk` constructor requires an `org` and a `credential`. These are generated when you create an organization on Snyk.

- `org`: Your Snyk organization ID
- `credential`: An `ApiCredential` instance using the `token` type (passed as `Authorization: token <token>` header)

### Format

The Snyk interface is exported as root like `SnykAuditResponse`.

```ts
export interface SnykAuditResponse {
  /** Does this package have one or more issues? **/
  ok: boolean;
  /** The issues found. **/
  issues: {
    vulnerabilities: SnykVulnerability[];
    licenses: SnykVulnerability[];
  };
  /** The number of dependencies the package has. **/
  dependencyCount: number;
  /** The organization this test was carried out for. **/
  org: {
    id: string;
    name: string;
  };
  /** The organization's licenses policy used for this test **/
  licensesPolicy: null | object;
  /** The package manager for this package **/
  packageManager: string;
}
```

## API

### Constructor

```ts
import * as vulnera from "@nodesecure/vulnera";

const db = new vulnera.Database.Snyk({
  org: process.env.SNYK_ORG,
  credential: new vulnera.ApiCredential(process.env.SNYK_TOKEN)
});
```

```ts
export interface SnykOptions {
  org: string;
  credential: ApiCredential;
}
```

### `findOne(parameters: SnykFindOneParameters): Promise<SnykAuditResponse>`

Find the vulnerabilities of a given package using available SnykFindOneParameters API parameters.

```ts
export type SnykFindOneParameters = {
  files: {
    target: {
      contents: string;
    };
    additional?: {
      contents: string;
    }[];
  };
};
```

```ts
import * as vulnera from "@nodesecure/vulnera";

const db = new vulnera.Database.Snyk({
  org: process.env.SNYK_ORG,
  credential: new vulnera.ApiCredential({
    type: "token",
    token: process.env.SNYK_TOKEN
  })
});
const result = await db.findOne({
  files: {
    target: { contents: packageJsonBase64 }
  }
});
```
