# OSV

OSV stand for <kbd>Open Source Vulnerability</kbd> database. This project is an open, precise, and distributed approach to producing and consuming vulnerability information for open source.

All advisories in this database use the [OpenSSF OSV format](https://ossf.github.io/osv-schema/), which was developed in collaboration with open source communities.

Lean more at [osv.dev](https://osv.dev/)

## Format

The OSV interface is exported as root like `StandardVulnerability`.

```ts
export interface OSV {
  schema_version: string;
  id: string;
  modified: string;
  published: string;
  withdraw: string;
  aliases: string[];
  related: string[];
  summary: string;
  details: string;
  severity: OSVSeverity[];
  affected: OSVAffected[];
  references: {
    type: OSVReferenceType;
    url: string;
  }[];
  credits: {
    name: string;
    contact: string[];
    type: OSVCreditType;
  }[];
  database_specific: Record<string, any>;
}
```

## API

### findOne(parameters: OSVApiParameter): Promise< OSV[] >
Find the vulnerabilities of a given package using available OSV API parameters.

```ts
export type OSVApiParameter = {
  version?: string;
  package: {
    name: string;
    /**
     * @default npm
     */
    ecosystem?: string;
  };
}
```

### findOneBySpec(spec: string): Promise< OSV[] >
Find the vulnerabilities of a given package using the NPM spec format like `packageName@version`.

```ts
import * as vulnera from "@nodesecure/vulnera";

const vulns = await vulnera.Database.osv.findOneBySpec(
  "01template1"
);
console.log(vulns);
```

### findMany< T extends string >(specs: T[]): Promise< Record< T, OSV[] > >
Find the vulnerabilities of many packages using the spec format.

Return a Record where keys are equals to the provided specs.
