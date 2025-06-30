# Sonatype

Sonatype provides software supply chain security and repository management tools to help organizations manage risks in their open source dependencies.

### Implementation Notes

The Sonatype integration uses the REST API (v3) available at [ossindex.sonatype.org](https://ossindex.sonatype.org/api/v3/component-report).

### Format

the Sonatype interface is exported as root like `SonatypeResponse`.

```ts
export type SonatypeResponse = { 
    coordinates: string; vulnerabilities: SonatypeVulnerability[]; 
    };
```
### API

### findOne(parameters: SonaTypeFindOneParameters): Promise< SonatypeResponse[] >

```ts
export type SonaTypeFindOneParameters = {
  coordinates: string[];
};
```

Find the vulnerabilities of a given package using available Sonatype API parameters.

### findMany(parameters: SonaTypeFindManyParameters): Promise< SonatypeResponse[] > >

```ts
export type SonaTypeFindManyParameters = {
  coordinates: string[][];
};
```

Find the vulnerabilities of many packages.