# Standard vulnerability format

We provide an high level format that work for all available strategy. It can be activated with the option `useFormat` equal `Standard`.

```ts
export interface StandardVulnerability {
  /** Unique identifier for the vulnerability **/
  id?: string;
  /** Vulnerability origin, either Snyk, Sonatype, GitHub or NodeSWG **/
  origin: Origin;
  /** Package associated with the vulnerability **/
  package: string;
  /** Vulnerability title **/
  title: string;
  /** Vulnerability description **/
  description?: string;
  /** Vulnerability link references on origin's website **/
  url?: string;
  /** Vulnerability severity levels given the strategy **/
  severity?: Severity;
  /** Common Vulnerabilities and Exposures dictionary */
  cves?: string[];
  /**
   * Common Vulnerability Scoring System (CVSS) provides a way to capture
   * the principal characteristics of a vulnerability,
   * and produce a numerical score reflecting its severity,
   * as well as a textual representation of that score. **/
  cvssVector?: string;
  /** CVSS Score **/
  cvssScore?: number;
  /** The range of vulnerable versions provided when too many versions are vulnerables */
  vulnerableRanges: string[];
  /** The set of versions that are vulnerable **/
  vulnerableVersions: string[];
  /** The set of versions that are patched **/
  patchedVersions?: string;
  /** Overview of available patches to get rid of listed vulnerabilities **/
  patches?: Patch[];
}
```
