import NpmStrategy from "./npm-strategy";
import SnykStrategy from "./snyk-strategy";

export = Strategy;

declare namespace Strategy {
  export type Kind = "npm" | "node" | "snyk" | "none";

  // Degraded version from scanner (only implement what we need).
  export interface VersionDescriptor {
    versions: string[];
    vulnerabilities?: any[];
  }

  export type Dependencies = Map<string, VersionDescriptor>;

  export interface Options {
    /** Force hydratation of the strategy local database (if the strategy has one obviously) **/
    hydrateDatabase?: boolean;
  }

  export interface HydratePayloadDependenciesOptions {
    /** Absolute path to the location to analyze (with a package.json and/or package-lock.json for NPM Audit for example) **/
    path?: string;
    useStandardFormat?: boolean;
  }

  export interface Definition {
    /** Name of the strategy **/
    strategy: Kind;
    /** Method to hydrate (insert/push) vulnerabilities in the dependencies retrieved by the Scanner **/
    hydratePayloadDependencies: (dependencies: Dependencies, options?: HydratePayloadDependenciesOptions) => Promise<void>;
    /** Hydrate local database (if the strategy need one obviously) **/
    hydrateDatabase?: () => Promise<void>;
    /** Method to delete the local vulnerabilities database (if available) **/
    deleteDatabase?: () => Promise<void>;
  }

  export type Severity = Exclude<NpmStrategy.Vulnerability['severity'] | SnykStrategy.Vulnerability['severity'], "moderate">;

  export interface Patch {
    id: string;
    comments: string[];
    modificationTime: string;
    urls: string[];
    version: string;
  }

  export type Origin = Exclude<Kind, "none">;

  export interface StandardVulnerability {
    /** Unique identifier for the vulnerability **/
    id?: string;
    /** Vulnerability origin, either Snyk, NPM or NodeSWG **/
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
    cves: string[];
    /** Common Vulnerability Scoring System (CVSS) provides a way to capture the principal characteristics of a vulnerability, and produce a numerical score reflecting its severity, as well as a textual representation of that score. **/
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

}
