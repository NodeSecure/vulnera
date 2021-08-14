export = Strategy;

declare namespace Strategy {
  export type Kind = "npm" | "node" | "none";

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
}
