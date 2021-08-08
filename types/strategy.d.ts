export = Strategy;

declare namespace Strategy {
  export type Mode = "npm" | "node";

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

  export interface Definition {
    /** Name of the strategy **/
    type: Mode;
    /** Method to hydrate (insert/push) vulnerabilities in the dependencies retrieved by the Scanner **/
    hydratePayloadDependencies: (dependencies: Dependencies, defaultRegistryAddr?: string) => Promise<void>;
    /** Hydrate local database (if the strategy need one obviously) **/
    hydrateDatabase?: () => Promise<void>;
    /** Method to delete the local vulnerabilities database (if available) **/
    deleteDatabase?: () => Promise<void>;
  }
}
