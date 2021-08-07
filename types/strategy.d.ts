export = Strategy;

declare namespace Strategy {
  export type Mode = "npm" | "node";

  export interface Options {
    hydrateDatabase?: boolean;
  }

  export interface Definition {
    type: Mode;
    hydratePayloadDependencies: (dependencies: any, defaultRegistryAddr?: string) => Promise<void>;
    hydrateDatabase?: () => Promise<void>;
    deleteDatabase?: () => Promise<void>;
  }
}
