

export interface NodeVulnerability {
  id: number;
  created_at: string;
  updated_at: string;
  title: string;
  author: {
      name: string;
      website: string | null;
      username: string | null;
  };
  module_name: string;
  publish_data: string;
  cves: string[];
  vulnerable_versions: string;
  patched_versions: string;
  overview: string;
  recommendation: string;
  references: string[];
  cvss_vector: string;
  cvss_score: number;
  coordinating_vendor: string;
}

// TODO: add NpmVulnerability interface

declare namespace Vuln {
  type Strategies = "npm" | "node";

  interface StrategyOptions {
    hydrateDatabase?: boolean;
  }

  interface Strategy {
    type: Strategies;
    hydratePayloadDependencies: (dependencies: any, defaultRegistryAddr?: string) => Promise<void>;
    hydrateDatabase?: () => Promise<void>;
    deleteDatabase?: () => Promise<void>;
  }

  export declare function setStrategy(name?: Strategies, options?: StrategyOptions): Promise<Strategy>;
  export declare function getStrategy(): Promise<Strategy>;
}

export = Vuln;
export as namespace Vuln;
