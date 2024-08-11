// Import Internal Dependencies
import type { StandardVulnerability } from "../../formats/standard/index.js";

export interface Dependency {
  metadata: any;
  versions: Record<string, any>;
  vulnerabilities: StandardVulnerability[];
}

export type Dependencies = Map<string, Dependency>;
