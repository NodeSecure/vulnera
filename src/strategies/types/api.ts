// Import Internal Types
import type { Dependencies } from "./scanner.js";
import type { StandardVulnerability } from "../../formats/standard/index.js";
import type { Kind } from "../../constants.js";

export type BaseStrategyFormat = "Preserve" | "Standard" | "OSV";

export interface BaseStrategyOptions {
  /**
   * @default "Preserve"
   */
  useFormat?: BaseStrategyFormat;
}

export interface HydratePayloadDepsOptions extends BaseStrategyOptions {
  /**
   * Absolute path to the location to analyze
   * (with a package.json and/or package-lock.json for NPM Audit for example)
   **/
  path?: string;
}

export interface BaseStrategy<T extends Kind> {
  /** Name of the strategy **/
  strategy: T;
  /** Method to hydrate (insert/push) vulnerabilities in the dependencies retrieved by the Scanner **/
  hydratePayloadDependencies: (
    dependencies: Dependencies,
    options?: HydratePayloadDepsOptions
  ) => Promise<void>;
}

export interface ExtendedStrategy<
  T extends Kind, VulnFormat
> extends BaseStrategy<T> {
  /** Method to get vulnerabilities using the current strategy **/
  getVulnerabilities: (
    path: string,
    options?: BaseStrategyOptions
  ) => Promise<(VulnFormat | StandardVulnerability)[]>;
}
