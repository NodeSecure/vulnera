import Strategy from "./strategy.js";

export { setStrategy, getStrategy, strategies, defaultStrategyName };

declare function setStrategy<T>(
  name?: Strategy.Kind,
  options?: Strategy.Options
): Promise<Strategy.Definition<T>>;
declare function getStrategy<T>(): Promise<Strategy.Definition<T>>;
declare const strategies: {
  SECURITY_WG: "node";
  NPM_AUDIT: "npm";
  SNYK: "snyk";
  SONATYPE: "sonatype";
  NONE: "none";
};
declare const defaultStrategyName: string;
