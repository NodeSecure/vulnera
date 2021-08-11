import Strategy from "./strategy";

export = {
  setStrategy,
  getStrategy,
  strategies,
  defaultStrategyName
}

declare function setStrategy(name?: Strategy.Kind, options?: Strategy.Options): Promise<Strategy.Definition>;
declare function getStrategy(): Promise<Strategy.Definition>;
declare const strategies: {
  SECURITY_WG: "node";
  NPM_AUDIT: "npm";
};
declare const defaultStrategyName: string;

