import Strategy from "./strategy";

export = {
  setStrategy,
  getStrategy,
  mode
}

declare function setStrategy(name?: Strategy.Mode, options?: Strategy.Options): Promise<Strategy.Definition>;
declare function getStrategy(): Promise<Strategy.Definition>;
declare const mode: {
  SECURITY_WG: "node";
  NPM_AUDIT: "npm";
};
