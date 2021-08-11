import cache from "./types/cache";

import { setStrategy, getStrategy, strategies, defaultStrategyName } from "./types/api";

import NpmStrategy from "./types/npm-strategy";
import NodeStrategy from "./types/node-strategy";
import Strategy from "./types/strategy";

export {
  // Api
  cache,

  setStrategy,
  getStrategy,
  strategies,
  defaultStrategyName,

  // Interfaces
  NodeStrategy,
  NpmStrategy,
  Strategy
};
