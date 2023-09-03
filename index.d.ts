import cache from "./types/cache.js";

import {
  setStrategy,
  getStrategy,
  strategies,
  defaultStrategyName,
} from "./types/api.js";

import GitHubAdvisoryStrategy from "./types/github-strategy.js";
import NodeStrategy from "./types/node-strategy.js";
import SnykStrategy from "./types/snyk-strategy.js";
import SonatypeStrategy from "./types/sonatype-strategy.js";
import Strategy from "./types/strategy.js";

export {
  // Api
  cache,
  setStrategy,
  getStrategy,
  strategies,
  defaultStrategyName,

  // Interfaces
  NodeStrategy,
  GitHubAdvisoryStrategy,
  SnykStrategy,
  SonatypeStrategy,
  Strategy,
};
