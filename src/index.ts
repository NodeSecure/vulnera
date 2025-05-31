// Import Internal Dependencies
import {
  GitHubAdvisoryStrategy,
  type GithubAdvisoryStrategyDefinition,
  type GithubVulnerability,
  type NpmAuditAdvisory,
  type PnpmAuditAdvisory
} from "./strategies/github-advisory.js";

import {
  SnykStrategy,
  type SnykStrategyDefinition
} from "./strategies/snyk.js";

import {
  SonatypeStrategy,
  type SonatypeStrategyDefinition,
  type SonatypeVulnerability
} from "./strategies/sonatype.js";

import {
  NoneStrategy,
  type NoneStrategyDefinition
} from "./strategies/none.js";

import {
  VULN_MODE,
  type Kind
} from "./constants.js";

import type {
  SnykVulnerability
} from "./formats/snyk/index.js";
import type {
  StandardVulnerability, Severity, StandardPatch
} from "./formats/standard/index.js";
import type {
  OSV
} from "./formats/osv/index.js";

import type {
  Dependencies
} from "./strategies/types/scanner.js";

import type {
  BaseStrategy,
  ExtendedStrategy,
  BaseStrategyOptions,
  HydratePayloadDepsOptions
} from "./strategies/types/api.js";

export * as Database from "./database/index.js";

export type AllStrategy = {
  none: NoneStrategyDefinition;
  "github-advisory": GithubAdvisoryStrategyDefinition;
  snyk: SnykStrategyDefinition;
  sonatype: SonatypeStrategyDefinition;
};
export type AnyStrategy = AllStrategy[keyof AllStrategy];

// CONSTANTS
const kAvailableStrategy = new Set(Object.values(VULN_MODE));

// VARS
let localVulnerabilityStrategy: AnyStrategy;

export function setStrategy<T extends Kind>(
  name: T
): AllStrategy[T] {
  if (!kAvailableStrategy.has(name)) {
    throw new Error(
      `Unknown strategy with name '${name}'. Available strategies are: ${[...kAvailableStrategy].join(", ")}`
    );
  }

  if (name === VULN_MODE.GITHUB_ADVISORY) {
    localVulnerabilityStrategy = Object.seal(GitHubAdvisoryStrategy());
  }
  else if (name === VULN_MODE.SNYK) {
    localVulnerabilityStrategy = Object.seal(SnykStrategy());
  }
  else if (name === VULN_MODE.SONATYPE) {
    localVulnerabilityStrategy = Object.seal(SonatypeStrategy());
  }
  else {
    localVulnerabilityStrategy = Object.seal(NoneStrategy());
  }

  return localVulnerabilityStrategy as AllStrategy[T];
}

export function getStrategy(): AnyStrategy {
  if (!localVulnerabilityStrategy) {
    return setStrategy(VULN_MODE.NONE);
  }

  return localVulnerabilityStrategy;
}

export const strategies = VULN_MODE;
export const defaultStrategyName = VULN_MODE.NONE;

export type {
  Kind,
  BaseStrategyOptions,
  BaseStrategy,
  ExtendedStrategy,
  HydratePayloadDepsOptions,
  Dependencies,

  StandardVulnerability,
  StandardPatch,
  Severity,

  GithubVulnerability,
  NpmAuditAdvisory,
  PnpmAuditAdvisory,
  SnykVulnerability,
  SonatypeVulnerability,

  OSV
};
