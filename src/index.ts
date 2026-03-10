// Import Internal Dependencies
import {
  GitHubAdvisoryStrategy,
  type GithubAdvisoryStrategyDefinition,
  type GithubVulnerability,
  type NpmAuditAdvisory,
  type PnpmAuditAdvisory
} from "./strategies/github-advisory.ts";

import {
  SnykStrategy,
  type SnykStrategyDefinition,
  type SnykStrategyOptions
} from "./strategies/snyk.ts";

import {
  SonatypeStrategy,
  type SonatypeStrategyDefinition,
  type SonatypeStrategyOptions,
  type SonatypeVulnerability
} from "./strategies/sonatype.ts";

import {
  NoneStrategy,
  type NoneStrategyDefinition
} from "./strategies/none.ts";

import {
  VULN_MODE,
  type Kind
} from "./constants.ts";

import { ApiCredential, type ApiCredentialOptions } from "./credential.ts";

import type {
  SnykVulnerability
} from "./formats/snyk/index.ts";
import type {
  StandardVulnerability, Severity, StandardPatch
} from "./formats/standard/index.ts";
import type {
  OSV
} from "./formats/osv/index.ts";

import type {
  Dependencies
} from "./strategies/types/scanner.ts";

import type {
  BaseStrategy,
  BaseStrategyOptions,
  BaseStrategyFormat,
  ExtendedStrategy,
  HydratePayloadDepsOptions
} from "./strategies/types/api.ts";

export * as Database from "./database/index.ts";
export { ApiCredential };
export type { ApiCredentialOptions };

export type AllStrategy = {
  none: NoneStrategyDefinition;
  "github-advisory": GithubAdvisoryStrategyDefinition;
  snyk: SnykStrategyDefinition;
  sonatype: SonatypeStrategyDefinition;
};
export type AnyStrategy = AllStrategy[keyof AllStrategy];

type StrategyOptions = {
  none: undefined;
  "github-advisory": undefined;
  snyk: SnykStrategyOptions;
  sonatype: SonatypeStrategyOptions;
};

// CONSTANTS
const kAvailableStrategy = new Set(Object.values(VULN_MODE));

// VARS
let localVulnerabilityStrategy: AnyStrategy;

export function setStrategy<T extends Kind>(
  name: T,
  options?: StrategyOptions[T]
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
    localVulnerabilityStrategy = Object.seal(SnykStrategy(options as SnykStrategyOptions));
  }
  else if (name === VULN_MODE.SONATYPE) {
    localVulnerabilityStrategy = Object.seal(SonatypeStrategy(options as SonatypeStrategyOptions));
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
  BaseStrategyFormat,
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
