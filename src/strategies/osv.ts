/* eslint-disable no-empty */
// Import Internal Dependencies
import { VULN_MODE } from "../constants.ts";
import type { OSV as OSVFormat } from "../formats/osv/index.ts";
import type { StandardVulnerability } from "../formats/standard/index.ts";
import { formatVulnsPayload } from "../formats/index.ts";
import type { Dependencies } from "./types/scanner.ts";
import type {
  BaseStrategyOptions,
  ExtendedStrategy,
  HydratePayloadDepsOptions
} from "./types/api.ts";
import { OSV } from "../database/index.ts";
import type { OSVQueryBatchEntry } from "../database/osv.ts";
import {
  NodeDependencyExtractor,
  type PackageSpec
} from "../extractor/index.ts";
import * as utils from "../utils.ts";

// CONSTANTS
const kBatchSize = 1000;

export type OSVStrategyDefinition = ExtendedStrategy<"osv", OSVFormat>;

/**
 * Creates an OSV vulnerability scanning strategy that queries the OSV database
 * directly using the /v1/querybatch endpoint for efficient batch lookups.
 * No credentials are required for the OSV public API.
 */
export function OSVStrategy(): OSVStrategyDefinition {
  const db = new OSV();

  return {
    strategy: VULN_MODE.OSV,
    hydratePayloadDependencies: hydratePayloadDependencies.bind(null, db),
    getVulnerabilities: getVulnerabilities.bind(null, db)
  };
}

type OSVAnnotatedFormat = OSVFormat & { package: string; };

function toQuery(
  { name, version }: PackageSpec
): OSVQueryBatchEntry {
  return {
    version,
    package: { name, ecosystem: "npm" }
  };
}

async function queryAndAnnotate(
  db: OSV,
  pairs: PackageSpec[]
): Promise<OSVAnnotatedFormat[]> {
  const queries = pairs.map(toQuery);
  const allResults: Awaited<ReturnType<OSV["queryBatch"]>> = [];

  for (const chunk of utils.chunkArray(queries, kBatchSize)) {
    const results = await db.queryBatch(chunk);
    allResults.push(...results);
  }

  const annotatedVulns: OSVAnnotatedFormat[] = [];
  for (let i = 0; i < allResults.length; i++) {
    const result = allResults[i];
    if (!result.vulns) {
      continue;
    }
    const { name } = pairs[i];
    for (const vuln of result.vulns) {
      annotatedVulns.push({ ...vuln, package: name });
    }
  }

  return annotatedVulns;
}

async function getVulnerabilities(
  db: OSV,
  path: string,
  options: BaseStrategyOptions = {}
): Promise<(OSVFormat | StandardVulnerability)[]> {
  const { useFormat } = options;

  const extractor = new NodeDependencyExtractor();
  const packages = await extractor.extract(path);
  const annotatedVulns = await queryAndAnnotate(db, packages);

  return formatVulnsPayload(
    useFormat
  )(VULN_MODE.OSV, annotatedVulns);
}

async function hydratePayloadDependencies(
  db: OSV,
  dependencies: Dependencies,
  options: HydratePayloadDepsOptions = {}
): Promise<void> {
  const { useFormat } = options;

  const pairs: PackageSpec[] = [];
  for (const [name, dep] of dependencies) {
    for (const version of Object.keys(dep.versions)) {
      pairs.push({ name, version });
    }
  }

  try {
    const annotatedVulns = await queryAndAnnotate(db, pairs);
    const formatVulnerabilities = formatVulnsPayload(useFormat);

    for (const annotated of annotatedVulns) {
      const dep = dependencies.get(annotated.package);
      if (dep) {
        const formatted = formatVulnerabilities(VULN_MODE.OSV, [annotated]);
        dep.vulnerabilities.push(...formatted);
      }
    }
  }
  catch { }
}
