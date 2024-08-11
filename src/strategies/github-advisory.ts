// Import Node.js Dependencies
import fs from "node:fs/promises";
import path from "node:path";

// Import Third-party Dependencies
import Arborist from "@npmcli/arborist";
import { audit, AuditAdvisory } from "@pnpm/audit";
import { getLocalRegistryURL } from "@nodesecure/npm-registry-sdk";
import { readWantedLockfile } from "@pnpm/lockfile-file";

// Import Internal Dependencies
import { VULN_MODE, NPM_TOKEN } from "../constants.js";
import { StandardVulnerability } from "../formats/standard/index.js";
import { formatVulnsPayload } from "../formats/index.js";
import type { Dependencies } from "./types/scanner.js";
import type {
  BaseStrategyOptions,
  ExtendedStrategy,
  HydratePayloadDepsOptions
} from "./types/api.js";

export type NpmAuditAdvisory = {
  /** The unique cache key for this vuln or metavuln. **/
  source: number;
  /** Same as source (but seems deprecated now) **/
  id?: number;
  /** The name of the package that this vulnerability is about**/
  name: string;
  /** For metavulns, the dependency that causes this package to be have a vulnerability. For advisories, the same as name. **/
  dependency: string;
  /** The text title of the advisory or metavuln **/
  title: string;
  /** The url for the advisory (null for metavulns) **/
  url: string;
  /** Publicly-known vulnerabilities have identification numbers, known as Common Vulnerabilities and Exposures (CVEs) */
  cwe?: string[];
  /** The Common Vulnerability Scoring System (CVSS) is a method used to supply a qualitative measure of severity. CVSS is not a measure of risk. */
  cvss?: {
    score: number;
    vectorString: string;
  };
  /** The severity level **/
  severity: "info" | "low" | "moderate" | "high" | "critical";
  /** The range that is vulnerable **/
  range: string;
  /** The set of versions that are vulnerable **/
  vulnerableVersions?: string[];
}

export type PnpmAuditAdvisory = Exclude<AuditAdvisory, "cwe"> & {
  github_advisory_id: string;
  npm_advisory_id: null | number;
  cwe: string | string[];
  cvss: {
    score: number;
    vectorString: string;
  }
};
export type GithubVulnerability = PnpmAuditAdvisory | NpmAuditAdvisory;

export type GithubAdvisoryStrategyDefinition = ExtendedStrategy<"github-advisory", GithubVulnerability>

export function GitHubAdvisoryStrategy(): GithubAdvisoryStrategyDefinition {
  return {
    strategy: VULN_MODE.GITHUB_ADVISORY,
    hydratePayloadDependencies,
    getVulnerabilities
  };
}

async function getVulnerabilities(
  lockDirOrManifestPath: string,
  options: BaseStrategyOptions = {}
): Promise<(GithubVulnerability | StandardVulnerability)[]> {
  const { useFormat } = options;

  const formatVulnerabilities = formatVulnsPayload(useFormat);
  const registry = getLocalRegistryURL();

  const lockfileDir = path.extname(lockDirOrManifestPath) === "" ?
    lockDirOrManifestPath :
    path.dirname(lockDirOrManifestPath);

  const isPnpm = await hasPnpmLockFile(
    lockfileDir
  );

  const vulnerabilities = isPnpm ?
    await pnpmAudit(lockfileDir, registry) :
    await npmAudit(lockDirOrManifestPath, registry);

  if (useFormat) {
    return formatVulnerabilities(
      isPnpm ? "github-advisory_pnpm" : VULN_MODE.GITHUB_ADVISORY,
      vulnerabilities
    );
  }

  return vulnerabilities;
}

async function hydratePayloadDependencies(
  dependencies: Dependencies,
  options: HydratePayloadDepsOptions
): Promise<void> {
  const { path, useFormat } = options;
  if (!path) {
    throw new Error("path argument is required for <github-advisory> strategy");
  }

  const formatVulnerabilities = formatVulnsPayload(useFormat);
  const registry = getLocalRegistryURL();

  try {
    const isPnpm = await hasPnpmLockFile(path);

    const vulnerabilities = isPnpm ?
      await pnpmAudit(path, registry) :
      await npmAudit(path, registry);

    for (const packageVulns of vulnerabilities) {
      const packageName = (packageVulns as NpmAuditAdvisory).name || (packageVulns as PnpmAuditAdvisory).module_name;
      if (!dependencies.has(packageName)) {
        continue;
      }

      const dependenciesVulnerabilities = dependencies.get(packageName)!.vulnerabilities;
      dependenciesVulnerabilities.push(
        ...formatVulnerabilities(
          isPnpm ? "github-advisory_pnpm" : VULN_MODE.GITHUB_ADVISORY,
          [packageVulns]
        )
      );
    }
  }
  catch { }
}

async function npmAudit(
  path: string,
  registry: string
): Promise<NpmAuditAdvisory[]> {
  const arborist = new Arborist({ ...NPM_TOKEN, registry, path });
  const { vulnerabilities } = (await arborist.audit()).toJSON() as { vulnerabilities: any[] };

  // TODO: remove Symbols?
  return Object.values(vulnerabilities)
    .flatMap((vuln) => (Array.isArray(vuln.via) && typeof vuln.via[0] === "object" ? vuln.via : []));
}

async function pnpmAudit(
  lockfileDir: string,
  registry: string
): Promise<PnpmAuditAdvisory[]> {
  const auditOptions = {
    include: { dependencies: true, devDependencies: true, optionalDependencies: false },
    lockfileDir,
    registry,
    virtualStoreDirMaxLength: 120
  };

  const lockfile = await readWantedLockfile(lockfileDir, {
    ignoreIncompatible: false
  });

  // eslint-disable-next-line
  const getAuthHeader = () => (void 0);
  const { advisories } = await audit(
    lockfile!,
    getAuthHeader,
    auditOptions
  );

  // Note: we need to cast because original interface is incomplete
  return Object.values(advisories) as PnpmAuditAdvisory[];
}

async function hasPnpmLockFile(lockfileDir: string): Promise<boolean> {
  try {
    await fs.access(
      path.join(lockfileDir, "pnpm-lock.yaml"),
      fs.constants.F_OK
    );

    return true;
  }
  catch {
    return false;
  }
}
