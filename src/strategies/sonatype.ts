// Import Third-Party Dependencies
import * as httpie from "@myunisoft/httpie";

// Import Internal Dependencies
import * as utils from "../utils.js";
import { VULN_MODE } from "../constants.js";
import { standardizeVulnsPayload } from "../formats/standard/index.js";
import type { Dependencies, Dependency } from "./types/scanner.js";
import type {
  BaseStrategyOptions,
  BaseStrategy
} from "./types/api.js";

// CONSTANTS
const kSonatypeApiURL = "https://ossindex.sonatype.org/api/v3/component-report";
const kRatelimitChunkSize = 128;

export interface SonatypeVulnerability {
  id: string;
  displayName: string;
  title: string;
  description: string;
  cvssScore: number;
  cvssVector: string;
  cwe: string;
  cve?: string;
  reference: string;
  externalReferences: string[];
  versionRanges?: string[];
  package: string;
}

export type SonatypeStrategyDefinition = BaseStrategy<"sonatype">;

export function SonatypeStrategy(): SonatypeStrategyDefinition {
  return {
    strategy: VULN_MODE.SONATYPE,
    hydratePayloadDependencies
  };
}

/**
 * If the package name contains a scope, it must be percent encoded to be spec compliant.
 * Otherwise, the Package URL is simply <package-name>@<package-version>.
 * See: https://github.com/package-url/purl-spec
 */
function toPackageURL(
  fullPackageName: string,
  packageVersion: string
): string {
  const isPackageNameScoped = fullPackageName.includes("/");

  if (isPackageNameScoped) {
    const [scope, packageName] = fullPackageName.split("/");
    // Each scope segment must be a percent-encoded string
    const scopeEncoded = encodeURIComponent(scope);

    return `pkg:npm/${scopeEncoded}/${packageName}@${packageVersion}`;
  }

  return `pkg:npm/${fullPackageName}@${packageVersion}`;
}

/**
 * Coordinates are Sonatype's component identifiers, we must build them
 * using package's name and different package's versions
 */
function createPackageURLCoordinates(
  [dependencyName, dependencyPayload]: [string, Dependency]
) {
  const { versions } = dependencyPayload;

  return Object.keys(versions).map((version) => toPackageURL(dependencyName, version));
}

type SonatypeHttpResponse = { coordinates: string, vulnerabilities: SonatypeVulnerability[] };

async function fetchDataForPackageURLs(
  unchunkedCoordinates: string[]
): Promise<SonatypeHttpResponse[]> {
  const requestOptions = {
    headers: {
      accept: "application/json"
    }
  };

  try {
    const chunkedCoordinates = [
      ...utils.chunkArray(unchunkedCoordinates, kRatelimitChunkSize)
    ];

    const rawHttpPromises = chunkedCoordinates.map((coordinates) => httpie.post<SonatypeHttpResponse>(kSonatypeApiURL, {
      ...requestOptions,
      body: { coordinates }
    }));

    return (
      await Promise.all(rawHttpPromises)
    ).flatMap((requestResponse) => requestResponse.data);
  }
  catch {
    return [];
  }
}

/**
 * When targetting npm repositories, the specification is the following:
 * pkg:npm/<package-name>@<package-version> such as: pkg:npm/foobar@12.3.1
 * For further reading see: https://github.com/package-url/purl-spec
 */
function extractNameFromPackageURL(purl: string): string {
  const [, packageData] = purl.split("npm/");
  const [packageName] = packageData.split("@");

  return decodeURIComponent(packageName);
}

/**
 * Package's name is not part of the vulnerability description returned back
 * by Sonatype. Given that the package name is required in the NodeSecure
 * vulnerability standard format, we must be sure to provide it back after
 * reaching the API.
 */
function vulnWithPackageName(packageName: string) {
  return function provideNameToVulnPayload(vuln: SonatypeVulnerability) {
    return { ...vuln, package: packageName };
  };
}

async function hydratePayloadDependencies(
  dependencies: Dependencies,
  options: BaseStrategyOptions = {}
): Promise<void> {
  const packageURLsData = await fetchDataForPackageURLs(
    Array.from(dependencies).flatMap(createPackageURLCoordinates)
  );

  const formatVulnerabilities = standardizeVulnsPayload(
    options.useStandardFormat
  );
  for (const sonatypeResponse of packageURLsData) {
    const packageName = extractNameFromPackageURL(sonatypeResponse.coordinates);

    const formattedVulnerabilities = formatVulnerabilities(
      VULN_MODE.SONATYPE,
      sonatypeResponse.vulnerabilities.map(vulnWithPackageName(packageName))
    );

    const { vulnerabilities } = dependencies.get(packageName)!;
    vulnerabilities.push(...formattedVulnerabilities);
  }
}
