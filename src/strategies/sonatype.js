// Import Third-Party Dependencies
import * as httpie from "@myunisoft/httpie";

// Import Internal Dependencies
import { VULN_MODE } from "../constants.js";
import { formatVulnerabilities } from "./vuln-payload/standardize.js";

// Constants
const kSonatypeApiURL = "https://ossindex.sonatype.org/api/v3/component-report";

export function SonatypeStrategy() {
  return {
    strategy: VULN_MODE.SONATYPE,
    hydratePayloadDependencies
  };
}

/**
 * @returns {PackageURL}, following the Package URL spec semantic
 * see: https://github.com/package-url/purl-spec
 */
function toPackageURL(packageName, packageVersion) {
  return `pkg:npm/${packageName}@${packageVersion}`;
}

/**
 * Coordinates are Sonatype's component identifiers, we must build them
 * using package's name and different package's versions
 */
function createPackageURLCoordinates([dependencyName, dependencyPayload]) {
  const { versions } = dependencyPayload;

  return versions.map((version) => toPackageURL(dependencyName, version));
}

const kSonatypeApiUrl = "https://ossindex.sonatype.org/api/v3/component-report";

async function fetchDataForPackageURLs(coordinates) {
  const requestOptions = {
    headers: {
      "Content-Type": "application/json; charset=utf-8"
    },
    body: JSON.stringify({ coordinates })
  };

  try {
    const { data } = await httpie.post(kSonatypeApiURL, requestOptions);

    return JSON.parse(data);
  }
  catch {
    return [];
  }
}

/**
 * @param {PackageURL} purl, following the Package URL spec semantic
 * see: https://github.com/package-url/purl-spec
 */
function extractNameFromPackageURL(purl) {
  const [, packageData] = purl.split("npm/");
  const [packageName] = packageData.split("@");

  return packageName;
}

/**
 * Package's name is not part of the vulnerability description returned back
 * by Sonatype. Given that the package name is required in the NodeSecure
 * vulnerability standard format,
 */
function vulnWithPackageName(packageName) {
  return function provideNameToVulnPayload(vuln) {
    return { ...vuln, package: packageName };
  };
}

async function hydratePayloadDependencies(dependencies, options = {}) {
  const packageURLsFromDependencies = Array.from(dependencies)
    .flatMap(createPackageURLCoordinates);

  const packageURLsData = await fetchDataForPackageURLs(packageURLsFromDependencies);

  for (const { coordinates, vulnerabilities: sonatypeVulns } of packageURLsData) {
    const packageName = extractNameFromPackageURL(coordinates);
    const formattedVulnerabilities = formatVulnerabilities(
      VULN_MODE.SONATYPE,
      sonatypeVulns.map(vulnWithPackageName(packageName))
    );

    const { vulnerabilities } = dependencies.get(packageName);
    vulnerabilities.push(...formattedVulnerabilities);
  }
}
