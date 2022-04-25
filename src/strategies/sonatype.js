// Import Third-Party Dependencies
import * as httpie from "@myunisoft/httpie";

// Import Internal Dependencies
import { VULN_MODE } from "../constants.js";
import { standardizeVulnsPayload } from "./vuln-payload/standardize.js";

// Constants
const kSonatypeApiURL = "https://ossindex.sonatype.org/api/v3/component-report";

export function SonatypeStrategy() {
  return {
    strategy: VULN_MODE.SONATYPE,
    hydratePayloadDependencies
  };
}

/**
 * @returns {PackageURL} package url, following the Package URL spec semantic
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

  return Object.keys(versions).map((version) => toPackageURL(dependencyName, version));
}

async function fetchDataForPackageURLs(coordinates) {
  const requestOptions = {
    headers: {
      Accept: "application/json"
    },
    body: { coordinates }
  };

  try {
    const { data } = await httpie.post(kSonatypeApiURL, requestOptions);

    return data;
  }
  catch {
    return [];
  }
}

/**
 * @param {string} purl - A string representing the specific Package URL
 * semantic.
 * When targetting npm repositories, the specification is the following:
 * pkg:npm/<package-name>@<package-version> such as: pkg:npm/foobar@12.3.1
 * For further reading see: https://github.com/package-url/purl-spec
 */
function extractNameFromPackageURL(purl) {
  const [, packageData] = purl.split("npm/");
  const [packageName] = packageData.split("@");

  return packageName;
}

/**
 * Package's name is not part of the vulnerability description returned back
 * by Sonatype. Given that the package name is required in the NodeSecure
 * vulnerability standard format, we must be sure to provide it back after
 * reaching the API.
 */
function vulnWithPackageName(packageName) {
  return function provideNameToVulnPayload(vuln) {
    return { ...vuln, package: packageName };
  };
}

async function hydratePayloadDependencies(dependencies, options = {}) {
  const formatVulnerabilities = standardizeVulnsPayload(options.useStandardFormat);
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
