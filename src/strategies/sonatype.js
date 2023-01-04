// Import Third-Party Dependencies
import * as httpie from "@myunisoft/httpie";

// Import Internal Dependencies
import { VULN_MODE } from "../constants.js";
import { standardizeVulnsPayload } from "./vuln-payload/standardize.js";

// CONSTANTS
const kSonatypeApiURL = "https://ossindex.sonatype.org/api/v3/component-report";

export function SonatypeStrategy() {
  return {
    strategy: VULN_MODE.SONATYPE,
    hydratePayloadDependencies,
    getVulnerabilities
  };
}

async function getVulnerabilities() {
  throw new Error("Not Yet Implemented");
}

/**
 * If the package name contains a scope, it must be percent encoded to be spec
 * compliant.
 * Otherwise, the Package URL is simply <package-name>@<package-version>.
 * See: https://github.com/package-url/purl-spec
 * @returns {PackageURL} standard Package URL string.
 */
function toPackageURL(fullPackageName, packageVersion) {
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
function createPackageURLCoordinates([dependencyName, dependencyPayload]) {
  const { versions } = dependencyPayload;

  return Object.keys(versions).map((version) => toPackageURL(dependencyName, version));
}

async function fetchDataForPackageURLs(coordinates) {
  if(coordinates.length > 128) {
  const perChunk = 128 

  coordinates = coordinates.reduce((finalArray, item, index) => { 
    const chunkIndex = Math.floor(index/perChunk)
  
    if(!finalArray[chunkIndex]) {
      resultArray[chunkIndex] = [] 
    }
  
    finalArray[chunkIndex].push(item)
  
    return finalArray
  }, [])
}

  const requestOptions = {
    headers: {
      accept: "application/json"
    },
    body: { coordinates }
  };

  try {
    if(requestOptions.body.length === 1) {
      const { data } = await httpie.post(kSonatypeApiURL, requestOptions);

      return data;
    }

    const { dataArray } = await coordinatesArray.map(elem => httpie.post(kSonatypeApiURL, {
      headers: {
        accept: "application/json"
      },
      body: elem
    }));

    return dataArray
  }
  catch {
    return [];
  }
}

/**
 * @param {PackageURL} - string representing the Package URL spec.
 * When targetting npm repositories, the specification is the following:
 * pkg:npm/<package-name>@<package-version> such as: pkg:npm/foobar@12.3.1
 * For further reading see: https://github.com/package-url/purl-spec
 */
function extractNameFromPackageURL(purl) {
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
function vulnWithPackageName(packageName) {
  return function provideNameToVulnPayload(vuln) {
    return { ...vuln, package: packageName };
  };
}

async function hydratePayloadDependencies(dependencies, options = {}) {
  const formatVulnerabilities = standardizeVulnsPayload(
    options.useStandardFormat
  );
  const packageURLsFromDependencies = Array.from(dependencies).flatMap(
    createPackageURLCoordinates
  );

  const packageURLsData = await fetchDataForPackageURLs(
    packageURLsFromDependencies
  );

  for (const {
    coordinates,
    vulnerabilities: sonatypeVulns
  } of packageURLsData) {
    const packageName = extractNameFromPackageURL(coordinates);
    const formattedVulnerabilities = formatVulnerabilities(
      VULN_MODE.SONATYPE,
      sonatypeVulns.map(vulnWithPackageName(packageName))
    );

    const { vulnerabilities } = dependencies.get(packageName);
    vulnerabilities.push(...formattedVulnerabilities);
  }
}
