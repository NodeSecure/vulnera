// Import Node.js Dependencies
import path from "path";
import { unlinkSync, promises as fs } from "fs";

// Import Third-party Dependencies
import { downloadAndExtract } from "@nodesecure/github";
import semver from "semver";

// Import Internal Dependencies
import { readJsonFile } from "../utils.js";
import { VULN_MODE, VULN_FILE_PATH, CACHE_DELAY } from "../constants.js";
import * as cache from "../cache.js";
import { standardizeVulnsPayload } from "./vuln-payload/standardize.js";

export async function SecurityWGStrategy(options = {}) {
  process.emitWarning("Node.js Security WG DB is deprecated and will be removed soon.", {
    code: "DEPRECATED",
    // eslint-disable-next-line max-len
    detail: "See https://nodejs.medium.com/node-js-ecosystem-vulnerability-reporting-program-winding-down-591d9a8cd2c7 for details."
  });

  const { hydrateDatabase: udpDb = false } = options;
  if (udpDb) {
    try {
      await checkHydrateDB();
    }
    catch { }
  }

  return {
    strategy: VULN_MODE.SECURITY_WG,
    hydratePayloadDependencies,
    hydrateDatabase,
    deleteDatabase,
    getVulnerabilities
  };
}

async function getVulnerabilities() {
  throw new Error("Not Yet Implemented");
}

async function checkHydrateDB() {
  const localCache = cache.load();
  const ts = Math.abs(Date.now() - localCache.lastUpdated);

  if (ts > CACHE_DELAY) {
    deleteDatabase();
    await hydrateDatabase();
    cache.refresh();
  }
}

async function hydratePayloadDependencies(dependencies, options = {}) {
  try {
    const vulnerabilities = await readJsonFile(VULN_FILE_PATH);
    if (vulnerabilities === null) {
      return;
    }

    const formatVulnerabilities = standardizeVulnsPayload(options.useStandardFormat);
    const uniqueDependenciesName = new Set([...dependencies.keys()]);
    const filtered = new Set(
      Object.keys(vulnerabilities).filter((name) => uniqueDependenciesName.has(name))
    );

    for (const name of filtered) {
      const dep = dependencies.get(name);
      const detectedVulnerabilities = [];
      for (const currVuln of vulnerabilities[name]) {
        const satisfied = dep.versions.some((version) => semver.satisfies(version, currVuln.vulnerable_versions));
        if (satisfied) {
          detectedVulnerabilities.push(currVuln);
        }
      }

      if (detectedVulnerabilities.length > 0) {
        dep.vulnerabilities = formatVulnerabilities(VULN_MODE.SECURITY_WG, detectedVulnerabilities);
      }
    }
  }
  catch { }
}

async function hydrateDatabase() {
  const { location } = await downloadAndExtract("nodejs.security-wg", { branch: "main" });
  const vulnPath = path.join(location, "vuln", "npm");

  try {
    const jsonFiles = (await fs.readdir(vulnPath))
      .filter((name) => path.extname(name) === ".json")
      .map((name) => path.join(vulnPath, name));

    const vulnerabilities = await Promise.all(
      jsonFiles.map((path) => readJsonFile(path))
    );

    const payload = new Map();
    for (const row of vulnerabilities) {
      const packageName = row.module_name;
      if (payload.has(packageName)) {
        payload.get(packageName).push(row);
      }
      else {
        payload.set(packageName, [row]);
      }
    }

    const data = JSON.stringify(Object.fromEntries(payload));
    await fs.writeFile(VULN_FILE_PATH, data);
  }
  finally {
    await fs.rm(location, { recursive: true, force: true });
  }
}

function deleteDatabase() {
  try {
    unlinkSync(VULN_FILE_PATH);
  }
  catch { }
}
