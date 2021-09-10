// Import Node.js Dependencies
import path from "path";
import { unlinkSync, promises as fs } from "fs";

// Import Third-party Dependencies
import download from "@slimio/github";
import semver from "semver";

// Import Internal Dependencies
import { readJsonFile } from "../utils.js";
import { VULN_MODE, VULN_FILE_PATH, CACHE_DELAY } from "../constants.js";
import * as cache from "../cache.js";
import { standardizeVulnsPayload } from "./vuln-payload/standardize.js";

export async function SecurityWGStrategy(options) {
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
    deleteDatabase
  };
}

export async function checkHydrateDB() {
  const localCache = cache.load();
  const ts = Math.abs(Date.now() - localCache.lastUpdated);

  if (ts > CACHE_DELAY) {
    deleteDatabase();
    await hydrateDatabase();
    cache.refresh();
  }
}

export async function hydratePayloadDependencies(dependencies, options = {}) {
  try {
    const vulnerabilities = await readJsonFile(VULN_FILE_PATH);
    if (vulnerabilities === null) {
      return;
    }

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
        dep.vulnerabilities = options.useStandardFormat
          ? standardizeVulnsPayload(VULN_MODE.SECURITY_WG, detectedVulnerabilities)
          : detectedVulnerabilities;
      }
    }
  }
  catch { }
}

export async function hydrateDatabase() {
  const location = await download("nodejs.security-wg", { extract: true, branch: "main" });
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

export function deleteDatabase() {
  try {
    unlinkSync(VULN_FILE_PATH);
  }
  catch { }
}
