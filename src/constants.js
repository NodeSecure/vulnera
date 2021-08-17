// Import Node.js Dependencies
import path from "path";
import os from "os";

export const NPM_TOKEN = typeof process.env.NODE_SECURE_TOKEN === "string" ? { token: process.env.NODE_SECURE_TOKEN } : {};
export const SNYK_ORG = process.env.SNYK_ORG || "8327bf87-23c7-46c0-84c6-e46d38685d68";
export const SNYK_TOKEN = process.env.SNYK_TOKEN || "2a8a9a2f-a867-4849-9fc8-882050f7b764";

export const VULN_MODE = Object.freeze({
  SECURITY_WG: "node",
  NPM_AUDIT: "npm",
  SNYK: "snyk",
  NONE: "none"
});
export const DEFAULT_VULN_MODE = VULN_MODE.NONE;

export const VULN_FILE_PATH = path.join(os.tmpdir(), "nsecure-vulnerabilities.json");
export const TMP_CACHE = path.join(os.tmpdir(), "nsecure-cache.json");

// Note: ONE DAY
export const CACHE_DELAY = 3600000 * 24;
