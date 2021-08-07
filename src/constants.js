// Import Node.js Dependencies
import path from "path";
import os from "os";

export const NPM_TOKEN = typeof process.env.NODE_SECURE_TOKEN === "string" ? { token: process.env.NODE_SECURE_TOKEN } : {};

export const VULN_MODE = Object.freeze({
  SECURITY_WG: "node",
  NPM_AUDIT: "npm"
});
export const DEFAULT_VULN_MODE = VULN_MODE.NPM_AUDIT;

export const VULN_FILE_PATH = path.join(os.tmpdir(), "nsecure-vulnerabilities.json");
export const TMP_CACHE = path.join(os.tmpdir(), "nsecure-cache.json");

// Note: ONE DAY
export const CACHE_DELAY = 3600000 * 24;
