// Import Node.js Dependencies
import os from "os";

export const NPM_TOKEN = typeof process.env.NODE_SECURE_TOKEN === "string" ? { token: process.env.NODE_SECURE_TOKEN } : {};

export const VULN_MODE = Object.freeze({
  SECURITY_WG: "node",
  NPM_AUDIT: "npm"
});

export const VULN_FILE_PATH = join(os.tmpdir(), "nsecure-vulnerabilities.json");
