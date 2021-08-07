// Import Node.js Dependencies
import os from "os";
import path from "path";
import { readFile } from "fs/promises";
import { existsSync, readFileSync, writeFileSync } from "fs";

export function loadNsecureCache(defaultPayload = Object.create(null)) {
  const filePath = path.join(os.tmpdir(), "nsecure-cache.json");

  if (existsSync(filePath)) {
    const buf = readFileSync(filePath);

    return JSON.parse(buf.toString());
  }

  const payload = Object.assign({}, JSON.parse(JSON.stringify(defaultPayload)), {
    lastUpdated: Date.now() - (3600000 * 48)
  });
  writeFileSync(filePath, JSON.stringify(payload));

  return payload;
}

export function writeNsecureCache() {
  const filePath = path.join(os.tmpdir(), "nsecure-cache.json");

  const payload = {
    lastUpdated: Date.now()
  };
  writeFileSync(filePath, JSON.stringify(payload));
}

export async function readJsonFile(path) {
  try {
    const buf = await readFile(path);

    return JSON.parse(buf.toString());
  }
  catch (err) {
    return null;
  }
}
