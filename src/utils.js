// Import Node.js Dependencies
import { readFile } from "node:fs/promises";

export async function readJsonFile(path) {
  try {
    const buf = await readFile(path);

    return JSON.parse(buf.toString());
  }
  catch {
    return null;
  }
}

export function fromMaybeStringToArray(value) {
  if (Array.isArray(value)) {
    return value;
  }

  return value ? [value] : [];
}

export function standardizeNpmSeverity(severity) {
  if (severity === "moderate") {
    return "medium";
  }

  return severity;
}

export function* chunkArray(arr, chunkSize) {
  for (let i = 0; i < arr.length; i += chunkSize) {
    yield arr.slice(i, i + chunkSize);
  }
}
