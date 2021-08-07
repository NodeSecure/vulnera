// Import Node.js Dependencies
import { readFile } from "fs/promises";

export async function readJsonFile(path) {
  try {
    const buf = await readFile(path);

    return JSON.parse(buf.toString());
  }
  catch {
    return null;
  }
}
