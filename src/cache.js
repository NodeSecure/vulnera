// Import Node.js Dependencies
import { existsSync, readFileSync, writeFileSync } from "fs";

// Import Internal Dependencies
import { TMP_CACHE, CACHE_DELAY } from "./constants.js";

export function load(
  defaultPayload = Object.create(null),
  dateGenerator = () => Date.now()
) {
  if (existsSync(TMP_CACHE)) {
    return JSON.parse(readFileSync(TMP_CACHE, "utf-8"));
  }

  const payload = Object.assign({}, JSON.parse(JSON.stringify(defaultPayload)), {
    lastUpdated: dateGenerator() - CACHE_DELAY
  });
  writeFileSync(TMP_CACHE, JSON.stringify(payload));

  return payload;
}

export function refresh(lastUpdated = Date.now()) {
  const payload = JSON.stringify({ lastUpdated });

  writeFileSync(TMP_CACHE, payload);
}
