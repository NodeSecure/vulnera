// Import Internal Dependencies
import { Severity } from "./formats/standard/index.js";

export function fromMaybeStringToArray(
  value: undefined | null | string | string[]
): string[] {
  if (Array.isArray(value)) {
    return value;
  }

  return value ? [value] : [];
}

export function standardizeNpmSeverity(
  severity: string
): Severity {
  if (severity === "moderate") {
    return "medium";
  }

  return severity as Severity;
}

export function* chunkArray<T = any>(
  arr: T[], chunkSize: number
): IterableIterator<T[]> {
  for (let i = 0; i < arr.length; i += chunkSize) {
    yield arr.slice(i, i + chunkSize);
  }
}
