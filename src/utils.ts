// Import Internal Dependencies
import type { Severity } from "./formats/standard/index.ts";

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

export function parseNpmSpec(
  spec: string
) {
  const parts = spec.split("@");

  return spec.startsWith("@") ?
    { name: `@${parts[1]}`, version: parts[2] ?? void 0 } :
    { name: parts[0], version: parts[1] ?? void 0 };
}

export function* chunkArray<T = any>(
  arr: T[], chunkSize: number
): IterableIterator<T[]> {
  for (let i = 0; i < arr.length; i += chunkSize) {
    yield arr.slice(i, i + chunkSize);
  }
}
