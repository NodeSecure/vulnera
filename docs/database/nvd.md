# NVD

NVD stands for <kbd>National Vulnerability Database</kbd>, which is the U.S. government repository of standards-based vulnerability management data. This database is maintained by NIST (National Institute of Standards and Technology).

## Implementation Notes

The NVD integration uses the REST API (v2.0) available at [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0).

### Search Parameters

While the NVD API supports CPE matching via parameters like `cpeName` and `virtualMatchString`, we've chosen not to use them for NPM packages. This decision was made because:

1. The CPE format for npm packages is not standardized in NVD
2. Attempted CPE patterns (like `cpe:2.3:a:*:package-name:*:*:*:*:*:node.js:*:*`) resulted in 404 errors
3. Keyword search provides more flexible results for JavaScript/NPM packages

The implementation might be enhanced in the future if NVD provides clearer guidelines for CPE matching of npm packages.

### Parameter Constraints

Some parameters have mutual exclusivity constraints enforced by the NVD API:

- `cvssV2Severity`, `cvssV3Severity`, and `cvssV4Severity` cannot be combined with each other.
- `cvssV2Metrics`, `cvssV3Metrics`, and `cvssV4Metrics` cannot be combined with each other.
- `keywordExactMatch` requires `keywordSearch` to be set.
- `pubStartDate` and `pubEndDate` must be used together; the maximum range is 120 days.
- `lastModStartDate` and `lastModEndDate` must be used together; the maximum range is 120 days.

## Format

The NVD API returns detailed vulnerability information.

The NVD interface is exported as root like `StandardVulnerability`.

```ts
export interface NVD {
  cve: Cve;
}
```

## API

### Constructor

```ts
import * as vulnera from "@nodesecure/vulnera";

const db = new vulnera.Database.NVD({
  credential: new vulnera.ApiCredential({
    type: "querystring",
    name: "apiKey",
    value: "your-api-key"
  })
});
```

```ts
export interface NVDOptions {
  credential: ApiCredential;
  /**
   * Delay in milliseconds between consecutive requests in findMany.
   *
   * The NVD API enforces rate limits:
   * - Without API key: 5 requests per 30-second window → set ~6 000 ms
   * - With API key:   50 requests per 30-second window → set ~600 ms
   *
   * @default 6000
   */
  requestDelay?: number;
}
```

> **Rate limiting:** The NVD API enforces strict rate limits (see [NVD developer docs](https://nvd.nist.gov/developers/start-here)). `findMany` sends requests sequentially with a `requestDelay` pause between each one to avoid being throttled. The default of 6 000 ms is safe for unauthenticated use. If you supply an API key you can safely lower it to ~600 ms.

### `find(parameters: NVDApiParameter): Promise<NVD[]>`
Find vulnerabilities using any combination of available NVD API parameters.

```ts
export type NVDApiParameter = {
  // Keyword search
  keywordSearch?: string;
  keywordExactMatch?: boolean;

  // Convenience fields (used by findBySpec / findMany)
  packageName?: string;
  ecosystem?: string; // default: "npm"

  // CVE identification
  cveId?: string;
  cveTag?: "disputed" | "unsupported-when-assigned" | "exclusively-hosted-service";
  cweId?: string;
  sourceIdentifier?: string;

  // CVSS severity (mutually exclusive across versions)
  cvssV2Severity?: "LOW" | "MEDIUM" | "HIGH";
  cvssV3Severity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  cvssV4Severity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

  // CVSS vector strings (mutually exclusive across versions)
  cvssV2Metrics?: string;
  cvssV3Metrics?: string;
  cvssV4Metrics?: string;

  // Boolean flags
  noRejected?: boolean;
  hasKev?: boolean;
  hasCertAlerts?: boolean;
  hasCertNotes?: boolean;
  hasOval?: boolean;

  // Date ranges (ISO-8601, max 120-day window per pair)
  pubStartDate?: string;
  pubEndDate?: string;
  lastModStartDate?: string;
  lastModEndDate?: string;

  // Pagination
  resultsPerPage?: number; // default and max: 2000
  startIndex?: number;     // default: 0
};
```

**Examples:**

```ts
// Filter by CVSSv3 severity
const vulns = await db.find({ keywordSearch: "express", cvssV3Severity: "CRITICAL" });

// Return only CVEs in the CISA Known Exploited Vulnerabilities catalog
const kevVulns = await db.find({ keywordSearch: "log4j", hasKev: true });

// Paginate results
const page2 = await db.find({ keywordSearch: "lodash", resultsPerPage: 100, startIndex: 100 });

// Filter by publication date range
const recent = await db.find({
  pubStartDate: "2024-01-01T00:00:00.000Z",
  pubEndDate:   "2024-04-30T23:59:59.000Z"
});
```

### `findByCveId(cveId: string): Promise<NVD[]>`
Find a specific vulnerability by its CVE identifier.

```ts
const vuln = await db.findByCveId("CVE-2021-44228");
console.log(vuln);
```

### `findBySpec(spec: string): Promise<NVD[]>`
Find vulnerabilities of a given package using the NPM spec format `packageName@version`.

```ts
const vulns = await db.findBySpec("express@4.0.0");
console.log(vulns);
```

### `findMany<T extends string>(specs: T[]): Promise<Record<T, NVD[]>>`
Find vulnerabilities for many packages using the spec format.

Returns a Record where keys are equal to the provided specs.

```ts
const vulns = await db.findMany(["express@4.0.0", "lodash@4.17.0"]);
console.log(vulns);
```
