// Import Node.js Dependencies
import timers from "node:timers/promises";

// Import Third-party Dependencies
import * as httpie from "@openally/httpie";

// Import Internal Dependencies
import * as utils from "../utils.ts";
import type { NVD as NVDFormat } from "../formats/nvd/index.ts";
import type { ApiCredential } from "../credential.ts";

/**
 * @description Parameters for querying the NVD API
 *
 * Note: While NVD API supports CPE-based matching (cpeName, virtualMatchString, etc.),
 * we don't use those parameters for npm packages due to compatibility issues with
 * the CPE format. Instead, we rely on keywordSearch which provides
 * more reliable results for npm packages.
 *
 * See docs/database/nvd.md for more details on this implementation choice.
 *
 * @see https://nvd.nist.gov/developers/vulnerabilities
 */
export type NVDApiParameter = {
  /**
   * Searches CVE descriptions by keyword or phrase.
   * Spaces should be encoded as %20; wildcard matching is implicit.
   */
  keywordSearch?: string;
  /**
   * When true, enforces exact phrase matching for multi-term searches.
   * Requires keywordSearch.
   */
  keywordExactMatch?: boolean;
  /**
   * Convenience parameter that maps to keywordSearch using the package name.
   * Used internally by findOneBySpec.
   * @default npm
   */
  packageName?: string;
  /**
   * @default npm
   */
  ecosystem?: string;
  /**
   * Returns a specific CVE by its CVE identifier (e.g. "CVE-2021-44228").
   */
  cveId?: string;
  /**
   * Filters CVE by tag type.
   */
  cveTag?: "disputed" | "unsupported-when-assigned" | "exclusively-hosted-service";
  /**
   * Filters by CWE identifier (e.g. "CWE-79") or placeholders
   * "NVD-CWE-Other" / "NVD-CWE-noinfo".
   */
  cweId?: string;
  /**
   * Filters by CVSSv2 severity level.
   * Cannot be combined with cvssV3Severity or cvssV4Severity.
   */
  cvssV2Severity?: "LOW" | "MEDIUM" | "HIGH";
  /**
   * Filters by CVSSv3 severity level.
   * Cannot be combined with cvssV2Severity or cvssV4Severity.
   */
  cvssV3Severity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  /**
   * Filters by CVSSv4 severity level.
   * Cannot be combined with cvssV2Severity or cvssV3Severity.
   */
  cvssV4Severity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  /**
   * Filters by CVSSv2 vector string (full or partial).
   * Cannot be combined with cvssV3Metrics or cvssV4Metrics.
   */
  cvssV2Metrics?: string;
  /**
   * Filters by CVSSv3 vector string (full or partial).
   * Cannot be combined with cvssV2Metrics or cvssV4Metrics.
   */
  cvssV3Metrics?: string;
  /**
   * Filters by CVSSv4 vector string (full or partial).
   * Cannot be combined with cvssV2Metrics or cvssV3Metrics.
   */
  cvssV4Metrics?: string;
  /**
   * When true, excludes CVE with REJECT or Rejected status.
   */
  noRejected?: boolean;
  /**
   * When true, returns only CVE appearing in the CISA Known Exploited
   * Vulnerabilities (KEV) catalog.
   */
  hasKev?: boolean;
  /**
   * When true, returns only CVE with US-CERT Technical Alerts.
   */
  hasCertAlerts?: boolean;
  /**
   * When true, returns only CVE with CERT/CC Vulnerability Notes.
   */
  hasCertNotes?: boolean;
  /**
   * When true, returns only CVE containing MITRE OVAL information.
   */
  hasOval?: boolean;
  /**
   * Start date for the publication date filter (ISO-8601, e.g. "2021-01-01T00:00:00.000Z").
   * Must be paired with pubEndDate. Maximum range is 120 days.
   */
  pubStartDate?: string;
  /**
   * End date for the publication date filter (ISO-8601).
   * Must be paired with pubStartDate. Maximum range is 120 days.
   */
  pubEndDate?: string;
  /**
   * Start date for the last-modified filter (ISO-8601).
   * Must be paired with lastModEndDate. Maximum range is 120 days.
   */
  lastModStartDate?: string;
  /**
   * End date for the last-modified filter (ISO-8601).
   * Must be paired with lastModStartDate. Maximum range is 120 days.
   */
  lastModEndDate?: string;
  /**
   * Filters by the exact data source identifier.
   */
  sourceIdentifier?: string;
  /**
   * Maximum number of CVE records returned per response.
   * @default 2000
   * @maximum 2000
   */
  resultsPerPage?: number;
  /**
   * Zero-based index of the first CVE record to return (for pagination).
   * @default 0
   */
  startIndex?: number;
};

export interface NVDOptions {
  credential: ApiCredential;
  /**
   * Delay in milliseconds between consecutive requests in findMany.
   *
   * The NVD API enforces rate limits:
   * - Without API key: 5 requests per 30-second window (~6 000 ms between requests)
   * - With API key:   50 requests per 30-second window (~600 ms between requests)
   *
   * @default 6000
   * @see https://nvd.nist.gov/developers/start-here
   */
  requestDelay?: number;
}

export class NVD {
  static readonly ROOT_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";

  readonly #credential: ApiCredential;
  readonly #requestDelay: number;

  constructor(
    options: NVDOptions
  ) {
    this.#credential = options.credential;
    this.#requestDelay = options.requestDelay ?? 6_000;
  }

  async find(
    parameters: NVDApiParameter
  ): Promise<NVDFormat[]> {
    const queryParams = new URLSearchParams();

    if (parameters.packageName) {
      queryParams.append("keywordSearch", parameters.packageName);
      /**
      * NVD doesn't support cpeMatchString for npm packages.
      * We only search by keyword.
      */
    }
    else if (parameters.keywordSearch) {
      queryParams.append("keywordSearch", parameters.keywordSearch);
    }

    if (parameters.keywordExactMatch) {
      queryParams.append("keywordExactMatch", "");
    }
    if (parameters.cveId) {
      queryParams.append("cveId", parameters.cveId);
    }
    if (parameters.cveTag) {
      queryParams.append("cveTag", parameters.cveTag);
    }
    if (parameters.cweId) {
      queryParams.append("cweId", parameters.cweId);
    }
    if (parameters.cvssV2Severity) {
      queryParams.append("cvssV2Severity", parameters.cvssV2Severity);
    }
    if (parameters.cvssV3Severity) {
      queryParams.append("cvssV3Severity", parameters.cvssV3Severity);
    }
    if (parameters.cvssV4Severity) {
      queryParams.append("cvssV4Severity", parameters.cvssV4Severity);
    }
    if (parameters.cvssV2Metrics) {
      queryParams.append("cvssV2Metrics", parameters.cvssV2Metrics);
    }
    if (parameters.cvssV3Metrics) {
      queryParams.append("cvssV3Metrics", parameters.cvssV3Metrics);
    }
    if (parameters.cvssV4Metrics) {
      queryParams.append("cvssV4Metrics", parameters.cvssV4Metrics);
    }
    if (parameters.noRejected) {
      queryParams.append("noRejected", "");
    }
    if (parameters.hasKev) {
      queryParams.append("hasKev", "");
    }
    if (parameters.hasCertAlerts) {
      queryParams.append("hasCertAlerts", "");
    }
    if (parameters.hasCertNotes) {
      queryParams.append("hasCertNotes", "");
    }
    if (parameters.hasOval) {
      queryParams.append("hasOval", "");
    }
    if (parameters.pubStartDate) {
      queryParams.append("pubStartDate", parameters.pubStartDate);
    }
    if (parameters.pubEndDate) {
      queryParams.append("pubEndDate", parameters.pubEndDate);
    }
    if (parameters.lastModStartDate) {
      queryParams.append("lastModStartDate", parameters.lastModStartDate);
    }
    if (parameters.lastModEndDate) {
      queryParams.append("lastModEndDate", parameters.lastModEndDate);
    }
    if (parameters.sourceIdentifier) {
      queryParams.append("sourceIdentifier", parameters.sourceIdentifier);
    }
    if (parameters.resultsPerPage !== undefined) {
      queryParams.append("resultsPerPage", String(parameters.resultsPerPage));
    }
    if (parameters.startIndex !== undefined) {
      queryParams.append("startIndex", String(parameters.startIndex));
    }

    for (const [name, value] of Object.entries(this.#credential.queryParams)) {
      queryParams.append(name, value);
    }

    const url = new URL(NVD.ROOT_API);
    url.search = queryParams.toString();

    const { data } = await httpie.get<{ vulnerabilities: NVDFormat[]; }>(
      url.toString()
    );

    return data.vulnerabilities || [];
  }

  findByCveId(
    cveId: string
  ): Promise<NVDFormat[]> {
    return this.find({ cveId });
  }

  findBySpec(
    spec: string
  ): Promise<NVDFormat[]> {
    const { name } = utils.parseNpmSpec(spec);

    return this.find({
      packageName: name,
      ecosystem: "npm"
    });
  }

  async findMany<T extends string = string>(
    specs: T[]
  ): Promise<Record<T, NVDFormat[]>> {
    const result = {} as Record<T, NVDFormat[]>;

    for (let i = 0; i < specs.length; i++) {
      result[specs[i]] = await this.findBySpec(specs[i]);

      if (i < specs.length - 1) {
        await timers.setTimeout(this.#requestDelay);
      }
    }

    return result;
  }
}
