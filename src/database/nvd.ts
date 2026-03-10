// Import Third-party Dependencies
import * as httpie from "@openally/httpie";

// Import Internal Dependencies
import * as utils from "../utils.ts";
import type { NVD as NVDFormat } from "../formats/nvd/index.ts";
import type { ApiCredential } from "../credential.ts";

/**
 * @description Parameters for querying the NVD API
 *
 * Note: While NVD API supports cpeMatchString for CPE-based matching,
 * we don't use it for npm packages due to compatibility issues with
 * the CPE format. Instead, we rely on keywordSearch which provides
 * more reliable results for npm packages.
 *
 * See docs/database/nvd.md for more details on this implementation choice.
 */
export type NVDApiParameter = {
  keywordSearch?: string;
  cweId?: string;
  cvssV3Severity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  packageName?: string;
  /**
   * @default npm
   */
  ecosystem?: string;
};

export interface NVDOptions {
  credential: ApiCredential;
}

export class NVD {
  static readonly ROOT_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";

  readonly #credential: ApiCredential;

  constructor(
    options: NVDOptions
  ) {
    this.#credential = options.credential;
  }

  async findOne(
    parameters: NVDApiParameter
  ): Promise<NVDFormat[]> {
    const queryParams = new URLSearchParams();

    if (parameters.packageName) {
      queryParams.append("keywordSearch", parameters.packageName);
      /**
      * NVD doesn't support cpeMatchString
      * We will only search by keyword for now
      */
    }
    if (parameters.cvssV3Severity) {
      queryParams.append("cvssV3Severity", parameters.cvssV3Severity);
    }
    if (parameters.cweId) {
      queryParams.append("cweId", parameters.cweId);
    }
    for (const [name, value] of Object.entries(this.#credential.queryParams)) {
      queryParams.append(name, value);
    }

    const url = new URL(NVD.ROOT_API);
    url.search = queryParams.toString();

    try {
      const { data } = await httpie.get<{ vulnerabilities: NVDFormat[]; }>(url.toString());

      return data.vulnerabilities || [];
    }
    catch (error: any) {
      console.error("NVD API Error:", error.message || error);

      return [];
    }
  }

  findOneBySpec(
    spec: string
  ): Promise<NVDFormat[]> {
    const { name } = utils.parseNpmSpec(spec);

    return this.findOne({
      packageName: name,
      ecosystem: "npm"
    });
  }

  async findMany<T extends string = string>(
    specs: T[]
  ): Promise<Record<T, NVDFormat[]>> {
    const entries = await Promise.all(
      specs.map(async(spec) => [spec, await this.findOneBySpec(spec)] as [T, NVDFormat[]])
    );

    return Object.fromEntries(entries) as Record<T, NVDFormat[]>;
  }
}
