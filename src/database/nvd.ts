// Import Third-party Dependencies
import * as httpie from "@myunisoft/httpie";

// Import Internal Dependencies
import * as utils from "../utils.js";
import type { NVD } from "../formats/nvd/index.js";

// CONSTANTS
export const ROOT_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";

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

export async function findOne(
  parameters: NVDApiParameter
): Promise<NVD[]> {
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

  const url = new URL(ROOT_API);
  url.search = queryParams.toString();

  try {
    const { data } = await httpie.get<{ vulnerabilities: NVD[]; }>(url.toString());

    return data.vulnerabilities || [];
  }
  catch (error) {
    console.error("NVD API Error:", error.message || error);

    return [];
  }
}

export function findOneBySpec(
  spec: string
) {
  const { name } = utils.parseNpmSpec(spec);

  return findOne({
    packageName: name,
    ecosystem: "npm"
  });
}

export async function findMany<T extends string = string>(
  specs: T[]
): Promise<Record<T, NVD[]>> {
  const packagesVulns = await Promise.all(
    specs.map(async(spec) => {
      return {
        [spec]: await findOneBySpec(spec)
      };
    })
  );

  // @ts-ignore
  return Object.assign(...packagesVulns);
}
