// Import Third-Party Dependencies
import * as httpie from "@myunisoft/httpie";

// Import Internal Dependencies
import { OSV } from "../formats/osv";
import * as utils from "../utils.js";

// CONSTANTS
export const ROOT_API = "https://api.osv.dev";

export type OSVApiParameter = {
  version?: string;
  package: {
    name: string;
    /**
     * @default npm
     */
    ecosystem?: string;
  };
}

export async function findOne(
  parameters: OSVApiParameter
): Promise<OSV[]> {
  if (!parameters.package.ecosystem) {
    parameters.package.ecosystem = "npm";
  }

  const { data } = await httpie.post<{ vulns: OSV[] }>(
    new URL("v1/query", ROOT_API),
    {
      body: parameters
    }
  );

  return data.vulns;
}

export function findOneBySpec(
  spec: string
) {
  const { name, version } = utils.parseNpmSpec(spec);

  return findOne({
    version,
    package: {
      name
    }
  });
}

export async function findMany<T extends string = string>(
  specs: T[]
): Promise<Record<T, OSV[]>> {
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
