// Import Third-party Dependencies
import * as httpie from "@openally/httpie";

// Import Internal Dependencies
import type { OSV as OSVFormat } from "../formats/osv/index.ts";
import * as utils from "../utils.ts";
import type { ApiCredential } from "../credential.ts";

export type OSVApiParameter = {
  version?: string;
  package: {
    name: string;
    /**
     * @default npm
     */
    ecosystem?: string;
  };
};

export interface OSVOptions {
  credential?: ApiCredential;
}

export class OSV {
  static readonly ROOT_API = "https://api.osv.dev";

  readonly #credential: ApiCredential | undefined;

  constructor(
    options: OSVOptions = {}
  ) {
    this.#credential = options.credential;
  }

  async findOne(
    parameters: OSVApiParameter
  ): Promise<OSVFormat[]> {
    if (!parameters.package.ecosystem) {
      parameters.package.ecosystem = "npm";
    }

    const { data } = await httpie.post<{ vulns: OSVFormat[]; }>(
      new URL("v1/query", OSV.ROOT_API),
      {
        headers: this.#credential?.headers,
        body: parameters
      }
    );

    return data.vulns;
  }

  findOneBySpec(
    spec: string
  ): Promise<OSVFormat[]> {
    const { name, version } = utils.parseNpmSpec(spec);

    return this.findOne({
      version,
      package: {
        name
      }
    });
  }

  async findMany<T extends string = string>(
    specs: T[]
  ): Promise<Record<T, OSVFormat[]>> {
    const entries = await Promise.all(
      specs.map(async(spec) => [spec, await this.findOneBySpec(spec)] as [T, OSVFormat[]])
    );

    return Object.fromEntries(entries) as Record<T, OSVFormat[]>;
  }
}
