// Import Third-party Dependencies
import * as httpie from "@openally/httpie";

// Import Internal Dependencies
import type { OSV as OSVFormat } from "../formats/osv/index.ts";
import * as utils from "../utils.ts";
import type { ApiCredential } from "../credential.ts";

export type OSVQueryBatchEntry = {
  version?: string;
  package: {
    name: string;
    /**
     * @default npm
     */
    ecosystem?: string;
  };
};

export interface OSVQueryBatchRequest {
  queries: OSVQueryBatchEntry[];
}

export interface OSVQueryBatchResult {
  vulns?: OSVFormat[];
}

export interface OSVQueryBatchResponse {
  results: OSVQueryBatchResult[];
}

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

  async query(
    query: OSVQueryBatchEntry
  ): Promise<OSVFormat[]> {
    if (!query.package.ecosystem) {
      query.package.ecosystem = "npm";
    }

    const { data } = await httpie.post<{ vulns: OSVFormat[]; }>(
      new URL("v1/query", OSV.ROOT_API),
      {
        headers: this.#credential?.headers,
        body: query
      }
    );

    return data.vulns;
  }

  queryBySpec(
    spec: string
  ): Promise<OSVFormat[]> {
    const { name, version } = utils.parseNpmSpec(spec);

    return this.query({
      version,
      package: {
        name,
        ecosystem: "npm"
      }
    });
  }

  async queryBatch(
    queries: OSVQueryBatchEntry[]
  ): Promise<OSVQueryBatchResult[]> {
    for (const query of queries) {
      if (!query.package.ecosystem) {
        query.package.ecosystem = "npm";
      }
    }

    const { data } = await httpie.post<OSVQueryBatchResponse>(
      new URL("v1/querybatch", OSV.ROOT_API),
      {
        headers: this.#credential?.headers,
        body: { queries }
      }
    );

    return data.results;
  }

  async findVulnById(
    id: string
  ): Promise<OSVFormat> {
    const { data } = await httpie.get<OSVFormat>(
      new URL(`v1/vulns/${id}`, OSV.ROOT_API),
      {
        headers: this.#credential?.headers
      }
    );

    return data;
  }
}
