// Import Third-party Dependencies
import * as httpie from "@openally/httpie";

// Import Internal Dependencies
import type { SnykAuditResponse } from "../formats/snyk/index.ts";
import type { ApiCredential } from "../credential.ts";

export type SnykFindOneParameters = {
  files: {
    target: {
      contents: string;
    };
    additional?: {
      contents: string;
    }[];
  };
};

export interface SnykOptions {
  org: string;
  credential: ApiCredential;
}

export class Snyk {
  static readonly ROOT_API = "https://snyk.io";

  readonly #org: string;
  readonly #credential: ApiCredential;

  constructor(
    options: SnykOptions
  ) {
    this.#org = options.org;
    this.#credential = options.credential;
  }

  async findOne(
    parameters: SnykFindOneParameters
  ): Promise<SnykAuditResponse> {
    const { data } = await httpie.post<SnykAuditResponse>(
      new URL(`/api/v1/test/npm?org=${this.#org}`, Snyk.ROOT_API),
      {
        headers: this.#credential.headers,
        body: parameters
      }
    );

    return data;
  }
}
