// Import Third-party Dependencies
import * as httpie from "@openally/httpie";

// Import Internal Dependencies
import type { SonatypeResponse } from "../formats/sonatype/index.ts";
import type { ApiCredential } from "../credential.ts";

export type SonaTypeFindOneParameters = {
  coordinates: string[];
};

export type SonaTypeFindManyParameters = {
  coordinates: string[][];
};

export interface SonatypeOptions {
  credential: ApiCredential;
}

export class Sonatype {
  static readonly ROOT_API = "https://ossindex.sonatype.org";

  readonly #credential: ApiCredential;

  constructor(
    options: SonatypeOptions
  ) {
    this.#credential = options.credential;
  }

  async findOne(
    parameters: SonaTypeFindOneParameters
  ): Promise<SonatypeResponse[]> {
    const headers: Record<string, string> = {
      accept: "application/json",
      ...this.#credential.headers
    };

    const { data } = await httpie.post<SonatypeResponse[]>(
      new URL("/api/v3/component-report", Sonatype.ROOT_API),
      {
        headers,
        body: parameters
      }
    );

    return data;
  }

  async findMany(
    parameters: SonaTypeFindManyParameters
  ): Promise<SonatypeResponse[]> {
    const data = await Promise.all(
      parameters.coordinates.map((coordinates) => this.findOne({ coordinates }))
    );

    return data.flat();
  }
}
