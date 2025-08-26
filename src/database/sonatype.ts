// Import Third-party Dependencies
import * as httpie from "@openally/httpie";

// Import Internal Dependencies
import type { SonatypeResponse } from "../formats/sonatype/index.js";

export type SonaTypeFindOneParameters = {
  coordinates: string[];
};

export type SonaTypeFindManyParameters = {
  coordinates: string[][];
};

// CONSTANTS
export const ROOT_API = "https://ossindex.sonatype.org";

export async function findOne(
  parameters: SonaTypeFindOneParameters
): Promise<SonatypeResponse[]> {
  const { data } = await httpie.post<SonatypeResponse[]>(
    new URL("/api/v3/component-report", ROOT_API),
    {
      headers: {
        accept: "application/json"
      },
      body: parameters
    }
  );

  return data;
}

export async function findMany(parameters: SonaTypeFindManyParameters): Promise<SonatypeResponse[]> {
  const data = await Promise.all(
    parameters.coordinates.map((coordinates) => findOne({ coordinates }))
  );

  return data.flat();
}
