// Import Third-Party Dependencies
import * as httpie from "@myunisoft/httpie";

// Import Internal Dependencies
import { SNYK_ORG, SNYK_TOKEN } from "../constants.js";
import { SnykAuditResponse } from "../formats/snyk/index.js";

// CONSTANTS
export const ROOT_API = "https://snyk.io";

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

export async function findOne(
  parameters: SnykFindOneParameters
): Promise<SnykAuditResponse> {
  const { data } = await httpie.post<SnykAuditResponse>(
    new URL(`/api/v1/test/npm?org=${SNYK_ORG}`, ROOT_API),
    {
      headers: {
        Authorization: `token ${SNYK_TOKEN}`
      },
      body: parameters
    }
  );

  return data;
}
