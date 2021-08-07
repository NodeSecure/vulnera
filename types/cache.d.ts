export = cache;

declare namespace cache {
  export interface Data {
    lastUpdated: number;
  }

  export function load(defaultPayload?: Data): Data;
  export function refresh(): void;
}
