export = cache;

declare namespace cache {
  export interface Data {
    /** Timestamp that indicate the last time the cache has been updated **/
    lastUpdated: number;
  }

  export function load(defaultPayload?: Data): Data;
  export function refresh(): void;
}
