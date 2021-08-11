export = NpmStrategy;

declare namespace NpmStrategy {
  export interface Vulnerability {
    /** The unique cache key for this vuln or metavuln. **/
    id?: string;
    /** The numeric ID of the advisory, or the cache key of the vulnerability that causes this metavuln **/
    source: number;
    /** The name of the package that this vulnerability is about**/
    name: string;
    /** For metavulns, the dependency that causes this package to be have a vulnerability. For advisories, the same as name. **/
    dependency: string;
    /** The text title of the advisory or metavuln **/
    title: string;
    /** The url for the advisory (null for metavulns) **/
    url: string;
    /** The severity level **/
    severity: "info" | "low" | "moderate" | "high" | "critical";
    /** The range that is vulnerable **/
    range: string;
    /** The set of versions that are vulnerable **/
    vulnerableVersions?: string[];
    /** Boolean indicating whether this vulnerability was updated since being read from cache. **/
    updated?: boolean;
  }
}
