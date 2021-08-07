export = NpmStrategy;

declare namespace NpmStrategy {
  // TODO: verify this interface
  export interface Vulnerability {
    id: string;
    title: string;
    module_name: string;
    severity: any;
    version: string;
    vulnerableVersions: string[];
    range: string;
  }
}
