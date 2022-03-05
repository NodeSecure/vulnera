export = SonatypeStrategy;

declare namespace SonatypeStrategy {    
  export interface Vulnerability {
    id: string;
    displayName: string;
    title: string;
    description: string;
    cvssScore: number;
    cvssVector: string;
    cwe: string;
    cve?: string;
    reference: string;
    externalReferences: string[];
    versionRanges: string[];
  }
}