export interface SonatypeVulnerability {
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
  versionRanges?: string[];
  package: string;
}

export type SonatypeResponse = { coordinates: string; vulnerabilities: SonatypeVulnerability[]; };
