export interface ScannerVersionDescriptor {
  versions: string[];
  vulnerabilities: any[];
}

export type Dependencies = Map<string, ScannerVersionDescriptor>;
