
/**
 * @see https://ossf.github.io/osv-schema/
 */
export interface OSV {
  schema_version: string;
  id: string;
  modified: string;
  published: string;
  withdraw: string;
  aliases: string[];
  related: string[];
  summary: string;
  details: string;
  severity: OSVSeverity[];
  affected: OSVAffected[];
  references: {
    type: OSVReferenceType;
    url: string;
  }[];
  credits: {
    name: string;
    contact: string[];
    type: OSVCreditType;
  }[];
  database_specific: Record<string, any>;
}

export type OSVReferenceType = "ADVISORY" |
  "ARTICLE" |
  "DETECTION" |
  "DISCUSSION" |
  "REPORT" |
  "FIX" |
  "GIT" |
  "INTRODUCED" |
  "PACKAGE" |
  "EVIDENCE" |
  "WEB";

export type OSVCreditType = "FINDER" |
  "REPORTER" |
  "ANALYST" |
  "COORDINATOR" |
  "REMEDIATION_DEVELOPER" |
  "REMEDIATION_REVIEWER" |
  "REMEDIATION_VERIFIER" |
  "TOOL" |
  "SPONSOR" |
  "OTHER";

export interface OSVAffected {
  package: {
    ecosystem: "npm";
    name: string;
    purl: string;
  };
  severity: OSVSeverity[];
  ranges: OSVRange[];
  versions: string[];
  ecosystem_specific: Record<string, any>;
  database_specific: Record<string, any>;
}

export interface OSVRange {
  type: string;
  repo: string;
  events: {
    introduced?: string;
    fixed?: string;
    last_affected?: string;
    limit?: string;
  }[];
  database_specific: Record<string, any>;
}

export interface OSVSeverity {
  type: string;
  score: string;
}
