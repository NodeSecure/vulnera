/**
 * @see https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema
 */
export interface NVD {
  cve: Cve;
}

interface Cve {
  id: string;
  sourceIdentifier?: string;
  vulnStatus?: string;
  published: string;
  lastModified: string;

  descriptions: LangString[];
  references: Reference[];

  metrics?: Metrics;

  weaknesses?: Weakness[];
  configurations?: Configuration[];
  vendorComments?: VendorComment[];

  evaluatorComment?: string;
  evaluatorSolution?: string;
  evaluatorImpact?: string;

  cisaExploitAdd?: string;
  cisaActionDue?: string;
  cisaRequiredAction?: string;
  cisaVulnerabilityName?: string;

  cveTags?: CveTag[];
}

interface LangString {
  lang: string;
  value: string;
}

interface Reference {
  url: string;
  source?: string;
  tags?: string[];
}

interface Metrics {
  cvssMetricV40?: CvssV40[];
  cvssMetricV31?: CvssV3x[];
  cvssMetricV30?: CvssV3x[];
  cvssMetricV2?: CvssV2[];
}

interface CvssV40 {
  source: string;
  type: "Primary" | "Secondary";
  cvssData: CvssV31;
}

interface CvssV3x {
  source: string;
  type: "Primary" | "Secondary";
  cvssData: CvssV31;
  exploitabilityScore?: number;
  impactScore?: number;
}

interface CvssV2 {
  source: string;
  type: "Primary" | "Secondary";
  cvssData: CvssV31;
  baseSeverity?: string;
  exploitabilityScore?: number;
  impactScore?: number;
  acInsufInfo?: boolean;
  obtainAllPrivilege?: boolean;
  obtainUserPrivilege?: boolean;
  obtainOtherPrivilege?: boolean;
  userInteractionRequired?: boolean;
}

interface Weakness {
  source: string;
  type: string;
  description: LangString[];
}

interface Configuration {
  operator?: "AND" | "OR";
  negate?: boolean;
  nodes: Node[];
}

interface Node {
  operator: "AND" | "OR";
  negate?: boolean;
  cpeMatch: CpeMatch[];
}

interface CpeMatch {
  vulnerable: boolean;
  criteria: string;
  matchCriteriaId: string;
  versionStartExcluding?: string;
  versionStartIncluding?: string;
  versionEndExcluding?: string;
  versionEndIncluding?: string;
}

interface VendorComment {
  organization: string;
  comment: string;
  lastModified: string;
}

interface CveTag {
  sourceIdentifier: string;
  tags: Array<"unsupported-when-assigned" | "exclusively-hosted-service" | "disputed">;
}

/**
 * @see https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v3.1.json
 */
interface CvssV31 {
  version: "3.1";
  vectorString: string;

  attackVector?: "NETWORK" | "ADJACENT_NETWORK" | "LOCAL" | "PHYSICAL";
  attackComplexity?: "HIGH" | "LOW";
  privilegesRequired?: "HIGH" | "LOW" | "NONE";
  userInteraction?: "NONE" | "REQUIRED";
  scope?: "UNCHANGED" | "CHANGED";
  confidentialityImpact?: "NONE" | "LOW" | "HIGH";
  integrityImpact?: "NONE" | "LOW" | "HIGH";
  availabilityImpact?: "NONE" | "LOW" | "HIGH";

  baseScore: number;
  baseSeverity: "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

  exploitCodeMaturity?: "UNPROVEN" | "PROOF_OF_CONCEPT" | "FUNCTIONAL" | "HIGH" | "NOT_DEFINED";
  remediationLevel?: "OFFICIAL_FIX" | "TEMPORARY_FIX" | "WORKAROUND" | "UNAVAILABLE" | "NOT_DEFINED";
  reportConfidence?: "UNKNOWN" | "REASONABLE" | "CONFIRMED" | "NOT_DEFINED";

  temporalScore?: number;
  temporalSeverity?: "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

  confidentialityRequirement?: "LOW" | "MEDIUM" | "HIGH" | "NOT_DEFINED";
  integrityRequirement?: "LOW" | "MEDIUM" | "HIGH" | "NOT_DEFINED";
  availabilityRequirement?: "LOW" | "MEDIUM" | "HIGH" | "NOT_DEFINED";

  modifiedAttackVector?: "NETWORK" | "ADJACENT_NETWORK" | "LOCAL" | "PHYSICAL" | "NOT_DEFINED";
  modifiedAttackComplexity?: "HIGH" | "LOW" | "NOT_DEFINED";
  modifiedPrivilegesRequired?: "HIGH" | "LOW" | "NONE" | "NOT_DEFINED";
  modifiedUserInteraction?: "NONE" | "REQUIRED" | "NOT_DEFINED";
  modifiedScope?: "UNCHANGED" | "CHANGED" | "NOT_DEFINED";
  modifiedConfidentialityImpact?: "NONE" | "LOW" | "HIGH" | "NOT_DEFINED";
  modifiedIntegrityImpact?: "NONE" | "LOW" | "HIGH" | "NOT_DEFINED";
  modifiedAvailabilityImpact?: "NONE" | "LOW" | "HIGH" | "NOT_DEFINED";

  environmentalScore?: number;
  environmentalSeverity?: "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
}
