export type VulnerabilityStrategy = "npm" | "node";

export interface Vulnerability {
  id: number;
  created_at: string;
  updated_at: string;
  title: string;
  author: {
      name: string;
      website: string | null;
      username: string | null;
  };
  module_name: string;
  publish_data: string;
  cves: string[];
  vulnerable_versions: string;
  patched_versions: string;
  overview: string;
  recommendation: string;
  references: string[];
  cvss_vector: string;
  cvss_score: number;
  coordinating_vendor: string;
}

