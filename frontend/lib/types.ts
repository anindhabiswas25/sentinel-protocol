/* ===== Sentinel Protocol – TypeScript types ===== */

export interface ContractMetadata {
  address: string;
  network: string;
  name: string | null;
  compiler_version: string | null;
  is_verified: boolean;
  creation_date: string | null;
  creator_address: string | null;
  is_proxy: boolean;
  implementation_address: string | null;
}

export interface TrustScore {
  overall_score: number;
  security_score: number;
  code_quality_score: number;
  verification_score: number;
  risk_level: string;
}

export interface VulnerabilityDetail {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  description: string;
  location: string | null;
  recommendation: string;
  confidence: number;
  cwe_id: string | null;
}

export interface AnalysisSummary {
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  informational_count: number;
  analysis_method: string;
  llm_insights: string;
}

export interface ContractAnalysisResponse {
  success: boolean;
  metadata: ContractMetadata;
  trust_score: TrustScore;
  summary: AnalysisSummary;
  vulnerabilities: VulnerabilityDetail[];
  recommendations: string[];
  analysis_timestamp: string;
  cached: boolean;
}

export interface HealthResponse {
  status: string;
  version: string;
  database: string;
  vector_db: string;
  blockchain: string;
}

export interface NetworkInfo {
  id: string;
  name: string;
  chain_id: number;
  explorer: string;
}

export interface AnalysisHistoryItem {
  id: number;
  contract_address: string;
  network: string;
  contract_name: string | null;
  is_verified: boolean;
  trust_score: number;
  created_at: string | null;
}

export interface StatsResponse {
  total_analyses: number;
  verified_contracts: number;
  unverified_contracts: number;
  average_trust_score: number;
}

export interface DetectNetworkResponse {
  address: string;
  found: boolean;
  networks: string[];
  primary?: string;
  message?: string;
}
