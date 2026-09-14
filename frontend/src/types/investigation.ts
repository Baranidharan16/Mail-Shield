export type InvestigationStatus = "QUEUED" | "PROCESSING" | "COMPLETED" | "FAILED";
export type Classification = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type CaseStatus = "OPEN" | "UNDER_INVESTIGATION" | "CONTAINED" | "RESOLVED" | "ARCHIVED";
export type AlertStatus = "DETECTED" | "TRIAGED" | "INVESTIGATING" | "CONTAINED" | "RESOLVED";

export interface InvestigationSummary {
  id: string;
  case_id: string;
  filename: string;
  original_filename?: string;
  status: InvestigationStatus;
  classification: Classification | null;
  risk_score: number | null;
  confidence: number | null;
  created_at: string;
  analyzed_at: string | null;
}

export interface InvestigationCreateResponse {
  id: string;
  case_id: string;
  status: InvestigationStatus;
  message: string;
}

export interface EmailMetadataOut {
  from_address: string | null;
  from_display_name: string | null;
  to_addresses: string[] | null;
  cc_addresses: string[] | null;
  bcc_addresses: string[] | null;
  subject: string | null;
  date_raw: string | null;
  date_parsed: string | null;
  reply_to: string | null;
  return_path: string | null;
  message_id: string | null;
  mime_version: string | null;
  content_type: string | null;
  x_mailer: string | null;
  user_agent: string | null;
  sender_domain: string | null;
  reply_to_domain: string | null;
  return_path_domain: string | null;
  attachments: Array<{ filename: string | null; content_type: string; size_bytes: number; sha256: string }> | null;
}

export interface ReceivedHopOut {
  hop_index: number;
  raw_header: string;
  from_host: string | null;
  by_host: string | null;
  with_protocol: string | null;
  ip_address: string | null;
  timestamp_raw: string | null;
  timestamp_parsed: string | null;
}

export interface AuthenticationResultOut {
  spf_result: string | null;
  spf_domain: string | null;
  dkim_result: string | null;
  dkim_domain: string | null;
  dmarc_result: string | null;
  dmarc_policy: string | null;
  from_return_path_aligned: boolean | null;
  from_reply_to_aligned: boolean | null;
  dkim_domain_aligned: boolean | null;
  dmarc_alignment_pass: boolean | null;
  raw_authentication_results_header: string | null;
  source: string;
}

export interface URLOut {
  url: string;
  hostname: string | null;
  scheme: string | null;
  source_location: string | null;
  anchor_text: string | null;
  is_https: boolean | null;
  is_ip_based: boolean | null;
  is_shortened: boolean | null;
  is_punycode: boolean | null;
  has_suspicious_tld: boolean | null;
  excessive_subdomains: boolean | null;
  has_encoded_chars: boolean | null;
  suspicious_query_params: boolean | null;
  anchor_text_mismatch: boolean | null;
  url_length: number | null;
  risk_score: number | null;
  risk_reasons: string[] | null;
}

export interface DomainOut {
  domain: string;
  role: string | null;
  is_punycode: boolean | null;
  suspicious_tld: boolean | null;
  excessive_hyphenation: boolean | null;
  lookalike_of: string | null;
  similarity_score: number | null;
  risk_score: number | null;
  evidence: string[] | null;
}

export interface IPAddressOut {
  ip_address: string;
  ip_version: number;
  source: string | null;
  is_private: boolean | null;
  hop_index: number | null;
}

export interface FindingOut {
  rule_id: string;
  title: string;
  category: string;
  severity: string;
  explanation: string;
  evidence: string[] | null;
  confidence: number;
}

export interface IndicatorOut {
  indicator_type: string;
  severity: string;
  matched_evidence: string | null;
  explanation: string;
  confidence: number;
}

export interface RiskScoreOut {
  overall_score: number;
  classification: Classification;
  confidence: number;
  authentication_score: number;
  header_score: number;
  sender_identity_score: number;
  domain_score: number;
  url_score: number;
  social_engineering_score: number;
  infrastructure_score: number;
  weights_used: Record<string, number>;
  explanation: {
    formula: string;
    dimension_breakdown: Record<string, { score: number; weight: number; weighted_contribution: number; signals: string[] }>;
  };
}

export interface InvestigationDetail {
  id: string;
  case_id: string;
  filename: string;
  original_filename: string;
  evidence_hash_sha256: string;
  file_size_bytes: number;
  mime_type: string | null;
  status: InvestigationStatus;
  classification: Classification | null;
  risk_score: number | null;
  confidence: number | null;
  error_message: string | null;
  created_at: string;
  updated_at: string;
  analyzed_at: string | null;
  case_status?: CaseStatus;
  analyst?: string | null;
  notes?: Array<{ author: string; text: string; created_at: string }>;
  email_metadata: EmailMetadataOut | null;
  received_hops: ReceivedHopOut[];
  authentication_result: AuthenticationResultOut | null;
  urls: URLOut[];
  domains: DomainOut[];
  ip_addresses: IPAddressOut[];
  findings: FindingOut[];
  indicators: IndicatorOut[];
  risk_score_breakdown: RiskScoreOut | null;
  ml_detection?: {
    prediction: string;
    phishing_probability: number;
    confidence: number;
  };
  nlp_detection?: {
    urgency: number;
    credential_request: number;
    financial_manipulation: number;
    impersonation: number;
    threat_language: number;
    suspicious_action: number;
  };
}

// Dashboard
export interface DashboardStats {
  total_investigations: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  processing: number;
  completed: number;
  failed: number;
  campaigns: number;
  active_alerts: number;
}

// Alerts
export interface AlertOut {
  id: string;
  investigation_id: string;
  case_id: string | null;
  original_filename: string | null;
  sender: string | null;
  subject: string | null;
  severity: string;
  threat_score: number;
  classification: string;
  key_reason: string;
  created_at: string;
  acknowledged: boolean;
  status: AlertStatus;
  analyst: string | null;
}

// Timeline
export interface TimelineEvent {
  type: string;
  label: string;
  detail: string;
  timestamp: string | null;
  icon: string;
  actor?: string;
}

export interface TimelineResponse {
  investigation_id: string;
  case_id: string;
  events: TimelineEvent[];
}

// Chain of Custody
export interface ChainOfCustodyResponse {
  case_id: string;
  investigation_id: string;
  evidence_hash: string;
  created_at: string | null;
  created_by: string;
  blockchain_anchor: {
    block_index: number | null;
    block_hash: string | null;
    anchored_at: string | null;
  };
  audit_trail: Array<{
    timestamp: string | null;
    actor: string;
    action: string;
    detail: string | null;
  }>;
  agent_actions: Array<{
    timestamp: string | null;
    tool: string;
    succeeded: boolean;
    duration_ms: number | null;
  }>;
}

// Blockchain
export interface BlockchainBlock {
  block_index: number;
  case_id: string;
  timestamp: string;
  evidence_hash: string;
  block_hash: string;
  previous_hash: string;
}

export interface BlockchainVerifyResult {
  verified: boolean;
  block_count: number;
  message: string;
}

export interface EvidenceVerifyResult {
  anchored: boolean;
  verified: boolean;
  status: string;
  block_index?: number;
  anchored_at?: string;
  evidence_hash_match?: boolean;
  report_hash_match?: boolean;
  chain_intact?: boolean;
  message?: string;
}

// Attack Graph
export interface GraphNode {
  id: string;
  label: string;
  type: string;
  value?: string;
  risk_score?: number;
  status?: string;
  severity?: string;
  classification?: string;
  is_suspicious?: boolean;
}

export interface GraphEdge {
  source: string;
  target: string;
  relation?: string;
  label?: string;
}

export interface AttackGraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  node_count?: number;
  edge_count?: number;
  case_id?: string;
  risk_level?: string;
  risk_score?: number;
  threat_category?: string;
}

// Recommendations
export interface Recommendation {
  id: string;
  action: string;
  severity: string;
  reason: string;
  requires_human_approval: boolean;
  approval_status: string;
}

// Geo / Threat Intel
export interface GeoResult {
  ip_address: string;
  source: string | null;
  hop_index: number | null;
  is_private: boolean | null;
  geo: {
    country?: string;
    country_code?: string;
    region?: string;
    city?: string;
    asn?: string;
    org?: string;
    isp?: string;
    latitude?: number;
    longitude?: number;
    error?: string;
  } | null;
}

export interface GeoResponse {
  investigation_id: string;
  disclaimer: string;
  results: GeoResult[];
}

// Campaign / Similar Cases
export interface CampaignMember {
  investigation_id: string;
  case_id: string;
  similarity_score: number;
  relationship_label: string;
  reasons: string[] | null;
}

export interface CampaignResponse {
  campaign: string | null;
  campaign_code?: string;
  name?: string;
  members?: CampaignMember[];
  message?: string;
}

// Attribution
export interface AttributionResponse {
  level: number;
  level_label: string;
  detection_confidence: number;
  infrastructure_confidence: number;
  campaign_confidence: number;
  attribution_confidence: number;
  explanation: Record<string, string>;
}

// ── Forensic AI Intelligence Layer ──────────────────────────────────────────

export interface EvidenceCard {
  id: string;
  name: string;
  finding: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE";
  impact: "HIGH" | "MEDIUM" | "LOW";
  source: string;  // [EMAIL HEADER] / [EMAIL CONTENT] / [LOCAL HEURISTIC] / [AI INFERENCE]
  explanation: string;
  risk_contribution: number;
  evidence_refs: string[];
}

export interface ReasoningStep {
  step: number;
  label: string;
  detail: string;
  evidence_ids: string[];
  leads_to: string | null;
}

export interface AttackChainNode {
  position: number;
  label: string;
  detail: string;
  threat: boolean;
}

export interface SocialEngineeringSignal {
  signal: string;
  score: number;
  detected: boolean;
  evidence: string;
  label: string;
}

export interface ThreatClassification {
  primary: string;
  secondary: string[];
  confidence: number;
}

export interface ThreatIntent {
  intent: string;
  confidence: number;
  reason: string;
}

export interface IOC {
  type: "EMAIL" | "URL" | "DOMAIN" | "IP" | "HASH";
  value: string;
  source: string;
  confidence: "HIGH" | "MEDIUM" | "LOW";
}

export interface ForensicAIResult {
  investigation_id: string;
  case_id: string;
  analysis_timestamp: string;
  artifacts_analyzed: number;
  disclaimer: string;

  // Verdict
  threat_severity: Classification;
  risk_score: number;
  ai_confidence: number;
  evidence_strength: "VERY HIGH" | "HIGH" | "MEDIUM" | "LOW" | "INSUFFICIENT";

  // Classification
  classification: ThreatClassification;

  // Intent
  threat_intent: ThreatIntent;

  // Social Engineering
  social_engineering_signals: SocialEngineeringSignal[];
  overall_manipulation_risk: number;

  // Evidence
  evidence_cards: EvidenceCard[];
  reasoning_chain: ReasoningStep[];
  attack_chain: AttackChainNode[];

  // IOCs & Cases
  iocs: IOC[];
  related_cases: Array<{
    case_id: string;
    investigation_id: string;
    similarity_score: number;
    relationship: string;
    reasons: string[];
  }>;

  // Conclusions
  forensic_conclusion: string;
  recommended_response: string;
}

export interface ForensicAIChatResponse {
  question: string;
  answer: string;
  evidence_refs: string[];
  suggested_followups: string[];
  disclaimer: string;
}

export interface MailShieldAnalysisResponse {
  analysis_id: string;
  email: {
    subject: string;
    sender: string;
    sender_domain: string;
    reply_to: string;
    reply_to_domain: string;
    date?: string;
    message_id?: string;
  };
  ml: {
    prediction: string;
    phishing_probability: number;
    confidence: number;
  };
  nlp: {
    urgency: number;
    credential_request: number;
    financial_manipulation: number;
    impersonation: number;
    threat_language: number;
    suspicious_action: number;
  };
  forensics: {
    spf: string;
    dkim: string;
    dmarc: string;
    reply_to_mismatch: boolean;
    suspicious_url_count: number;
    domains: string[];
    urls?: string[];
    received_hop_count?: number;
    attachment_count?: number;
    attachments?: string[];
    suspicious_url_details?: Array<{ url: string; domain: string; reasons: string[] }>;
  };
  risk: {
    score: number;
    level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
    contributing_factors: string[];
  };
  ai_reasoning: {
    summary: string;
    why_detected: string[];
    key_indicators: string[];
    recommended_actions: string[];
    confidence_note: string;
  };
}

export interface ModelStatusResponse {
  ml_model_loaded: boolean;
  nlp_model_loaded: boolean;
  forensic_engine_active?: boolean;
  gemini_status?: string;
  sarvam_voice_status?: string;
  ollama_status?: string;
  ml_model_path: string;
  nlp_model_path: string;
  reasoning_provider: string;
  gemini_configured: boolean;
}

