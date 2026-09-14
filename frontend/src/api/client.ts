import axios from "axios";
import type {
  InvestigationCreateResponse,
  InvestigationDetail,
  InvestigationSummary,
  FindingOut,
  IndicatorOut,
  DashboardStats,
  AlertOut,
  TimelineResponse,
  ChainOfCustodyResponse,
  BlockchainBlock,
  BlockchainVerifyResult,
  EvidenceVerifyResult,
  AttackGraphData,
  Recommendation,
  GeoResponse,
  CampaignResponse,
  AttributionResponse,
  ForensicAIResult,
  ForensicAIChatResponse,
  MailShieldAnalysisResponse,
  ModelStatusResponse,
} from "../types/investigation";


import type {
  UserProfile,
  AuthResponse,
  AuthStatusResponse,
} from "../types/auth";

const BASE_URL =
  import.meta.env.VITE_API_BASE_URL ||
  (typeof window !== "undefined" && (window.location.port === "8000" || window.location.origin.includes(":8000"))
    ? "/api/v1"
    : "http://localhost:8000/api/v1");

export const apiClient = axios.create({
  baseURL: BASE_URL,
  timeout: 60000,
});

// Attach JWT Bearer token automatically to every request if present
apiClient.interceptors.request.use((config) => {
  const token = typeof window !== "undefined" ? localStorage.getItem("mailshield_token") : null;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

axios.interceptors.request.use((config) => {
  const token = typeof window !== "undefined" ? localStorage.getItem("mailshield_token") : null;
  if (token && !config.headers.Authorization) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// ── Authentication ──────────────────────────────────────────────────────────
export async function registerUser(payload: {
  name: string;
  email: string;
  password: string;
  confirm_password: string;
}): Promise<AuthResponse> {
  const rootUrl = BASE_URL.replace(/\/api\/v1\/?$/, "");
  const { data } = await axios.post<AuthResponse>(`${rootUrl}/api/auth/register`, payload);
  return data;
}

export async function loginUser(payload: {
  email: string;
  password: string;
}): Promise<AuthResponse> {
  const rootUrl = BASE_URL.replace(/\/api\/v1\/?$/, "");
  const { data } = await axios.post<AuthResponse>(`${rootUrl}/api/auth/login`, payload);
  return data;
}

export async function logoutUser(): Promise<{ message: string }> {
  const rootUrl = BASE_URL.replace(/\/api\/v1\/?$/, "");
  const { data } = await apiClient.post<{ message: string }>(`${rootUrl}/api/auth/logout`);
  return data;
}

export async function getCurrentUser(): Promise<UserProfile> {
  const rootUrl = BASE_URL.replace(/\/api\/v1\/?$/, "");
  const { data } = await apiClient.get<UserProfile>(`${rootUrl}/api/auth/me`);
  return data;
}

export async function getAuthStatus(): Promise<AuthStatusResponse> {
  const rootUrl = BASE_URL.replace(/\/api\/v1\/?$/, "");
  const { data } = await apiClient.get<AuthStatusResponse>(`${rootUrl}/api/auth/status`);
  return data;
}

// ── Investigations ──────────────────────────────────────────────────────────
export async function uploadEmail(file: File): Promise<InvestigationCreateResponse> {
  const form = new FormData();
  form.append("file", file);
  const { data } = await apiClient.post<InvestigationCreateResponse>("/investigations", form, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return data;
}

export async function listInvestigations(limit = 50): Promise<InvestigationSummary[]> {
  const { data } = await apiClient.get<InvestigationSummary[]>("/investigations", { params: { limit } });
  return data;
}

export async function getInvestigation(id: string): Promise<InvestigationDetail> {
  const { data } = await apiClient.get<InvestigationDetail>(`/investigations/${id}`);
  return data;
}

export async function getFindings(id: string): Promise<FindingOut[]> {
  const { data } = await apiClient.get<FindingOut[]>(`/investigations/${id}/findings`);
  return data;
}

export async function getIndicators(id: string): Promise<IndicatorOut[]> {
  const { data } = await apiClient.get<IndicatorOut[]>(`/investigations/${id}/indicators`);
  return data;
}

export async function getReport(id: string): Promise<Record<string, unknown>> {
  const { data } = await apiClient.get<Record<string, unknown>>(`/investigations/${id}/report`);
  return data;
}

export async function triggerAnalyze(id: string): Promise<InvestigationCreateResponse> {
  const { data } = await apiClient.post<InvestigationCreateResponse>(`/investigations/${id}/analyze`);
  return data;
}

export async function getAttackGraph(id: string): Promise<AttackGraphData> {
  const { data } = await apiClient.get<AttackGraphData>(`/investigations/${id}/graph`);
  return data;
}

export async function getRecommendations(id: string): Promise<Recommendation[]> {
  const { data } = await apiClient.get<Recommendation[]>(`/investigations/${id}/recommendations`);
  return data;
}

export async function verifyEvidence(id: string): Promise<EvidenceVerifyResult> {
  const { data } = await apiClient.get<EvidenceVerifyResult>(`/investigations/${id}/evidence/verify`);
  return data;
}

export async function getGeoIntelligence(id: string): Promise<GeoResponse> {
  const { data } = await apiClient.get<GeoResponse>(`/investigations/${id}/geo`);
  return data;
}

export async function getCampaign(id: string): Promise<CampaignResponse> {
  const { data } = await apiClient.get<CampaignResponse>(`/investigations/${id}/campaign`);
  return data;
}

export async function getAttribution(id: string): Promise<AttributionResponse> {
  const { data } = await apiClient.get<AttributionResponse>(`/investigations/${id}/attribution`);
  return data;
}

export async function getTimeline(id: string): Promise<TimelineResponse> {
  const { data } = await apiClient.get<TimelineResponse>(`/investigations/${id}/timeline`);
  return data;
}

// ── Dashboard ───────────────────────────────────────────────────────────────
export async function getDashboardStats(): Promise<DashboardStats> {
  const { data } = await apiClient.get<DashboardStats>("/dashboard/stats");
  return data;
}

export async function getRecentAlerts(limit = 20): Promise<AlertOut[]> {
  const { data } = await apiClient.get<AlertOut[]>("/dashboard/recent_alerts", { params: { limit } });
  return data;
}

// ── Alerts ──────────────────────────────────────────────────────────────────
export async function listAlerts(limit = 200): Promise<AlertOut[]> {
  const { data } = await apiClient.get<AlertOut[]>("/alerts", { params: { limit } });
  return data;
}

export async function acknowledgeAlert(id: string): Promise<void> {
  await apiClient.patch(`/alerts/${id}`, { acknowledged: true });
}

// ── Cases ───────────────────────────────────────────────────────────────────
export async function getChainOfCustody(id: string): Promise<ChainOfCustodyResponse> {
  const { data } = await apiClient.get<ChainOfCustodyResponse>(`/cases/${id}/chain-of-custody`);
  return data;
}

export async function updateCase(
  id: string,
  body: { case_status?: string; analyst?: string; note?: string },
): Promise<unknown> {
  const { data } = await apiClient.patch(`/cases/${id}`, body);
  return data;
}

// ── Blockchain ──────────────────────────────────────────────────────────────
export async function listBlockchainBlocks(limit = 50): Promise<BlockchainBlock[]> {
  const { data } = await apiClient.get<BlockchainBlock[]>("/blockchain/blocks", { params: { limit } });
  return data;
}

export async function verifyBlockchain(): Promise<BlockchainVerifyResult> {
  const { data } = await apiClient.get<BlockchainVerifyResult>("/blockchain/verify");
  return data;
}

// ── Health ──────────────────────────────────────────────────────────────────
export async function checkHealth(): Promise<{ status: string; app_name: string; database: string }> {
  const { data } = await apiClient.get("/health");
  return data;
}

// ── Forensic AI Intelligence Layer ─────────────────────────────────────────
export async function getForensicAI(id: string): Promise<ForensicAIResult> {
  const { data } = await apiClient.get<ForensicAIResult>(`/investigations/${id}/forensic-ai`);
  return data;
}

export async function postForensicAIChat(
  id: string,
  question: string,
): Promise<ForensicAIChatResponse> {
  const { data } = await apiClient.post<ForensicAIChatResponse>(
    `/investigations/${id}/forensic-ai/chat`,
    { question },
  );
  return data;
}

export async function getForensicAIReport(id: string): Promise<Record<string, unknown>> {
  const { data } = await apiClient.get<Record<string, unknown>>(
    `/investigations/${id}/forensic-ai/report`,
  );
  return data;
}

export async function getForensicSuggestedQuestions(id: string): Promise<{ suggested_questions: string[] }> {
  const { data } = await apiClient.get<{ suggested_questions: string[] }>(
    `/investigations/${id}/forensic-ai/suggested-questions`,
  );
  return data;
}

// ── MailShield AI Chatbot ────────────────────────────────────────────────────
export interface MailShieldEmailContext {
  case_id?: string;
  threat_score?: number;
  threat_level?: string;
  spf?: string;
  dkim?: string;
  dmarc?: string;
  sender?: string;
  sender_domain?: string;
  subject?: string;
  url_risk?: string;
  url_count?: number;
  attachments?: { filename?: string }[];
  findings?: { severity?: string; title?: string; explanation?: string }[];
  indicators?: { indicator_type?: string; explanation?: string }[];
  classification?: string;
  system_stats?: Record<string, any>;
  recent_alerts?: Record<string, any>[];
}

export interface ChatHistoryEntry {
  role: "user" | "model";
  text: string;
}

export async function postMailShieldChat(
  message: string,
  emailContext?: MailShieldEmailContext,
  history?: ChatHistoryEntry[],
): Promise<{ reply: string; engine?: string }> {
  const { data } = await apiClient.post<{ reply: string; engine?: string }>("/chat", {
    message,
    email_context: emailContext ?? null,
    history: history ?? [],
  });
  return data;
}

// ── MailShield AI Assistant — Gemini Reasoning + Sarvam Multilingual Voice ─

export interface AgentChatResponse {
  answer: string;
  suggested_followups: string[];
  disclaimer: string;
  engine: string;
  language_code?: string;
}

export interface AgentVoiceResponse {
  audio_base64: string | null;
  format: string | null;
  engine: string;
  language_code?: string;
  language_name?: string;
  speaker?: string;
  text_used?: string;
  error?: string;
}

export interface AgentTranscribeResponse {
  transcript: string;
  language_code: string;
  language_name: string;
  confidence: number;
  engine: string;
  error?: string;
}

export async function postAgentChat(
  investigationId: string,
  question: string,
  languageCode: string = "en-IN",
  languageName?: string,
): Promise<AgentChatResponse> {
  const { data } = await apiClient.post<AgentChatResponse>(
    `/investigations/${investigationId}/agent/chat`,
    { question, language_code: languageCode, language_name: languageName },
  );
  return data;
}

export async function postAgentVoice(
  investigationId: string,
  text: string,
  voice = "priya",
  language = "en-IN",
): Promise<AgentVoiceResponse> {
  const { data } = await apiClient.post<AgentVoiceResponse>(
    `/investigations/${investigationId}/agent/voice`,
    { text, voice, language },
  );
  return data;
}

export async function postAgentTranscribe(
  investigationId: string,
  audioBlob: Blob,
): Promise<AgentTranscribeResponse> {
  const formData = new FormData();
  formData.append("file", audioBlob, "speech.wav");
  const { data } = await apiClient.post<AgentTranscribeResponse>(
    `/investigations/${investigationId}/agent/transcribe`,
    formData,
    {
      headers: {
        "Content-Type": "multipart/form-data",
      },
    },
  );
  return data;
}

// ── SIH 26106: Layer 3 Origin Traceability & System Interfaces ─────────────

export interface ObservableNode {
  hop_index: number;
  ip_address: string;
  from_host: string;
  by_host: string;
  protocol: string;
  timestamp_raw: string;
  timestamp_parsed: string | null;
  is_private: boolean;
  is_earliest_reliable: boolean;
  infrastructure_type: string;
  geo_data?: {
    country?: string;
    city?: string;
    region?: string;
    isp?: string;
    org?: string;
    asn?: string;
    lat?: number;
    lon?: number;
    timezone?: string;
    hosting?: boolean;
    proxy?: boolean;
  } | null;
  flags: string[];
}

export interface OriginTraceResult {
  earliest_node: ObservableNode | null;
  total_hops: number;
  public_hops: number;
  relay_path: ObservableNode[];
  anomalies: Array<{
    type: string;
    severity: string;
    hop_index?: number;
    description: string;
  }>;
  confidence_score: number;
  infrastructure_type: string;
  summary_verdict: string;
  disclaimer: string;
}

export interface SystemPerformance {
  status: string;
  uptime_seconds: number;
  uptime_formatted: string;
  autonomous_agent: {
    status: string;
    mailbox_monitoring: string;
    last_event_time: string;
    sync_interval_seconds: number;
    mode: string;
  };
  engine_statuses: Record<string, string>;
  latencies: {
    database_query_ms: number;
    blockchain_verify_ms: number;
    email_ingest_avg_ms: number;
    header_parsing_avg_ms: number;
    geoip_lookup_avg_ms: number;
    ai_inference_avg_ms: number;
    websocket_sse_latency_ms: number;
  };
  metrics: {
    total_cases: number;
    completed_cases: number;
    blockchain_anchors: number;
    memory_usage_mb: number;
    error_rate_percent: number;
  };
}

export interface DemoScenario {
  id: string;
  title: string;
  threat_class: string;
  severity: string;
  expected_score: number;
  sender: string;
  subject: string;
  description: string;
}

export interface CampaignCase {
  investigation_id: string;
  case_id: string;
  risk_score: number;
  classification: string;
  subject: string;
  sender: string;
  created_at: string;
}

export interface CampaignAttribution {
  type: string;
  confidence: number;
  reasons: string[];
}

export interface CampaignItem {
  campaign_code: string;
  name: string;
  threat_class: string;
  case_count: number;
  average_risk_score: number;
  confidence_percent: number;
  domains: string[];
  ips: string[];
  cases: CampaignCase[];
  attribution_support: CampaignAttribution | string;
}


export interface GlobalGraphData {
  nodes: Array<{
    id: string;
    label: string;
    type: string;
    risk?: number;
    val?: number;
  }>;
  links: Array<{
    source: string;
    target: string;
    relation: string;
  }>;
  total_cases: number;
  total_nodes: number;
  total_links: number;
}

export async function getOriginTrace(investigationId: string): Promise<OriginTraceResult> {
  const { data } = await apiClient.get<OriginTraceResult>(`/investigations/${investigationId}/origin-trace`);
  return data;
}

export async function getSystemPerformance(): Promise<SystemPerformance> {
  const { data } = await apiClient.get<SystemPerformance>("/system/performance");
  return data;
}

export async function getDemoScenarios(): Promise<DemoScenario[]> {
  const { data } = await apiClient.get<DemoScenario[]>("/system/demo-scenarios");
  return data;
}

export async function loadDemoScenario(scenarioId: string): Promise<{
  status: string;
  scenario_id: string;
  case_id: string;
  investigation_id: string;
  threat_class: string;
  subject: string;
}> {
  const { data } = await apiClient.post("/system/load-scenario", { scenario_id: scenarioId });
  return data;
}

export async function getCampaigns(): Promise<CampaignItem[]> {
  const { data } = await apiClient.get<CampaignItem[]>("/system/campaigns");
  return data;
}

export async function getGlobalGraph(): Promise<GlobalGraphData> {
  const { data } = await apiClient.get<GlobalGraphData>("/system/global-graph");
  return data;
}

export async function postThreatAction(
  investigationId: string,
  actionType: "QUARANTINE_MESSAGE" | "REVOKE_TOKEN" | "ISOLATE_MAILBOX" | "PUSH_FIREWALL_BLOCK" | "DISMISS",
  notes?: string,
): Promise<{ status: string; action_id: string; action: string; timestamp: string }> {
  const { data } = await apiClient.post("/system/action", {
    investigation_id: investigationId,
    action: actionType,
    notes: notes || "Executed via SOC Containment Console",
  });
  return data;
}

// ── MailShield Real-Time Direct Analysis ─────────────────────────────────────

export async function analyzeEmailDirect(file: File): Promise<MailShieldAnalysisResponse> {
  const form = new FormData();
  form.append("file", file);
  // Using relative path or base url compatible with /api/analyze-email
  const rootUrl = BASE_URL.replace(/\/api\/v1\/?$/, "");
  const targetUrl = `${rootUrl}/api/analyze-email`;
  const { data } = await axios.post<MailShieldAnalysisResponse>(targetUrl, form, {
    headers: { "Content-Type": "multipart/form-data" },
    timeout: 60000,
  });
  return data;
}

export async function analyzeRawTextDirect(rawText: string, subject?: string): Promise<MailShieldAnalysisResponse> {
  const form = new FormData();
  form.append("raw_text", rawText);
  if (subject) form.append("subject", subject);
  const rootUrl = BASE_URL.replace(/\/api\/v1\/?$/, "");
  const targetUrl = `${rootUrl}/api/analyze-email`;
  const { data } = await axios.post<MailShieldAnalysisResponse>(targetUrl, form, {
    headers: { "Content-Type": "multipart/form-data" },
    timeout: 60000,
  });
  return data;
}

export async function getModelStatus(): Promise<ModelStatusResponse> {
  const rootUrl = BASE_URL.replace(/\/api\/v1\/?$/, "");
  const { data } = await axios.get<ModelStatusResponse>(`${rootUrl}/api/model-status`);
  return data;
}

export async function postAssistantChat(
  question: string,
  context?: any,
  history?: any[],
  language: string = "en-IN",
): Promise<{ answer: string; engine: string; language: string; sources?: string[] }> {
  const rootUrl = BASE_URL.replace(/\/api\/v1\/?$/, "");
  const { data } = await axios.post<{ answer: string; engine: string; language: string; sources?: string[] }>(
    `${rootUrl}/api/assistant/chat`,
    { question, context, history, language }
  );
  return data;
}

export async function postAssistantTranscribe(
  audioBlob: Blob,
  languageCode?: string,
): Promise<{ transcript: string; language_code: string; language_name: string; confidence: number; engine: string }> {
  const form = new FormData();
  form.append("file", audioBlob, "recording.wav");
  if (languageCode) form.append("language_code", languageCode);
  const rootUrl = BASE_URL.replace(/\/api\/v1\/?$/, "");
  const { data } = await axios.post<{ transcript: string; language_code: string; language_name: string; confidence: number; engine: string }>(
    `${rootUrl}/api/assistant/transcribe`,
    form,
    { headers: { "Content-Type": "multipart/form-data" } }
  );
  return data;
}

export async function postAssistantSpeak(
  text: string,
  language: string = "en-IN",
  voice: string = "priya",
): Promise<{ audio_base64: string; format: string; engine: string; language_code: string; language_name: string }> {
  const rootUrl = BASE_URL.replace(/\/api\/v1\/?$/, "");
  const { data } = await axios.post<{ audio_base64: string; format: string; engine: string; language_code: string; language_name: string }>(
    `${rootUrl}/api/assistant/speak`,
    { text, language, voice }
  );
  return data;
}

// ── Gmail Integration API ───────────────────────────────────────────────────
export interface GmailMessageItem {
  id: string;
  threadId: string;
  sender: string;
  subject: string;
  date: string;
  snippet: string;
  threat_preview?: "SAFE" | "SUSPICIOUS" | "HIGH" | "CRITICAL";
  is_quarantined?: boolean;
  labels?: string[];
}

export interface GmailStatusResponse {
  connected: boolean;
  email: string;
  messages_total: number;
  quarantined_count: number;
}

export async function getGmailStatus(): Promise<GmailStatusResponse> {
  const { data } = await apiClient.get<GmailStatusResponse>("/gmail/status");
  return data;
}

export async function getGmailAuthUrl(): Promise<{ authorization_url: string }> {
  const { data } = await apiClient.get<{ authorization_url: string }>("/auth/google");
  return data;
}

export async function getGmailMessages(q: string = ""): Promise<GmailMessageItem[]> {
  const { data } = await apiClient.get<{ messages: GmailMessageItem[] }>("/gmail/messages", {
    params: { q },
  });
  return data.messages;
}

export async function analyzeGmailMessage(messageId: string): Promise<{
  analysis: MailShieldAnalysisResponse;
  investigation_id: string;
  case_id: string;
  quarantined: boolean;
  evidence_hash: string;
}> {
  const { data } = await apiClient.post(`/gmail/analyze/${messageId}`);
  return data;
}

export async function quarantineGmailMessage(messageId: string, destination?: string): Promise<any> {
  const { data } = await apiClient.post(`/gmail/quarantine/${messageId}`, null, {
    params: destination ? { destination } : undefined,
  });
  return data;
}

export async function quarantineInvestigation(investigationId: string, destination?: string): Promise<any> {
  const { data } = await apiClient.post(`/investigations/${investigationId}/quarantine`, null, {
    params: destination ? { destination } : undefined,
  });
  return data;
}

export async function releaseGmailMessage(messageId: string): Promise<any> {
  const { data } = await apiClient.post(`/gmail/release/${messageId}`);
  return data;
}

export async function connectGmailSandbox(): Promise<{ status: string; email: string }> {
  const { data } = await apiClient.post("/gmail/connect-sandbox");
  return data;
}

export async function disconnectGmail(): Promise<{ status: string }> {
  const { data } = await apiClient.post("/gmail/disconnect");
  return data;
}

export async function registerBlockchainEvidence(evidenceId: string, caseId?: string): Promise<any> {
  const { data } = await apiClient.post(`/blockchain/register/${evidenceId}`, null, {
    params: { case_id: caseId },
  });
  return data;
}
