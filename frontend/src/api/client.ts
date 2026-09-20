import axios from "axios";
import type { AxiosError, InternalAxiosRequestConfig } from "axios";
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
  ForensicVerdict,
  MonitorStatus,
  MonitoredEmail,
} from "../types/investigation";


import type {
  UserProfile,
  AuthResponse,
  AuthStatusResponse,
} from "../types/auth";

// API base URL.
//  * Development: "/api/v1" — proxied by the Vite dev server (vite.config.ts).
//  * Same-origin production (backend serves dist / nginx proxy): "/api/v1".
//  * Split production: set VITE_API_BASE_URL=https://backend.example.com/api/v1 at build time.
export const BASE_URL: string = (import.meta.env.VITE_API_BASE_URL || "/api/v1").replace(/\/+$/, "");
export const API_ROOT: string = BASE_URL.replace(/\/api\/v1$/, "");
const AUTH_URL = `${API_ROOT}/api/auth`;

// Send the httpOnly refresh cookie on cross-origin requests too (split deployments).
axios.defaults.withCredentials = true;

export const apiClient = axios.create({
  baseURL: BASE_URL,
  timeout: 60000,
  withCredentials: true,
});

// ── Access-token store ──────────────────────────────────────────────────────
// The short-lived access token lives in memory only (not localStorage), so an
// XSS bug cannot read a long-lived credential. The session survives page
// reloads through the httpOnly refresh cookie (see refreshSession()).
let accessToken: string | null = null;

export function setAccessToken(token: string | null) {
  accessToken = token;
}
export function getAccessToken(): string | null {
  return accessToken;
}

// Remove credentials left behind by older versions of the app.
try {
  localStorage.removeItem("mailshield_token");
  localStorage.removeItem("mailshield_user");
} catch {
  /* storage unavailable */
}

function attachToken(config: InternalAxiosRequestConfig) {
  if (accessToken && !config.headers.Authorization) {
    config.headers.Authorization = `Bearer ${accessToken}`;
  }
  return config;
}
apiClient.interceptors.request.use(attachToken);
axios.interceptors.request.use(attachToken);

// ── Silent refresh on 401 ───────────────────────────────────────────────────
let refreshInFlight: Promise<AuthResponse> | null = null;

/** Exchanges the refresh cookie for a new access token. Concurrent callers share one request. */
export function refreshSession(): Promise<AuthResponse> {
  if (!refreshInFlight) {
    refreshInFlight = axios
      .post<AuthResponse>(`${AUTH_URL}/refresh`, null, { withCredentials: true, timeout: 20000 })
      .then(({ data }) => {
        setAccessToken(data.access_token);
        return data;
      })
      .finally(() => {
        refreshInFlight = null;
      });
  }
  return refreshInFlight;
}

/** Fired when the session can no longer be refreshed; AuthContext listens and signs out. */
export const SESSION_EXPIRED_EVENT = "mailshield:session-expired";

async function handleAuthError(error: AxiosError) {
  const original = error.config as (InternalAxiosRequestConfig & { _retried?: boolean }) | undefined;
  const url = original?.url || "";
  const isAuthCall = /\/auth\/(login|register|refresh|logout)/.test(url);
  if (error.response?.status === 401 && original && !original._retried && !isAuthCall) {
    original._retried = true;
    try {
      const { access_token } = await refreshSession();
      original.headers.Authorization = `Bearer ${access_token}`;
      return axios.request(original);
    } catch {
      setAccessToken(null);
      window.dispatchEvent(new CustomEvent(SESSION_EXPIRED_EVENT));
    }
  }
  return Promise.reject(error);
}
apiClient.interceptors.response.use((r) => r, handleAuthError);
axios.interceptors.response.use((r) => r, handleAuthError);

/** Turns any API error into a short, human-readable message. */
export function getApiErrorMessage(err: unknown, fallback = "Something went wrong. Please try again."): string {
  const e = err as AxiosError<{ detail?: unknown }>;
  if (!e || !e.isAxiosError) return fallback;
  if (!e.response) {
    if (e.code === "ECONNABORTED") return "The server took too long to respond. Please try again.";
    return "Cannot reach the MailShield server. Check that the backend is running and your connection is online.";
  }
  const { status, data } = e.response;
  const detail = data?.detail;
  if (Array.isArray(detail)) {
    // FastAPI/Pydantic validation errors: [{loc, msg}, ...]
    const msgs = detail
      .map((d: any) => String(d?.msg || "").replace(/^Value error, /, ""))
      .filter(Boolean);
    if (msgs.length) return Array.from(new Set(msgs)).join(" ");
  }
  if (typeof detail === "string" && detail) return detail;
  if (status === 503) return "The database is temporarily unavailable. Please try again shortly.";
  if (status === 429) return "Too many attempts. Please wait a few minutes and try again.";
  if (status >= 500) return "The server encountered an error. Please try again.";
  return fallback;
}

// ── Authentication ──────────────────────────────────────────────────────────
export async function registerUser(payload: {
  name: string;
  email: string;
  password: string;
  confirm_password: string;
}): Promise<AuthResponse> {
  const { data } = await axios.post<AuthResponse>(`${AUTH_URL}/register`, payload);
  setAccessToken(data.access_token);
  return data;
}

export async function loginUser(payload: {
  email: string;
  password: string;
  remember_me?: boolean;
}): Promise<AuthResponse> {
  const { data } = await axios.post<AuthResponse>(`${AUTH_URL}/login`, payload);
  setAccessToken(data.access_token);
  return data;
}

export async function logoutUser(): Promise<{ message: string }> {
  try {
    const { data } = await axios.post<{ message: string }>(`${AUTH_URL}/logout`);
    return data;
  } finally {
    setAccessToken(null);
  }
}

export async function logoutAllDevices(): Promise<{ message: string }> {
  const { data } = await apiClient.post<{ message: string }>(`${AUTH_URL}/logout-all`);
  setAccessToken(null);
  return data;
}

export async function getCurrentUser(): Promise<UserProfile> {
  const { data } = await apiClient.get<UserProfile>(`${AUTH_URL}/me`);
  return data;
}

export async function updateProfile(name: string): Promise<UserProfile> {
  const { data } = await apiClient.patch<UserProfile>(`${AUTH_URL}/me`, { name });
  return data;
}

export async function changePassword(payload: {
  current_password: string;
  new_password: string;
  confirm_password: string;
}): Promise<{ message: string }> {
  const { data } = await apiClient.post<{ message: string }>(`${AUTH_URL}/change-password`, payload);
  return data;
}

export async function requestPasswordReset(email: string): Promise<{ message: string }> {
  const { data } = await axios.post<{ message: string }>(`${AUTH_URL}/forgot-password`, { email });
  return data;
}

export async function resetPassword(payload: {
  token: string;
  new_password: string;
  confirm_password: string;
}): Promise<{ message: string }> {
  const { data } = await axios.post<{ message: string }>(`${AUTH_URL}/reset-password`, payload);
  return data;
}

export async function getAuthStatus(): Promise<AuthStatusResponse> {
  const { data } = await apiClient.get<AuthStatusResponse>(`${AUTH_URL}/status`);
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
  const rootUrl = API_ROOT;
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
  const rootUrl = API_ROOT;
  const targetUrl = `${rootUrl}/api/analyze-email`;
  const { data } = await axios.post<MailShieldAnalysisResponse>(targetUrl, form, {
    headers: { "Content-Type": "multipart/form-data" },
    timeout: 60000,
  });
  return data;
}

export async function getModelStatus(): Promise<ModelStatusResponse> {
  const rootUrl = API_ROOT;
  const { data } = await axios.get<ModelStatusResponse>(`${rootUrl}/api/model-status`);
  return data;
}

export async function postAssistantChat(
  question: string,
  context?: any,
  history?: any[],
  language: string = "en-IN",
): Promise<{ answer: string; engine: string; language: string; sources?: string[] }> {
  const rootUrl = API_ROOT;
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
  const rootUrl = API_ROOT;
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
  const rootUrl = API_ROOT;
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
  gmail_error?: string | null;
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

/**
 * Quarantine flow shared by every Quarantine button:
 *  1. Move the email to the Gmail "Quarantine" label.
 *  2. If the account has no "Quarantine" label, the backend moves nothing and
 *     answers 409 QUARANTINE_LABEL_MISSING. We then ask the user for permission;
 *     only if they agree is the email moved to Spam instead.
 */
async function quarantineWithSpamFallback(url: string, destination?: string): Promise<any> {
  try {
    const { data } = await apiClient.post(url, null, {
      params: destination ? { destination } : undefined,
    });
    return data;
  } catch (err: any) {
    const detail = err?.response?.data?.detail;
    if (err?.response?.status === 409 && detail?.code === "QUARANTINE_LABEL_MISSING") {
      const ok = window.confirm(
        `${detail.message || "This Gmail account has no 'Quarantine' label."}\n\n` +
          "OK = move this email to Spam\nCancel = leave it in the Inbox",
      );
      if (ok) {
        const { data } = await apiClient.post(url, null, { params: { destination: "spam" } });
        return data;
      }
      // Normalise to the string-detail shape the Quarantine buttons already display.
      const cancelled: any = new Error("cancelled");
      cancelled.response = {
        status: 409,
        data: { detail: "No 'Quarantine' label in this Gmail account; you chose not to move it to Spam. The email is still in the Inbox." },
      };
      throw cancelled;
    }
    if (detail && typeof detail === "object") {
      err.response.data.detail = detail.message || JSON.stringify(detail);
    }
    throw err;
  }
}

export async function quarantineGmailMessage(messageId: string, destination?: string): Promise<any> {
  return quarantineWithSpamFallback(`/gmail/quarantine/${messageId}`, destination);
}

export async function quarantineInvestigation(investigationId: string, destination?: string): Promise<any> {
  return quarantineWithSpamFallback(`/investigations/${investigationId}/quarantine`, destination);
}

export async function releaseGmailMessage(messageId: string): Promise<any> {
  const { data } = await apiClient.post(`/gmail/release/${messageId}`);
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


// ── Forensic verdict, real-time monitor & privacy controls ──────────────────
export async function getForensicVerdict(id: string): Promise<ForensicVerdict> {
  const { data } = await apiClient.get<ForensicVerdict>(`/investigations/${id}/verdict`, { timeout: 90000 });
  return data;
}

export async function getMonitorStatus(): Promise<MonitorStatus> {
  const { data } = await apiClient.get<MonitorStatus>("/monitor/status");
  return data;
}

export async function setMonitorEnabled(enabled: boolean): Promise<{ enabled: boolean }> {
  const { data } = await apiClient.post<{ enabled: boolean }>("/monitor/toggle", { enabled });
  return data;
}

export async function runMonitorNow(): Promise<{ analyzed: number }> {
  const { data } = await apiClient.post<{ analyzed: number }>("/monitor/run-now", null, { timeout: 180000 });
  return data;
}

export async function getMonitoredEmails(limit = 30): Promise<MonitoredEmail[]> {
  const { data } = await apiClient.get<MonitoredEmail[]>("/monitor/recent", { params: { limit } });
  return data;
}

export async function getMyDataSummary(): Promise<Record<string, unknown>> {
  const { data } = await apiClient.get<Record<string, unknown>>("/privacy/my-data");
  return data;
}

export async function deleteMyData(): Promise<{ deleted_investigations: number; message: string }> {
  const { data } = await apiClient.delete("/privacy/my-data");
  return data;
}

export async function deleteInvestigation(id: string): Promise<void> {
  await apiClient.delete(`/investigations/${id}`);
}
