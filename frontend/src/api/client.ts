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
} from "../types/investigation";


const BASE_URL =
  import.meta.env.VITE_API_BASE_URL ||
  (typeof window !== "undefined" && (window.location.port === "8000" || window.location.origin.includes(":8000"))
    ? "/api/v1"
    : "http://localhost:8000/api/v1");

export const apiClient = axios.create({
  baseURL: BASE_URL,
  timeout: 60000,
});

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


