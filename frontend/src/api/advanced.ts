// API + types for the isolated sandbox / AI-security / GRC / VAPT / SOC-alarm pipeline.
import { apiClient } from "./client";

export type Verdict = "SAFE" | "SUSPICIOUS" | "MALICIOUS";
export type CheckStatus = "PASS" | "WARN" | "FAIL" | "NOT_ASSESSED";

export interface SandboxFinding {
  rule_id: string; title: string; severity: string; confidence: number; category: string;
  explanation: string; evidence: string; mitre?: string | null; behavior?: string | null;
}
export interface SandboxFile {
  filename: string; declared_content_type?: string | null; extension?: string | null; detected_type: string;
  size_bytes: number; sha256: string; sha1: string; md5: string; entropy: number;
  verdict: Verdict; score: number; reasons: string[]; findings: SandboxFinding[];
  iocs: { urls: string[]; ips: string[]; emails: string[]; domains: string[] };
  mitre_techniques: string[]; predicted_behavior: string[]; strings_sample: string[]; children: SandboxFile[];
}
export interface SandboxUrl { url: string; verdict: Verdict; score: number; reasons: string[]; findings: SandboxFinding[]; mitre_techniques: string[] }
export interface SandboxResult {
  engine_version: string; analysis_mode: string; verdict: Verdict; score: number; reasons: string[];
  files: SandboxFile[]; urls: SandboxUrl[]; skipped_files: { filename: string; reason: string }[];
  html_body: { verdict: Verdict; score: number; findings: SandboxFinding[] };
  predicted_behavior: string[]; mitre_techniques: string[]; duration_ms?: number;
  isolation?: { mode: string; limits: Record<string, string | number>; wall_timeout_s: number };
  summary?: Record<string, number>; error?: string;
}
export interface AIFinding { rule_id: string; title: string; severity: string; confidence: number; explanation: string; evidence: string; mitre_atlas_or_attack?: string; targets?: string }
export interface AISecurity {
  verdict: "CLEAN" | "SUSPICIOUS" | "MANIPULATION_DETECTED"; score: number; ai_generated_likelihood: number; ai_generated_note: string;
  findings: AIFinding[]; guardrails: { control: string; status: string; detail: string }[]; summary: string;
}
export interface GrcItem { rule_id: string; framework: string; provision: string; title: string; type: "VIOLATION" | "OBLIGATION" | "CONTROL_GAP"; severity: string; description: string; evidence: string[]; actions: string[] }
export interface Grc {
  status: string; violations: number; obligations: number; control_gaps: number; items: GrcItem[];
  reporting_channels: { name: string; contact: string; when: string }[]; disclaimer: string;
}
export interface VaptIntent { intent: string; label: string; confidence: number; evidence: string[]; attacker_objective: string }
export interface VaptWeakness { id: string; location: string; title: string; description: string; evidence: string[]; remediation: string; owner: string; likelihood: string; impact: string; score: number; rating: string }
export interface Vapt {
  primary_intent: VaptIntent; intents: VaptIntent[];
  kill_chain: { stage: string; observed: boolean; evidence: string; mitre?: string | null }[];
  mitre_attack: string[]; weaknesses: VaptWeakness[]; exploitability_score: number; attack_path: string; scope_note: string;
}
export interface Checkpoint { checkpoint: string; status: CheckStatus; summary: string; evidence: string[] }
export interface ThreatReport {
  case_id: string; generated_at: string; final_verdict: Verdict; final_score: number; verdict_reasons: string[];
  pipeline: { step: string; status: string; at: string | null; detail: string | null }[];
  where_it_went_wrong: Checkpoint[];
}
export interface AdvancedAnalysis {
  exists: boolean; pipeline_status: string; trigger?: string;
  quarantine?: { status: string; reason: string | null; at: string | null };
  sandbox?: { status: string; verdict: Verdict | null; score: number | null; attempts: number; error: string | null;
    submission: { files: { filename: string; size_bytes: number; sha256: string; skipped?: string }[]; url_count: number; html_body_count: number; artifact_bundle_sha256: string; data_sent: string; note?: string } | null;
    result: SandboxResult | null; started_at: string | null; completed_at: string | null };
  ai_security?: AISecurity | null; grc?: Grc | null; vapt?: Vapt | null; threat_report?: ThreatReport | null;
  final_verdict?: Verdict | null; final_score?: number | null;
  ledger?: { block_index: number | null; block_hash: string | null; report_hash: string | null; case_ref: string | null };
  error?: string | null;
}

export async function getAdvancedAnalysis(id: string): Promise<AdvancedAnalysis> {
  const { data } = await apiClient.get<AdvancedAnalysis>(`/investigations/${id}/advanced`);
  return data;
}
export async function runSandbox(id: string): Promise<{ queued: boolean; detail: string }> {
  const { data } = await apiClient.post(`/investigations/${id}/sandbox/run`);
  return data;
}
export async function downloadThreatReport(id: string, caseId: string, kind: "pdf" | "json") {
  const res = await apiClient.get(`/investigations/${id}/threat-report${kind === "pdf" ? "/pdf" : ""}`,
    { responseType: kind === "pdf" ? "blob" : "json", timeout: 90000 });
  const blob = kind === "pdf" ? (res.data as Blob) : new Blob([JSON.stringify(res.data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${caseId}_threat_report.${kind}`;
  a.click();
  URL.revokeObjectURL(url);
}

// ── SOC ──────────────────────────────────────────────────────────────────────
export interface SocConfig {
  alarm_enabled: boolean; min_severity: "MEDIUM" | "HIGH" | "CRITICAL"; sound_enabled: boolean; browser_notifications: boolean;
  repeat_until_ack: boolean; repeat_interval_seconds: number; sandbox_scope: "SUSPICIOUS" | "ALL" | "OFF";
  alarm_on_sandbox_malicious: boolean; alarm_on_grc_violation: boolean; auto_escalate_critical: boolean;
  escalation_contact: string | null; webhook_url: string | null; updated_at?: string | null;
}
export interface SocAlarm {
  id: string; investigation_id: string | null; case_id: string | null; severity: string; source: string; title: string;
  message: string | null; status: string; escalated: boolean; webhook_status: string | null;
  acknowledged_by: string | null; acknowledged_at: string | null; created_at: string | null;
}
export const SOC_CONFIG_EVENT = "mailshield:soc-config-updated";

export async function getSocConfig(): Promise<SocConfig> {
  const { data } = await apiClient.get<SocConfig>("/soc/config");
  return data;
}
export async function updateSocConfig(patch: Partial<SocConfig>): Promise<SocConfig> {
  const { data } = await apiClient.put<SocConfig>("/soc/config", patch);
  window.dispatchEvent(new CustomEvent(SOC_CONFIG_EVENT, { detail: data }));
  return data;
}
export async function getSocAlarms(status?: string, limit = 50): Promise<{ active_count: number; alarms: SocAlarm[] }> {
  const { data } = await apiClient.get("/soc/alarms", { params: { status, limit } });
  return data;
}
export async function ackSocAlarm(id: string): Promise<SocAlarm> {
  const { data } = await apiClient.post(`/soc/alarms/${id}/ack`);
  return data;
}
export async function ackAllSocAlarms(): Promise<{ acknowledged: number }> {
  const { data } = await apiClient.post("/soc/alarms/ack-all");
  return data;
}
export async function testSocAlarm(): Promise<SocAlarm> {
  const { data } = await apiClient.post("/soc/alarms/test");
  return data;
}
export async function getSandboxHealth(): Promise<{ reachable: boolean; configured: boolean; engine?: string; detail?: string; auth_configured?: boolean; isolation?: Record<string, unknown> }> {
  const { data } = await apiClient.get("/soc/sandbox/health", { timeout: 20000 });
  return data;
}
