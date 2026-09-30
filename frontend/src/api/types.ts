/**
 * TypeScript data models mirroring backend Pydantic schemas.
 */

export interface User {
  id: number;
  email: string;
  role: 'admin' | 'user';
  is_active: boolean;
  created_at: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  user: User;
}

export interface Target {
  id: number;
  owner_id: number;
  name: string;
  base_url: string;
  scope_hosts: string[];
  ownership_status: 'unverified' | 'verified' | 'lab';
  ownership_token: string;
  verified_at: string | null;
  created_at: string;
}

export interface TargetVerifyResponse {
  verified: boolean;
  instructions: string;
}

export interface TargetAccount {
  id: number;
  target_id: number;
  role_label: string;
  privilege_level: number;
  login_url: string;
  username: string;
  username_selector: string;
  password_selector: string;
  submit_selector: string;
  dismiss_selectors: string[];
  success_url_contains: string | null;
  identifiers: string[];
}

export interface AccountCreate {
  role_label: string;
  privilege_level: number;
  login_url: string;
  username: string;
  password: string;
  username_selector: string;
  password_selector: string;
  submit_selector: string;
  dismiss_selectors?: string[];
  success_url_contains?: string | null;
  identifiers?: string[];
}

export interface ScanOptions {
  max_pages?: number;
  max_depth?: number;
  request_delay_ms?: number;
  max_replays?: number;
  seed_paths?: string[];
  modules?: string[];
}

export interface ScanSummary {
  requests_recorded: number;
  replays_sent: number;
  findings_by_severity: {
    Critical: number;
    High: number;
    Medium: number;
    Low: number;
    Info: number;
  };
  discarded_low_confidence: number;
}

export interface Scan {
  id: number;
  target_id: number;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  options: ScanOptions;
  progress_percent: number;
  progress_stage: string;
  error_message: string | null;
  cancel_requested: boolean;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  summary: ScanSummary;
}

export interface ScanEvent {
  id: number;
  scan_id: number;
  level: string;
  stage: string;
  message: string;
  percent: number;
  created_at: string;
}

export interface Endpoint {
  id: number;
  scan_id: number;
  account_label: string;
  method: string;
  url: string;
  signature: string;
  resource_type: string;
  status_code: number;
  content_type: string | null;
  created_at: string;
}

export interface FindingEvidenceSection {
  role: string;
  status: number;
  headers: Record<string, string>;
  body_preview: string;
}

export interface FindingEvidence {
  original?: FindingEvidenceSection;
  replay?: FindingEvidenceSection;
  similarity?: number;
  stability?: number;
  signals?: string[];
  confidence_breakdown?: Record<string, any>;
  other_urls?: string[];
}

export interface Finding {
  id: number;
  scan_id: number;
  fingerprint: string;
  type: string;
  title: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  confidence: number;
  cvss_score: number;
  cvss_vector: string;
  cwe: string;
  owasp: string;
  method: string;
  url: string;
  signature: string;
  source_role: string;
  tested_role: string;
  status: 'open' | 'false_positive' | 'fixed' | 'accepted';
  created_at: string;
  description?: string;
  remediation?: string;
  note?: string | null;
  evidence?: FindingEvidence;
}

export interface FindingSummary {
  id: number;
  fingerprint: string;
  type: string;
  title: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  confidence: number;
  signature: string;
  url: string;
  status: string;
}

export interface CompareResult {
  new: FindingSummary[];
  fixed: FindingSummary[];
  persisting: FindingSummary[];
}

export interface AuditLog {
  id: number;
  user_id: number | null;
  action: string;
  resource_type: string | null;
  resource_id: number | null;
  ip: string | null;
  details: Record<string, any>;
  created_at: string;
}
