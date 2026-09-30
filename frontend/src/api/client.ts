/**
 * Typed API client for Aegis-Web backend.
 */

import {
  AuthResponse,
  CompareResult,
  Endpoint,
  Finding,
  FindingSummary,
  Scan,
  ScanEvent,
  ScanOptions,
  Target,
  TargetAccount,
  AccountCreate,
  TargetVerifyResponse,
  User,
  AuditLog,
} from './types';

export class ApiError extends Error {
  status: number;
  detail: string;

  constructor(status: number, detail: string) {
    super(`API Error ${status}: ${detail}`);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

let authToken: string | null = null;
let onUnauthorizedCallback: (() => void) | null = null;

export function setToken(token: string | null) {
  authToken = token;
}

export function getToken(): string | null {
  return authToken;
}

export function setOnUnauthorized(cb: () => void) {
  onUnauthorizedCallback = cb;
}

export function getBaseUrl(): string {
  const envUrl = import.meta.env.VITE_API_BASE_URL;
  if (envUrl) {
    return envUrl.replace(/\/+$/, '');
  }
  return '/api/v1';
}

async function request<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const baseUrl = getBaseUrl();
  const url = `${baseUrl}${path.startsWith('/') ? path : `/${path}`}`;

  const headers: Record<string, string> = {
    'Accept': 'application/json',
    ...(options.headers as Record<string, string> || {}),
  };

  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }

  if (options.body && typeof options.body === 'string' && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }

  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (response.status === 401) {
    setToken(null);
    if (typeof window !== 'undefined') {
      sessionStorage.removeItem('aegis_token');
    }
    if (onUnauthorizedCallback) {
      onUnauthorizedCallback();
    } else if (typeof window !== 'undefined' && window.location.pathname !== '/login') {
      window.location.href = '/login';
    }
    let detail = 'Unauthorized';
    try {
      const errJson = await response.json();
      detail = errJson.detail || detail;
    } catch {}
    throw new ApiError(401, detail);
  }

  if (!response.ok) {
    let detail = response.statusText;
    try {
      const errJson = await response.json();
      detail = errJson.detail || detail;
    } catch {}
    throw new ApiError(response.status, typeof detail === 'string' ? detail : JSON.stringify(detail));
  }

  if (response.status === 204) {
    return null as T;
  }

  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return (await response.json()) as T;
  }
  return (await response.text()) as unknown as T;
}

// -------------------------------------------------------------
// Authentication Endpoints
// -------------------------------------------------------------
export async function health(): Promise<{ status: string }> {
  return request<{ status: string }>('/health');
}

export async function register(email: string, password: string): Promise<User> {
  return request<User>('/auth/register', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
}

export async function login(email: string, password: string): Promise<AuthResponse> {
  const data = await request<AuthResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
  setToken(data.access_token);
  return data;
}

export async function getMe(): Promise<User> {
  return request<User>('/auth/me');
}

// -------------------------------------------------------------
// Target & Account Endpoints
// -------------------------------------------------------------
export async function createTarget(payload: {
  name: string;
  base_url: string;
  scope_hosts?: string[];
}): Promise<Target> {
  return request<Target>('/targets', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function listTargets(): Promise<Target[]> {
  return request<Target[]>('/targets');
}

export async function getTarget(id: number): Promise<Target> {
  return request<Target>(`/targets/${id}`);
}

export async function deleteTarget(id: number): Promise<void> {
  return request<void>(`/targets/${id}`, { method: 'DELETE' });
}

export async function verifyTarget(id: number): Promise<TargetVerifyResponse> {
  return request<TargetVerifyResponse>(`/targets/${id}/verify`, { method: 'POST' });
}

export async function markTargetLab(id: number): Promise<Target> {
  return request<Target>(`/targets/${id}/mark-lab`, { method: 'POST' });
}

export async function createAccount(
  targetId: number,
  payload: AccountCreate
): Promise<TargetAccount> {
  return request<TargetAccount>(`/targets/${targetId}/accounts`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function listAccounts(targetId: number): Promise<TargetAccount[]> {
  return request<TargetAccount[]>(`/targets/${targetId}/accounts`);
}

export async function deleteAccount(targetId: number, accountId: number): Promise<void> {
  return request<void>(`/targets/${targetId}/accounts/${accountId}`, { method: 'DELETE' });
}

// -------------------------------------------------------------
// Scans & Findings Endpoints
// -------------------------------------------------------------
export async function createScan(targetId: number, options?: ScanOptions): Promise<Scan> {
  return request<Scan>('/scans', {
    method: 'POST',
    body: JSON.stringify({ target_id: targetId, options: options || {} }),
  });
}

export async function listScans(): Promise<Scan[]> {
  return request<Scan[]>('/scans');
}

export async function getScan(id: number): Promise<Scan> {
  return request<Scan>(`/scans/${id}`);
}

export async function getScanEvents(id: number, after: number = 0): Promise<ScanEvent[]> {
  return request<ScanEvent[]>(`/scans/${id}/events?after=${after}`);
}

export async function cancelScan(id: number): Promise<Scan> {
  return request<Scan>(`/scans/${id}/cancel`, { method: 'POST' });
}

export async function getScanEndpoints(id: number): Promise<Endpoint[]> {
  return request<Endpoint[]>(`/scans/${id}/endpoints`);
}

export async function getScanFindings(
  id: number,
  filters?: { severity?: string; type?: string; status?: string }
): Promise<Finding[]> {
  const params = new URLSearchParams();
  if (filters?.severity) params.set('severity', filters.severity);
  if (filters?.type) params.set('type', filters.type);
  if (filters?.status) params.set('status', filters.status);
  const q = params.toString() ? `?${params.toString()}` : '';
  return request<Finding[]>(`/scans/${id}/findings${q}`);
}

export async function compareScans(id: number, otherId: number): Promise<CompareResult> {
  return request<CompareResult>(`/scans/${id}/compare/${otherId}`);
}

export async function getMarkdownReport(id: number): Promise<string> {
  return request<string>(`/scans/${id}/report.md`, {
    headers: { 'Accept': 'text/markdown' },
  });
}

export async function getJsonReport(id: number): Promise<{ scan: Scan; findings: Finding[] }> {
  return request<{ scan: Scan; findings: Finding[] }>(`/scans/${id}/report.json`);
}

export async function getFinding(id: number): Promise<Finding> {
  return request<Finding>(`/findings/${id}`);
}

export async function updateFinding(
  id: number,
  payload: { status?: string; note?: string }
): Promise<Finding> {
  return request<Finding>(`/findings/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  });
}

// -------------------------------------------------------------
// Admin Endpoints
// -------------------------------------------------------------
export async function getAuditLogs(limit: number = 50, offset: number = 0): Promise<AuditLog[]> {
  return request<AuditLog[]>(`/admin/audit-log?limit=${limit}&offset=${offset}`);
}
