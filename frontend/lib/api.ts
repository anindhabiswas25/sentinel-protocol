/* ===== Sentinel Protocol – API Client ===== */

import { API_BASE_URL } from "./constants";
import type {
  ContractAnalysisResponse,
  HealthResponse,
  NetworkInfo,
  AnalysisHistoryItem,
  StatsResponse,
} from "./types";

const BASE = `${API_BASE_URL}/api/v1`;

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(
      (body as Record<string, string>).detail ??
        `API error ${res.status}: ${res.statusText}`
    );
  }
  return res.json() as Promise<T>;
}

/* ── Contract Analysis ─────────────────────────────── */

export async function analyzeContract(
  address: string,
  network: string
): Promise<ContractAnalysisResponse> {
  return request<ContractAnalysisResponse>("/analyze", {
    method: "POST",
    body: JSON.stringify({ contract_address: address, network }),
  });
}

export async function analyzeSourceCode(
  sourceCode: string,
  contractName?: string
): Promise<ContractAnalysisResponse> {
  return request<ContractAnalysisResponse>("/analyze/source", {
    method: "POST",
    body: JSON.stringify({
      source_code: sourceCode,
      contract_name: contractName ?? "UserContract",
    }),
  });
}

/* ── Info Endpoints ────────────────────────────────── */

export async function getHealth(): Promise<HealthResponse> {
  return request<HealthResponse>("/health");
}

export async function getNetworks(): Promise<NetworkInfo[]> {
  return request<NetworkInfo[]>("/networks");
}

export async function getHistory(
  limit = 20
): Promise<AnalysisHistoryItem[]> {
  return request<AnalysisHistoryItem[]>(`/history?limit=${limit}`);
}

export async function getStats(): Promise<StatsResponse> {
  return request<StatsResponse>("/stats");
}

export async function validateAddress(
  address: string,
  network: string
): Promise<{ valid: boolean; address: string; network: string }> {
  return request(`/validate/${address}?network=${network}`);
}

export async function seedPatterns(): Promise<{ message: string }> {
  return request("/seed-patterns", { method: "POST" });
}
