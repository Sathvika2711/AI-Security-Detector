export type RiskLevel = 'low' | 'medium' | 'high';

export interface Usage {
  llm_calls: number;
  input_tokens: number;
  output_tokens: number;
  cost_usd: number;
  latency_ms: number;
  cache_hit: boolean;
}

export interface Verdict {
  request_id: string;
  risk_level: RiskLevel;
  attack_type: string;
  confidence: number;
  is_malicious: boolean;
  reasoning: string;
  safe_to_process: boolean;
  method: string;
  rule_flags: string[];
  usage: Usage;
}

export interface Metrics {
  window_days: number;
  total_requests: number;
  requests_without_llm_call_pct?: number;
  rule_short_circuit_count?: number;
  cache_hit_rate_pct?: number;
  llm_calls?: number;
  input_tokens?: number;
  output_tokens?: number;
  total_cost_usd?: number;
  avg_cost_per_request_usd?: number;
  latency_ms?: { avg: number; p50: number; p95: number };
  by_risk_level?: Partial<Record<RiskLevel, number>>;
  by_method?: Record<string, number>;
}

export interface AuditFlag {
  timestamp: string;
  request_id: string;
  user: string;
  input_text: string;
  risk_level: RiskLevel;
  attack_type: string;
  reasoning: string;
  method: string;
  rule_flags: string;
}
