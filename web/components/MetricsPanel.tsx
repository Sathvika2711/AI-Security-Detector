'use client';

import { useCallback, useEffect, useState } from 'react';
import { apiFetch } from '@/lib/api';
import type { Metrics, RiskLevel } from '@/lib/types';

const RISKS: RiskLevel[] = ['low', 'medium', 'high'];

export default function MetricsPanel({ token }: { token: string }) {
  const [m, setM] = useState<Metrics | null>(null);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setError('');
    try {
      setM(await apiFetch<Metrics>('/metrics?days=7', token));
    } catch (e) {
      setError((e as Error).message);
    }
  }, [token]);

  useEffect(() => { load(); }, [load]);

  if (error) return <div className="card error">{error}</div>;
  if (!m) return <div className="card muted">Loading metrics…</div>;
  if (m.total_requests === 0) return <div className="card muted">No requests in the last {m.window_days} days yet — run a scan first.</div>;

  const tiles: [string, string][] = [
    ['Requests (7 days)', m.total_requests.toLocaleString()],
    ['Resolved without LLM', `${m.requests_without_llm_call_pct}%`],
    ['Cache hit rate', `${m.cache_hit_rate_pct}%`],
    ['Total Bedrock cost', `$${(m.total_cost_usd ?? 0).toFixed(4)}`],
    ['Cost per 1k requests', `$${((m.avg_cost_per_request_usd ?? 0) * 1000).toFixed(3)}`],
    ['Latency p50 / p95', `${Math.round(m.latency_ms?.p50 ?? 0)} / ${Math.round(m.latency_ms?.p95 ?? 0)} ms`],
  ];
  const total = m.total_requests;

  return (
    <section className="stack">
      <div className="row between">
        <h2>Last {m.window_days} days</h2>
        <button className="ghost" onClick={load}>Refresh</button>
      </div>
      <div className="tiles">
        {tiles.map(([label, value]) => (
          <div className="card tile" key={label}>
            <div className="tile-label">{label}</div>
            <div className="tile-value num">{value}</div>
          </div>
        ))}
      </div>
      <div className="card">
        <h3>Verdicts by risk level</h3>
        {RISKS.map((r) => {
          const n = m.by_risk_level?.[r] ?? 0;
          const pct = total ? (100 * n) / total : 0;
          return (
            <div className="bar-row" key={r}>
              <span className="bar-label">{r}</span>
              <div className="bar-track"><div className={`bar-fill risk-${r}`} style={{ width: `${pct}%` }} /></div>
              <span className="bar-value num">{n} ({pct.toFixed(0)}%)</span>
            </div>
          );
        })}
      </div>
    </section>
  );
}
