'use client';

import { useEffect, useState } from 'react';
import { ApiError, apiFetch } from '@/lib/api';
import type { AuditFlag } from '@/lib/types';

export default function AuditPanel({ token, isAdmin }: { token: string; isAdmin: boolean }) {
  const [flags, setFlags] = useState<AuditFlag[] | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    apiFetch<{ flags: AuditFlag[] }>('/audit?limit=50', token)
      .then((r) => setFlags(r.flags))
      .catch((e: ApiError) =>
        setError(e.status === 403 ? 'The audit log contains raw user inputs, so it is restricted to the "admins" group.' : e.message));
  }, [token]);

  if (error) {
    return (
      <div className="card">
        <h3>Access restricted</h3>
        <p className="muted">{error}</p>
        {!isAdmin && <p className="hint">The API enforces this with the token's cognito:groups claim — hiding the tab alone would not be enough.</p>}
      </div>
    );
  }
  if (!flags) return <div className="card muted">Loading audit log…</div>;
  if (flags.length === 0) return <div className="card muted">No flagged inputs yet.</div>;

  return (
    <div className="card table-wrap">
      <table>
        <thead>
          <tr><th>Time (UTC)</th><th>Risk</th><th>Type</th><th>Decided by</th><th>User</th><th>Input</th></tr>
        </thead>
        <tbody>
          {flags.map((f) => (
            <tr key={f.request_id}>
              <td className="mono nowrap">{f.timestamp.slice(0, 19).replace('T', ' ')}</td>
              <td><span className={`badge risk-${f.risk_level}`}>{f.risk_level}</span></td>
              <td>{f.attack_type.replaceAll('_', ' ')}</td>
              <td>{f.method.replaceAll('_', ' ')}</td>
              <td className="nowrap">{f.user}</td>
              <td className="input-cell" title={f.input_text}>{f.input_text}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
