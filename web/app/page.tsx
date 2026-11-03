'use client';

import { useEffect, useState } from 'react';
import { useAuth } from 'react-oidc-context';
import AuditPanel from '@/components/AuditPanel';
import MetricsPanel from '@/components/MetricsPanel';
import ScanPanel from '@/components/ScanPanel';
import { config, isConfigured } from '@/lib/config';

type Tab = 'scan' | 'metrics' | 'audit';

export default function Home() {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  if (!mounted) return null;
  if (!isConfigured) return <NotConfigured />;
  return <Dashboard />;
}

function Dashboard() {
  const auth = useAuth();
  const [tab, setTab] = useState<Tab>('scan');

  if (auth.isLoading) return <Centered>Signing in…</Centered>;
  if (auth.error) return <Centered>Sign-in error: {auth.error.message}</Centered>;

  if (!auth.isAuthenticated || !auth.user) {
    return (
      <Centered>
        <h1 className="brand">AI Guardrail</h1>
        <p className="muted">Screens text for prompt injection before it reaches an LLM.</p>
        <button className="primary" onClick={() => auth.signinRedirect()}>Sign in</button>
      </Centered>
    );
  }

  const token = auth.user.access_token;
  const email = (auth.user.profile.email as string) ?? 'signed in';
  const groups = (auth.user.profile['cognito:groups'] as string[] | undefined) ?? [];
  const isAdmin = groups.includes('admins');

  const signOut = async () => {
    await auth.removeUser();
    const logoutUri = encodeURIComponent(`${window.location.origin}/`);
    window.location.href = `${config.cognitoDomain}/logout?client_id=${config.clientId}&logout_uri=${logoutUri}`;
  };

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">AI Guardrail</div>
        <nav className="tabs" aria-label="Sections">
          {(['scan', 'metrics', 'audit'] as Tab[]).map((t) => (
            <button key={t} className={tab === t ? 'tab active' : 'tab'} onClick={() => setTab(t)}>
              {t === 'scan' ? 'Scan' : t === 'metrics' ? 'Metrics' : 'Audit log'}
            </button>
          ))}
        </nav>
        <div className="user">
          <span className="muted">{email}{isAdmin ? ' · admin' : ''}</span>
          <button className="ghost" onClick={signOut}>Sign out</button>
        </div>
      </header>
      <main className="content">
        {tab === 'scan' && <ScanPanel token={token} />}
        {tab === 'metrics' && <MetricsPanel token={token} />}
        {tab === 'audit' && <AuditPanel token={token} isAdmin={isAdmin} />}
      </main>
    </div>
  );
}

function NotConfigured() {
  return (
    <Centered>
      <h1 className="brand">AI Guardrail</h1>
      <p className="muted">
        Not configured yet. Copy <code>web/.env.example</code> to <code>web/.env.local</code>, fill in the
        values from the <code>cdk deploy</code> outputs, and restart <code>npm run dev</code>.
      </p>
    </Centered>
  );
}

function Centered({ children }: { children: React.ReactNode }) {
  return <div className="centered"><div className="card narrow">{children}</div></div>;
}
