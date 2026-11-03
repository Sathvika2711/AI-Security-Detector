'use client';

import { WebStorageStateStore } from 'oidc-client-ts';
import { AuthProvider } from 'react-oidc-context';
import { authority, config, isConfigured } from '@/lib/config';

/**
 * OAuth 2.0 Authorization Code flow with PKCE against Cognito (OIDC).
 * No client secret exists in the browser; tokens live in sessionStorage
 * and are cleared when the tab closes.
 */
export default function Providers({ children }: { children: React.ReactNode }) {
  if (!isConfigured || typeof window === 'undefined') return <>{children}</>;

  return (
    <AuthProvider
      authority={authority}
      client_id={config.clientId}
      redirect_uri={`${window.location.origin}/`}
      response_type="code"
      scope="openid email profile"
      userStore={new WebStorageStateStore({ store: window.sessionStorage })}
      onSigninCallback={() => window.history.replaceState({}, document.title, window.location.pathname)}
    >
      {children}
    </AuthProvider>
  );
}
