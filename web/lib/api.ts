import { config } from './config';

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

/** Call the guardrail API with the signed-in user's Cognito access token. */
export async function apiFetch<T>(path: string, token: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`${config.apiUrl}${path}`, {
    ...init,
    headers: { ...(init.headers ?? {}), Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, (body as { error?: string }).error ?? `Request failed (${res.status})`);
  return body as T;
}
