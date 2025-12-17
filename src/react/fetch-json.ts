import type { AuthApiError, FetchLike } from './types.js';

export async function fetchJson<T>(
  fetchFn: FetchLike,
  url: string,
  init: RequestInit & { json?: unknown } = {}
): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.json !== undefined) headers.set('content-type', 'application/json; charset=utf-8');

  const res = await fetchFn(url, {
    ...init,
    headers,
    body: init.json !== undefined ? JSON.stringify(init.json) : init.body
  });

  const text = await res.text();
  const data = text ? safeJsonParse(text) : null;

  if (!res.ok) {
    const err = (data as AuthApiError | null)?.error;
    const message = err?.message ?? `Request failed (${res.status})`;
    const code = err?.code ?? 'http_error';
    throw Object.assign(new Error(message), { code, status: res.status, response: data });
  }

  return data as T;
}

function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}
