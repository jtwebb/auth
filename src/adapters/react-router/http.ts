import { AuthError } from "../../core/auth-error.js";

export function json(data: unknown, init: ResponseInit & { headers?: HeadersInit } = {}): Response {
  const headers = new Headers(init.headers);
  if (!headers.has("content-type")) headers.set("content-type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(data), { ...init, headers });
}

export function redirect(location: string, init: ResponseInit & { headers?: HeadersInit } = {}): Response {
  const headers = new Headers(init.headers);
  headers.set("location", location);
  return new Response(null, { ...init, status: init.status ?? 302, headers });
}

export async function readJson<T = any>(request: Request): Promise<T> {
  const ct = request.headers.get("content-type") ?? "";
  if (!ct.includes("application/json")) throw new AuthError("invalid_input", "Expected application/json request body");
  return (await request.json()) as T;
}

export async function readForm(request: Request): Promise<FormData> {
  const ct = request.headers.get("content-type") ?? "";
  if (!ct.includes("application/x-www-form-urlencoded") && !ct.includes("multipart/form-data")) {
    throw new AuthError("invalid_input", "Expected form-encoded request body");
  }
  return await request.formData();
}

export function assertSameOrigin(request: Request, allowedOrigins: readonly string[]): void {
  // For state-changing actions, ensure request came from our own site(s).
  // RR actions run server-side; Origin header is present for fetch/XHR and form POSTs in modern browsers.
  const origin = request.headers.get("origin");
  if (!origin) return; // allow non-browser clients; callers can enforce stricter policy
  if (!allowedOrigins.includes(origin)) {
    throw new AuthError("forbidden", "CSRF protection: invalid origin", { status: 403, publicMessage: "Forbidden" });
  }
}


