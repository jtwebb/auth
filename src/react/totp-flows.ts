import { fetchJson } from "./fetch-json.js";
import type { FetchLike, TotpEnrollmentFinishPayload, TotpEnrollmentStartPayload, TotpEnrollmentStartResult } from "./types.js";

export type TotpEndpoints = {
  enrollmentStartUrl: string;
  enrollmentFinishUrl: string;
  verifyUrl: string;
};

export type TotpDeps = {
  fetchFn?: FetchLike;
};

export function createTotpFlows(endpoints: TotpEndpoints, deps: TotpDeps = {}) {
  const fetchFn = deps.fetchFn ?? fetch;

  return {
    async startEnrollment(input: TotpEnrollmentStartPayload) {
      return await fetchJson<TotpEnrollmentStartResult>(fetchFn, endpoints.enrollmentStartUrl, {
        method: "POST",
        json: input,
        credentials: "include",
      });
    },

    async finishEnrollment(input: TotpEnrollmentFinishPayload) {
      await fetchJson(fetchFn, endpoints.enrollmentFinishUrl, {
        method: "POST",
        json: input,
        credentials: "include",
      });
      return { enabled: true as const };
    },

    async verify(code: string) {
      // Adapter expects form-encoded for totpVerify; pending token is in httpOnly cookie.
      const res = await fetchFn(endpoints.verifyUrl, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ code }),
        credentials: "include",
      });
      if (!res.ok) {
        const text = await res.text();
        const data = text ? safeJsonParse(text) : null;
        const message = (data as any)?.error?.message ?? `Request failed (${res.status})`;
        const err = Object.assign(new Error(message), { code: (data as any)?.error?.code ?? "http_error", status: res.status });
        throw err;
      }
      return { ok: true as const };
    },
  };
}

function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}


