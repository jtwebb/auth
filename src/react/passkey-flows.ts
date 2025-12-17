import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { fetchJson } from "./fetch-json.js";
import type {
  FetchLike,
  PasskeyLoginFinishPayload,
  PasskeyLoginStartPayload,
  PasskeyLoginStartResult,
  PasskeyRegistrationFinishPayload,
  PasskeyRegistrationStartPayload,
  PasskeyRegistrationStartResult,
} from "./types.js";

export type PasskeyEndpoints = {
  registrationStartUrl: string;
  registrationFinishUrl: string;
  loginStartUrl: string;
  loginFinishUrl: string;
};

export type PasskeyDeps = {
  fetchFn?: FetchLike;
  startRegistrationFn?: typeof startRegistration;
  startAuthenticationFn?: typeof startAuthentication;
};

export function createPasskeyFlows(endpoints: PasskeyEndpoints, deps: PasskeyDeps = {}) {
  const fetchFn = deps.fetchFn ?? fetch;
  const startRegistrationFn = deps.startRegistrationFn ?? startRegistration;
  const startAuthenticationFn = deps.startAuthenticationFn ?? startAuthentication;

  return {
    async register(input: PasskeyRegistrationStartPayload) {
      const start = await fetchJson<PasskeyRegistrationStartResult>(fetchFn, endpoints.registrationStartUrl, {
        method: "POST",
        json: input,
        credentials: "include",
      });

      const response = await startRegistrationFn(start.options);
      const finishPayload: PasskeyRegistrationFinishPayload = {
        userId: input.userId,
        challengeId: start.challengeId,
        response,
      };
      await fetchJson(fetchFn, endpoints.registrationFinishUrl, { method: "POST", json: finishPayload, credentials: "include" });
      return { challengeId: start.challengeId };
    },

    async login(input: PasskeyLoginStartPayload = {}) {
      const start = await fetchJson<PasskeyLoginStartResult>(fetchFn, endpoints.loginStartUrl, {
        method: "POST",
        json: input,
        credentials: "include",
      });

      const response = await startAuthenticationFn(start.options);
      const finishPayload: PasskeyLoginFinishPayload = {
        challengeId: start.challengeId,
        response,
      };
      await fetchJson(fetchFn, endpoints.loginFinishUrl, { method: "POST", json: finishPayload, credentials: "include" });
      return { challengeId: start.challengeId };
    },
  };
}


