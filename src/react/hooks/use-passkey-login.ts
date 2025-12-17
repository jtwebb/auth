import * as React from "react";
import type { PasskeyEndpoints } from "../passkey-flows.js";
import { createPasskeyFlows } from "../passkey-flows.js";

export function usePasskeyLogin(endpoints: Pick<PasskeyEndpoints, "loginStartUrl" | "loginFinishUrl">) {
  const [isLoading, setIsLoading] = React.useState(false);
  const [error, setError] = React.useState<Error | null>(null);

  const login = React.useCallback(
    async (input?: { userId?: string }) => {
      setIsLoading(true);
      setError(null);
      try {
        const flows = createPasskeyFlows({
          registrationStartUrl: "",
          registrationFinishUrl: "",
          loginStartUrl: endpoints.loginStartUrl,
          loginFinishUrl: endpoints.loginFinishUrl,
        });
        return await flows.login(input);
      } catch (e) {
        const err = e instanceof Error ? e : new Error("Login failed");
        setError(err);
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [endpoints.loginFinishUrl, endpoints.loginStartUrl],
  );

  return { login, isLoading, error };
}


