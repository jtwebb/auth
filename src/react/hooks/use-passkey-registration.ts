import * as React from "react";
import type { PasskeyEndpoints } from "../passkey-flows.js";
import { createPasskeyFlows } from "../passkey-flows.js";

export function usePasskeyRegistration(
  endpoints: Pick<PasskeyEndpoints, "registrationStartUrl" | "registrationFinishUrl">,
) {
  const [isLoading, setIsLoading] = React.useState(false);
  const [error, setError] = React.useState<Error | null>(null);

  const register = React.useCallback(
    async (input: { userId: string; userName: string; userDisplayName?: string }) => {
      setIsLoading(true);
      setError(null);
      try {
        const flows = createPasskeyFlows({
          registrationStartUrl: endpoints.registrationStartUrl,
          registrationFinishUrl: endpoints.registrationFinishUrl,
          loginStartUrl: "",
          loginFinishUrl: "",
        });
        return await flows.register(input);
      } catch (e) {
        const err = e instanceof Error ? e : new Error("Registration failed");
        setError(err);
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [endpoints.registrationFinishUrl, endpoints.registrationStartUrl],
  );

  return { register, isLoading, error };
}


