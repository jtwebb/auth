import * as React from 'react';
import { createTotpFlows, type TotpEndpoints } from '../totp-flows.js';

export function useTotpVerify(endpoints: Pick<TotpEndpoints, 'verifyUrl'>) {
  const [isLoading, setIsLoading] = React.useState(false);
  const [error, setError] = React.useState<Error | null>(null);

  const verify = React.useCallback(
    async (code: string) => {
      setIsLoading(true);
      setError(null);
      try {
        const flows = createTotpFlows({
          enrollmentStartUrl: '',
          enrollmentFinishUrl: '',
          verifyUrl: endpoints.verifyUrl
        });
        return await flows.verify(code);
      } catch (e) {
        const err = e instanceof Error ? e : new Error('Invalid code');
        setError(err);
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [endpoints.verifyUrl]
  );

  return { verify, isLoading, error };
}
