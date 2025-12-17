import * as React from 'react';
import { createTotpFlows, type TotpEndpoints } from '../totp-flows.js';
import type { TotpEnrollmentStartResult } from '../types.js';

export function useTotpEnrollment(
  endpoints: Pick<TotpEndpoints, 'enrollmentStartUrl' | 'enrollmentFinishUrl'>
) {
  const [isLoading, setIsLoading] = React.useState(false);
  const [error, setError] = React.useState<Error | null>(null);
  const [enrollment, setEnrollment] = React.useState<TotpEnrollmentStartResult | null>(null);

  const start = React.useCallback(
    async (input: { userId: string; accountName: string }) => {
      setIsLoading(true);
      setError(null);
      try {
        const flows = createTotpFlows({ ...endpoints, verifyUrl: '' });
        const res = await flows.startEnrollment(input);
        setEnrollment(res);
        return res;
      } catch (e) {
        const err = e instanceof Error ? e : new Error('TOTP enrollment failed');
        setError(err);
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [endpoints.enrollmentStartUrl, endpoints.enrollmentFinishUrl]
  );

  const finish = React.useCallback(
    async (input: { userId: string; code: string }) => {
      setIsLoading(true);
      setError(null);
      try {
        const flows = createTotpFlows({ ...endpoints, verifyUrl: '' });
        const res = await flows.finishEnrollment(input);
        return res;
      } catch (e) {
        const err = e instanceof Error ? e : new Error('TOTP enrollment failed');
        setError(err);
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [endpoints.enrollmentStartUrl, endpoints.enrollmentFinishUrl]
  );

  return { start, finish, enrollment, isLoading, error };
}
