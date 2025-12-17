import * as React from "react";
import { useTotpEnrollment } from "../hooks/use-totp-enrollment.js";

export type TotpSetupProps = {
  enrollmentStartUrl: string;
  enrollmentFinishUrl: string;
  userId: string;
  accountName: string;
  onEnabled?: () => void;
};

export function TotpSetup(props: TotpSetupProps) {
  const { start, finish, enrollment, isLoading, error } = useTotpEnrollment({
    enrollmentStartUrl: props.enrollmentStartUrl,
    enrollmentFinishUrl: props.enrollmentFinishUrl,
  });
  const [code, setCode] = React.useState("");

  return (
    <div>
      <button type="button" disabled={isLoading} onClick={() => start({ userId: props.userId, accountName: props.accountName })}>
        Start TOTP setup
      </button>

      {enrollment ? (
        <div>
          <p>Add this to your authenticator app (otpauth URI):</p>
          <pre>{enrollment.otpauthUri}</pre>

          <form
            onSubmit={async (e) => {
              e.preventDefault();
              await finish({ userId: props.userId, code });
              props.onEnabled?.();
            }}
          >
            <label>
              Code
              <input value={code} onChange={(e) => setCode(e.currentTarget.value)} autoComplete="one-time-code" />
            </label>
            <button type="submit" disabled={isLoading}>
              Enable TOTP
            </button>
          </form>
        </div>
      ) : null}

      {error ? <div role="alert">{error.message}</div> : null}
    </div>
  );
}


