import * as React from "react";
import { useTotpVerify } from "../hooks/use-totp-verify.js";

export type TotpVerifyFormProps = {
  verifyUrl: string;
  onSuccess?: () => void;
};

export function TotpVerifyForm(props: TotpVerifyFormProps) {
  const { verify, isLoading, error } = useTotpVerify({ verifyUrl: props.verifyUrl });
  const [code, setCode] = React.useState("");

  return (
    <form
      method="post"
      onSubmit={async (e) => {
        e.preventDefault();
        await verify(code);
        props.onSuccess?.();
      }}
    >
      <label>
        Authenticator code
        <input value={code} onChange={(e) => setCode(e.currentTarget.value)} autoComplete="one-time-code" />
      </label>
      <button type="submit" disabled={isLoading}>
        Verify
      </button>
      {error ? <div role="alert">{error.message}</div> : null}
    </form>
  );
}


