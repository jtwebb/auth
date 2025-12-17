import { usePasskeyLogin } from "../hooks/use-passkey-login.js";

export type PasskeyLoginButtonProps = {
  loginStartUrl: string;
  loginFinishUrl: string;
  userId?: string;
  label?: string;
  onSuccess?: () => void;
};

export function PasskeyLoginButton(props: PasskeyLoginButtonProps) {
  const { login, isLoading, error } = usePasskeyLogin({
    loginStartUrl: props.loginStartUrl,
    loginFinishUrl: props.loginFinishUrl,
  });

  return (
    <div>
      <button
        type="button"
        disabled={isLoading}
        onClick={async () => {
          await login({ userId: props.userId });
          props.onSuccess?.();
        }}
      >
        {props.label ?? "Sign in with passkey"}
      </button>
      {error ? <div role="alert">{error.message}</div> : null}
    </div>
  );
}


