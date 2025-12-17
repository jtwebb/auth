import { usePasskeyRegistration } from "../hooks/use-passkey-registration.js";

export type PasskeyRegistrationButtonProps = {
  registrationStartUrl: string;
  registrationFinishUrl: string;
  userId: string;
  userName: string;
  userDisplayName?: string;
  label?: string;
  onSuccess?: () => void;
};

export function PasskeyRegistrationButton(props: PasskeyRegistrationButtonProps) {
  const { register, isLoading, error } = usePasskeyRegistration({
    registrationStartUrl: props.registrationStartUrl,
    registrationFinishUrl: props.registrationFinishUrl,
  });

  return (
    <div>
      <button
        type="button"
        disabled={isLoading}
        onClick={async () => {
          await register({ userId: props.userId, userName: props.userName, userDisplayName: props.userDisplayName });
          props.onSuccess?.();
        }}
      >
        {props.label ?? "Add passkey"}
      </button>
      {error ? <div role="alert">{error.message}</div> : null}
    </div>
  );
}


