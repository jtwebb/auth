import * as React from 'react';

export type BackupCodeRedeemFormProps = {
  onSubmit: (input: { code: string }) => Promise<void> | void;
  submitLabel?: string;
};

export function BackupCodeRedeemForm(props: BackupCodeRedeemFormProps) {
  const [code, setCode] = React.useState('');
  const [isSubmitting, setIsSubmitting] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  return (
    <form
      method="post"
      onSubmit={async e => {
        e.preventDefault();
        setIsSubmitting(true);
        setError(null);
        try {
          await props.onSubmit({ code });
        } catch (err) {
          setError(err instanceof Error ? err.message : 'Redeem failed');
        } finally {
          setIsSubmitting(false);
        }
      }}
    >
      <label>
        Backup code
        <input
          name="code"
          value={code}
          onChange={e => setCode(e.currentTarget.value)}
          autoComplete="one-time-code"
        />
      </label>
      <button type="submit" disabled={isSubmitting}>
        {props.submitLabel ?? 'Use backup code'}
      </button>
      {error ? <div role="alert">{error}</div> : null}
    </form>
  );
}
