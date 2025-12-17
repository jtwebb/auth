import * as React from 'react';

export type LoginFormProps = {
  onSubmit: (input: { identifier: string; password: string }) => Promise<void> | void;
  defaultIdentifier?: string;
  submitLabel?: string;
};

export function LoginForm(props: LoginFormProps) {
  const [identifier, setIdentifier] = React.useState(props.defaultIdentifier ?? '');
  const [password, setPassword] = React.useState('');
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
          await props.onSubmit({ identifier, password });
        } catch (err) {
          setError(err instanceof Error ? err.message : 'Login failed');
        } finally {
          setIsSubmitting(false);
        }
      }}
    >
      <label>
        Identifier
        <input
          name="identifier"
          autoComplete="username"
          value={identifier}
          onChange={e => setIdentifier(e.currentTarget.value)}
        />
      </label>

      <label>
        Password
        <input
          name="password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={e => setPassword(e.currentTarget.value)}
        />
      </label>

      <button type="submit" disabled={isSubmitting}>
        {props.submitLabel ?? 'Sign in'}
      </button>

      {error ? <div role="alert">{error}</div> : null}
    </form>
  );
}
