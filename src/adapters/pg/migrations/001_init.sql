-- 001_init.sql
-- Postgres schema for @jtwebb/auth pg adapter
--
-- Notes:
-- - user ids are stored as TEXT (DB-agnostic); the adapter generates UUID strings by default.
-- - session tokens are never stored plaintext; only token_hash is stored.
-- - TOTP secrets must be encrypted at rest (encrypted_secret).

CREATE TABLE IF NOT EXISTS auth_users (
  id text PRIMARY KEY,
  identifier text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS auth_password_credentials (
  user_id text PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE,
  password_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NULL
);

CREATE TABLE IF NOT EXISTS auth_webauthn_credentials (
  id text PRIMARY KEY, -- credential ID (base64url)
  user_id text NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  credential_id text NOT NULL UNIQUE,
  public_key bytea NOT NULL,
  counter integer NOT NULL,
  transports text[] NULL,
  credential_device_type text NULL,
  credential_backed_up boolean NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NULL
);

CREATE TABLE IF NOT EXISTS auth_challenges (
  id text PRIMARY KEY,
  type text NOT NULL, -- passkey_register | passkey_login | totp_pending
  user_id text NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  challenge text NOT NULL,
  expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_challenges_expires_at_idx ON auth_challenges(expires_at);

CREATE TABLE IF NOT EXISTS auth_sessions (
  token_hash text PRIMARY KEY,
  user_id text NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL,
  last_seen_at timestamptz NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz NULL,
  rotated_from_hash text NULL
);
CREATE INDEX IF NOT EXISTS auth_sessions_user_id_idx ON auth_sessions(user_id);
CREATE INDEX IF NOT EXISTS auth_sessions_expires_at_idx ON auth_sessions(expires_at);

CREATE TABLE IF NOT EXISTS auth_backup_codes (
  user_id text NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  code_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  consumed_at timestamptz NULL,
  PRIMARY KEY (user_id, code_hash)
);
CREATE INDEX IF NOT EXISTS auth_backup_codes_user_id_consumed_idx ON auth_backup_codes(user_id, consumed_at);

CREATE TABLE IF NOT EXISTS auth_totp (
  user_id text PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE,
  encrypted_secret text NOT NULL,
  enabled_at timestamptz NULL,
  pending_created_at timestamptz NULL,
  last_used_at timestamptz NULL,
  last_used_step integer NULL
);


