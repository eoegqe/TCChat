ALTER TABLE tc_chat_messages ADD COLUMN encrypted_payload TEXT;

CREATE TABLE IF NOT EXISTS tc_chat_user_keys (
  user_id TEXT PRIMARY KEY NOT NULL,
  public_key_jwk TEXT NOT NULL,
  encrypted_private_key TEXT NOT NULL,
  private_key_iv TEXT NOT NULL,
  salt TEXT NOT NULL,
  kdf_iterations INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tc_chat_user_keys_updated
  ON tc_chat_user_keys(updated_at);
