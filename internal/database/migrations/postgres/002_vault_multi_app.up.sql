-- Add app_slug column to github_tokens for multi-app (Vault) support.
-- In single-app mode (no vault), app_slug will be empty string.

ALTER TABLE github_tokens ADD COLUMN app_slug TEXT NOT NULL DEFAULT '';

-- Replace the unique constraint: (user_id) -> (user_id, app_slug).
ALTER TABLE github_tokens DROP CONSTRAINT github_tokens_user_id_key;
ALTER TABLE github_tokens ADD CONSTRAINT github_tokens_user_app_unique UNIQUE (user_id, app_slug);
