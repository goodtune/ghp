-- Revert multi-app support: remove app_slug, restore UNIQUE(user_id).

-- Delete duplicate rows keeping only the most recently updated per user.
DELETE FROM github_tokens a
USING github_tokens b
WHERE a.user_id = b.user_id AND a.updated_at < b.updated_at;

ALTER TABLE github_tokens DROP CONSTRAINT github_tokens_user_app_unique;
ALTER TABLE github_tokens ADD CONSTRAINT github_tokens_user_id_key UNIQUE (user_id);
ALTER TABLE github_tokens DROP COLUMN app_slug;
