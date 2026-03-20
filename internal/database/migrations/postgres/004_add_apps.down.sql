ALTER TABLE proxy_tokens DROP COLUMN IF EXISTS app_id;
ALTER TABLE github_tokens DROP COLUMN IF EXISTS app_id;
DROP INDEX IF EXISTS apps_single_default;
DROP TABLE IF EXISTS apps;
