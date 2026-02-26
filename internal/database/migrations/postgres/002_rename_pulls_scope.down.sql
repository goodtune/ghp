UPDATE proxy_tokens
SET scopes = REPLACE(scopes::text, '"pull_requests":', '"pulls":')::jsonb
WHERE scopes::text LIKE '%"pull_requests"%';
