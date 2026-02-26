UPDATE proxy_tokens
SET scopes = REPLACE(scopes::text, '"pulls":', '"pull_requests":')::jsonb
WHERE scopes::text LIKE '%"pulls"%';
