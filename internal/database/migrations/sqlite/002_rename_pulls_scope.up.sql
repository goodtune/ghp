UPDATE proxy_tokens
SET scopes = REPLACE(scopes, '"pulls":', '"pull_requests":')
WHERE scopes LIKE '%"pulls"%';
