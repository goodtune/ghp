UPDATE proxy_tokens
SET scopes = REPLACE(scopes, '"pull_requests":', '"pulls":')
WHERE scopes LIKE '%"pull_requests"%';
