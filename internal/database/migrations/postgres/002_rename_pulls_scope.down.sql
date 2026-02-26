UPDATE proxy_tokens
SET scopes = (scopes - 'pull_requests') || jsonb_build_object('pulls', scopes->'pull_requests')
WHERE scopes ? 'pull_requests';
