UPDATE proxy_tokens
SET scopes = (scopes - 'pulls') || jsonb_build_object('pull_requests', scopes->'pulls')
WHERE scopes ? 'pulls';
