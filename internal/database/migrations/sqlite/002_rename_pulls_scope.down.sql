UPDATE proxy_tokens
SET scopes = json_set(
    json_remove(scopes, '$.pull_requests'),
    '$.pulls',
    json_extract(scopes, '$.pull_requests')
)
WHERE json_extract(scopes, '$.pull_requests') IS NOT NULL;
