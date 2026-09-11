UPDATE proxy_tokens
SET scopes = json_set(
    json_remove(scopes, '$.pulls'),
    '$.pull_requests',
    json_extract(scopes, '$.pulls')
)
WHERE json_extract(scopes, '$.pulls') IS NOT NULL;
