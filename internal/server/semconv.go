package server

// OpenTelemetry attribute keys used by the access and audit log records.
//
// Where an OpenTelemetry semantic convention exists for a concept we use its
// canonical key (the http.*, url.*, network.*, client.*, server.*,
// user_agent.* and enduser.* namespaces). GHP-specific concepts that have no
// standard convention live under the "ghp.*" namespace so they are clearly
// distinguishable from upstream conventions.
const (
	// HTTP / URL / network conventions.
	attrHTTPRequestMethod         = "http.request.method"
	attrHTTPResponseStatusCode    = "http.response.status_code"
	attrHTTPResponseBodySize      = "http.response.body.size"
	attrHTTPServerRequestDuration = "http.server.request.duration"
	attrHTTPRequestHeaderPrefix   = "http.request.header."
	attrHTTPResponseHeaderPrefix  = "http.response.header."
	attrURLPath                   = "url.path"
	attrURLQuery                  = "url.query"
	attrURLScheme                 = "url.scheme"
	attrNetworkProtocolName       = "network.protocol.name"
	attrNetworkProtocolVersion    = "network.protocol.version"
	attrClientAddress             = "client.address"
	attrClientPort                = "client.port"
	attrServerAddress             = "server.address"
	attrServerPort                = "server.port"
	attrUserAgentOriginal         = "user_agent.original"

	// End-user identity convention.
	attrEndUserID = "enduser.id"

	// GHP-specific attributes.
	attrGHPBackend     = "ghp.backend"
	attrGHPCacheState  = "ghp.cache.state"
	attrGHPCacheRepo   = "ghp.cache.repo"
	attrGHPRawAuth     = "ghp.raw.auth"
	attrGHPAuditAction = "ghp.audit.action"
	attrGHPUserName    = "ghp.user.name"
	attrGHPTokenID     = "ghp.token.id"
	attrGHPTokenType   = "ghp.token.type"
	attrGHPSessionID   = "ghp.session.id"
	attrGHPRepository  = "ghp.repository"
)
