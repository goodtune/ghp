package proxy

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Reason values for graphQLDecision.Reason (the verdict vocabulary).
const (
	reasonAllow            = "allow"
	reasonParse            = "parse"
	reasonSubscription     = "deny:subscription"
	reasonUnmapped         = "deny:unmapped"
	reasonCrossRepo        = "deny:cross_repo"
	reasonMutationRepo     = "deny:mutation_repo"
	reasonUnpinned         = "deny:unpinned"
	reasonNoRepoRef        = "deny:no_repo_ref"
	reasonRepoNotAllowed   = "deny:repo_not_allowed"
	reasonMutationUnscoped = "deny:mutation_unscoped"
	reasonMissingScope     = "deny:missing_scope"
)

// graphQLDecision is the allow/deny outcome of graphQLVerdict.
type graphQLDecision struct {
	Allow            bool
	Status           int    // 0 when Allow; 400 for parse; 403 for denials
	Message          string // text passed to writeGraphQLError
	Reason           string // one of the reason* constants
	Repo             string // set for deny:repo_not_allowed, and for allow with exactly one referenced repo
	Analyzed         bool   // false only for the open-scoped shortcut (no analysis ran)
	Analysis         graphQLAnalysis
	AnalysisDuration time.Duration // time spent in analyzeGraphQLRequest
}

func graphQLDeny(d graphQLDecision, reason, msg string) graphQLDecision {
	d.Allow = false
	d.Status = http.StatusForbidden
	d.Reason = reason
	d.Message = msg
	return d
}

// graphQLVerdict decides whether a GraphQL request body is permitted for a
// token with the given scope restrictions. It is pure (no I/O, no metrics)
// so that it can be exercised offline; handleGraphQL owns metrics, logging
// and the HTTP response.
func graphQLVerdict(body []byte, si tokenScopeInfo) graphQLDecision {
	// Open-scoped tokens skip static analysis entirely.
	if si.isOpenScoped() {
		return graphQLDecision{Allow: true, Reason: reasonAllow}
	}

	// Static analysis: parse the query and extract required scopes,
	// referenced repositories, and any unknown fields encountered.
	analysisStart := time.Now()
	analysis, err := analyzeGraphQLRequest(body)
	d := graphQLDecision{Analyzed: true, AnalysisDuration: time.Since(analysisStart)}
	if err != nil {
		// Fail closed: a query we cannot parse is a query we cannot scope.
		// `analyzeGraphQLRequest` already prefixes its error strings with
		// "graphql:"; surface them directly so the message reads as a
		// single sentence rather than nesting two GraphQL-specific
		// prefixes.
		d.Status = http.StatusBadRequest
		d.Reason = reasonParse
		d.Message = fmt.Sprintf("Invalid request: %s", err.Error())
		return d
	}
	d.Analysis = analysis

	// Subscriptions are never permitted: GitHub's GraphQL endpoint does not
	// support them over HTTP, and even if it did the proxy has no way to
	// stream-scope per-event payloads.
	if analysis.hasSubscription {
		return graphQLDeny(d, reasonSubscription, "GraphQL subscriptions are not supported")
	}

	// Deny-by-default: any unknown field rejects the request when the token
	// has any restriction. The rendered field list is capped so an
	// adversarial query cannot inflate the response body (or audit log
	// line) to O(request size).
	if len(analysis.unknownFields) > 0 {
		return graphQLDeny(d, reasonUnmapped,
			fmt.Sprintf("GraphQL request references unmapped fields: %s", summariseFieldList(analysis.unknownFields, maxRenderedFieldNames)))
	}

	// Repository-scope enforcement.
	if len(si.Repos) > 0 {
		// Cross-repo fields cannot be statically constrained to a repo
		// allowlist (e.g. `search`, `node(id:)`, `viewer.repositories`).
		if len(analysis.crossRepoFields) > 0 {
			return graphQLDeny(d, reasonCrossRepo,
				fmt.Sprintf("Token is repository-restricted; GraphQL request uses cross-repository fields: %s",
					summariseFieldList(analysis.crossRepoFields, maxRenderedFieldNames)))
		}
		// GraphQL mutations on GitHub take an opaque `repositoryId`
		// (global node ID) which the proxy cannot statically map to its
		// allowlist.
		if analysis.hasMutation {
			return graphQLDeny(d, reasonMutationRepo,
				"Token is repository-restricted; GraphQL mutations are not supported for repository-scoped tokens (mutations identify their target by global node ID, which the proxy cannot statically map to a repository)")
		}
		// A `repository(owner, name)` selection whose arguments are not
		// literal strings cannot be validated against the allowlist, even
		// if other literal allowlisted lookups are present.
		if analysis.hasUnpinnedRepositoryLookup {
			return graphQLDeny(d, reasonUnpinned,
				"Token is repository-restricted; every repository(owner, name) selection must use literal string arguments (variable-driven lookups cannot be allowlist-checked)")
		}
		// Repository-restricted queries must include at least one literal
		// repository(owner, name) reference, and every referenced
		// repository must be in the allowlist.
		if len(analysis.referencedRepos) == 0 {
			return graphQLDeny(d, reasonNoRepoRef,
				"Token is repository-restricted; GraphQL request must reference repository(owner, name) with literal arguments")
		}
		for _, repo := range analysis.referencedRepos {
			if !si.repoAllowed(repo) {
				d.Repo = repo
				return graphQLDeny(d, reasonRepoNotAllowed, fmt.Sprintf("Token is not scoped to %s", repo))
			}
		}
	}

	// Permission-scope enforcement.
	if len(si.Scopes) > 0 {
		// Mutations require at least one mapped write scope (the
		// unknown-fields check above usually catches this first).
		if analysis.hasMutation && len(analysis.requiredScopes) == 0 {
			return graphQLDeny(d, reasonMutationUnscoped,
				"GraphQL mutation could not be statically scoped; rejected by deny-by-default policy")
		}
		if missing := analysis.missingScopes(si.Scopes); len(missing) > 0 {
			return graphQLDeny(d, reasonMissingScope,
				fmt.Sprintf("Token does not grant required GraphQL scopes: %s", strings.Join(missing, ", ")))
		}
	}

	d.Allow = true
	d.Reason = reasonAllow
	if len(analysis.referencedRepos) == 1 {
		d.Repo = analysis.referencedRepos[0]
	}
	return d
}
