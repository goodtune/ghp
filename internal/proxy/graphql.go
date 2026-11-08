package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/goodtune/ghp/internal/database"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

// graphQLRequestBody is the JSON envelope GitHub's GraphQL endpoint expects.
// It is decoded by parseGraphQLEnvelope, never by encoding/json struct-field
// matching (which folds case and Unicode, so `Query` or `variableſ` would be
// read as `query` or `variables` while GitHub ignores them). Variables are
// kept as json.RawMessage: the analyser only reads the members that a
// `repository(owner:, name:)` lookup references (see resolveVariables).
type graphQLRequestBody struct {
	Query         string
	OperationName string
	Variables     json.RawMessage
}

// graphQLEnvelopeKeys are the only top-level members a request body may have.
var graphQLEnvelopeKeys = map[string]bool{
	"query": true, "operationName": true, "variables": true, "extensions": true,
}

// parseGraphQLEnvelope decodes the request envelope strictly: the body must
// be a JSON object whose keys are each exactly one of graphQLEnvelopeKeys,
// with no duplicates. Anything else is an error (400), because the proxy and
// GitHub could otherwise read different queries or variables from the same
// bytes. `query` and `operationName` must be strings (or null); `variables`
// is kept raw.
func parseGraphQLEnvelope(body []byte) (graphQLRequestBody, error) {
	var req graphQLRequestBody
	members, ok := objectMembers(body)
	if !ok {
		return req, fmt.Errorf("graphql: invalid request envelope: body must be a JSON object")
	}
	seen := map[string]bool{}
	for _, m := range members {
		if !graphQLEnvelopeKeys[m.key] {
			return req, fmt.Errorf("graphql: invalid request envelope: unexpected top-level key %q (allowed: query, operationName, variables, extensions)", m.key)
		}
		if seen[m.key] {
			return req, fmt.Errorf("graphql: invalid request envelope: duplicate top-level key %q", m.key)
		}
		seen[m.key] = true
		switch m.key {
		case "query":
			if err := decodeOptionalString(m.value, &req.Query); err != nil {
				return req, fmt.Errorf("graphql: invalid request envelope: query must be a string")
			}
		case "operationName":
			if err := decodeOptionalString(m.value, &req.OperationName); err != nil {
				return req, fmt.Errorf("graphql: invalid request envelope: operationName must be a string")
			}
		case "variables":
			req.Variables = m.value
		}
	}
	return req, nil
}

func decodeOptionalString(raw json.RawMessage, dst *string) error {
	raw = bytes.TrimSpace(raw)
	if string(raw) == "null" {
		return nil
	}
	if len(raw) == 0 || raw[0] != '"' {
		return fmt.Errorf("not a string")
	}
	return json.Unmarshal(raw, dst)
}

// graphQLAnalysis is the result of statically analysing a GraphQL request
// against the proxy token's scopes.
type graphQLAnalysis struct {
	// requiredScopes lists the (permission, level) pairs that must be granted
	// for this query to be permitted. A token must satisfy every entry.
	requiredScopes []scopeRequirement
	// referencedRepos lists every "owner/name" pair that appears as the
	// arguments to a `repository(owner, name)` selection in the query.
	referencedRepos []string
	// hasMutation is true when the operation selected for analysis (per
	// the request's `operationName`, or the sole operation when omitted)
	// is a mutation.
	hasMutation bool
	// hasSubscription is true when the operation selected for analysis is
	// a subscription. GitHub does not support GraphQL subscriptions over
	// HTTP; the proxy rejects them outright.
	hasSubscription bool
	// crossRepoFields lists fields that can return data from repositories
	// other than those pinned by `repository(owner, name)` (for example
	// `search`, `node`, `viewer.repositories`, `organization.repositories`).
	// A repository-restricted token cannot enforce its allowlist when these
	// fields are present, so the request is denied.
	crossRepoFields []string
	// unknownFields lists every field name encountered that is not on the
	// allowlist. Scoped tokens are denied if this list is non-empty
	// (deny-by-default). Open-scoped tokens ignore it.
	unknownFields []string
	// hasUnpinnedRepositoryLookup is true when a `repository(...)`
	// selection has arguments that do not resolve to strings (see
	// gqlAnalyzer.stringArg) and so cannot be pinned to an owner/name.
	// Repository-restricted tokens must reject such requests even if the
	// query also references at least one literal allowlisted repo —
	// otherwise an attacker could mix one literal allowlisted lookup
	// with an unresolvable lookup that bypasses the
	// allowlist.
	hasUnpinnedRepositoryLookup bool
	// introspectionOnly is true when the selected operation is a query
	// whose root selections (fragments expanded) are all `__type`,
	// `__schema` or `__typename` (#342). Such an operation selects no
	// repository data, so repository-restricted tokens do not need a
	// repository(owner, name) reference for it. Every other check still
	// applies.
	introspectionOnly bool
}

// scopeRequirement is a single (permission, level) entry.
type scopeRequirement struct {
	permission string
	level      string
}

// alwaysAllowedFields names the GraphQL fields that the proxy treats as
// metadata: they require no specific permission scope and are always
// allowed (subject to repository scoping for repo-pinned fields).
//
// The list intentionally errs on the side of "no permission needed" for
// fields that GitHub returns under metadata read access on every App
// installation — names, ids, descriptions, URLs, timestamps, owner login,
// etc. Anything that exposes a permission-gated resource (issues, pulls,
// secrets, deployments, …) must be mapped via fieldScopeRequirements
// instead.
var alwaysAllowedFields = map[string]struct{}{
	// Generic identity / metadata fields.
	"__typename":               {},
	"__schema":                 {},
	"__type":                   {},
	"id":                       {},
	"databaseId":               {},
	"name":                     {},
	"nameWithOwner":            {},
	"login":                    {},
	"slug":                     {},
	"url":                      {},
	"resourcePath":             {},
	"avatarUrl":                {},
	"description":              {},
	"createdAt":                {},
	"updatedAt":                {},
	"pushedAt":                 {},
	"isPrivate":                {},
	"isFork":                   {},
	"isArchived":               {},
	"isDisabled":               {},
	"isLocked":                 {},
	"isMirror":                 {},
	"isTemplate":               {},
	"isInOrganization":         {},
	"visibility":               {},
	"diskUsage":                {},
	"forkCount":                {},
	"stargazerCount":           {},
	"watchers":                 {},
	"languages":                {},
	"primaryLanguage":          {},
	"defaultBranchRef":         {},
	"licenseInfo":              {},
	"owner":                    {},
	"repositoryTopics":         {},
	"topics":                   {},
	"homepageUrl":              {},
	"sshUrl":                   {},
	"mirrorUrl":                {},
	"hasIssuesEnabled":         {},
	"hasProjectsEnabled":       {},
	"hasWikiEnabled":           {},
	"hasDiscussionsEnabled":    {},
	"openGraphImageUrl":        {},
	"usesCustomOpenGraphImage": {},
	"fundingLinks":             {},
	"codeOfConduct":            {},

	// Pagination & connection helpers.
	"nodes":           {},
	"edges":           {},
	"pageInfo":        {},
	"totalCount":      {},
	"hasNextPage":     {},
	"hasPreviousPage": {},
	"endCursor":       {},
	"startCursor":     {},
	"cursor":          {},
	// Edge.node. Root node(id:) is a lookup handled by rootLookupFields
	// before this table is consulted, and stays cross-repository.
	"node": {},

	// Root fields that are themselves harmless without further selection;
	// the children determine the actual scope requirement.
	"viewer":                  {},
	"repository":              {},
	"repositoryOwner":         {},
	"user":                    {},
	"organization":            {},
	"rateLimit":               {},
	"meta":                    {},
	"codeOfConducts":          {},
	"licenses":                {},
	"license":                 {},
	"marketplaceListing":      {},
	"marketplaceCategories":   {},
	"securityAdvisory":        {},
	"securityAdvisories":      {},
	"securityVulnerabilities": {},

	// Common scalar projections on identity types.
	"email":           {},
	"company":         {},
	"location":        {},
	"bio":             {},
	"twitterUsername": {},
	"websiteUrl":      {},
	"isViewer":        {},
	"isSiteAdmin":     {},

	// Actor references on an already-gated parent (#298): the parent field
	// (issue, pullRequest, reviewRequests, autoMergeRequest, reactionGroups)
	// carries the scope; these return only User/Bot/Team/Mannequin identity.
	"assignees":         {},
	"author":            {},
	"enabledBy":         {},
	"requestedReviewer": {},
	"users":             {},

	// Introspection shape under __type (#298, gh feature-detection probes).
	// The name `fields` also exists on ProjectV2, whose parent is gated by
	// projects:read. `args`, `type` and `ofType` are deliberately absent
	// until gh is seen sending them (`type` collides with object fields).
	"enumValues": {},
	"fields":     {},
}

// fieldScopeRequirements maps GraphQL field names to the GitHub App
// permission scope they require. The lookup is by field name only — the
// proxy does not load GitHub's full SDL, so a field with the same name on
// different parent types is treated identically. This is conservative for
// security purposes: where ambiguity exists we err on the side of requiring
// the strictest scope.
//
// Unknown fields in a scoped query are rejected (deny-by-default); add new
// entries here as legitimate use cases surface.
var fieldScopeRequirements = map[string]scopeRequirement{
	// Issues
	"issue":                          {"issues", "read"},
	"issues":                         {"issues", "read"},
	"issueOrPullRequest":             {"issues", "read"},
	"closedByPullRequestsReferences": {"issues", "read"},
	"timelineItems":                  {"issues", "read"},
	"reactions":                      {"issues", "read"},
	"reactionGroups":                 {"issues", "read"},
	// #298. Issue-graph fields that can point outside the repository
	// (blockedBy, blocking, parent, subIssues) are also in
	// metadataOnlySubtreeFields (#339).
	// `parent` is also Repository.parent (fork source): issues:read is the
	// stricter of the two meanings. `comments` is also on PullRequest,
	// Commit and PullRequestReview: PR comments are issue comments.
	// `labels` and `milestone` have no gated parent under repository{}.
	"blockedBy":        {"issues", "read"},
	"blocking":         {"issues", "read"},
	"comments":         {"issues", "read"},
	"issueType":        {"issues", "read"},
	"labels":           {"issues", "read"},
	"milestone":        {"issues", "read"},
	"parent":           {"issues", "read"},
	"subIssues":        {"issues", "read"},
	"subIssuesSummary": {"issues", "read"},

	// Pull requests
	"pullRequest":              {"pull_requests", "read"},
	"pullRequests":             {"pull_requests", "read"},
	"reviews":                  {"pull_requests", "read"},
	"reviewRequests":           {"pull_requests", "read"},
	"reviewThreads":            {"pull_requests", "read"},
	"latestReviews":            {"pull_requests", "read"},
	"latestOpinionatedReviews": {"pull_requests", "read"},
	"mergeQueue":               {"pull_requests", "read"},
	"mergeQueueEntry":          {"pull_requests", "read"},
	// #298. headRepository/headRepositoryOwner can name a fork outside the
	// allowlist; also in metadataOnlySubtreeFields (#339).
	"autoMergeRequest":    {"pull_requests", "read"},
	"headRepository":      {"pull_requests", "read"},
	"headRepositoryOwner": {"pull_requests", "read"},

	// Discussions
	"discussion":           {"discussions", "read"},
	"discussions":          {"discussions", "read"},
	"discussionCategory":   {"discussions", "read"},
	"discussionCategories": {"discussions", "read"},

	// Contents / git data
	"object":                {"contents", "read"},
	"ref":                   {"contents", "read"},
	"refs":                  {"contents", "read"},
	"branchProtectionRule":  {"administration", "read"},
	"branchProtectionRules": {"administration", "read"},
	"rulesets":              {"administration", "read"},
	"ruleset":               {"administration", "read"},
	"release":               {"contents", "read"},
	"releases":              {"contents", "read"},
	"tag":                   {"contents", "read"},
	"tags":                  {"contents", "read"},
	"file":                  {"contents", "read"},
	"tree":                  {"contents", "read"},
	"blob":                  {"contents", "read"},
	"commit":                {"contents", "read"},
	"commitComments":        {"contents", "read"},
	"history":               {"contents", "read"},
	"baseRef":               {"contents", "read"}, // #298, like ref/refs
	"commits":               {"contents", "read"}, // #298

	// Deployments / environments
	"deployment":   {"deployments", "read"},
	"deployments":  {"deployments", "read"},
	"environment":  {"environments", "read"},
	"environments": {"environments", "read"},

	// Actions / workflows
	"workflowRun":       {"actions", "read"},
	"workflowRuns":      {"actions", "read"},
	"actionsCacheUsage": {"actions", "read"},
	"workflowFile":      {"actions", "read"},
	"workflow":          {"actions", "read"}, // #298, like workflowRun

	// Statuses & checks
	"status":            {"statuses", "read"},
	"statuses":          {"statuses", "read"},
	"statusCheckRollup": {"checks", "read"},
	"checkSuite":        {"checks", "read"},
	"checkSuites":       {"checks", "read"},
	"checkRun":          {"checks", "read"},
	"checkRuns":         {"checks", "read"},
	// #298. StatusCheckRollup.contexts mixes CheckRun and StatusContext
	// items; one entry holds one scope, so checks:read (same as
	// statusCheckRollup) is required and StatusContext data rides on it.
	"checkRunCountsByState":      {"checks", "read"},
	"contexts":                   {"checks", "read"},
	"statusContextCountsByState": {"statuses", "read"},

	// Security
	"vulnerabilityAlerts":    {"vulnerability_alerts", "read"},
	"securityScanningAlerts": {"secret_scanning_alerts", "read"},

	// Repository administration
	"collaborators": {"administration", "read"},
	"invitations":   {"administration", "read"},

	// Repository lists (#298, gh repo list). Also in
	// crossRepoAnywhereFields, so repository-restricted tokens stay denied.
	"repositories": {"metadata", "read"},

	// Organization members
	"membersWithRole": {"members", "read"},
	"pendingMembers":  {"members", "read"},
	"memberStatuses":  {"members", "read"},

	// Projects
	"project":    {"projects", "read"},
	"projects":   {"projects", "read"},
	"projectsV2": {"projects", "read"},
	"projectV2":  {"projects", "read"},
	// #298. gh issue/pr view project item probes.
	"fieldValueByName": {"projects", "read"},
	"projectItems":     {"projects", "read"},

	// Webhooks (no GraphQL surface for webhook config today, but reserve the
	// field name in case GitHub adds one).
	"hooks": {"repository_hooks", "read"},
}

// crossRepoRootOnlyFields lists fields that are cross-repository when used
// as a root selection (`{ node(id: ...) { ... } }`) but are unrelated
// connection helpers when nested (e.g. `Connection.nodes`,
// `Edge.node`). The analyzer only flags these when the field appears at
// an operation's top level.
var crossRepoRootOnlyFields = map[string]struct{}{
	"node":     {},
	"nodes":    {},
	"resource": {},
}

// rootLookupFields names the root fields that fetch arbitrary objects by
// global ID, URL or search query (#324). Their result type is an interface
// or union, so the field name alone says nothing about what is read. At the
// operation root they never pass through alwaysAllowedFields: each fragment
// at the result position must name a type condition in
// typeConditionScopeRequirements, and that scope is required. A result
// position with no fragment, or a fragment with an unmapped type condition,
// is unknown (denied). Nested uses (e.g. `Connection.nodes`) are not
// affected. These names also stay in crossRepoRootOnlyFields or
// crossRepoAnywhereFields, so repository-restricted tokens still deny them.
var rootLookupFields = map[string]struct{}{
	"node":     {},
	"nodes":    {},
	"resource": {},
	"search":   {},
}

// typeConditionScopeRequirements maps an inline or named fragment type
// condition beneath a root lookup (see rootLookupFields) to the scope that
// reading that object type requires. Any type condition not listed here is
// denied. Interface type conditions (e.g. `Node`, `Comment`) are
// deliberately absent: they do not pin a concrete type.
var typeConditionScopeRequirements = map[string]scopeRequirement{
	"Bot":           {"metadata", "read"},
	"CheckRun":      {"checks", "read"},
	"CheckSuite":    {"checks", "read"},
	"Commit":        {"contents", "read"},
	"Discussion":    {"discussions", "read"},
	"Issue":         {"issues", "read"},
	"Organization":  {"metadata", "read"},
	"PullRequest":   {"pull_requests", "read"},
	"Release":       {"contents", "read"},
	"Repository":    {"metadata", "read"},
	"StatusContext": {"statuses", "read"},
	"Team":          {"metadata", "read"},
	"User":          {"metadata", "read"},
}

// crossRepoAnywhereFields lists fields that can leak data from
// repositories other than those addressed by the request's
// `repository(owner, name)` selections. Repository-scoped tokens cannot
// statically prove the repositories returned by these fields fall inside
// the allowlist, so the request is rejected wherever they appear.
var crossRepoAnywhereFields = map[string]struct{}{
	"search":                  {},
	"searchUsers":             {},
	"repositories":            {},
	"topRepositories":         {},
	"watching":                {},
	"starredRepositories":     {},
	"contributedRepositories": {},
	"pinnedRepositories":      {},
	"recentProjects":          {},
}

// metadataOnlySubtreeFields names fields that can return an object from a
// repository outside the request's pinned `repository(owner, name)`
// selections (#339): a pull request's head fork or its owner, a fork's
// parent repository, or a linked issue. The field itself keeps its scope
// from fieldScopeRequirements. Beneath it, every selection must be in
// alwaysAllowedFields or be a scalar leaf in metadataSubtreeLeaves;
// anything else is recorded as the cross-repository field
// `<subtree>.<field>`, so repository-restricted tokens are denied. Scope and
// unmapped classification still run, so permission-only tokens see no
// change.
//
// closedByPullRequestsReferences can name pull requests in other
// repositories and is treated the same way. timelineItems children that
// point at other repositories (CrossReferencedEvent.source,
// ConnectedEvent.subject, MarkedAsDuplicateEvent.canonical) are denied
// today only because `source`, `subject` and `canonical` are unmapped; if
// they are ever mapped they must be added here as metadata-only.
var metadataOnlySubtreeFields = map[string]struct{}{
	"blockedBy":                      {},
	"blocking":                       {},
	"closedByPullRequestsReferences": {},
	"headRepository":                 {},
	"headRepositoryOwner":            {},
	"parent":                         {},
	"subIssues":                      {},
}

// metadataSubtreeLeaves are scalar leaves permitted beneath a
// metadataOnlySubtreeFields entry in addition to alwaysAllowedFields.
// `gh issue view` selects `parent{id,number,title,url,state,...}` and the
// same shape under subIssues, blockedBy and blocking, so a linked issue's
// number, title and state in another repository are disclosed (documented
// trade-off). They are accepted only as leaves, never with a selection set.
var metadataSubtreeLeaves = map[string]struct{}{
	"number": {},
	"state":  {},
	"title":  {},
}

// crossRepoParentAwareFields are connections that span repositories unless
// they hang directly off a pinned `repository(owner, name)` lookup (#340).
// `User.issues`, `Viewer.pullRequests`, `User.issueComments` and the like
// return objects from every repository the credential can see. They are
// cross-repository unless the immediate parent field (fragments are
// transparent) is a pinned repository lookup. A bare `repository` with no
// arguments (e.g. `Issue.repository`) is not pinned.
var crossRepoParentAwareFields = map[string]struct{}{
	"commitComments": {},
	"issueComments":  {},
	"issues":         {},
	"pullRequests":   {},
}

// introspectionRootFields are the root selections that leave an operation
// introspection-only (see graphQLAnalysis.introspectionOnly).
var introspectionRootFields = map[string]struct{}{
	"__schema":   {},
	"__type":     {},
	"__typename": {},
}

// mutationScopeRequirements maps GitHub GraphQL mutation field names to the
// permission scope they require. The list covers the well-known mutations
// agents use; unknown mutations fall through to the default-deny path.
var mutationScopeRequirements = map[string]scopeRequirement{
	// Issues
	"createIssue":                   {"issues", "write"},
	"updateIssue":                   {"issues", "write"},
	"closeIssue":                    {"issues", "write"},
	"reopenIssue":                   {"issues", "write"},
	"deleteIssue":                   {"issues", "write"},
	"transferIssue":                 {"issues", "write"},
	"lockLockable":                  {"issues", "write"},
	"unlockLockable":                {"issues", "write"},
	"pinIssue":                      {"issues", "write"},
	"unpinIssue":                    {"issues", "write"},
	"addAssigneesToAssignable":      {"issues", "write"},
	"removeAssigneesFromAssignable": {"issues", "write"},
	"addLabelsToLabelable":          {"issues", "write"},
	"removeLabelsFromLabelable":     {"issues", "write"},
	"clearLabelsFromLabelable":      {"issues", "write"},
	"updateIssueComment":            {"issues", "write"},
	"deleteIssueComment":            {"issues", "write"},
	"addComment":                    {"issues", "write"},

	// Pull requests
	"createPullRequest":               {"pull_requests", "write"},
	"updatePullRequest":               {"pull_requests", "write"},
	"closePullRequest":                {"pull_requests", "write"},
	"reopenPullRequest":               {"pull_requests", "write"},
	"mergePullRequest":                {"pull_requests", "write"},
	"markPullRequestReadyForReview":   {"pull_requests", "write"},
	"convertPullRequestToDraft":       {"pull_requests", "write"},
	"enablePullRequestAutoMerge":      {"pull_requests", "write"},
	"disablePullRequestAutoMerge":     {"pull_requests", "write"},
	"requestReviews":                  {"pull_requests", "write"},
	"removeRequestedReviewers":        {"pull_requests", "write"},
	"addPullRequestReview":            {"pull_requests", "write"},
	"updatePullRequestReview":         {"pull_requests", "write"},
	"submitPullRequestReview":         {"pull_requests", "write"},
	"deletePullRequestReview":         {"pull_requests", "write"},
	"dismissPullRequestReview":        {"pull_requests", "write"},
	"addPullRequestReviewComment":     {"pull_requests", "write"},
	"updatePullRequestReviewComment":  {"pull_requests", "write"},
	"deletePullRequestReviewComment":  {"pull_requests", "write"},
	"addPullRequestReviewThread":      {"pull_requests", "write"},
	"resolveReviewThread":             {"pull_requests", "write"},
	"unresolveReviewThread":           {"pull_requests", "write"},
	"addPullRequestReviewThreadReply": {"pull_requests", "write"},

	// Contents / git data
	"createCommitOnBranch":       {"contents", "write"},
	"createRef":                  {"contents", "write"},
	"updateRef":                  {"contents", "write"},
	"deleteRef":                  {"contents", "write"},
	"createRepository":           {"administration", "write"},
	"updateRepository":           {"administration", "write"},
	"createBranchProtectionRule": {"administration", "write"},
	"updateBranchProtectionRule": {"administration", "write"},
	"deleteBranchProtectionRule": {"administration", "write"},
	"createTag":                  {"contents", "write"},
	"createRelease":              {"contents", "write"},
	"updateRelease":              {"contents", "write"},
	"deleteRelease":              {"contents", "write"},

	// Discussions
	"createDiscussion":                {"discussions", "write"},
	"updateDiscussion":                {"discussions", "write"},
	"deleteDiscussion":                {"discussions", "write"},
	"addDiscussionComment":            {"discussions", "write"},
	"updateDiscussionComment":         {"discussions", "write"},
	"deleteDiscussionComment":         {"discussions", "write"},
	"markDiscussionCommentAsAnswer":   {"discussions", "write"},
	"unmarkDiscussionCommentAsAnswer": {"discussions", "write"},

	// Reactions are scoped to the parent resource. Without schema
	// information we cannot tell whether a reaction targets an issue,
	// discussion, pr, or commit. Conservatively require issues:write,
	// matching GitHub's behaviour for issue-attached reactions.
	"addReaction":    {"issues", "write"},
	"removeReaction": {"issues", "write"},

	// Deployments
	"createDeployment":       {"deployments", "write"},
	"createDeploymentStatus": {"deployments", "write"},

	// Projects
	"addProjectCard":                {"projects", "write"},
	"updateProjectCard":             {"projects", "write"},
	"deleteProjectCard":             {"projects", "write"},
	"createProjectV2":               {"projects", "write"},
	"updateProjectV2":               {"projects", "write"},
	"deleteProjectV2":               {"projects", "write"},
	"addProjectV2ItemById":          {"projects", "write"},
	"deleteProjectV2Item":           {"projects", "write"},
	"updateProjectV2ItemFieldValue": {"projects", "write"},
}

// analyzeGraphQLRequest parses a GraphQL request body and returns a static
// analysis describing the required scopes, referenced repositories, and
// any unknown fields encountered. The caller decides whether the analysis
// satisfies the proxy token's restrictions.
//
// An empty or unparseable body returns an error so the caller can fail
// closed. A request that contains no operations is treated the same way.
func analyzeGraphQLRequest(body []byte) (graphQLAnalysis, error) {
	req, err := parseGraphQLEnvelope(body)
	if err != nil {
		return graphQLAnalysis{}, err
	}
	if strings.TrimSpace(req.Query) == "" {
		return graphQLAnalysis{}, fmt.Errorf("graphql: empty query")
	}
	doc, err := parser.ParseQuery(&ast.Source{Input: req.Query})
	if err != nil {
		return graphQLAnalysis{}, fmt.Errorf("graphql: parse error: %w", err)
	}
	if len(doc.Operations) == 0 {
		return graphQLAnalysis{}, fmt.Errorf("graphql: no operation in document")
	}

	// Build a fragment lookup table so we can resolve fragment spreads.
	fragments := map[string]*ast.FragmentDefinition{}
	for _, frag := range doc.Fragments {
		fragments[frag.Name] = frag
	}

	// GitHub executes a single operation per request: the one named by
	// `operationName`, or — when omitted — the sole operation in the
	// document. Match that semantic so a multi-operation document is not
	// punished for operations the executor would never run.
	op, err := selectOperation(doc, req.OperationName)
	if err != nil {
		return graphQLAnalysis{}, err
	}

	a := &gqlAnalyzer{
		varDefs:       op.VariableDefinitions,
		vars:          resolveVariables(req.Variables, len(doc.Operations)),
		fragments:     fragments,
		fragmentStack: map[string]bool{},
		seenScopes:    map[scopeRequirement]struct{}{},
		seenRepos:     map[string]struct{}{},
		seenCrossRepo: map[string]struct{}{},
		seenUnknown:   map[string]struct{}{},
	}

	switch op.Operation {
	case ast.Mutation:
		a.result.hasMutation = true
	case ast.Subscription:
		a.result.hasSubscription = true
	}
	// Walk the selection set. Top-level selections are special only in
	// that mutations also carry a per-field scope requirement; otherwise
	// the walk treats every selection identically.
	a.walkSelectionSet(op.SelectionSet, op.Operation == ast.Mutation, true, 1, walkCtx{})
	a.result.introspectionOnly = op.Operation == ast.Query && a.sawRootField && !a.sawNonIntrospectionRoot
	if a.tooDeep {
		return graphQLAnalysis{}, fmt.Errorf("graphql: query exceeds maximum analysis depth (%d)", maxAnalysisDepth)
	}

	// Materialise the deduplicated maps into deterministic slices. When the
	// query requires both read and write of the same permission, keep only
	// the stricter (write) entry: write implies read in
	// database.Scopes.HasPermission.
	collapsed := map[string]string{}
	for s := range a.seenScopes {
		existing, ok := collapsed[s.permission]
		if !ok || (existing == "read" && s.level == "write") {
			collapsed[s.permission] = s.level
		}
	}
	for perm, lvl := range collapsed {
		a.result.requiredScopes = append(a.result.requiredScopes, scopeRequirement{permission: perm, level: lvl})
	}
	sort.Slice(a.result.requiredScopes, func(i, j int) bool {
		if a.result.requiredScopes[i].permission != a.result.requiredScopes[j].permission {
			return a.result.requiredScopes[i].permission < a.result.requiredScopes[j].permission
		}
		return a.result.requiredScopes[i].level < a.result.requiredScopes[j].level
	})
	for r := range a.seenRepos {
		a.result.referencedRepos = append(a.result.referencedRepos, r)
	}
	sort.Strings(a.result.referencedRepos)
	for f := range a.seenCrossRepo {
		a.result.crossRepoFields = append(a.result.crossRepoFields, f)
	}
	sort.Strings(a.result.crossRepoFields)
	for f := range a.seenUnknown {
		a.result.unknownFields = append(a.result.unknownFields, f)
	}
	sort.Strings(a.result.unknownFields)

	return a.result, nil
}

// selectOperation picks the single operation that GitHub will execute for
// a request. When `operationName` is non-empty it must match one of the
// operations in the document; otherwise the document must contain exactly
// one operation. A request that supplies multiple operations without
// naming one is ambiguous and rejected — the proxy refuses to forward
// queries it cannot statically scope.
func selectOperation(doc *ast.QueryDocument, operationName string) (*ast.OperationDefinition, error) {
	if operationName != "" {
		for _, op := range doc.Operations {
			if op.Name == operationName {
				return op, nil
			}
		}
		return nil, fmt.Errorf("graphql: operationName %q not found in document", operationName)
	}
	if len(doc.Operations) > 1 {
		return nil, fmt.Errorf("graphql: document has multiple operations; operationName is required")
	}
	return doc.Operations[0], nil
}

type gqlAnalyzer struct {
	// varDefs are the selected operation's variable definitions and vars
	// the request's variables, or nil when they must not be trusted (see
	// resolveVariables). Both are used only to pin repository lookups.
	varDefs   ast.VariableDefinitionList
	vars      map[string]json.RawMessage
	fragments map[string]*ast.FragmentDefinition
	// fragmentStack holds the fragment names currently being walked, so
	// recursive fragment spreads (which the GraphQL spec disallows) cannot
	// drive the analyzer into infinite recursion. Unlike a flat
	// "visited" set, the stack permits the same fragment to be analysed
	// multiple times in unrelated contexts (e.g. once at the operation
	// root and once again inside a nested selection), which matters because
	// the `atRoot`/`inMutation` flags affect mutation root-field scoping.
	fragmentStack map[string]bool
	result        graphQLAnalysis
	seenScopes    map[scopeRequirement]struct{}
	seenRepos     map[string]struct{}
	seenCrossRepo map[string]struct{}
	seenUnknown   map[string]struct{}
	// tooDeep is set if the walk exceeds maxAnalysisDepth; the caller
	// surfaces this as a 400 instead of forwarding the request, since a
	// query the analyzer cannot fully traverse cannot be safely scoped.
	tooDeep bool
	// sawRootField and sawNonIntrospectionRoot track the operation's root
	// selections for graphQLAnalysis.introspectionOnly.
	sawRootField            bool
	sawNonIntrospectionRoot bool
}

// walkCtx is the parent context passed down the walk. Fragments pass it
// through unchanged, so a field inside `... on User { }` sees the field
// that holds the fragment as its parent.
type walkCtx struct {
	// parent is the immediate enclosing field name ("" at the root).
	parent string
	// pinnedRepo is true when parent is a `repository(owner, name)`
	// lookup whose arguments resolved (see crossRepoParentAwareFields).
	pinnedRepo bool
	// metadataOnly names the enclosing metadataOnlySubtreeFields entry, or
	// "" outside such a subtree.
	metadataOnly string
}

// maxAnalysisDepth caps the depth of the AST walk so that a malicious
// (but still ≤ maxGraphQLBodyBytes) query with extreme nesting cannot
// drive the proxy into stack growth/overflow. Real GitHub queries rarely
// exceed ~30 levels; 100 leaves comfortable headroom for nested
// connections and fragments without enabling unbounded recursion.
const maxAnalysisDepth = 100

func (a *gqlAnalyzer) walkSelectionSet(set ast.SelectionSet, inMutation, atRoot bool, depth int, ctx walkCtx) {
	if depth > maxAnalysisDepth {
		a.tooDeep = true
		return
	}
	for _, sel := range set {
		switch s := sel.(type) {
		case *ast.Field:
			a.walkField(s, inMutation, atRoot, depth, ctx)
		case *ast.InlineFragment:
			// Inline fragments are an in-place type narrowing; they
			// preserve the surrounding selection's root-ness.
			a.walkSelectionSet(s.SelectionSet, inMutation, atRoot, depth+1, ctx)
		case *ast.FragmentSpread:
			// A fragment spread that refers to a fragment we are already
			// inside is a recursion: skip it. A spread that names a
			// fragment the document does not define is treated as an
			// unknown field — silently skipping would let a malformed
			// query slip past the fail-closed posture and reach GitHub.
			// Otherwise push the name on the stack, walk the fragment
			// with the caller's atRoot preserved (so mutation root
			// fields sourced via fragments are still treated as root
			// fields), and pop on the way out.
			if a.fragmentStack[s.Name] {
				continue
			}
			frag, ok := a.fragments[s.Name]
			if !ok {
				a.seenUnknown["fragment:"+s.Name] = struct{}{}
				continue
			}
			a.fragmentStack[s.Name] = true
			a.walkSelectionSet(frag.SelectionSet, inMutation, atRoot, depth+1, ctx)
			delete(a.fragmentStack, s.Name)
		}
	}
}

func (a *gqlAnalyzer) walkField(f *ast.Field, inMutation, atRoot bool, depth int, ctx walkCtx) {
	name := f.Name

	if atRoot {
		a.sawRootField = true
		if _, ok := introspectionRootFields[name]; !ok {
			a.sawNonIntrospectionRoot = true
		}
	}

	// Capture repository(owner, name) arguments when the field is invoked
	// as a lookup (i.e. has arguments). Nested `Repository` accessors with
	// no arguments — `PullRequest.repository`, `Issue.repository`, etc. —
	// are not lookups and must not be flagged as "unpinned". When a lookup
	// is present but its arguments do not resolve to strings (a literal, or
	// a String variable with a JSON string value; see stringArg), or for
	// single-arg forms like
	// `Organization.repository(name:)` whose owner is implied by the parent
	// type), record it as "unpinned" so repo-restricted tokens fail closed:
	// otherwise an attacker could mix one literal allowlisted lookup with a
	// variable-driven lookup and bypass the allowlist.
	pinned := false
	if name == "repository" && len(f.Arguments) > 0 {
		if owner, repo := a.repositoryArgs(f); owner != "" && repo != "" {
			a.seenRepos[owner+"/"+repo] = struct{}{}
			pinned = true
		} else {
			a.result.hasUnpinnedRepositoryLookup = true
		}
	}

	// Cross-repo fields can leak data from outside the repo allowlist.
	// Some field names (`node`, `nodes`) are only cross-repo when used as
	// a root selection — at non-root positions they are connection
	// helpers and benign.
	if _, ok := crossRepoAnywhereFields[name]; ok {
		a.seenCrossRepo[name] = struct{}{}
	} else if atRoot {
		if _, ok := crossRepoRootOnlyFields[name]; ok {
			a.seenCrossRepo[name] = struct{}{}
		}
	}
	flagged := a.checkCrossRepoContext(f, ctx)

	// Root object lookups are gated on fragment type conditions (#324).
	if atRoot && !inMutation {
		if _, ok := rootLookupFields[name]; ok {
			if name == "search" {
				a.walkSearchResult(f.SelectionSet, depth+1)
			} else {
				a.walkLookupResult(name, f.SelectionSet, depth+1)
			}
			return
		}
	}

	// Mutation root fields require a write-level scope.
	if inMutation && atRoot {
		if name == "__typename" {
			// #299: `__typename` at a mutation root returns the type
			// name "Mutation" and changes nothing, so it needs no scope.
			// A mutation that selects only `__typename` still has no
			// write scope and is denied by the mutation checks in
			// graphQLVerdict.
		} else if req, ok := mutationScopeRequirements[name]; ok {
			a.seenScopes[req] = struct{}{}
		} else {
			a.seenUnknown[name] = struct{}{}
		}
	} else if _, ok := alwaysAllowedFields[name]; ok {
		// no-op — metadata field, no scope required.
	} else if req, ok := fieldScopeRequirements[name]; ok {
		a.seenScopes[req] = struct{}{}
	} else if len(f.SelectionSet) == 0 {
		if atRoot {
			// Root-level scalar leaves have no parent field to
			// establish an access context, so they must remain
			// deny-by-default unless explicitly allow-listed or mapped
			// to a scope.
			a.seenUnknown[name] = struct{}{}
		}
		// Otherwise: a scalar leaf nested under an object parent. The
		// parent field has already established the access context —
		// for object-typed parents mapped to a scope (e.g.
		// `Repository.issues`) the parent scope gates the leaf; for
		// always-allowed metadata parents (e.g. `repository`, `user`,
		// `viewer`) the leaf is itself metadata-style. Treating every
		// nested leaf as "unknown" would force the allowlist to
		// enumerate every scalar field name in GitHub's schema
		// (hundreds of entries), which is impractical without
		// schema-aware validation.
		//
		// The known trade-off: an unmapped scalar projected directly
		// under an always-allowed parent is not flagged, even though
		// in principle GitHub could one day expose a sensitive scalar
		// at that position. The risk is bounded by what the underlying
		// credential can read; operators who want stricter enforcement
		// must either reject GraphQL for the affected token or extend
		// `fieldScopeRequirements` to map the offending scalar to a
		// permission. Object-typed fields (those with their own
		// selection set) remain subject to deny-by-default below.
	} else {
		// Object-typed field with a selection set that does not appear in
		// the allow-list or scope-requirement tables. The standard
		// introspection fields (`__schema`, `__type`) are already
		// allow-listed via alwaysAllowedFields, so any other `__*` field
		// is treated like any other unknown — exempting the entire
		// introspection namespace would let an attacker hide arbitrary
		// selections under a `__Anything { ... }` wrapper.
		a.seenUnknown[name] = struct{}{}
	}

	// Recurse into the selection set if any. Children of a mutation root
	// field are not themselves "root" — their permission is implied by the
	// mutation's required scope.
	if len(f.SelectionSet) > 0 {
		child := walkCtx{parent: name, pinnedRepo: pinned, metadataOnly: ctx.metadataOnly}
		if flagged {
			// The request is already cross-repository; flagging every
			// descendant as well only adds noise to the denial message.
			child.metadataOnly = ""
		}
		if child.metadataOnly == "" {
			if _, ok := metadataOnlySubtreeFields[name]; ok {
				child.metadataOnly = name
			}
		}
		a.walkSelectionSet(f.SelectionSet, false, false, depth+1, child)
	}
}

// checkCrossRepoContext applies the parent-aware cross-repository rules:
// inside a metadata-only subtree (#339) only metadata may be selected, and
// crossRepoParentAwareFields (#340) must hang directly off a pinned
// repository lookup. It returns true when the field was flagged by the
// metadata-only rule.
func (a *gqlAnalyzer) checkCrossRepoContext(f *ast.Field, ctx walkCtx) bool {
	name := f.Name
	flagged := false
	if ctx.metadataOnly != "" {
		_, meta := alwaysAllowedFields[name]
		if !meta && len(f.SelectionSet) == 0 {
			_, meta = metadataSubtreeLeaves[name]
		}
		if !meta {
			a.seenCrossRepo[ctx.metadataOnly+"."+name] = struct{}{}
			flagged = true
		}
	}
	if _, ok := crossRepoParentAwareFields[name]; ok && !ctx.pinnedRepo {
		if ctx.parent == "" {
			a.seenCrossRepo[name] = struct{}{}
		} else {
			a.seenCrossRepo[ctx.parent+"."+name] = struct{}{}
		}
	}
	return flagged
}

// walkLookupResult checks the result position of a root lookup (see
// rootLookupFields). Only `__typename` and `id` may be selected directly;
// every other selection must sit inside a fragment whose type condition is
// in typeConditionScopeRequirements. Fragments without a type condition
// (e.g. `... @include(if: $x) { ... }`) are transparent. The fragment body
// is then walked by walkGatedBody, which also gates fragments nested
// directly in it. A result position with no
// mapped fragment is recorded as unknown under the lookup name.
func (a *gqlAnalyzer) walkLookupResult(lookup string, set ast.SelectionSet, depth int) {
	if !a.walkLookupSelections(lookup, set, depth) {
		a.seenUnknown[lookup] = struct{}{}
	}
}

// walkLookupSelections returns true when at least one mapped fragment was
// found in set.
func (a *gqlAnalyzer) walkLookupSelections(lookup string, set ast.SelectionSet, depth int) bool {
	if depth > maxAnalysisDepth {
		a.tooDeep = true
		return false
	}
	found := false
	for _, sel := range set {
		switch s := sel.(type) {
		case *ast.Field:
			if s.Name != "__typename" && s.Name != "id" {
				a.seenUnknown[lookup+"."+s.Name] = struct{}{}
			}
		case *ast.InlineFragment:
			if s.TypeCondition == "" {
				if a.walkLookupSelections(lookup, s.SelectionSet, depth+1) {
					found = true
				}
				continue
			}
			if a.gateTypeCondition(lookup, s.TypeCondition) {
				found = true
			}
			a.walkGatedBody(lookup, s.TypeCondition, s.SelectionSet, depth+1)
		case *ast.FragmentSpread:
			if a.fragmentStack[s.Name] {
				continue
			}
			frag, ok := a.fragments[s.Name]
			if !ok {
				a.seenUnknown["fragment:"+s.Name] = struct{}{}
				continue
			}
			if a.gateTypeCondition(lookup, frag.TypeCondition) {
				found = true
			}
			a.fragmentStack[s.Name] = true
			a.walkGatedBody(lookup, frag.TypeCondition, frag.SelectionSet, depth+1)
			delete(a.fragmentStack, s.Name)
		}
	}
	return found
}

// walkGatedBody walks the body of a root-lookup fragment whose type
// condition is enclosing. Fields are walked as ordinary nested selections.
// A fragment directly in the body (inline or named) with a type condition
// that differs from enclosing is gated through typeConditionScopeRequirements
// as well, so `... on Bot { ...F }` with `fragment F on Issue` needs
// issues:read. Interfaces and unmapped types are unknown. GitHub rejects
// such non-overlapping spreads today, but the analyzer does not rely on it.
func (a *gqlAnalyzer) walkGatedBody(lookup, enclosing string, set ast.SelectionSet, depth int) {
	if depth > maxAnalysisDepth {
		a.tooDeep = true
		return
	}
	for _, sel := range set {
		switch s := sel.(type) {
		case *ast.Field:
			a.walkField(s, false, false, depth, walkCtx{parent: lookup})
		case *ast.InlineFragment:
			inner := enclosing
			if s.TypeCondition != "" && s.TypeCondition != enclosing {
				a.gateTypeCondition(lookup, s.TypeCondition)
				inner = s.TypeCondition
			}
			a.walkGatedBody(lookup, inner, s.SelectionSet, depth+1)
		case *ast.FragmentSpread:
			if a.fragmentStack[s.Name] {
				continue
			}
			frag, ok := a.fragments[s.Name]
			if !ok {
				a.seenUnknown["fragment:"+s.Name] = struct{}{}
				continue
			}
			inner := enclosing
			if frag.TypeCondition != enclosing {
				a.gateTypeCondition(lookup, frag.TypeCondition)
				inner = frag.TypeCondition
			}
			a.fragmentStack[s.Name] = true
			a.walkGatedBody(lookup, inner, frag.SelectionSet, depth+1)
			delete(a.fragmentStack, s.Name)
		}
	}
}

// gateTypeCondition records the scope for a mapped type condition, or an
// unknown entry for an unmapped one. It returns true when mapped.
func (a *gqlAnalyzer) gateTypeCondition(lookup, typeCondition string) bool {
	req, ok := typeConditionScopeRequirements[typeCondition]
	if !ok {
		a.seenUnknown[lookup+"...on "+typeCondition] = struct{}{}
		return false
	}
	a.seenScopes[req] = struct{}{}
	return true
}

// walkSearchResult checks the selection set of a root `search` field.
// `nodes` and `edges { node }` are result positions and are checked with
// walkLookupResult. Scalar leaves (e.g. `issueCount`), `pageInfo` and
// `__typename` may sit beside them. Anything else is unknown, and so is a
// search with no result position.
func (a *gqlAnalyzer) walkSearchResult(set ast.SelectionSet, depth int) {
	if depth > maxAnalysisDepth {
		a.tooDeep = true
		return
	}
	found := false
	for _, sel := range set {
		s, ok := sel.(*ast.Field)
		if !ok {
			// Fragments on SearchResultItemConnection add nothing a
			// client needs; deny rather than reason about them.
			a.seenUnknown["search:fragment"] = struct{}{}
			continue
		}
		switch {
		case s.Name == "nodes":
			a.walkLookupResult("search.nodes", s.SelectionSet, depth+1)
			found = true
		case s.Name == "edges":
			for _, esel := range s.SelectionSet {
				ef, ok := esel.(*ast.Field)
				switch {
				case !ok:
					a.seenUnknown["search.edges:fragment"] = struct{}{}
				case ef.Name == "node":
					a.walkLookupResult("search.edges.node", ef.SelectionSet, depth+2)
					found = true
				case len(ef.SelectionSet) == 0:
					// cursor, __typename and other scalar leaves.
				default:
					a.seenUnknown["search.edges."+ef.Name] = struct{}{}
				}
			}
		case s.Name == "pageInfo":
			a.walkSelectionSet(s.SelectionSet, false, false, depth+1, walkCtx{parent: "pageInfo"})
		case len(s.SelectionSet) == 0:
			// issueCount, repositoryCount, __typename and similar leaves.
		default:
			a.seenUnknown["search."+s.Name] = struct{}{}
		}
	}
	if !found {
		// A search that selects no result position (counts only) has no
		// fragment to gate on, so it stays denied like the other lookups.
		a.seenUnknown["search"] = struct{}{}
	}
}

// repositoryArgs extracts the (owner, name) arguments from a
// `repository(owner:, name:)` field selection. It returns empty strings if
// either argument is missing or does not resolve to a string (see
// stringArg). The caller then records the lookup as unpinned, which fails
// closed for repository-restricted tokens. Cross-repo tracking is not
// populated from this helper.
func (a *gqlAnalyzer) repositoryArgs(f *ast.Field) (string, string) {
	var owner, repo string
	for _, arg := range f.Arguments {
		switch arg.Name {
		case "owner":
			owner, _ = a.stringArg(arg.Value)
		case "name":
			repo, _ = a.stringArg(arg.Value)
		}
	}
	return owner, repo
}

// stringArg resolves an argument value to a string. It accepts exactly:
//
//   - a literal GraphQL string; or
//   - a variable `$v` that the selected operation declares with the named
//     type `String` (nullable or non-null, not a list), whose member in the
//     request's `variables` object is a JSON string.
//
// Operation default values are never used: a variable that is absent from
// `variables` does not resolve. A null, number, boolean, array or object
// value does not resolve. When the variables are not trusted (a.vars is nil,
// see resolveVariables) no variable resolves.
func (a *gqlAnalyzer) stringArg(v *ast.Value) (string, bool) {
	if v == nil {
		return "", false
	}
	switch v.Kind {
	case ast.StringValue:
		return v.Raw, true
	case ast.Variable:
		if a.vars == nil {
			return "", false
		}
		def := a.varDefs.ForName(v.Raw)
		if def == nil || def.Type == nil || def.Type.Elem != nil || def.Type.NamedType != "String" {
			return "", false
		}
		raw, ok := a.vars[v.Raw]
		if !ok {
			return "", false
		}
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 || raw[0] != '"' {
			return "", false
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", false
		}
		return s, true
	}
	return "", false
}

// resolveVariables returns the request's variables for repository pinning,
// or nil when they must not be trusted: the document has more than one
// operation, or `variables` is absent, not a JSON object, or has duplicate
// keys (so the proxy and GitHub cannot read different values for the same
// name). The envelope itself was already checked by parseGraphQLEnvelope,
// and the body that is analysed is the body handleGraphQL forwards, byte
// for byte.
func resolveVariables(variables json.RawMessage, operations int) map[string]json.RawMessage {
	if operations != 1 {
		return nil
	}
	members, ok := objectMembers(variables)
	if !ok {
		return nil
	}
	vars := make(map[string]json.RawMessage, len(members))
	for _, m := range members {
		if _, dup := vars[m.key]; dup {
			return nil
		}
		vars[m.key] = m.value
	}
	return vars
}

type jsonMember struct {
	key   string
	value json.RawMessage
}

// objectMembers returns the members of a JSON object in document order,
// duplicates included, with keys exactly as decoded (no case folding). It
// reports false when raw is not a single JSON object.
func objectMembers(raw []byte) ([]jsonMember, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, false
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, false
	}
	var members []jsonMember
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, false
		}
		k, ok := tok.(string)
		if !ok {
			return nil, false
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, false
		}
		members = append(members, jsonMember{key: k, value: v})
	}
	if _, err := dec.Token(); err != nil {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return members, true
}

// satisfiedBy reports whether the given proxy-token scopes grant every
// scope required by this analysis. The token is allowed when every entry
// in requiredScopes appears in scopes at sufficient level (write implies
// read, per database.Scopes.HasPermission).
func (a graphQLAnalysis) satisfiedBy(scopes database.Scopes) bool {
	for _, req := range a.requiredScopes {
		if !scopes.HasPermission(req.permission, req.level) {
			return false
		}
	}
	return true
}

// missingScopes returns the scope requirements that are not granted by the
// supplied token scopes, formatted as "permission:level" entries sorted
// alphabetically. Used to build helpful 403 messages.
func (a graphQLAnalysis) missingScopes(scopes database.Scopes) []string {
	var missing []string
	for _, req := range a.requiredScopes {
		if !scopes.HasPermission(req.permission, req.level) {
			missing = append(missing, req.permission+":"+req.level)
		}
	}
	sort.Strings(missing)
	return missing
}
