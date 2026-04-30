package proxy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/goodtune/ghp/internal/database"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

// graphQLRequestBody is the JSON envelope GitHub's GraphQL endpoint expects.
type graphQLRequestBody struct {
	Query         string         `json:"query"`
	OperationName string         `json:"operationName,omitempty"`
	Variables     map[string]any `json:"variables,omitempty"`
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
	"__typename":   {},
	"__schema":     {},
	"__type":       {},
	"id":           {},
	"databaseId":   {},
	"name":         {},
	"nameWithOwner": {},
	"login":        {},
	"slug":         {},
	"url":          {},
	"resourcePath": {},
	"avatarUrl":    {},
	"description":  {},
	"createdAt":    {},
	"updatedAt":    {},
	"pushedAt":     {},
	"isPrivate":    {},
	"isFork":       {},
	"isArchived":   {},
	"isDisabled":   {},
	"isLocked":     {},
	"isMirror":     {},
	"isTemplate":   {},
	"isInOrganization": {},
	"visibility":   {},
	"diskUsage":    {},
	"forkCount":    {},
	"stargazerCount": {},
	"watchers":     {},
	"languages":    {},
	"primaryLanguage": {},
	"defaultBranchRef": {},
	"licenseInfo":  {},
	"owner":        {},
	"repositoryTopics": {},
	"topics":       {},
	"homepageUrl":  {},
	"sshUrl":       {},
	"mirrorUrl":    {},
	"hasIssuesEnabled":     {},
	"hasProjectsEnabled":   {},
	"hasWikiEnabled":       {},
	"hasDiscussionsEnabled": {},
	"openGraphImageUrl":    {},
	"usesCustomOpenGraphImage": {},
	"fundingLinks": {},
	"codeOfConduct": {},

	// Pagination & connection helpers.
	"nodes":      {},
	"edges":      {},
	"pageInfo":   {},
	"totalCount": {},
	"hasNextPage": {},
	"hasPreviousPage": {},
	"endCursor":   {},
	"startCursor": {},
	"cursor":      {},

	// Root fields that are themselves harmless without further selection;
	// the children determine the actual scope requirement.
	"viewer":           {},
	"repository":       {},
	"repositoryOwner":  {},
	"user":             {},
	"organization":     {},
	"rateLimit":        {},
	"meta":             {},
	"codeOfConducts":   {},
	"licenses":         {},
	"license":          {},
	"marketplaceListing": {},
	"marketplaceCategories": {},
	"securityAdvisory": {},
	"securityAdvisories": {},
	"securityVulnerabilities": {},

	// Common scalar projections on identity types.
	"email":       {},
	"company":     {},
	"location":    {},
	"bio":         {},
	"twitterUsername": {},
	"websiteUrl":  {},
	"isViewer":    {},
	"isSiteAdmin": {},
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

	// Pull requests
	"pullRequest":         {"pull_requests", "read"},
	"pullRequests":        {"pull_requests", "read"},
	"reviews":             {"pull_requests", "read"},
	"reviewRequests":      {"pull_requests", "read"},
	"reviewThreads":       {"pull_requests", "read"},
	"latestReviews":       {"pull_requests", "read"},
	"latestOpinionatedReviews": {"pull_requests", "read"},
	"mergeQueue":          {"pull_requests", "read"},
	"mergeQueueEntry":     {"pull_requests", "read"},

	// Discussions
	"discussion":         {"discussions", "read"},
	"discussions":        {"discussions", "read"},
	"discussionCategory": {"discussions", "read"},
	"discussionCategories": {"discussions", "read"},

	// Contents / git data
	"object":         {"contents", "read"},
	"ref":            {"contents", "read"},
	"refs":           {"contents", "read"},
	"branchProtectionRule": {"administration", "read"},
	"branchProtectionRules": {"administration", "read"},
	"rulesets":       {"administration", "read"},
	"ruleset":        {"administration", "read"},
	"release":        {"contents", "read"},
	"releases":       {"contents", "read"},
	"tag":            {"contents", "read"},
	"tags":           {"contents", "read"},
	"file":           {"contents", "read"},
	"tree":           {"contents", "read"},
	"blob":           {"contents", "read"},
	"commit":         {"contents", "read"},
	"commitComments": {"contents", "read"},
	"history":        {"contents", "read"},

	// Deployments / environments
	"deployment":  {"deployments", "read"},
	"deployments": {"deployments", "read"},
	"environment": {"environments", "read"},
	"environments": {"environments", "read"},

	// Actions / workflows
	"workflowRun":         {"actions", "read"},
	"workflowRuns":        {"actions", "read"},
	"actionsCacheUsage":   {"actions", "read"},
	"workflowFile":        {"workflows", "read"},

	// Statuses & checks
	"status":       {"statuses", "read"},
	"statuses":     {"statuses", "read"},
	"statusCheckRollup": {"checks", "read"},
	"checkSuite":   {"checks", "read"},
	"checkSuites":  {"checks", "read"},
	"checkRun":     {"checks", "read"},
	"checkRuns":    {"checks", "read"},

	// Security
	"vulnerabilityAlerts": {"vulnerability_alerts", "read"},
	"securityScanningAlerts": {"secret_scanning_alerts", "read"},

	// Repository administration
	"collaborators": {"administration", "read"},
	"invitations":   {"administration", "read"},

	// Organization members
	"membersWithRole": {"members", "read"},
	"pendingMembers":  {"members", "read"},
	"memberStatuses":  {"members", "read"},

	// Projects
	"project":      {"projects", "read"},
	"projects":     {"projects", "read"},
	"projectsV2":   {"projects", "read"},
	"projectV2":    {"projects", "read"},

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

// crossRepoAnywhereFields lists fields that can leak data from
// repositories other than those addressed by the request's
// `repository(owner, name)` selections. Repository-scoped tokens cannot
// statically prove the repositories returned by these fields fall inside
// the allowlist, so the request is rejected wherever they appear.
var crossRepoAnywhereFields = map[string]struct{}{
	"search":            {},
	"searchUsers":       {},
	"repositories":      {},
	"topRepositories":   {},
	"watching":          {},
	"starredRepositories": {},
	"contributedRepositories": {},
	"pinnedRepositories":      {},
	"recentProjects":          {},
}

// mutationScopeRequirements maps GitHub GraphQL mutation field names to the
// permission scope they require. The list covers the well-known mutations
// agents use; unknown mutations fall through to the default-deny path.
var mutationScopeRequirements = map[string]scopeRequirement{
	// Issues
	"createIssue":          {"issues", "write"},
	"updateIssue":          {"issues", "write"},
	"closeIssue":           {"issues", "write"},
	"reopenIssue":          {"issues", "write"},
	"deleteIssue":          {"issues", "write"},
	"transferIssue":        {"issues", "write"},
	"lockLockable":         {"issues", "write"},
	"unlockLockable":       {"issues", "write"},
	"pinIssue":             {"issues", "write"},
	"unpinIssue":           {"issues", "write"},
	"addAssigneesToAssignable":      {"issues", "write"},
	"removeAssigneesFromAssignable": {"issues", "write"},
	"addLabelsToLabelable":          {"issues", "write"},
	"removeLabelsFromLabelable":     {"issues", "write"},
	"clearLabelsFromLabelable":      {"issues", "write"},
	"updateIssueComment":   {"issues", "write"},
	"deleteIssueComment":   {"issues", "write"},
	"addComment":           {"issues", "write"},

	// Pull requests
	"createPullRequest":             {"pull_requests", "write"},
	"updatePullRequest":             {"pull_requests", "write"},
	"closePullRequest":              {"pull_requests", "write"},
	"reopenPullRequest":             {"pull_requests", "write"},
	"mergePullRequest":              {"pull_requests", "write"},
	"markPullRequestReadyForReview": {"pull_requests", "write"},
	"convertPullRequestToDraft":     {"pull_requests", "write"},
	"enablePullRequestAutoMerge":    {"pull_requests", "write"},
	"disablePullRequestAutoMerge":   {"pull_requests", "write"},
	"requestReviews":                {"pull_requests", "write"},
	"removeRequestedReviewers":      {"pull_requests", "write"},
	"addPullRequestReview":          {"pull_requests", "write"},
	"updatePullRequestReview":       {"pull_requests", "write"},
	"submitPullRequestReview":       {"pull_requests", "write"},
	"deletePullRequestReview":       {"pull_requests", "write"},
	"dismissPullRequestReview":      {"pull_requests", "write"},
	"addPullRequestReviewComment":   {"pull_requests", "write"},
	"updatePullRequestReviewComment": {"pull_requests", "write"},
	"deletePullRequestReviewComment": {"pull_requests", "write"},
	"addPullRequestReviewThread":    {"pull_requests", "write"},
	"resolveReviewThread":           {"pull_requests", "write"},
	"unresolveReviewThread":         {"pull_requests", "write"},
	"addPullRequestReviewThreadReply": {"pull_requests", "write"},

	// Contents / git data
	"createCommitOnBranch": {"contents", "write"},
	"createRef":            {"contents", "write"},
	"updateRef":            {"contents", "write"},
	"deleteRef":            {"contents", "write"},
	"createRepository":     {"administration", "write"},
	"updateRepository":     {"administration", "write"},
	"createBranchProtectionRule": {"administration", "write"},
	"updateBranchProtectionRule": {"administration", "write"},
	"deleteBranchProtectionRule": {"administration", "write"},
	"createTag":            {"contents", "write"},
	"createRelease":        {"contents", "write"},
	"updateRelease":        {"contents", "write"},
	"deleteRelease":        {"contents", "write"},

	// Discussions
	"createDiscussion":        {"discussions", "write"},
	"updateDiscussion":        {"discussions", "write"},
	"deleteDiscussion":        {"discussions", "write"},
	"addDiscussionComment":    {"discussions", "write"},
	"updateDiscussionComment": {"discussions", "write"},
	"deleteDiscussionComment": {"discussions", "write"},
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
	"addProjectCard":     {"projects", "write"},
	"updateProjectCard":  {"projects", "write"},
	"deleteProjectCard":  {"projects", "write"},
	"createProjectV2":    {"projects", "write"},
	"updateProjectV2":    {"projects", "write"},
	"deleteProjectV2":    {"projects", "write"},
	"addProjectV2ItemById": {"projects", "write"},
	"deleteProjectV2Item":  {"projects", "write"},
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
	var req graphQLRequestBody
	if err := json.Unmarshal(body, &req); err != nil {
		return graphQLAnalysis{}, fmt.Errorf("graphql: invalid JSON body: %w", err)
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
		fragments:       fragments,
		fragmentStack:   map[string]bool{},
		seenScopes:      map[scopeRequirement]struct{}{},
		seenRepos:       map[string]struct{}{},
		seenCrossRepo:   map[string]struct{}{},
		seenUnknown:     map[string]struct{}{},
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
	a.walkSelectionSet(op.SelectionSet, op.Operation == ast.Mutation, true, 1)
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
}

// maxAnalysisDepth caps the depth of the AST walk so that a malicious
// (but still ≤ maxGraphQLBodyBytes) query with extreme nesting cannot
// drive the proxy into stack growth/overflow. Real GitHub queries rarely
// exceed ~30 levels; 100 leaves comfortable headroom for nested
// connections and fragments without enabling unbounded recursion.
const maxAnalysisDepth = 100

func (a *gqlAnalyzer) walkSelectionSet(set ast.SelectionSet, inMutation, atRoot bool, depth int) {
	if depth > maxAnalysisDepth {
		a.tooDeep = true
		return
	}
	for _, sel := range set {
		switch s := sel.(type) {
		case *ast.Field:
			a.walkField(s, inMutation, atRoot, depth)
		case *ast.InlineFragment:
			// Inline fragments are an in-place type narrowing; they
			// preserve the surrounding selection's root-ness.
			a.walkSelectionSet(s.SelectionSet, inMutation, atRoot, depth+1)
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
			a.walkSelectionSet(frag.SelectionSet, inMutation, atRoot, depth+1)
			delete(a.fragmentStack, s.Name)
		}
	}
}

func (a *gqlAnalyzer) walkField(f *ast.Field, inMutation, atRoot bool, depth int) {
	name := f.Name

	// Capture repository(owner, name) arguments wherever the field appears.
	if name == "repository" {
		if owner, repo := repositoryArgs(f); owner != "" && repo != "" {
			a.seenRepos[owner+"/"+repo] = struct{}{}
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

	// Mutation root fields require a write-level scope.
	if inMutation && atRoot {
		if req, ok := mutationScopeRequirements[name]; ok {
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
		a.walkSelectionSet(f.SelectionSet, false, false, depth+1)
	}
}

// repositoryArgs extracts the (owner, name) arguments from a
// `repository(owner: "X", name: "Y")` field selection. It returns empty
// strings if either argument is missing or non-literal (for example
// supplied via a GraphQL variable). In that case the helper does not
// have a statically pinned repository to record; policy enforcement
// then treats the lookup as having no pinned repository, which causes
// the `len(referencedRepos) == 0` check in the caller to reject the
// request for repository-restricted tokens. Cross-repo tracking is not
// populated from this helper.
func repositoryArgs(f *ast.Field) (string, string) {
	var owner, repo string
	for _, arg := range f.Arguments {
		if arg.Value == nil || arg.Value.Kind != ast.StringValue {
			continue
		}
		switch arg.Name {
		case "owner":
			owner = arg.Value.Raw
		case "name":
			repo = arg.Value.Raw
		}
	}
	return owner, repo
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
