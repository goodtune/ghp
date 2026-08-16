package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/goodtune/ghp/internal/auth"
	"github.com/goodtune/ghp/internal/database"
)

// Bounds for forward proxy ruleset inputs. Rulesets are admin-managed, so the
// limits are generous; they exist to keep route table compilation and the
// JSON columns bounded.
const (
	maxForwardProxyNameLength        = 128
	maxForwardProxyDescriptionLength = 1024
	maxForwardProxyTargets           = 32
	maxForwardProxyRules             = 128
	maxForwardProxyWeight            = 10000
)

// forwardProxyNameRe restricts ruleset names to path- and label-safe
// characters: the name is used as a Prometheus label value and as a Vault KV
// path segment.
var forwardProxyNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

type forwardProxyRulesetResponse struct {
	ID          string                       `json:"id"`
	Name        string                       `json:"name"`
	Description string                       `json:"description"`
	Algorithm   string                       `json:"algorithm"`
	Proxies     []database.ForwardProxyEntry `json:"proxies"`
	Rules       []database.ForwardProxyRule  `json:"rules"`
	Enabled     bool                         `json:"enabled"`
	CreatedAt   string                       `json:"created_at"`
	UpdatedAt   string                       `json:"updated_at"`
}

func forwardProxyRulesetToResponse(rs *database.ForwardProxyRuleset) forwardProxyRulesetResponse {
	proxies := rs.Proxies
	if proxies == nil {
		proxies = make([]database.ForwardProxyEntry, 0)
	}
	rules := rs.Rules
	if rules == nil {
		rules = make([]database.ForwardProxyRule, 0)
	}
	return forwardProxyRulesetResponse{
		ID:          rs.ID,
		Name:        rs.Name,
		Description: rs.Description,
		Algorithm:   rs.Algorithm,
		Proxies:     proxies,
		Rules:       rules,
		Enabled:     rs.Enabled,
		CreatedAt:   rs.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   rs.UpdatedAt.Format(time.RFC3339),
	}
}

func validForwardProxyAlgorithm(algo string) bool {
	switch algo {
	case database.ForwardProxyAlgoRoundRobin, database.ForwardProxyAlgoWeighted, database.ForwardProxyAlgoSticky:
		return true
	}
	return false
}

// validateForwardProxyName checks ruleset name syntax and length.
func validateForwardProxyName(name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if len(name) > maxForwardProxyNameLength {
		return fmt.Errorf("name must be at most %d characters", maxForwardProxyNameLength)
	}
	if !forwardProxyNameRe.MatchString(name) {
		return fmt.Errorf("name may only contain alphanumerics, dots, hyphens, and underscores, and must start with an alphanumeric")
	}
	return nil
}

// validateForwardProxyEntries validates the proxy target list and normalizes
// omitted weights to 1 in place.
func validateForwardProxyEntries(entries []database.ForwardProxyEntry) error {
	if len(entries) == 0 {
		return fmt.Errorf("at least one proxy target is required")
	}
	if len(entries) > maxForwardProxyTargets {
		return fmt.Errorf("at most %d proxy targets are allowed", maxForwardProxyTargets)
	}
	for i := range entries {
		e := &entries[i]
		u, err := url.Parse(e.URL)
		if err != nil {
			return fmt.Errorf("proxies[%d]: malformed URL", i)
		}
		switch u.Scheme {
		case "http", "https", "socks5", "socks5h":
		default:
			return fmt.Errorf("proxies[%d]: scheme must be http, https, socks5, or socks5h", i)
		}
		if u.Host == "" {
			return fmt.Errorf("proxies[%d]: host is required", i)
		}
		if u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("proxies[%d]: query string and fragment are not allowed", i)
		}
		if e.Weight < 0 {
			return fmt.Errorf("proxies[%d]: weight must not be negative", i)
		}
		if e.Weight == 0 {
			e.Weight = 1
		}
		if e.Weight > maxForwardProxyWeight {
			return fmt.Errorf("proxies[%d]: weight must be at most %d", i, maxForwardProxyWeight)
		}
	}
	return nil
}

// validateForwardProxyRules validates the rule list: rule types must be
// known, app/token values must be well-formed UUIDs, net values must be valid
// CIDRs, and system rules must carry no value.
func validateForwardProxyRules(rules []database.ForwardProxyRule) error {
	if len(rules) > maxForwardProxyRules {
		return fmt.Errorf("at most %d rules are allowed", maxForwardProxyRules)
	}
	for i, rule := range rules {
		if rule.IncludeNonGitHub && rule.Type != database.ForwardProxyRuleControl {
			return fmt.Errorf("rules[%d]: include_non_github is only valid on control rules", i)
		}
		switch rule.Type {
		case database.ForwardProxyRuleSystem, database.ForwardProxyRuleControl:
			if rule.Value != "" {
				return fmt.Errorf("rules[%d]: %s rules must not carry a value", i, rule.Type)
			}
		case database.ForwardProxyRuleApp:
			if !isValidUUID(rule.Value) {
				return fmt.Errorf("rules[%d]: app rules require a valid app record UUID", i)
			}
		case database.ForwardProxyRuleToken:
			if !isValidUUID(rule.Value) {
				return fmt.Errorf("rules[%d]: token rules require a valid token UUID", i)
			}
		case database.ForwardProxyRuleNet:
			if _, _, err := net.ParseCIDR(rule.Value); err != nil {
				return fmt.Errorf("rules[%d]: net rules require a valid CIDR (e.g. 10.0.0.0/16)", i)
			}
		default:
			return fmt.Errorf("rules[%d]: type must be one of system, app, token, net, control", i)
		}
	}
	return nil
}

// reloadForwardProxyRouter rebuilds the router's route table after a ruleset
// mutation so changes take effect immediately on this instance. Failures are
// logged but not surfaced to the API caller: the mutation is already
// persisted, and the periodic refresh will converge the route table.
func (a *API) reloadForwardProxyRouter(r *http.Request) {
	if a.forwardProxyRouter == nil {
		return
	}
	if err := a.forwardProxyRouter.Reload(r.Context()); err != nil {
		a.logger.Error("forward proxy router reload failed after mutation", "error", err)
	}
}

func (a *API) handleListForwardProxyRulesets(w http.ResponseWriter, r *http.Request) {
	rulesets, err := a.store.ListForwardProxyRulesets(r.Context())
	if err != nil {
		a.logger.Error("failed to list forward proxy rulesets", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Internal error"})
		return
	}
	result := make([]forwardProxyRulesetResponse, 0, len(rulesets))
	for _, rs := range rulesets {
		result = append(result, forwardProxyRulesetToResponse(rs))
	}
	writeJSON(w, http.StatusOK, result)
}

type createForwardProxyRulesetRequest struct {
	Name        string                       `json:"name"`
	Description string                       `json:"description"`
	Algorithm   string                       `json:"algorithm"`
	Proxies     []database.ForwardProxyEntry `json:"proxies"`
	Rules       []database.ForwardProxyRule  `json:"rules"`
	Enabled     *bool                        `json:"enabled"`
}

func (a *API) handleCreateForwardProxyRuleset(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req createForwardProxyRulesetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"message": "Request body too large"})
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid request body"})
		}
		return
	}

	if err := validateForwardProxyName(req.Name); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}
	if len(req.Description) > maxForwardProxyDescriptionLength {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": fmt.Sprintf("description must be at most %d characters", maxForwardProxyDescriptionLength)})
		return
	}
	if !validForwardProxyAlgorithm(req.Algorithm) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "algorithm must be one of round_robin, weighted, sticky"})
		return
	}
	if err := validateForwardProxyEntries(req.Proxies); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}
	if err := validateForwardProxyRules(req.Rules); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}

	// Check for duplicate names up front for a clean 409.
	existing, err := a.store.GetForwardProxyRulesetByName(r.Context(), req.Name)
	if err != nil {
		a.logger.Error("failed to check forward proxy ruleset name", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Internal error"})
		return
	}
	if existing != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"message": "A forward proxy ruleset with this name already exists"})
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if req.Rules == nil {
		req.Rules = make([]database.ForwardProxyRule, 0)
	}

	rs := &database.ForwardProxyRuleset{
		Name:        req.Name,
		Description: req.Description,
		Algorithm:   req.Algorithm,
		Proxies:     req.Proxies,
		Rules:       req.Rules,
		Enabled:     enabled,
	}
	if err := a.store.CreateForwardProxyRuleset(r.Context(), rs); err != nil {
		// Handle race condition: concurrent create may hit the unique constraint.
		if strings.Contains(err.Error(), "UNIQUE constraint") || strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "already exists") {
			writeJSON(w, http.StatusConflict, map[string]string{"message": "A forward proxy ruleset with this name already exists"})
			return
		}
		a.logger.Error("failed to create forward proxy ruleset", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to create forward proxy ruleset"})
		return
	}

	session := auth.SessionFromContext(r.Context())
	a.logger.Info("forward_proxy_ruleset_created", "user", session.Username, "ruleset", rs.Name, "ruleset_id", rs.ID)
	a.reloadForwardProxyRouter(r)

	writeJSON(w, http.StatusCreated, forwardProxyRulesetToResponse(rs))
}

func (a *API) handleGetForwardProxyRuleset(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !isValidUUID(id) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid forward proxy ruleset ID format"})
		return
	}
	rs, err := a.store.GetForwardProxyRulesetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "Forward proxy ruleset not found"})
			return
		}
		a.logger.Error("failed to get forward proxy ruleset", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Internal error"})
		return
	}
	writeJSON(w, http.StatusOK, forwardProxyRulesetToResponse(rs))
}

type updateForwardProxyRulesetRequest struct {
	Name        *string                       `json:"name"`
	Description *string                       `json:"description"`
	Algorithm   *string                       `json:"algorithm"`
	Proxies     *[]database.ForwardProxyEntry `json:"proxies"`
	Rules       *[]database.ForwardProxyRule  `json:"rules"`
	Enabled     *bool                         `json:"enabled"`
}

func (a *API) handleUpdateForwardProxyRuleset(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req updateForwardProxyRulesetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"message": "Request body too large"})
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid request body"})
		}
		return
	}

	id := r.PathValue("id")
	if !isValidUUID(id) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid forward proxy ruleset ID format"})
		return
	}

	existing, err := a.store.GetForwardProxyRulesetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "Forward proxy ruleset not found"})
			return
		}
		a.logger.Error("failed to get forward proxy ruleset", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Internal error"})
		return
	}

	if req.Name != nil && *req.Name != existing.Name {
		if err := validateForwardProxyName(*req.Name); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		conflicting, err := a.store.GetForwardProxyRulesetByName(r.Context(), *req.Name)
		if err != nil {
			a.logger.Error("failed to check forward proxy ruleset name", "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Internal error"})
			return
		}
		if conflicting != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"message": "A forward proxy ruleset with this name already exists"})
			return
		}
		existing.Name = *req.Name
	}
	if req.Description != nil {
		if len(*req.Description) > maxForwardProxyDescriptionLength {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": fmt.Sprintf("description must be at most %d characters", maxForwardProxyDescriptionLength)})
			return
		}
		existing.Description = *req.Description
	}
	if req.Algorithm != nil {
		if !validForwardProxyAlgorithm(*req.Algorithm) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "algorithm must be one of round_robin, weighted, sticky"})
			return
		}
		existing.Algorithm = *req.Algorithm
	}
	if req.Proxies != nil {
		if err := validateForwardProxyEntries(*req.Proxies); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		existing.Proxies = *req.Proxies
	}
	if req.Rules != nil {
		if err := validateForwardProxyRules(*req.Rules); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		existing.Rules = *req.Rules
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}

	if err := a.store.UpdateForwardProxyRuleset(r.Context(), existing); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") || strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "already exists") {
			writeJSON(w, http.StatusConflict, map[string]string{"message": "A forward proxy ruleset with this name already exists"})
			return
		}
		a.logger.Error("failed to update forward proxy ruleset", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to update forward proxy ruleset"})
		return
	}

	session := auth.SessionFromContext(r.Context())
	a.logger.Info("forward_proxy_ruleset_updated", "user", session.Username, "ruleset", existing.Name, "ruleset_id", existing.ID)
	a.reloadForwardProxyRouter(r)

	writeJSON(w, http.StatusOK, forwardProxyRulesetToResponse(existing))
}

func (a *API) handleDeleteForwardProxyRuleset(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !isValidUUID(id) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid forward proxy ruleset ID format"})
		return
	}
	if err := a.store.DeleteForwardProxyRuleset(r.Context(), id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "Forward proxy ruleset not found"})
		} else {
			a.logger.Error("failed to delete forward proxy ruleset", "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to delete forward proxy ruleset"})
		}
		return
	}

	session := auth.SessionFromContext(r.Context())
	a.logger.Info("forward_proxy_ruleset_deleted", "user", session.Username, "ruleset_id", id)
	a.reloadForwardProxyRouter(r)
	writeJSON(w, http.StatusOK, map[string]string{"message": "Forward proxy ruleset deleted"})
}
