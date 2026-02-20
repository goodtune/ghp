// Package backend defines the upstream backend identifiers used across
// the proxy for routing, access logging, and Prometheus metric labels.
package backend

const (
	API     = "api.github.com"
	GitHub  = "github.com"
	Copilot = "copilot"
	Mgmt    = "management"
)
