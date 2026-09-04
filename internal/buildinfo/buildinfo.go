// Package buildinfo contains values injected into release binaries at link time.
package buildinfo

const (
	// SettingsSchemaVersion changes only when a new manager cannot safely use
	// the settings persisted by the previous manager without a core restart.
	SettingsSchemaVersion = 1
	// CaptureInjectorVersion changes when the nftables, policy-routing, DNS, or
	// process-handoff contract changes in a way that requires rebuilding the
	// live dataplane.
	CaptureInjectorVersion = 1
)

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)
