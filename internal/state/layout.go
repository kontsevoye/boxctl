package state

import (
	"fmt"
	"path/filepath"
)

const (
	DefaultRoot = "/opt/boxctl"
	// FirstStartPending keeps a fresh installation in management-only mode
	// until the operator successfully starts the selected core once.
	FirstStartPending = ".install/start-stopped-until-first-success"
)

// Layout contains only paths owned by boxctl.
type Layout struct {
	Root              string
	BinDir            string
	StateDir          string
	ProfilesDir       string
	EnginesDir        string
	LocalRulesDir     string
	RuleProvidersDir  string
	ProxyProvidersDir string
	SubscriptionsDir  string
	DashboardDir      string
	MihomoConfig      string
	SingBoxConfig     string
	ActiveProfile     string
	Settings          string
	Password          string
	SessionSecrets    string
	ProfileSourcesDir string
	DNSBackup         string
}

func NewLayout(root string) (Layout, error) {
	if root == "" {
		root = DefaultRoot
	}
	if !filepath.IsAbs(root) {
		return Layout{}, fmt.Errorf("state: layout root must be absolute: %q", root)
	}
	root = filepath.Clean(root)
	stateDir := filepath.Join(root, ".boxctl")
	return Layout{
		Root:              root,
		BinDir:            filepath.Join(root, "bin"),
		StateDir:          stateDir,
		ProfilesDir:       filepath.Join(root, "configs"),
		EnginesDir:        filepath.Join(root, "engines"),
		LocalRulesDir:     filepath.Join(root, "local-rules"),
		RuleProvidersDir:  filepath.Join(root, "rule-providers"),
		ProxyProvidersDir: filepath.Join(root, "proxy-providers"),
		SubscriptionsDir:  filepath.Join(root, "subscriptions"),
		DashboardDir:      filepath.Join(root, "ui"),
		MihomoConfig:      filepath.Join(root, "config.yaml"),
		SingBoxConfig:     filepath.Join(root, "config.json"),
		ActiveProfile:     filepath.Join(stateDir, "active-profile"),
		Settings:          filepath.Join(stateDir, "settings"),
		Password:          filepath.Join(stateDir, "password"),
		SessionSecrets:    filepath.Join(stateDir, "session-secrets.v1.json"),
		ProfileSourcesDir: filepath.Join(stateDir, "profile-sources"),
		DNSBackup:         filepath.Join(stateDir, "dns-backup.json"),
	}, nil
}
