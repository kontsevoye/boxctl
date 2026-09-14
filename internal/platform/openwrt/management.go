package openwrt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ManagementConfig is backed exclusively by the boxctl.main UCI section.
type ManagementConfig struct {
	PublicOrigin   string
	AllowedHosts   string
	TLSCertificate string
	TLSKey         string
}

// ManagementUCIOptions is the complete set of panel-managed UCI options.
var ManagementUCIOptions = []string{"public_origin", "allowed_hosts", "tls_certificate", "tls_key"}

var ErrManagementConfigConflict = errors.New("OpenWrt panel settings changed or have external pending changes")

type ManagementSnapshot struct {
	Config   ManagementConfig
	Revision string
	Pending  bool
	Exists   bool
}

type ManagementUCI struct {
	Runner    Runner
	ConfigDir string
	TempDir   string
}

func (manager ManagementUCI) command(ctx context.Context, delta string, args ...string) (Result, error) {
	options := []string{"-q"}
	if manager.ConfigDir != "" {
		options = append(options, "-c", manager.ConfigDir)
	}
	if delta != "" {
		// -P disables commit in the UCI CLI; -t selects the private savedir
		// while retaining real commit semantics. Never use a shared delta file.
		options = append(options, "-t", delta)
	}
	return manager.Runner.Run(ctx, Command{Name: "uci", Args: append(options, args...)})
}

func (manager ManagementUCI) Read(ctx context.Context) (ManagementSnapshot, error) {
	result, err := manager.command(ctx, "", "export", "boxctl")
	if err != nil {
		return ManagementSnapshot{}, err
	}
	if result.ExitCode != 0 {
		directory := manager.ConfigDir
		if directory == "" {
			directory = "/etc/config"
		}
		if _, err := os.Lstat(filepath.Join(directory, "boxctl")); errors.Is(err, os.ErrNotExist) {
			return ManagementSnapshot{}, nil
		}
		return ManagementSnapshot{}, errors.New("cannot read boxctl UCI configuration")
	}
	if len(result.Stdout) > 1<<20 {
		return ManagementSnapshot{}, errors.New("boxctl UCI configuration exceeds limit")
	}
	config, err := parseManagementConfig(string(result.Stdout))
	if err != nil {
		return ManagementSnapshot{}, err
	}
	digest := sha256.Sum256(result.Stdout)
	changes, err := manager.command(ctx, "", "changes", "boxctl")
	if err != nil || changes.ExitCode != 0 {
		return ManagementSnapshot{}, errors.New("cannot inspect pending boxctl UCI changes")
	}
	return ManagementSnapshot{Config: config, Revision: hex.EncodeToString(digest[:]), Pending: len(strings.TrimSpace(string(changes.Stdout))) > 0, Exists: true}, nil
}

func (manager ManagementUCI) Save(ctx context.Context, config ManagementConfig, revision string) (ManagementSnapshot, error) {
	before, err := manager.Read(ctx)
	if err != nil {
		return ManagementSnapshot{}, err
	}
	if !before.Exists {
		return ManagementSnapshot{}, errors.New("boxctl UCI configuration is missing; install the OpenWrt integration files")
	}
	if before.Pending || revision == "" || revision != before.Revision {
		return ManagementSnapshot{}, ErrManagementConfigConflict
	}
	if before.Config == config {
		return before, nil
	}
	delta, err := os.MkdirTemp(manager.TempDir, "boxctl-panel-uci-")
	if err != nil {
		return ManagementSnapshot{}, err
	}
	defer os.RemoveAll(delta)
	values := []string{config.PublicOrigin, config.AllowedHosts, config.TLSCertificate, config.TLSKey}
	previous := []string{before.Config.PublicOrigin, before.Config.AllowedHosts, before.Config.TLSCertificate, before.Config.TLSKey}
	// The fixed section and option names are code-owned; each value is a
	// separate argv element, never shell text or a UCI batch interpolation.
	commands := []string{"boxctl.main=boxctl"}
	for index, name := range ManagementUCIOptions {
		if values[index] != previous[index] {
			commands = append(commands, "boxctl.main."+name+"="+values[index])
		}
	}
	for _, assignment := range commands {
		result, err := manager.command(ctx, delta, "set", assignment)
		if err != nil || result.ExitCode != 0 {
			return ManagementSnapshot{}, errors.New("cannot stage panel settings in UCI")
		}
	}
	// Do not commit another client's deltas or overwrite a stale browser draft.
	current, err := manager.Read(ctx)
	if err != nil {
		return ManagementSnapshot{}, err
	}
	if current.Pending || current.Revision != before.Revision {
		return ManagementSnapshot{}, ErrManagementConfigConflict
	}
	result, err := manager.command(ctx, delta, "commit", "boxctl")
	if err != nil || result.ExitCode != 0 {
		return ManagementSnapshot{}, errors.New("cannot commit panel settings to UCI")
	}
	saved, err := manager.Read(ctx)
	if err != nil {
		return saved, err
	}
	if saved.Config != config {
		return saved, errors.New("committed panel settings failed verification")
	}
	return saved, nil
}

func parseManagementConfig(content string) (ManagementConfig, error) {
	values := make(map[string]string)
	main := false
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		words, err := parseUCIWords(line)
		if err != nil {
			return ManagementConfig{}, errors.New("invalid boxctl UCI configuration")
		}
		if len(words) >= 2 && words[0] == "config" {
			main = len(words) == 3 && words[2] == "main"
			if main && words[1] != "boxctl" {
				return ManagementConfig{}, errors.New("boxctl.main has an unexpected section type")
			}
			continue
		}
		if main && len(words) == 3 && (words[0] == "option" || words[0] == "list") {
			for _, name := range ManagementUCIOptions {
				if words[1] == name {
					if words[0] != "option" {
						return ManagementConfig{}, fmt.Errorf("boxctl.main.%s must be a string option", name)
					}
					values[name] = words[2]
				}
			}
		}
	}
	return ManagementConfig{PublicOrigin: values["public_origin"], AllowedHosts: values["allowed_hosts"], TLSCertificate: values["tls_certificate"], TLSKey: values["tls_key"]}, nil
}
