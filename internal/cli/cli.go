// Package cli implements the public boxctl command contract.
package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/kontsevoye/boxctl/internal/buildinfo"
	"github.com/kontsevoye/boxctl/internal/state"
)

// Streams contains the command's standard streams.
type Streams struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
}

// ServeOptions controls the long-running manager.
type ServeOptions struct {
	Root         string
	Listen       string
	NoCore       bool
	NoGateway    bool
	StartStopped bool
}

// DoctorOptions controls diagnostics output.
type DoctorOptions struct {
	Root string
	JSON bool
}

// SelfUpdateOptions describes a manager update. Install uses GitHub Releases
// unless File is set; Rollback restores the immediately preceding binary.
type SelfUpdateOptions struct {
	Action             string
	Root               string
	Repository         string
	File               string
	SHA256             string
	NoRestart          bool
	FullRestart        bool
	ConfirmFullRestart func(string) (bool, error)
}

// ConfigValidateOptions selects the native validator for one engine. The
// legacy ValidateConfig action remains the Mihomo default until application
// wiring implements EngineConfigActions.
type ConfigValidateOptions struct {
	Engine string
	File   string
}

// EngineInstallOptions describes an explicit offline engine install. Custom
// files are never treated as an automatic-update channel.
type EngineInstallOptions struct {
	Engine string
	Root   string
	File   string
	SHA256 string
}

// HotplugOptions describes an OpenWrt topology event. Interface is required
// for a TUN netdev event so the application can compare it with the active,
// validated capture plan instead of relying on a hard-coded device name.
type HotplugOptions struct {
	Event     string
	Interface string
}

// Actions are implemented by the application layer. CLI parsing never starts
// a service implicitly: every operation is an explicit method call.
type Actions interface {
	Serve(context.Context, ServeOptions) error
	Firewall(context.Context, string) error
	Hotplug(context.Context, HotplugOptions) error
	Cleanup(context.Context) error
	SetPassword(context.Context, io.Reader, io.Writer) error
	ValidateConfig(context.Context, string) error
	Doctor(context.Context, DoctorOptions) error
	SelfUpdate(context.Context, SelfUpdateOptions) error
}

// EngineConfigActions is an optional application extension. Keeping it out of
// Actions preserves source compatibility while the multi-engine application
// coordinator is wired.
type EngineConfigActions interface {
	ValidateEngineConfig(context.Context, ConfigValidateOptions) error
}

// EngineInstallActions is an optional application extension for the verified,
// versioned engine installer in internal/update.
type EngineInstallActions interface {
	InstallEngine(context.Context, EngineInstallOptions) error
}

// UsageError marks invalid command input. Callers should print the message and
// exit with status 2 without invoking any application action.
type UsageError struct {
	Message string
}

func (e *UsageError) Error() string { return e.Message }

// Execute parses args and invokes exactly one explicit action.
func Execute(ctx context.Context, args []string, streams Streams, actions Actions) error {
	if streams.In == nil {
		streams.In = strings.NewReader("")
	}
	if streams.Out == nil {
		streams.Out = io.Discard
	}
	if streams.Err == nil {
		streams.Err = io.Discard
	}

	if len(args) == 0 {
		printRootUsage(streams.Out)
		return nil
	}

	switch args[0] {
	case "help", "-h", "--help":
		printRootUsage(streams.Out)
		return nil
	case "version", "-v", "--version":
		if len(args) == 2 && args[1] == "--json" {
			return json.NewEncoder(streams.Out).Encode(struct {
				Version                string `json:"version"`
				Commit                 string `json:"commit"`
				Date                   string `json:"date"`
				SettingsSchemaVersion  int    `json:"settingsSchemaVersion"`
				CaptureInjectorVersion int    `json:"captureInjectorVersion"`
			}{buildinfo.Version, buildinfo.Commit, buildinfo.Date, buildinfo.SettingsSchemaVersion, buildinfo.CaptureInjectorVersion})
		}
		if len(args) != 1 {
			return usage("version accepts only --json")
		}
		_, err := fmt.Fprintf(streams.Out, "boxctl %s (commit %s, built %s)\n", buildinfo.Version, buildinfo.Commit, buildinfo.Date)
		return err
	case "serve":
		fs := newFlagSet("serve", streams.Err)
		options := ServeOptions{}
		fs.StringVar(&options.Root, "root", state.DefaultRoot, "boxctl data root")
		fs.StringVar(&options.Listen, "listen", "", "HTTP listen address; defaults to the detected LAN address on port 9091")
		fs.BoolVar(&options.NoCore, "no-core", false, "do not start a proxy core")
		fs.BoolVar(&options.NoGateway, "no-gateway", false, "do not apply gateway or DNS state")
		fs.BoolVar(&options.StartStopped, "start-stopped", false, "start the management service without initially starting the proxy core")
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		if options.StartStopped && options.NoCore {
			return usage("--start-stopped requires an owned core lifecycle and cannot be used with --no-core")
		}
		return actions.Serve(ctx, options)
	case "fw":
		if len(args) != 2 {
			return usage("usage: boxctl fw start|stop|update|diagnose")
		}
		switch args[1] {
		case "start", "stop", "update", "diagnose":
			return actions.Firewall(ctx, args[1])
		default:
			return usage("unknown firewall action %q", args[1])
		}
	case "hotplug":
		if len(args) < 2 {
			return usage("usage: boxctl hotplug wan | boxctl hotplug tun --interface NAME")
		}
		switch args[1] {
		case "wan":
			if len(args) != 2 {
				return usage("boxctl hotplug wan accepts no arguments")
			}
			return actions.Hotplug(ctx, HotplugOptions{Event: "wan"})
		case "tun":
			fs := newFlagSet("hotplug tun", streams.Err)
			interfaceName := fs.String("interface", "", "TUN interface reported by OpenWrt hotplug")
			if err := parse(fs, args[2:]); err != nil {
				return err
			}
			if strings.TrimSpace(*interfaceName) == "" {
				return usage("hotplug tun requires --interface NAME")
			}
			return actions.Hotplug(ctx, HotplugOptions{Event: "tun", Interface: *interfaceName})
		default:
			return usage("unknown hotplug event %q", args[1])
		}
	case "cleanup":
		if len(args) != 1 {
			return usage("cleanup accepts no arguments")
		}
		return actions.Cleanup(ctx)
	case "setpass":
		if len(args) != 1 {
			return usage("setpass reads the password from the terminal and accepts no arguments")
		}
		return actions.SetPassword(ctx, streams.In, streams.Out)
	case "config":
		if len(args) < 2 || args[1] != "validate" {
			return usage("usage: boxctl config validate [--engine mihomo|sing-box] [--file PATH]")
		}
		fs := newFlagSet("config validate", streams.Err)
		engine := fs.String("engine", state.EngineMihomo, "configuration engine")
		file := fs.String("file", "", "engine configuration file")
		if err := parse(fs, args[2:]); err != nil {
			return err
		}
		if *engine != state.EngineMihomo && *engine != state.EngineSingBox {
			return usage("unsupported configuration engine %q", *engine)
		}
		if *file == "" {
			*file = state.DefaultRoot + "/config.yaml"
			if *engine == state.EngineSingBox {
				*file = state.DefaultRoot + "/config.json"
			}
		}
		if *engine == state.EngineMihomo {
			return actions.ValidateConfig(ctx, *file)
		}
		engineActions, ok := actions.(EngineConfigActions)
		if !ok {
			return errors.New("sing-box configuration validation is not wired by the application")
		}
		return engineActions.ValidateEngineConfig(ctx, ConfigValidateOptions{Engine: *engine, File: *file})
	case "engine":
		if len(args) < 3 || args[1] != "install" {
			return usage("usage: boxctl engine install sing-box --file PATH [--sha256 HEX] [--root PATH]")
		}
		options := EngineInstallOptions{Engine: args[2], Root: state.DefaultRoot}
		if options.Engine != state.EngineSingBox {
			return usage("unsupported managed engine %q", options.Engine)
		}
		fs := newFlagSet("engine install", streams.Err)
		fs.StringVar(&options.File, "file", "", "local sing-box arm64-musl tar.gz archive")
		fs.StringVar(&options.SHA256, "sha256", "", "expected archive SHA-256; defaults to FILE.sha256")
		fs.StringVar(&options.Root, "root", state.DefaultRoot, "boxctl data root")
		if err := parse(fs, args[3:]); err != nil {
			return err
		}
		if strings.TrimSpace(options.File) == "" {
			return usage("engine install sing-box requires --file PATH")
		}
		engineActions, ok := actions.(EngineInstallActions)
		if !ok {
			return errors.New("sing-box engine installation is not wired by the application")
		}
		return engineActions.InstallEngine(ctx, options)
	case "doctor":
		fs := newFlagSet("doctor", streams.Err)
		options := DoctorOptions{}
		fs.StringVar(&options.Root, "root", state.DefaultRoot, "boxctl data root")
		fs.BoolVar(&options.JSON, "json", false, "emit machine-readable output")
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		return actions.Doctor(ctx, options)
	case "self-update":
		if len(args) < 2 {
			return usage("usage: boxctl self-update check|install|rollback")
		}
		options := SelfUpdateOptions{Action: args[1], Root: state.DefaultRoot, Repository: "kontsevoye/boxctl"}
		switch options.Action {
		case "check":
			fs := newFlagSet("self-update check", streams.Err)
			fs.StringVar(&options.Root, "root", state.DefaultRoot, "boxctl data root")
			fs.StringVar(&options.Repository, "repo", "kontsevoye/boxctl", "GitHub repository")
			if err := parse(fs, args[2:]); err != nil {
				return err
			}
		case "install":
			fs := newFlagSet("self-update install", streams.Err)
			fs.StringVar(&options.Root, "root", state.DefaultRoot, "boxctl data root")
			fs.StringVar(&options.Repository, "repo", "kontsevoye/boxctl", "GitHub repository")
			fs.StringVar(&options.File, "file", "", "install from a local raw Linux/AArch64 binary")
			fs.StringVar(&options.SHA256, "sha256", "", "expected local file SHA-256; defaults to FILE.sha256")
			fs.BoolVar(&options.NoRestart, "no-restart", false, "install the binary without restarting boxctl")
			fs.BoolVar(&options.FullRestart, "full-restart", false, "restart boxctl and Mihomo; also approve a required compatibility restart")
			if err := parse(fs, args[2:]); err != nil {
				return err
			}
			if options.File == "" && options.SHA256 != "" {
				return usage("--sha256 requires --file")
			}
		case "rollback":
			fs := newFlagSet("self-update rollback", streams.Err)
			fs.StringVar(&options.Root, "root", state.DefaultRoot, "boxctl data root")
			fs.BoolVar(&options.NoRestart, "no-restart", false, "restore the previous binary without restarting boxctl")
			fs.BoolVar(&options.FullRestart, "full-restart", false, "restart boxctl and Mihomo; also approve a required compatibility restart")
			if err := parse(fs, args[2:]); err != nil {
				return err
			}
		default:
			return usage("unknown self-update action %q", options.Action)
		}
		if options.NoRestart && options.FullRestart {
			return usage("--no-restart and --full-restart cannot be used together")
		}
		options.ConfirmFullRestart = func(warning string) (bool, error) {
			if _, err := fmt.Fprintln(streams.Err, warning); err != nil {
				return false, err
			}
			if options.FullRestart {
				return true, nil
			}
			if _, err := fmt.Fprint(streams.Err, "Continue with a full restart that interrupts active connections? [y/N] "); err != nil {
				return false, err
			}
			line, err := bufio.NewReader(streams.In).ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return false, err
			}
			answer := strings.ToLower(strings.TrimSpace(line))
			return answer == "y" || answer == "yes", nil
		}
		return actions.SelfUpdate(ctx, options)
	default:
		return usage("unknown command %q; run 'boxctl help'", args[0])
	}
}

func newFlagSet(name string, errOut io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() {}
	return fs
}

func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return &UsageError{Message: err.Error()}
	}
	if fs.NArg() != 0 {
		return usage("unexpected argument %q", fs.Arg(0))
	}
	return nil
}

func usage(format string, args ...any) error {
	return &UsageError{Message: fmt.Sprintf(format, args...)}
}

// IsUsage reports whether err was caused by invalid command input.
func IsUsage(err error) bool {
	var target *UsageError
	return errors.As(err, &target)
}

func printRootUsage(w io.Writer) {
	_, _ = io.WriteString(w, `boxctl selective-routing manager

Usage:
  boxctl serve [--root PATH] [--listen ADDRESS] [--start-stopped]
  boxctl fw start|stop|update|diagnose
	  boxctl hotplug wan
	  boxctl hotplug tun --interface NAME
  boxctl cleanup
  boxctl setpass
  boxctl config validate [--engine mihomo|sing-box] [--file PATH]
  boxctl engine install sing-box --file PATH [--sha256 HEX] [--root PATH]
  boxctl doctor [--json] [--root PATH]
  boxctl self-update check [--repo OWNER/REPO] [--root PATH]
  boxctl self-update install [--repo OWNER/REPO] [--file PATH] [--sha256 HEX] [--no-restart|--full-restart] [--root PATH]
  boxctl self-update rollback [--no-restart|--full-restart] [--root PATH]
  boxctl version [--json]
`)
}
