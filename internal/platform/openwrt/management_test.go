package openwrt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type managementUCIRunner struct {
	values   map[string]string
	staged   map[string]string
	pending  bool
	fail     string
	commands []Command
}

func (runner *managementUCIRunner) Run(_ context.Context, command Command) (Result, error) {
	runner.commands = append(runner.commands, command)
	if command.Name != "uci" {
		return Result{}, errors.New("unexpected non-UCI command")
	}
	args := command.Args
	delta := ""
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "-q":
			args = args[1:]
		case "-c":
			args = args[2:]
		case "-t":
			delta, args = args[1], args[2:]
		default:
			return Result{}, errors.New("unexpected UCI flag")
		}
	}
	if args[0] == runner.fail || (args[0] == "set" && strings.Contains(args[1], runner.fail) && runner.fail != "") {
		return Result{ExitCode: 1}, nil
	}
	switch args[0] {
	case "export":
		var keys []string
		for key := range runner.values {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		content := "package boxctl\nconfig boxctl 'main'\n"
		for _, key := range keys {
			content += fmt.Sprintf(" option %s %s\n", key, quoteUCI(runner.values[key]))
		}
		content += "config unrelated 'other'\n option keep 'unchanged'\n"
		return Result{Stdout: []byte(content)}, nil
	case "changes":
		if runner.pending {
			return Result{Stdout: []byte("boxctl.other.keep='pending'\n")}, nil
		}
		return Result{}, nil
	case "set":
		if delta == "" {
			return Result{}, errors.New("write attempted without private delta directory")
		}
		key, value, _ := strings.Cut(args[1], "=")
		if key != "boxctl.main" {
			runner.staged[strings.TrimPrefix(key, "boxctl.main.")] = value
		}
		return Result{}, nil
	case "commit":
		if delta == "" || args[1] != "boxctl" {
			return Result{}, errors.New("unexpected commit target")
		}
		for key, value := range runner.staged {
			runner.values[key] = value
		}
		clear(runner.staged)
		return Result{}, nil
	default:
		return Result{}, errors.New("unexpected UCI action")
	}
}

func TestManagementUCIReadsFreshValuesAndCommitsOnlyManagedOptions(t *testing.T) {
	runner := &managementUCIRunner{values: map[string]string{"public_origin": "https://old.example", "unknown_option": "keep me"}, staged: make(map[string]string)}
	manager := ManagementUCI{Runner: runner, TempDir: t.TempDir()}
	before, err := manager.Read(context.Background())
	if err != nil || before.Config.PublicOrigin != "https://old.example" {
		t.Fatalf("read = %+v, %v", before, err)
	}
	config := ManagementConfig{PublicOrigin: "https://panel.example", AllowedHosts: "router.home,router.lan", TLSCertificate: "/etc/ssl/panel cert.pem", TLSKey: "/etc/ssl/key 'quoted' $(literal).pem"}
	saved, err := manager.Save(context.Background(), config, before.Revision)
	if err != nil || saved.Config != config || saved.Revision == before.Revision {
		t.Fatalf("save = %+v, %v", saved, err)
	}
	if runner.values["unknown_option"] != "keep me" {
		t.Fatal("unrelated option changed")
	}
	runner.values["public_origin"] = "https://edited-outside.example"
	latest, err := manager.Read(context.Background())
	if err != nil || latest.Config.PublicOrigin != runner.values["public_origin"] {
		t.Fatalf("stale read = %+v, %v", latest, err)
	}
	for _, command := range runner.commands {
		for index, arg := range command.Args {
			if arg == "-t" {
				if _, err := os.Stat(command.Args[index+1]); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("private delta directory was not removed: %v", err)
				}
			}
		}
	}
}

func TestManagementUCIRejectsConflictsAndDoesNotCommitPartialSaves(t *testing.T) {
	for _, failure := range []string{"pending", "stale", "allowed_hosts", "commit"} {
		t.Run(failure, func(t *testing.T) {
			runner := &managementUCIRunner{values: map[string]string{"public_origin": "https://old.example", "unknown_option": "keep me"}, staged: make(map[string]string)}
			manager := ManagementUCI{Runner: runner, TempDir: t.TempDir()}
			before, err := manager.Read(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "pending":
				runner.pending = true
			case "stale":
				runner.values["unknown_option"] = "edited elsewhere"
			default:
				runner.fail = failure
			}
			_, err = manager.Save(context.Background(), ManagementConfig{PublicOrigin: "https://new.example", AllowedHosts: "panel.example"}, before.Revision)
			if err == nil {
				t.Fatal("failed or conflicting save was accepted")
			}
			if runner.values["public_origin"] != "https://old.example" {
				t.Fatal("failed save changed the committed value")
			}
			if failure == "pending" && !runner.pending {
				t.Fatal("external pending changes were discarded")
			}
		})
	}
}

// This test also runs on OpenWrt against the real UCI CLI. Every mutation uses
// a temporary config directory and private delta directory; no service runs.
func TestManagementUCIWithRealCLI(t *testing.T) {
	if _, err := exec.LookPath("uci"); err != nil {
		t.Skip("UCI CLI is not installed")
	}
	directory := t.TempDir()
	file := filepath.Join(directory, "boxctl")
	if err := os.WriteFile(file, []byte("config boxctl 'main'\n option public_origin 'https://old.example'\n option untouched 'keep this'\nconfig unrelated 'other'\n option keep 'yes'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := ManagementUCI{Runner: ExecRunner{}, ConfigDir: directory, TempDir: directory}
	before, err := manager.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	config := ManagementConfig{PublicOrigin: "https://new.example", AllowedHosts: "router.home,router.lan", TLSCertificate: "/tmp/certificate with spaces", TLSKey: "/tmp/key 'quoted' $(literal)"}
	after, err := manager.Save(context.Background(), config, before.Revision)
	if err != nil || after.Config != config || after.Pending {
		t.Fatalf("real UCI commit = %+v, %v", after, err)
	}
	result, err := (ExecRunner{}).Run(context.Background(), Command{Name: "uci", Args: []string{"-c", directory, "get", "boxctl.other.keep"}})
	if err != nil || string(result.Stdout) != "yes\n" {
		t.Fatalf("unrelated UCI section changed: %s, %v", result.Stdout, err)
	}
}
