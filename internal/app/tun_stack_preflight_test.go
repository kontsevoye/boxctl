package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

func TestMipsPreflightRejectsBeforeSavingOrStoppingLiveRuntime(t *testing.T) {
	t.Parallel()
	for _, nativeMips := range []bool{false, true} {
		name := "changed saved stack"
		if nativeMips {
			name = "entering TUN with native mips"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "engines", "mihomo"), 0o700); err != nil {
				t.Fatal(err)
			}
			// The old core accepts ordinary configs but rejects the new enum in
			// its native config check. Do not infer compatibility from -v output.
			const oldCore = `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-f" ]; then shift; config="$1"; fi
  shift
done
if grep -q 'stack: "mips"' "$config"; then
  echo 'invalid tun stack: mips' >&2
  exit 1
fi
exit 0
`
			if err := os.WriteFile(filepath.Join(root, "engines", "mihomo", "mihomo"), []byte(oldCore), 0o700); err != nil {
				t.Fatal(err)
			}
			source := "mode: rule\ntun:\n  stack: system\n"
			original := state.Settings{"PROXY_MODE": "tun", "TUN_STACK": "system", "FUTURE_KEY": "preserve"}
			stack, mode := "mips", "tun"
			patch := web.SettingsPatch{TUNStack: &stack}
			if nativeMips {
				source = "mode: rule\ntun:\n  stack: mips\n"
				original = state.Settings{"PROXY_MODE": "tproxy", "FUTURE_KEY": "preserve"}
				patch = web.SettingsPatch{CaptureMode: &mode}
			}
			if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			service, err := NewSettingsService(root)
			if err != nil {
				t.Fatal(err)
			}
			if err := service.State.SaveSettings(settingsRelativePath, original); err != nil {
				t.Fatal(err)
			}
			before, err := service.State.Read(settingsRelativePath)
			if err != nil {
				t.Fatal(err)
			}
			live := engine.PreparedCore{Engine: "mihomo", BinaryPath: "/live/core", RuntimeConfigPath: "/live/runtime.yaml", Capture: engine.CapturePlan{TUNStack: "system"}}
			health := engine.HealthStatus{Running: true, ControllerReady: true, PID: 42}
			fake := &lifecycleFake{prepared: live, health: health}
			service.Lifecycle = &Lifecycle{Core: fake, Preparer: fake, Activation: fake, snap: LifecycleSnapshot{State: LifecycleRunning, Prepared: live, Health: health}}
			beforeSnapshot := service.Lifecycle.Snapshot()
			preparer, err := NewActiveMihomoPreparer(root, engine.NewMihomoDriver(engine.MihomoOptions{}))
			if err != nil {
				t.Fatal(err)
			}
			preparer.RuntimeDir = t.TempDir()
			service.ValidateRuntimeSettings = func(ctx context.Context, candidate RuntimeSettings) error {
				if service.Lifecycle.opMu.TryLock() {
					service.Lifecycle.opMu.Unlock()
					t.Fatal("preflight must execute under the operation gate")
				}
				return preparer.ValidateRuntimeSettings(ctx, candidate)
			}
			service.OnChanged = func(ctx context.Context, _ bool) error {
				_, err := service.Lifecycle.RestartIfRunning(ctx)
				return err
			}
			_, err = service.UpdateSettings(context.Background(), patch)
			var public *web.PublicError
			if !errors.As(err, &public) || public.Code != "runtime_settings_rejected" || !strings.Contains(public.Message, "not saved") || !strings.Contains(public.Message, "requires Mihomo v1.19.31") {
				t.Fatalf("preflight error = %v", err)
			}
			after, err := service.State.Read(settingsRelativePath)
			if err != nil || string(after) != string(before) {
				t.Fatalf("failed preflight changed settings: %s, %v", after, err)
			}
			if !reflect.DeepEqual(service.Lifecycle.Snapshot(), beforeSnapshot) || len(fake.events) != 0 || !fake.health.Running {
				t.Fatalf("failed preflight touched live runtime: snapshot=%+v events=%v", service.Lifecycle.Snapshot(), fake.events)
			}
			entries, err := os.ReadDir(preparer.RuntimeDir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("failed preflight left files: %v, %v", entries, err)
			}
			unchanged, err := os.ReadFile(filepath.Join(root, "config.yaml"))
			if err != nil || string(unchanged) != source {
				t.Fatalf("source changed: %s, %v", unchanged, err)
			}
		})
	}
}

func TestExplicitDefaultStackPreflightAndRestartOverrideNativeStack(t *testing.T) {
	t.Parallel()
	service, err := NewSettingsService(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	service.ValidateRuntimeSettings = func(_ context.Context, candidate RuntimeSettings) error {
		calls = append(calls, "preflight")
		capture, err := candidate.CapturePlan(ManagedMihomoSettings{TUNStack: "mips"})
		if err != nil || capture.TUNStack != "system" {
			t.Fatalf("explicit override = %+v, %v", capture, err)
		}
		if _, err := service.State.Read(settingsRelativePath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("preflight ran after save: %v", err)
		}
		return nil
	}
	service.OnChanged = func(_ context.Context, restart bool) error {
		if !restart {
			t.Fatal("explicit default overrides native source and requires restart")
		}
		calls = append(calls, "restart")
		return nil
	}
	stack := "system"
	if _, err := service.UpdateSettings(context.Background(), web.SettingsPatch{TUNStack: &stack}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"preflight", "restart"}) {
		t.Fatalf("calls = %v", calls)
	}
}

func TestTUNSettingsPreflightIsBoundedAndPreservesSettings(t *testing.T) {
	t.Parallel()
	service, err := NewSettingsService(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service.Lifecycle = &Lifecycle{PrepareTimeout: time.Millisecond}
	service.ValidateRuntimeSettings = func(ctx context.Context, _ RuntimeSettings) error { <-ctx.Done(); return ctx.Err() }
	stack := "mips"
	if _, err := service.UpdateSettings(context.Background(), web.SettingsPatch{TUNStack: &stack}); err == nil {
		t.Fatal("preflight timeout succeeded")
	}
	if _, err := service.State.Read(settingsRelativePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("timeout persisted settings: %v", err)
	}
}

func TestTUNSettingsPreflightDefersOnlyMissingInstallationWhileStopped(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		source     string
		binary     string
		binaryMode os.FileMode
		running    bool
		wantSave   bool
	}{
		{name: "uninstalled", wantSave: true},
		{name: "source missing", binary: "#!/bin/sh\nexit 0\n", binaryMode: 0o700, wantSave: true},
		{name: "binary missing", source: "mode: rule\n", wantSave: true},
		{name: "malformed source", source: "tun: [unfinished\n"},
		{name: "non-executable binary", source: "mode: rule\n", binary: "invalid executable", binaryMode: 0o600},
		{name: "native validation rejection while stopped", source: "mode: rule\n", binary: "#!/bin/sh\necho 'invalid tun stack: mips' >&2\nexit 1\n", binaryMode: 0o700},
		{name: "live core with missing installation", running: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if test.source != "" {
				if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte(test.source), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if test.binary != "" {
				if err := os.MkdirAll(filepath.Join(root, "engines", "mihomo"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "engines", "mihomo", "mihomo"), []byte(test.binary), test.binaryMode); err != nil {
					t.Fatal(err)
				}
			}
			service, err := NewSettingsService(root)
			if err != nil {
				t.Fatal(err)
			}
			original := state.Settings{"FUTURE_KEY": "preserve"}
			if err := service.State.SaveSettings(settingsRelativePath, original); err != nil {
				t.Fatal(err)
			}
			service.Lifecycle = &Lifecycle{snap: LifecycleSnapshot{State: LifecycleStopped}}
			if test.running {
				service.Lifecycle.snap = LifecycleSnapshot{State: LifecycleRunning, Health: engine.HealthStatus{Running: true, PID: 42}}
			}
			preparer, err := NewActiveMihomoPreparer(root, engine.NewMihomoDriver(engine.MihomoOptions{}))
			if err != nil {
				t.Fatal(err)
			}
			preparer.RuntimeDir = t.TempDir()
			service.ValidateRuntimeSettings = preparer.ValidateRuntimeSettings
			stack, theme := "system", "dark"
			saved, err := service.UpdateSettings(context.Background(), web.SettingsPatch{TUNStack: &stack, Theme: &theme})
			if test.wantSave {
				if err != nil || saved.TUNStack != stack || saved.Theme != theme {
					t.Fatalf("pre-install full save = %+v, %v", saved, err)
				}
			} else if err == nil {
				t.Fatal("invalid installed/source state was ignored")
			}
			raw, readErr := service.State.LoadSettings(settingsRelativePath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !test.wantSave && !reflect.DeepEqual(raw, original) {
				t.Fatalf("rejection changed settings: %+v", raw)
			}
			if raw["FUTURE_KEY"] != "preserve" {
				t.Fatalf("unrelated setting lost: %+v", raw)
			}
		})
	}
}
