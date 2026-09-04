package cli

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/kontsevoye/boxctl/internal/state"
)

type actionRecorder struct {
	called        string
	serve         ServeOptions
	doctor        DoctorOptions
	hotplug       HotplugOptions
	update        SelfUpdateOptions
	validate      ConfigValidateOptions
	engineInstall EngineInstallOptions
}

func (r *actionRecorder) Serve(_ context.Context, options ServeOptions) error {
	r.called, r.serve = "serve", options
	return nil
}
func (r *actionRecorder) Firewall(_ context.Context, action string) error {
	r.called = "fw:" + action
	return nil
}
func (r *actionRecorder) Hotplug(_ context.Context, options HotplugOptions) error {
	r.called, r.hotplug = "hotplug:"+options.Event, options
	return nil
}
func (r *actionRecorder) Cleanup(context.Context) error { r.called = "cleanup"; return nil }
func (r *actionRecorder) SetPassword(context.Context, io.Reader, io.Writer) error {
	r.called = "setpass"
	return nil
}
func (r *actionRecorder) ValidateConfig(_ context.Context, path string) error {
	r.called = "validate:" + path
	return nil
}
func (r *actionRecorder) Doctor(_ context.Context, options DoctorOptions) error {
	r.called, r.doctor = "doctor", options
	return nil
}
func (r *actionRecorder) SelfUpdate(_ context.Context, options SelfUpdateOptions) error {
	r.called, r.update = "self-update:"+options.Action, options
	return nil
}
func (r *actionRecorder) ValidateEngineConfig(_ context.Context, options ConfigValidateOptions) error {
	r.called, r.validate = "validate-engine:"+options.Engine, options
	return nil
}
func (r *actionRecorder) InstallEngine(_ context.Context, options EngineInstallOptions) error {
	r.called, r.engineInstall = "install-engine:"+options.Engine, options
	return nil
}

func TestUnknownOptionsNeverStartServe(t *testing.T) {
	t.Parallel()
	recorder := &actionRecorder{}
	err := Execute(context.Background(), []string{"--definitely-not-valid"}, Streams{}, recorder)
	if !IsUsage(err) {
		t.Fatalf("expected usage error, got %v", err)
	}
	if recorder.called != "" {
		t.Fatalf("unexpected action %q", recorder.called)
	}
}

func TestHelpAndVersionDoNotInvokeActions(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"--help"}, {"--version"}, nil} {
		recorder := &actionRecorder{}
		var output bytes.Buffer
		if err := Execute(context.Background(), args, Streams{Out: &output}, recorder); err != nil {
			t.Fatalf("Execute(%v): %v", args, err)
		}
		if recorder.called != "" {
			t.Fatalf("Execute(%v) invoked %q", args, recorder.called)
		}
		if output.Len() == 0 {
			t.Fatalf("Execute(%v) produced no output", args)
		}
	}
}

func TestVersionJSONIncludesCompatibilityVersions(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	if err := Execute(context.Background(), []string{"version", "--json"}, Streams{Out: &output}, &actionRecorder{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"settingsSchemaVersion":1`) || !strings.Contains(output.String(), `"captureInjectorVersion":1`) {
		t.Fatalf("version JSON = %s", output.String())
	}
}

func TestServeMustBeExplicit(t *testing.T) {
	t.Parallel()
	recorder := &actionRecorder{}
	if err := Execute(context.Background(), []string{"serve"}, Streams{}, recorder); err != nil {
		t.Fatal(err)
	}
	if recorder.called != "serve" || recorder.serve.Root != state.DefaultRoot {
		t.Fatalf("unexpected invocation: %#v", recorder)
	}

	recorder = &actionRecorder{}
	recorder = &actionRecorder{}
	err := Execute(context.Background(), []string{"serve", "--removed-option"}, Streams{}, recorder)
	if !IsUsage(err) || recorder.called != "" {
		t.Fatalf("removed option accepted: err=%v called=%q", err, recorder.called)
	}
}

func TestServeStartStoppedIsExplicitlyForwarded(t *testing.T) {
	t.Parallel()
	recorder := &actionRecorder{}
	if err := Execute(context.Background(), []string{"serve", "--start-stopped"}, Streams{}, recorder); err != nil {
		t.Fatal(err)
	}
	if recorder.called != "serve" || !recorder.serve.StartStopped {
		t.Fatalf("start-stopped invocation = %#v", recorder)
	}
}

func TestServeStartStoppedRejectsModesWithoutOwnedCoreLifecycle(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"serve", "--start-stopped", "--no-core"}} {
		recorder := &actionRecorder{}
		err := Execute(context.Background(), args, Streams{}, recorder)
		if !IsUsage(err) {
			t.Fatalf("Execute(%v) error = %v, want usage error", args, err)
		}
		if recorder.called != "" {
			t.Fatalf("Execute(%v) invoked %q", args, recorder.called)
		}
	}
}

func TestCommandsUseCanonicalBoxctlRootByDefault(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "serve", args: []string{"serve"}, want: "serve"},
		{name: "doctor", args: []string{"doctor"}, want: "doctor"},
		{name: "validate", args: []string{"config", "validate"}, want: "validate:" + state.DefaultRoot + "/config.yaml"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := &actionRecorder{}
			if err := Execute(context.Background(), test.args, Streams{}, recorder); err != nil {
				t.Fatal(err)
			}
			if recorder.called != test.want {
				t.Fatalf("called = %q, want %q", recorder.called, test.want)
			}
			switch test.name {
			case "serve":
				if recorder.serve.Root != state.DefaultRoot {
					t.Fatalf("serve root = %q, want %q", recorder.serve.Root, state.DefaultRoot)
				}
			case "doctor":
				if recorder.doctor.Root != state.DefaultRoot {
					t.Fatalf("doctor root = %q, want %q", recorder.doctor.Root, state.DefaultRoot)
				}
			}
		})
	}
}

func TestTUNHotplugRequiresAndPassesReportedInterface(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"hotplug", "tun"},
		{"hotplug", "tun", "--interface", ""},
		{"hotplug", "wan", "unexpected"},
	} {
		recorder := &actionRecorder{}
		err := Execute(context.Background(), args, Streams{}, recorder)
		if !IsUsage(err) || recorder.called != "" {
			t.Fatalf("Execute(%v) = err %v, called %q", args, err, recorder.called)
		}
	}

	recorder := &actionRecorder{}
	if err := Execute(context.Background(), []string{"hotplug", "tun", "--interface", "mihomo0"}, Streams{}, recorder); err != nil {
		t.Fatal(err)
	}
	if recorder.called != "hotplug:tun" || recorder.hotplug.Interface != "mihomo0" {
		t.Fatalf("TUN hotplug invocation = %#v", recorder)
	}
}

func TestEngineAwareConfigValidation(t *testing.T) {
	t.Parallel()
	recorder := &actionRecorder{}
	if err := Execute(context.Background(), []string{"config", "validate", "--engine", "sing-box"}, Streams{}, recorder); err != nil {
		t.Fatal(err)
	}
	if recorder.called != "validate-engine:sing-box" || recorder.validate.File != state.DefaultRoot+"/config.json" {
		t.Fatalf("sing-box validation = %#v", recorder)
	}

	recorder = &actionRecorder{}
	if err := Execute(context.Background(), []string{"config", "validate", "--engine", "sing-box", "--file", "/tmp/profile.json"}, Streams{}, recorder); err != nil {
		t.Fatal(err)
	}
	if recorder.validate.File != "/tmp/profile.json" {
		t.Fatalf("explicit validation file = %#v", recorder.validate)
	}

	for _, args := range [][]string{
		{"config", "validate", "--engine", "unknown"},
		{"config", "unknown"},
	} {
		recorder = &actionRecorder{}
		err := Execute(context.Background(), args, Streams{}, recorder)
		if !IsUsage(err) || recorder.called != "" {
			t.Fatalf("Execute(%v) = %v, called %q", args, err, recorder.called)
		}
	}
}

func TestOfflineSingBoxEngineInstallParsing(t *testing.T) {
	t.Parallel()
	recorder := &actionRecorder{}
	args := []string{"engine", "install", "sing-box", "--file", "/tmp/sing-box-1.14.0-linux-arm64-musl.tar.gz", "--sha256", strings.Repeat("a", 64), "--root", "/srv/boxctl"}
	if err := Execute(context.Background(), args, Streams{}, recorder); err != nil {
		t.Fatal(err)
	}
	if recorder.called != "install-engine:sing-box" || recorder.engineInstall.Root != "/srv/boxctl" || recorder.engineInstall.File != args[4] || recorder.engineInstall.SHA256 != strings.Repeat("a", 64) {
		t.Fatalf("engine install = %#v", recorder.engineInstall)
	}
	for _, invalid := range [][]string{
		{"engine"},
		{"engine", "install"},
		{"engine", "install", "mihomo", "--file", "/tmp/mihomo"},
		{"engine", "install", "sing-box"},
	} {
		recorder = &actionRecorder{}
		err := Execute(context.Background(), invalid, Streams{}, recorder)
		if !IsUsage(err) || recorder.called != "" {
			t.Fatalf("Execute(%v) = %v, called %q", invalid, err, recorder.called)
		}
	}
}

func TestOptionalEngineActionsFailClosedWhenApplicationIsLegacy(t *testing.T) {
	t.Parallel()
	legacy := &legacyActionRecorder{}
	if err := Execute(context.Background(), []string{"config", "validate", "--engine", "sing-box"}, Streams{}, legacy); err == nil || !strings.Contains(err.Error(), "not wired") {
		t.Fatalf("legacy sing-box validation error = %v", err)
	}
	if err := Execute(context.Background(), []string{"engine", "install", "sing-box", "--file", "/tmp/archive"}, Streams{}, legacy); err == nil || !strings.Contains(err.Error(), "not wired") {
		t.Fatalf("legacy engine install error = %v", err)
	}
}

type legacyActionRecorder actionRecorder

func (r *legacyActionRecorder) Serve(ctx context.Context, options ServeOptions) error {
	return (*actionRecorder)(r).Serve(ctx, options)
}
func (r *legacyActionRecorder) Firewall(ctx context.Context, action string) error {
	return (*actionRecorder)(r).Firewall(ctx, action)
}
func (r *legacyActionRecorder) Hotplug(ctx context.Context, options HotplugOptions) error {
	return (*actionRecorder)(r).Hotplug(ctx, options)
}
func (r *legacyActionRecorder) Cleanup(ctx context.Context) error {
	return (*actionRecorder)(r).Cleanup(ctx)
}
func (r *legacyActionRecorder) SetPassword(ctx context.Context, in io.Reader, out io.Writer) error {
	return (*actionRecorder)(r).SetPassword(ctx, in, out)
}
func (r *legacyActionRecorder) ValidateConfig(ctx context.Context, path string) error {
	return (*actionRecorder)(r).ValidateConfig(ctx, path)
}
func (r *legacyActionRecorder) Doctor(ctx context.Context, options DoctorOptions) error {
	return (*actionRecorder)(r).Doctor(ctx, options)
}
func (r *legacyActionRecorder) SelfUpdate(ctx context.Context, options SelfUpdateOptions) error {
	return (*actionRecorder)(r).SelfUpdate(ctx, options)
}

func TestSelfUpdateCommandsAreExplicitlyParsed(t *testing.T) {
	t.Parallel()
	recorder := &actionRecorder{}
	if err := Execute(context.Background(), []string{"self-update", "check"}, Streams{}, recorder); err != nil {
		t.Fatal(err)
	}
	if recorder.called != "self-update:check" || recorder.update.Repository != "kontsevoye/boxctl" || recorder.update.Root != state.DefaultRoot {
		t.Fatalf("default self-update check = %#v", recorder.update)
	}

	recorder = &actionRecorder{}
	args := []string{"self-update", "install", "--file", "/tmp/boxctl", "--sha256", "abcd", "--no-restart", "--root", "/srv/boxctl"}
	if err := Execute(context.Background(), args, Streams{}, recorder); err != nil {
		t.Fatal(err)
	}
	if recorder.called != "self-update:install" || recorder.update.File != "/tmp/boxctl" || recorder.update.SHA256 != "abcd" || !recorder.update.NoRestart || recorder.update.Root != "/srv/boxctl" {
		t.Fatalf("local self-update install = %#v", recorder.update)
	}

	recorder = &actionRecorder{}
	if err := Execute(context.Background(), []string{"self-update", "rollback", "--no-restart"}, Streams{}, recorder); err != nil {
		t.Fatal(err)
	}
	if recorder.called != "self-update:rollback" || !recorder.update.NoRestart {
		t.Fatalf("self-update rollback = %#v", recorder.update)
	}

	recorder = &actionRecorder{}
	if err := Execute(context.Background(), []string{"self-update", "install", "--full-restart"}, Streams{}, recorder); err != nil {
		t.Fatal(err)
	}
	if !recorder.update.FullRestart || recorder.update.ConfirmFullRestart == nil {
		t.Fatalf("full self-update install = %#v", recorder.update)
	}
}

func TestSelfUpdateRejectsAmbiguousOrUnknownInput(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"self-update"},
		{"self-update", "unknown"},
		{"self-update", "check", "--file", "/tmp/boxctl"},
		{"self-update", "install", "--sha256", "abcd"},
		{"self-update", "install", "--no-restart", "--full-restart"},
	} {
		recorder := &actionRecorder{}
		err := Execute(context.Background(), args, Streams{}, recorder)
		if !IsUsage(err) || recorder.called != "" {
			t.Fatalf("Execute(%v) = err %v, called %q", args, err, recorder.called)
		}
	}
}
