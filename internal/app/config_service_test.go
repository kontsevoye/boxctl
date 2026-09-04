package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

func TestConfigServiceRequiresRevisionAndUpdatesActiveMirror(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "engines", "mihomo"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "engines", "mihomo", "mihomo"), []byte("fake"), 0o700); err != nil {
		t.Fatal(err)
	}
	profiles, err := state.NewProfileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	profile := state.ActiveProfile{Name: "default", Engine: state.EngineMihomo}
	old := []byte("external-controller: 0.0.0.0:9090\nsecret: old\n")
	if err := profiles.Create(context.Background(), profile, old); err != nil {
		t.Fatal(err)
	}
	if err := profiles.Activate(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	preparer, err := NewActiveMihomoPreparer(root, &recordingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	service := &ConfigService{Preparer: preparer}
	refreshes := 0
	service.OnChanged = func(context.Context) (bool, error) {
		refreshes++
		return true, nil
	}
	document, err := service.RawConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SaveRawConfig(context.Background(), web.RawConfigUpdate{Content: "external-controller: 0.0.0.0:9090\n"}); err == nil {
		t.Fatal("save without revision succeeded")
	}
	result, err := service.SaveRawConfig(context.Background(), web.RawConfigUpdate{Content: "external-controller: 0.0.0.0:9090\nsecret: new\n", Revision: document.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if result.ReloadRequired || result.Revision == document.Revision || refreshes != 1 {
		t.Fatalf("result = %+v", result)
	}
	stored, err := profiles.Get(profile)
	if err != nil {
		t.Fatal(err)
	}
	active, err := os.ReadFile(filepath.Join(root, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(active) || string(active) != "external-controller: 0.0.0.0:9090\nsecret: new\n" {
		t.Fatalf("stored=%q active=%q", stored, active)
	}
}

func TestConfigServiceSupportsSaveReloadAndRestart(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "engines", "mihomo"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "engines", "mihomo", "mihomo"), []byte("fake"), 0o700); err != nil {
		t.Fatal(err)
	}
	profiles, err := state.NewProfileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	profile := state.ActiveProfile{Name: "default", Engine: state.EngineMihomo}
	if err := profiles.Create(context.Background(), profile, []byte("mode: rule\n")); err != nil {
		t.Fatal(err)
	}
	if err := profiles.Activate(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	preparer, err := NewActiveMihomoPreparer(root, &recordingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	service := &ConfigService{Preparer: preparer}
	reloads := 0
	restarts := 0
	service.OnReload = func(context.Context) (bool, error) { reloads++; return true, nil }
	service.OnChanged = func(context.Context) (bool, error) { restarts++; return true, nil }

	document, err := service.RawConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	saved, err := service.SaveRawConfig(context.Background(), web.RawConfigUpdate{Content: "mode: direct\n", Revision: document.Revision, Apply: "save"})
	if err != nil {
		t.Fatal(err)
	}
	if saved.Applied || !saved.ReloadRequired || saved.Apply != "save" || reloads != 0 || restarts != 0 {
		t.Fatalf("save result = %+v reloads=%d restarts=%d", saved, reloads, restarts)
	}
	reloaded, err := service.SaveRawConfig(context.Background(), web.RawConfigUpdate{Content: "mode: global\n", Revision: saved.Revision, Apply: "reload"})
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.Applied || reloaded.ReloadRequired || reloaded.Apply != "reload" || reloads != 1 || restarts != 0 {
		t.Fatalf("reload result = %+v reloads=%d restarts=%d", reloaded, reloads, restarts)
	}
	restarted, err := service.SaveRawConfig(context.Background(), web.RawConfigUpdate{Content: "mode: rule\n", Revision: reloaded.Revision, Apply: "restart"})
	if err != nil {
		t.Fatal(err)
	}
	if !restarted.Applied || restarted.Apply != "restart" || reloads != 1 || restarts != 1 {
		t.Fatalf("restart result = %+v reloads=%d restarts=%d", restarted, reloads, restarts)
	}
	if _, err := service.SaveRawConfig(context.Background(), web.RawConfigUpdate{Content: "mode: rule\n", Revision: restarted.Revision, Apply: "invalid"}); err == nil {
		t.Fatal("invalid apply mode succeeded")
	}
}

func TestConfigServiceValidationDoesNotEchoNativeError(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "engines", "mihomo"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "engines", "mihomo", "mihomo"), []byte("fake"), 0o700); err != nil {
		t.Fatal(err)
	}
	preparer, err := NewActiveMihomoPreparer(root, &recordingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	service := &ConfigService{Preparer: preparer}
	validation, err := service.ValidateRawConfig(context.Background(), web.RawConfigUpdate{Content: "secret: |\n  do-not-echo\n"})
	if err != nil {
		t.Fatal(err)
	}
	if validation.Valid || len(validation.Diagnostics) != 1 || validation.Diagnostics[0].Message == "do-not-echo" {
		t.Fatalf("validation = %+v", validation)
	}
}

func TestConfigServiceValidationDefaultsControllerToLoopback(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "engines", "mihomo"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "engines", "mihomo", "mihomo"), []byte("fake"), 0o700); err != nil {
		t.Fatal(err)
	}
	recorder := &recordingConfig{}
	preparer, err := NewActiveMihomoPreparer(root, recorder)
	if err != nil {
		t.Fatal(err)
	}
	service := &ConfigService{Preparer: preparer}
	if err := service.ValidateMihomoContent(context.Background(), []byte("mixed-port: 7890\n")); err != nil {
		t.Fatal(err)
	}
	if recorder.request.Controller.Listen != defaultMihomoControllerListen || recorder.request.Controller.Secret != "" {
		t.Fatalf("validation controller = %+v", recorder.request.Controller)
	}
	if _, err := os.Lstat(recorder.request.RuntimeDir); !os.IsNotExist(err) {
		t.Fatalf("private validation directory survived: %v", err)
	}
}
