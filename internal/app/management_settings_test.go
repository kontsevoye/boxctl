package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontsevoye/boxctl/internal/platform/openwrt"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

type managementServiceRunner struct {
	content     string
	pending     bool
	running     bool
	failRestart bool
	queued      map[string]any
}

func (runner *managementServiceRunner) Run(_ context.Context, command openwrt.Command) (openwrt.Result, error) {
	if command.Name == "uci" {
		switch command.Args[1] {
		case "export":
			return openwrt.Result{Stdout: []byte(runner.content)}, nil
		case "changes":
			if runner.pending {
				return openwrt.Result{Stdout: []byte("boxctl.main.public_origin='pending'\n")}, nil
			}
			return openwrt.Result{}, nil
		}
	}
	if command.Name == "ubus" && len(command.Args) == 4 {
		if command.Args[2] == "list" {
			if runner.running {
				return openwrt.Result{Stdout: []byte(`{"boxctl-panel-restart":{"instances":{"restart":{"running":true}}}}`)}, nil
			}
			return openwrt.Result{Stdout: []byte(`{}`)}, nil
		}
		if command.Args[2] == "set" {
			if runner.failRestart {
				return openwrt.Result{ExitCode: 1}, nil
			}
			if err := json.Unmarshal([]byte(command.Args[3]), &runner.queued); err != nil {
				return openwrt.Result{}, err
			}
			runner.running = true
			return openwrt.Result{}, nil
		}
	}
	return openwrt.Result{}, errors.New("unexpected mutation or command")
}

func TestManagementSettingsReadTracksSavedVersusActiveAndExternalChanges(t *testing.T) {
	runner := &managementServiceRunner{content: "config boxctl 'main'\n option public_origin 'https://boxctl.lan'\n"}
	service := &ManagementSettingsService{UCI: openwrt.ManagementUCI{Runner: runner}, Active: openwrt.ManagementConfig{PublicOrigin: "https://boxctl.lan"}}
	before, err := service.ManagementSettings(context.Background())
	if err != nil || !before.Supported || before.RestartRequired || before.PendingChanges {
		t.Fatalf("initial settings = %+v, %v", before, err)
	}
	runner.content = "config boxctl 'main'\n option public_origin 'https://new.lan'\n"
	runner.pending = true
	after, err := service.ManagementSettings(context.Background())
	if err != nil || after.PublicOrigin != "https://new.lan" || !after.RestartRequired || !after.PendingChanges || after.Revision == before.Revision {
		t.Fatalf("external changes = %+v, %v", after, err)
	}
	// Startup canonicalizes file paths; redundant separators must not leave a perpetual restart warning.
	service.Active = openwrt.ManagementConfig{TLSCertificate: "/etc/ssl/cert", TLSKey: "/etc/ssl/key"}
	view := service.view(openwrt.ManagementSnapshot{Config: openwrt.ManagementConfig{TLSCertificate: "/etc//ssl/cert", TLSKey: "/etc/ssl/./key"}})
	if view.RestartRequired {
		t.Fatal("equivalent active paths require restart")
	}
}

func TestManagementSettingsApplyQueuesIndependentFullRestartAndRejectsConflicts(t *testing.T) {
	for _, scenario := range []string{"success", "pending", "stale", "invalid", "already-running", "ubus-failure"} {
		t.Run(scenario, func(t *testing.T) {
			runner := &managementServiceRunner{content: "config boxctl 'main'\n option public_origin 'https://boxctl.lan'\n"}
			service := &ManagementSettingsService{UCI: openwrt.ManagementUCI{Runner: runner}, State: state.Store{Root: t.TempDir()}}
			before, err := service.ManagementSettings(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "pending":
				runner.pending = true
			case "stale":
				runner.content += " option unknown 'changed'\n"
			case "invalid":
				runner.content = "config boxctl 'main'\n option public_origin 'https://boxctl.lan/path'\n"
				before, err = service.ManagementSettings(context.Background())
				if err != nil {
					t.Fatal(err)
				}
			case "already-running":
				runner.running = true
			case "ubus-failure":
				runner.failRestart = true
			}
			err = service.ApplyManagementSettings(context.Background(), before.Revision)
			if scenario != "success" && scenario != "already-running" {
				if err == nil || runner.queued != nil {
					t.Fatalf("unsafe apply: queued=%v err=%v", runner.queued, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "already-running" {
				if runner.queued != nil {
					t.Fatal("duplicate restart queued")
				}
				return
			}
			if runner.queued["name"] != managementRestartService {
				t.Fatalf("wrong service = %v", runner.queued)
			}
			instance := runner.queued["instances"].(map[string]any)["restart"].(map[string]any)
			command := instance["command"].([]any)
			if len(command) != 3 || command[0] != "/bin/sh" || command[1] != "-c" || command[2] != "sleep 1; exec /etc/init.d/boxctl restart" || instance["respawn"] != nil {
				t.Fatalf("unsafe restart worker: %v", instance)
			}
		})
	}
}

func TestManagementSettingsValidationPrecedesAnyUCIMutation(t *testing.T) {
	service := &ManagementSettingsService{UCI: openwrt.ManagementUCI{Runner: &managementServiceRunner{}}, State: state.Store{Root: t.TempDir()}}
	for _, config := range []web.ManagementConfig{
		{PublicOrigin: "https://boxctl.lan/path"}, {AllowedHosts: "https://boxctl.lan"},
		{TLSCertificate: "/certificate"}, {TLSCertificate: "relative", TLSKey: "/key"},
		{TLSCertificate: "/cert,extra", TLSKey: "/key"},
		{PublicOrigin: "http://boxctl.lan", TLSCertificate: "/cert", TLSKey: "/key"},
		{AllowedHosts: "router.lan\nunsafe"}, {PublicOrigin: strings.Repeat("x", 4097)},
	} {
		_, err := service.UpdateManagementSettings(context.Background(), web.ManagementSettingsUpdate{ManagementConfig: config, Revision: "revision"})
		var public *web.PublicError
		if !errors.As(err, &public) || public.Status != 400 {
			t.Fatalf("invalid config %+v returned %v", config, err)
		}
	}
}

func TestManagementTLSUsesStartupRulesAndChecksMatchingFiles(t *testing.T) {
	directory := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "boxctl.test"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(directory, "certificate.pem"), filepath.Join(directory, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateManagementTLS(certPath, keyPath); err != nil {
		t.Fatalf("valid TLS pair: %v", err)
	}
	link := filepath.Join(directory, "linked.pem")
	if err := os.Symlink(certPath, link); err != nil {
		t.Fatal(err)
	}
	if err := validateManagementTLS(link, keyPath); err == nil {
		t.Fatal("accepted a symlink rejected by startup")
	}
	if err := os.WriteFile(keyPath, []byte("invalid private key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateManagementTLS(certPath, keyPath); err == nil {
		t.Fatal("accepted invalid key")
	}
}
