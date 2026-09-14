package app

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kontsevoye/boxctl/internal/platform/openwrt"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

const managementRestartService = "boxctl-panel-restart"

type ManagementSettingsService struct {
	UCI    openwrt.ManagementUCI
	State  state.Store
	Active openwrt.ManagementConfig
}

func (service *ManagementSettingsService) ManagementSettings(ctx context.Context) (web.ManagementSettings, error) {
	snapshot, err := service.UCI.Read(ctx)
	if err != nil {
		return web.ManagementSettings{}, err
	}
	return service.view(snapshot), nil
}

func (service *ManagementSettingsService) view(snapshot openwrt.ManagementSnapshot) web.ManagementSettings {
	return web.ManagementSettings{
		ManagementConfig: web.ManagementConfig(snapshot.Config), Supported: snapshot.Exists,
		Revision: snapshot.Revision, PendingChanges: snapshot.Pending,
		RestartRequired: normalizeManagementConfig(snapshot.Config) != normalizeManagementConfig(service.Active),
	}
}

func (service *ManagementSettingsService) UpdateManagementSettings(ctx context.Context, request web.ManagementSettingsUpdate) (view web.ManagementSettings, returnErr error) {
	config := normalizeManagementConfig(openwrt.ManagementConfig(request.ManagementConfig))
	if err := service.validate(config); err != nil {
		return view, err
	}
	lock, err := service.State.Lock(ctx, "self-update")
	if err != nil {
		return view, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Unlock()) }()
	snapshot, err := service.UCI.Save(ctx, config, request.Revision)
	if errors.Is(err, openwrt.ErrManagementConfigConflict) {
		return view, managementSettingsConflict()
	}
	if err != nil {
		return view, err
	}
	return service.view(snapshot), nil
}

func (service *ManagementSettingsService) ApplyManagementSettings(ctx context.Context, revision string) (returnErr error) {
	lock, err := service.State.Lock(ctx, "self-update")
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Unlock()) }()
	snapshot, err := service.UCI.Read(ctx)
	if err != nil {
		return err
	}
	if !snapshot.Exists || snapshot.Pending || revision == "" || snapshot.Revision != revision {
		return managementSettingsConflict()
	}
	if err := service.validate(normalizeManagementConfig(snapshot.Config)); err != nil {
		return err
	}
	status, err := service.procd(ctx, "list", map[string]string{"name": managementRestartService})
	if err != nil {
		return err
	}
	var services map[string]struct {
		Instances map[string]struct {
			Running bool `json:"running"`
		} `json:"instances"`
	}
	if err := json.Unmarshal(status, &services); err != nil {
		return err
	}
	for _, instance := range services[managementRestartService].Instances {
		if instance.Running {
			return nil
		}
	}
	// A separate procd instance survives manager shutdown. The fixed delay
	// allows the HTTP response to arrive before the listener closes. No user
	// value enters this command and the worker is never configured to respawn.
	_, err = service.procd(ctx, "set", map[string]any{
		"name": managementRestartService,
		"instances": map[string]any{"restart": map[string]any{
			"command": []string{"/bin/sh", "-c", "sleep 1; exec /etc/init.d/boxctl restart"},
			"stdout":  true, "stderr": true,
		}},
	})
	return err
}

func (service *ManagementSettingsService) procd(ctx context.Context, method string, payload any) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	result, err := service.UCI.Runner.Run(ctx, openwrt.Command{Name: "ubus", Args: []string{"call", "service", method, string(data)}})
	if err != nil || result.ExitCode != 0 {
		return nil, errors.New("cannot schedule panel service restart")
	}
	return result.Stdout, nil
}

func normalizeManagementConfig(config openwrt.ManagementConfig) openwrt.ManagementConfig {
	config.PublicOrigin = strings.TrimSpace(config.PublicOrigin)
	config.TLSCertificate = strings.TrimSpace(config.TLSCertificate)
	config.TLSKey = strings.TrimSpace(config.TLSKey)
	if config.TLSCertificate != "" {
		config.TLSCertificate = filepath.Clean(config.TLSCertificate)
	}
	if config.TLSKey != "" {
		config.TLSKey = filepath.Clean(config.TLSKey)
	}
	var hosts []string
	for _, host := range strings.Split(config.AllowedHosts, ",") {
		if host = strings.TrimSpace(host); host != "" {
			hosts = append(hosts, host)
		}
	}
	config.AllowedHosts = strings.Join(hosts, ",")
	return config
}

func (service *ManagementSettingsService) validate(config openwrt.ManagementConfig) error {
	for _, value := range []string{config.PublicOrigin, config.AllowedHosts, config.TLSCertificate, config.TLSKey} {
		if len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
			return &web.PublicError{Status: http.StatusBadRequest, Code: "invalid_management_settings", Message: "Panel settings contain an invalid or oversized value"}
		}
	}
	if err := web.ValidateManagementAccess(web.ManagementConfig(config)); err != nil {
		return err
	}
	if config.TLSCertificate == "" && config.TLSKey == "" {
		return nil
	}
	if !filepath.IsAbs(config.TLSCertificate) || !filepath.IsAbs(config.TLSKey) || strings.Contains(config.TLSCertificate+config.TLSKey, ",") {
		return &web.PublicError{Status: http.StatusBadRequest, Code: "invalid_tls_paths", Message: "Certificate and private key must both use absolute file paths without commas, or both be empty"}
	}
	if config.PublicOrigin != "" && !strings.HasPrefix(strings.ToLower(config.PublicOrigin), "https://") {
		return &web.PublicError{Status: http.StatusBadRequest, Code: "invalid_public_origin", Message: "Public URL must use HTTPS when the panel serves TLS directly"}
	}
	if err := validateManagementTLS(config.TLSCertificate, config.TLSKey); err != nil {
		return &web.PublicError{Status: http.StatusBadRequest, Code: "invalid_tls_pair", Message: "Certificate and private key must be readable files containing a matching TLS certificate and key"}
	}
	return nil
}

func validateManagementTLS(certificate, key string) error {
	// Use exactly the startup path rules, including rejection of symlinks.
	if _, err := parseTLSSetting(certificate + "," + key); err != nil {
		return err
	}
	for _, name := range []string{certificate, key} {
		info, err := os.Stat(name)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > 1<<20 {
			return errors.New("invalid TLS file")
		}
	}
	_, err := tls.LoadX509KeyPair(certificate, key)
	return err
}

func managementSettingsConflict() error {
	return &web.PublicError{Status: http.StatusConflict, Code: "management_settings_conflict", Message: "Panel settings changed or have external pending UCI changes. Reload the values and finish external changes before saving or applying"}
}
