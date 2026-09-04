package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"unicode/utf8"

	configpkg "github.com/kontsevoye/boxctl/internal/config"
	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

type ConfigService struct {
	Preparer *ActiveMihomoPreparer
	// OnChanged restarts a running lifecycle after a validated config change.
	// OnReload asks the core to use its native reload endpoint. Their bool
	// reports whether the new config became live; stopped services return false
	// without error so the API can surface ReloadRequired honestly.
	OnChanged func(context.Context) (bool, error)
	OnReload  func(context.Context) (bool, error)
}

const (
	configApplySave    = "save"
	configApplyReload  = "reload"
	configApplyRestart = "restart"
)

func (service *ConfigService) RawConfig(_ context.Context) (web.RawConfigDocument, error) {
	if service == nil || service.Preparer == nil {
		return web.RawConfigDocument{}, errors.New("config service is not initialized")
	}
	content, err := readBoundedRegular(service.Preparer.Layout.MihomoConfig, 32<<20)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return web.RawConfigDocument{}, web.ErrNotFound
		}
		return web.RawConfigDocument{}, err
	}
	info, _ := os.Stat(service.Preparer.Layout.MihomoConfig)
	result := web.RawConfigDocument{Format: "yaml", Content: string(content), Revision: contentRevision(content)}
	if info != nil {
		result.UpdatedAt = info.ModTime().UTC()
	}
	return result, nil
}

func (service *ConfigService) ValidateRawConfig(ctx context.Context, update web.RawConfigUpdate) (web.ConfigValidation, error) {
	if err := validateRawDocument(update.Content); err != nil {
		// Validation failures are returned as API data, not transport errors.
		//nolint:nilerr
		return web.ConfigValidation{Valid: false, Diagnostics: []web.ConfigDiagnostic{{Severity: "error", Message: "Configuration must be non-empty UTF-8 YAML within the size limit"}}}, nil
	}
	if err := service.ValidateMihomoContent(ctx, []byte(update.Content)); err != nil {
		// Native-core rejection is a validation result for the editor.
		//nolint:nilerr
		return web.ConfigValidation{Valid: false, Diagnostics: []web.ConfigDiagnostic{{Severity: "error", Message: "Mihomo rejected the native configuration"}}}, nil
	}
	return web.ConfigValidation{Valid: true}, nil
}

func (service *ConfigService) SaveRawConfig(ctx context.Context, update web.RawConfigUpdate) (web.ConfigSaveResult, error) {
	apply, err := normalizeConfigApply(update.Apply)
	if err != nil {
		return web.ConfigSaveResult{}, err
	}
	if err := validateRawDocument(update.Content); err != nil {
		return web.ConfigSaveResult{}, &web.PublicError{Status: http.StatusBadRequest, Code: "invalid_config", Message: "Configuration must be non-empty UTF-8 YAML within the size limit"}
	}
	current, err := readBoundedRegular(service.Preparer.Layout.MihomoConfig, 32<<20)
	if err != nil {
		return web.ConfigSaveResult{}, err
	}
	if update.Revision == "" {
		return web.ConfigSaveResult{}, &web.PublicError{Status: http.StatusPreconditionRequired, Code: "revision_required", Message: "Configuration revision is required"}
	}
	if update.Revision != contentRevision(current) {
		return web.ConfigSaveResult{}, &web.PublicError{Status: http.StatusConflict, Code: "revision_conflict", Message: "Configuration changed since it was loaded"}
	}
	content := []byte(strings.TrimRight(update.Content, "\r\n") + "\n")
	if err := service.ValidateMihomoContent(ctx, content); err != nil {
		return web.ConfigSaveResult{}, &web.PublicError{Status: http.StatusBadRequest, Code: "invalid_config", Message: "Mihomo rejected the native configuration"}
	}

	active, activeErr := service.Preparer.Profiles.Current()
	if activeErr == nil && active.Engine == state.EngineMihomo {
		oldProfile, err := service.Preparer.Profiles.Get(active)
		if err != nil {
			return web.ConfigSaveResult{}, err
		}
		if err := service.Preparer.Profiles.Update(ctx, active, content); err != nil {
			return web.ConfigSaveResult{}, err
		}
		if err := service.Preparer.Profiles.Activate(ctx, active); err != nil {
			rollbackUpdate := service.Preparer.Profiles.Update(context.Background(), active, oldProfile)
			rollbackActivate := service.Preparer.Profiles.Activate(context.Background(), active)
			return web.ConfigSaveResult{}, errors.Join(err, rollbackUpdate, rollbackActivate)
		}
	} else if activeErr == nil {
		return web.ConfigSaveResult{}, &web.PublicError{Status: http.StatusConflict, Code: "wrong_engine", Message: "The active profile is not a Mihomo profile"}
	} else if errors.Is(activeErr, fs.ErrNotExist) {
		if err := state.WriteFileAtomic(service.Preparer.Layout.MihomoConfig, content, 0o600); err != nil {
			return web.ConfigSaveResult{}, err
		}
	} else {
		return web.ConfigSaveResult{}, activeErr
	}
	info, _ := os.Stat(service.Preparer.Layout.MihomoConfig)
	applied := false
	var applyCallback func(context.Context) (bool, error)
	switch apply {
	case configApplySave:
		applyCallback = nil
	case configApplyReload:
		applyCallback = service.OnReload
	default:
		applyCallback = service.OnChanged
	}
	if applyCallback != nil {
		applied, err = applyCallback(ctx)
		if err != nil {
			return web.ConfigSaveResult{}, fmt.Errorf("configuration was saved but %s failed: %w", apply, err)
		}
	}
	result := web.ConfigSaveResult{Revision: contentRevision(content), ReloadRequired: !applied, Applied: applied, Apply: apply}
	if info != nil {
		result.UpdatedAt = info.ModTime().UTC()
	}
	return result, nil
}

func normalizeConfigApply(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", configApplyRestart:
		return configApplyRestart, nil
	case configApplySave:
		return configApplySave, nil
	case configApplyReload:
		return configApplyReload, nil
	default:
		return "", &web.PublicError{Status: http.StatusBadRequest, Code: "invalid_apply_mode", Message: "Apply must be save, reload, or restart"}
	}
}

func (service *ConfigService) ValidateMihomoContent(ctx context.Context, content []byte) error {
	if service == nil || service.Preparer == nil || service.Preparer.Config == nil {
		return errors.New("config validator is not initialized")
	}
	if err := validateRawDocument(string(content)); err != nil {
		return err
	}
	managed, err := configpkg.InspectMihomo(content)
	if err != nil {
		return err
	}
	settings, err := LoadRuntimeSettings(service.Preparer.State)
	if err != nil {
		return err
	}
	runtimeContent, err := service.Preparer.applyRuntimeProviderSettings(ctx, content, settings, false)
	if err != nil {
		return err
	}
	managedSettings, err := managedRuntimeSettings(managed)
	if err != nil {
		return err
	}
	capture, err := settings.CapturePlan(managedSettings)
	if err != nil {
		return err
	}
	controller := managedMihomoController(managed)
	binary, err := service.Preparer.binaryPath()
	if err != nil {
		return err
	}
	directory, err := os.MkdirTemp(os.TempDir(), "boxctl-validate-")
	if err != nil {
		return err
	}
	defer os.Remove(directory)
	source, err := os.CreateTemp(directory, "source-*.yaml")
	if err != nil {
		return err
	}
	sourcePath := source.Name()
	defer os.Remove(sourcePath)
	if err := source.Chmod(0o600); err != nil {
		_ = source.Close()
		return err
	}
	if _, err := source.Write(runtimeContent); err != nil {
		_ = source.Close()
		return err
	}
	if err := source.Close(); err != nil {
		return err
	}
	prepared, err := service.Preparer.Config.Prepare(ctx, engine.PrepareRequest{
		BinaryPath: binary, SourceConfigPath: sourcePath, RuntimeDir: directory,
		HomeDir: service.Preparer.Layout.Root, Capture: capture, Controller: controller,
	})
	defer engine.CleanupPreparedRuntime(prepared)
	return err
}

func validateRawDocument(content string) error {
	if len(content) == 0 || len(content) > 32<<20 || !utf8.ValidString(content) || strings.IndexByte(content, 0) >= 0 || len(bytes.TrimSpace([]byte(content))) == 0 {
		return errors.New("invalid raw document")
	}
	return nil
}

func contentRevision(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

var _ web.ConfigService = (*ConfigService)(nil)

func (service *ConfigService) String() string {
	if service == nil || service.Preparer == nil {
		return "ConfigService{uninitialized}"
	}
	return fmt.Sprintf("ConfigService{root:%s}", service.Preparer.Layout.Root)
}
