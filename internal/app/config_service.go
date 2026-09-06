package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	configpkg "github.com/kontsevoye/boxctl/internal/config"
	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

type ConfigService struct {
	Preparer *ActiveMihomoPreparer
	// EnginePreparer and Lifecycle enable profile-addressed validation and a
	// rollback-capable restart for every installed engine. Preparer remains for
	// the legacy config.yaml API and Mihomo-native validation.
	EnginePreparer *EnginePreparer
	Lifecycle      *Lifecycle
	Revisions      *ProfileRevisionStore
	ValidateEngine func(context.Context, string, []byte) error
	MutationMu     *sync.Mutex
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

func (service *ConfigService) RawConfig(ctx context.Context) (web.RawConfigDocument, error) {
	if service == nil || service.Preparer == nil {
		return web.RawConfigDocument{}, errors.New("config service is not initialized")
	}
	if active, err := service.Preparer.Profiles.Current(); err == nil {
		return service.ProfileConfig(ctx, profileID(active))
	} else if !errors.Is(err, fs.ErrNotExist) {
		return web.RawConfigDocument{}, err
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
	if service != nil && service.Preparer != nil {
		if active, err := service.Preparer.Profiles.Current(); err == nil {
			return service.ValidateProfileConfig(ctx, profileID(active), update)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return web.ConfigValidation{}, err
		}
	}
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
	if service != nil && service.Preparer != nil {
		if active, currentErr := service.Preparer.Profiles.Current(); currentErr == nil {
			return service.SaveProfileConfig(ctx, profileID(active), update)
		} else if !errors.Is(currentErr, fs.ErrNotExist) {
			return web.ConfigSaveResult{}, currentErr
		}
	}
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
	if apply == configApplyRestart {
		ctx = panelRestart(ctx, "save-and-restart")
	}
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

func (service *ConfigService) ProfileConfig(_ context.Context, id string) (web.RawConfigDocument, error) {
	entry, err := service.profileEntry(id)
	if err != nil {
		return web.RawConfigDocument{}, err
	}
	content, err := service.Preparer.Profiles.Get(entry.ActiveProfile)
	if err != nil {
		return web.RawConfigDocument{}, err
	}
	if len(content) > 32<<20 {
		return web.RawConfigDocument{}, errors.New("profile configuration exceeds the editor size limit")
	}
	active, activeErr := service.Preparer.Profiles.Current()
	if activeErr != nil && !errors.Is(activeErr, fs.ErrNotExist) {
		return web.RawConfigDocument{}, activeErr
	}
	result := web.RawConfigDocument{
		Format: formatForEngine(entry.Engine), Content: string(content), Revision: contentRevision(content),
		Profile: &web.ProfileRef{ID: id, Name: entry.Name, Engine: entry.Engine},
		Engine:  entry.Engine, Active: activeErr == nil && active == entry.ActiveProfile,
	}
	if info, statErr := os.Stat(entry.Path); statErr == nil {
		result.UpdatedAt = info.ModTime().UTC()
	}
	if service.Revisions != nil {
		revision, pending, revisionErr := service.Revisions.Pending(entry.ActiveProfile)
		if revisionErr != nil {
			return web.RawConfigDocument{}, revisionErr
		}
		result.AppliedRevision = revision.AppliedRevision
		result.Pending = result.Active && pending
	}
	return result, nil
}

func (service *ConfigService) ValidateProfileConfig(ctx context.Context, id string, update web.RawConfigUpdate) (web.ConfigValidation, error) {
	entry, err := service.profileEntry(id)
	if err != nil {
		return web.ConfigValidation{}, err
	}
	if err := validateRawDocument(update.Content); err != nil {
		//nolint:nilerr // syntax rejection is represented as validation data
		return invalidConfigValidation(entry.Engine), nil
	}
	if err := service.validateEngineContent(ctx, entry.Engine, []byte(update.Content)); err != nil {
		//nolint:nilerr // native-engine rejection is represented as validation data
		return invalidConfigValidation(entry.Engine), nil
	}
	return web.ConfigValidation{Valid: true}, nil
}

func (service *ConfigService) SaveProfileConfig(ctx context.Context, id string, update web.RawConfigUpdate) (web.ConfigSaveResult, error) {
	if service != nil && service.MutationMu != nil {
		service.MutationMu.Lock()
		defer service.MutationMu.Unlock()
	}
	apply, err := normalizeConfigApply(update.Apply)
	if err != nil {
		return web.ConfigSaveResult{}, err
	}
	entry, err := service.profileEntry(id)
	if err != nil {
		return web.ConfigSaveResult{}, err
	}
	if apply == configApplyReload && entry.Engine != state.EngineMihomo {
		return web.ConfigSaveResult{}, &web.PublicError{
			Status: http.StatusConflict, Code: "reload_unsupported",
			Message: "Native reload is not supported for this engine; save or restart instead",
		}
	}
	if err := validateRawDocument(update.Content); err != nil {
		return web.ConfigSaveResult{}, &web.PublicError{Status: http.StatusBadRequest, Code: "invalid_config", Message: "Configuration must be non-empty UTF-8 within the size limit"}
	}
	current, err := service.Preparer.Profiles.Get(entry.ActiveProfile)
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
	if err := service.validateEngineContent(ctx, entry.Engine, content); err != nil {
		return web.ConfigSaveResult{}, &web.PublicError{Status: http.StatusBadRequest, Code: "invalid_config", Message: engineValidationMessage(entry.Engine)}
	}

	active, activeErr := service.Preparer.Profiles.Current()
	if activeErr != nil && !errors.Is(activeErr, fs.ErrNotExist) {
		return web.ConfigSaveResult{}, activeErr
	}
	isActive := activeErr == nil && active == entry.ActiveProfile
	isRunning := isActive && service.Lifecycle != nil && service.Lifecycle.Snapshot().State == LifecycleRunning
	newRevision := contentRevision(content)
	oldRevision := contentRevision(current)
	var oldRevisionRecord profileRevision
	oldRevisionExisted := false
	if isActive && service.Revisions != nil {
		oldRevisionRecord, oldRevisionExisted, err = service.Revisions.Snapshot(entry.ActiveProfile)
		if err != nil {
			return web.ConfigSaveResult{}, fmt.Errorf("snapshot profile revision state: %w", err)
		}
	}

	if err := service.Preparer.Profiles.Update(ctx, entry.ActiveProfile, content); err != nil {
		return web.ConfigSaveResult{}, err
	}
	if isActive {
		if err := service.Preparer.Profiles.Activate(ctx, entry.ActiveProfile); err != nil {
			restoreErr := service.Preparer.Profiles.Update(context.Background(), entry.ActiveProfile, current)
			if restoreErr == nil {
				restoreErr = service.Preparer.Profiles.Activate(context.Background(), entry.ActiveProfile)
			}
			return web.ConfigSaveResult{}, errors.Join(err, restoreErr)
		}
		if service.Revisions != nil {
			if err := service.Revisions.MarkPending(ctx, entry.ActiveProfile, oldRevision); err != nil {
				rollbackContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
				defer cancel()
				restoreSourceErr := service.Preparer.Profiles.Update(rollbackContext, entry.ActiveProfile, current)
				var restoreMirrorErr error
				if restoreSourceErr == nil {
					restoreMirrorErr = service.Preparer.Profiles.Activate(rollbackContext, entry.ActiveProfile)
				}
				restoreRevisionErr := service.Revisions.Restore(rollbackContext, entry.ActiveProfile, oldRevisionRecord, oldRevisionExisted)
				return web.ConfigSaveResult{}, errors.Join(
					fmt.Errorf("record pending configuration revision: %w", err),
					restoreSourceErr, restoreMirrorErr, restoreRevisionErr,
				)
			}
		}
	}

	if apply == configApplyRestart {
		ctx = panelRestart(ctx, "save-and-restart")
	}
	applied := false
	switch {
	case !isActive || apply == configApplySave:
		// Inactive documents and save-only writes intentionally do not touch the
		// live process. A selected running profile remains visibly pending.
	case isRunning && apply == configApplyRestart && service.EnginePreparer != nil:
		target, prepareErr := service.EnginePreparer.PrepareProfile(ctx, entry.ActiveProfile)
		if prepareErr != nil {
			return web.ConfigSaveResult{}, fmt.Errorf("configuration was saved but target preparation failed: %w", prepareErr)
		}
		if target.SourceRevision != newRevision {
			engine.CleanupPreparedRuntime(target)
			return web.ConfigSaveResult{}, errors.New("configuration changed while the restart candidate was being prepared")
		}
		commit := func() error {
			latest, latestErr := service.Preparer.Profiles.Get(entry.ActiveProfile)
			if latestErr != nil {
				return latestErr
			}
			if contentRevision(latest) != target.SourceRevision {
				return errors.New("configuration changed before the prepared runtime could be committed")
			}
			if service.Revisions == nil {
				return nil
			}
			return service.Revisions.MarkAppliedRevision(context.WithoutCancel(ctx), entry.ActiveProfile, target.SourceRevision)
		}
		applied, err = service.Lifecycle.ReconfigurePrepared(ctx, target, commit)
		if err != nil {
			return web.ConfigSaveResult{}, fmt.Errorf("configuration was saved but restart failed: %w", err)
		}
	case apply == configApplyReload && service.OnReload != nil:
		applied, err = service.OnReload(ctx)
	case apply == configApplyRestart && service.OnChanged != nil:
		applied, err = service.OnChanged(ctx)
	}
	if err != nil {
		return web.ConfigSaveResult{}, fmt.Errorf("configuration was saved but %s failed: %w", apply, err)
	}
	if applied && service.Revisions != nil {
		if err := service.Revisions.MarkAppliedRevision(context.WithoutCancel(ctx), entry.ActiveProfile, newRevision); err != nil {
			return web.ConfigSaveResult{}, fmt.Errorf("configuration is live but applied revision could not be recorded: %w", err)
		}
	}
	info, _ := os.Stat(entry.Path)
	result := web.ConfigSaveResult{
		Revision: newRevision, ReloadRequired: isActive && !applied,
		Applied: applied, Apply: apply,
	}
	if info != nil {
		result.UpdatedAt = info.ModTime().UTC()
	}
	return result, nil
}

func (service *ConfigService) profileEntry(id string) (state.ProfileEntry, error) {
	if service == nil || service.Preparer == nil {
		return state.ProfileEntry{}, errors.New("config service is not initialized")
	}
	profile, err := parseProfileID(id)
	if err != nil {
		return state.ProfileEntry{}, web.ErrNotFound
	}
	entries, err := service.Preparer.Profiles.List()
	if err != nil {
		return state.ProfileEntry{}, err
	}
	for _, entry := range entries {
		if entry.ActiveProfile == profile {
			return entry, nil
		}
	}
	return state.ProfileEntry{}, web.ErrNotFound
}

func (service *ConfigService) validateEngineContent(ctx context.Context, engineName string, content []byte) error {
	if service.ValidateEngine != nil {
		return service.ValidateEngine(ctx, engineName, content)
	}
	if engineName == state.EngineMihomo {
		return service.ValidateMihomoContent(ctx, content)
	}
	if engineName != state.EngineSingBox {
		return errors.New("unsupported profile engine")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil || document == nil {
		return errors.New("sing-box profile is not a JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("sing-box profile contains trailing JSON")
	}
	return nil
}

func invalidConfigValidation(engineName string) web.ConfigValidation {
	return web.ConfigValidation{Valid: false, Diagnostics: []web.ConfigDiagnostic{{Severity: "error", Message: engineValidationMessage(engineName)}}}
}

func engineValidationMessage(engineName string) string {
	if engineName == state.EngineSingBox {
		return "sing-box rejected the native JSON configuration"
	}
	return "Mihomo rejected the native YAML configuration"
}

func formatForEngine(engineName string) string {
	if engineName == state.EngineSingBox {
		return "json"
	}
	return "yaml"
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
