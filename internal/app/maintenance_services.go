package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kontsevoye/boxctl/internal/backup"
	configpkg "github.com/kontsevoye/boxctl/internal/config"
	"github.com/kontsevoye/boxctl/internal/fakeip"
	"github.com/kontsevoye/boxctl/internal/rulelist"
	"github.com/kontsevoye/boxctl/internal/web"
)

type RuleListService struct {
	Store  *rulelist.Store
	Config *ConfigService
}

var fakeIPWhitelistRuleListName = strings.TrimSuffix(strings.ToLower(fakeip.FileName), strings.ToLower(filepath.Ext(fakeip.FileName)))

func (service RuleListService) RuleLists(ctx context.Context) ([]web.RuleList, error) {
	items, err := service.Store.List()
	if err != nil {
		return nil, err
	}
	var configContent []byte
	if service.Config != nil {
		document, configErr := service.Config.RawConfig(ctx)
		if configErr != nil {
			return nil, configErr
		}
		configContent = []byte(document.Content)
	}
	result := make([]web.RuleList, 0, len(items))
	for _, item := range items {
		if isReservedRuleListName(item.Name) {
			continue
		}
		document, getErr := service.Store.Get(item.Name)
		if getErr != nil {
			return nil, getErr
		}
		webItem := webRuleList(document, document.Content)
		if len(configContent) > 0 {
			binding, bindingErr := configpkg.InspectLocalRuleListBinding(configContent, document.Name)
			if bindingErr != nil {
				return nil, bindingErr
			}
			applyRuleListBinding(&webItem, binding)
		}
		result = append(result, webItem)
	}
	return result, nil
}

func (service RuleListService) RuleList(ctx context.Context, id string) (web.RuleListDocument, error) {
	if isReservedRuleListName(id) {
		return web.RuleListDocument{}, reservedRuleListError()
	}
	item, err := service.Store.Get(id)
	if err != nil {
		return web.RuleListDocument{}, mapRuleListError(err)
	}
	result := web.RuleListDocument{RuleList: webRuleList(item, item.Content), Content: item.Content}
	if service.Config != nil {
		document, configErr := service.Config.RawConfig(ctx)
		if configErr != nil {
			return web.RuleListDocument{}, configErr
		}
		binding, bindingErr := configpkg.InspectLocalRuleListBinding([]byte(document.Content), item.Name)
		if bindingErr != nil {
			return web.RuleListDocument{}, bindingErr
		}
		applyRuleListBinding(&result.RuleList, binding)
	}
	return result, nil
}

func (service RuleListService) CreateRuleList(_ context.Context, draft web.RuleListDraft) (web.RuleListDocument, error) {
	if isReservedRuleListName(draft.Name) {
		return web.RuleListDocument{}, reservedRuleListError()
	}
	if !supportedRuleListFormat(draft.Format) {
		return web.RuleListDocument{}, &web.PublicError{Status: http.StatusBadRequest, Code: "unsupported_rule_format", Message: "Only plain text Mihomo provider lists are supported in v1"}
	}
	content := rulelist.AutoPrefixContent(draft.Name, draft.Content)
	item, err := service.Store.Create(draft.Name, content)
	if err != nil {
		return web.RuleListDocument{}, mapRuleListError(err)
	}
	return web.RuleListDocument{RuleList: webRuleList(item, item.Content), Content: item.Content}, nil
}

func (service RuleListService) UpdateRuleList(ctx context.Context, id string, update web.RuleListUpdate) (web.RuleListDocument, error) {
	if isReservedRuleListName(id) || (update.Name != nil && isReservedRuleListName(*update.Name)) {
		return web.RuleListDocument{}, reservedRuleListError()
	}
	current, err := service.Store.Get(id)
	if err != nil {
		return web.RuleListDocument{}, mapRuleListError(err)
	}
	if update.Revision != current.Revision {
		return web.RuleListDocument{}, web.ErrConflict
	}
	if update.Format != nil && !supportedRuleListFormat(*update.Format) {
		return web.RuleListDocument{}, &web.PublicError{Status: http.StatusBadRequest, Code: "unsupported_rule_format", Message: "Only plain text Mihomo provider lists are supported in v1"}
	}
	content := current.Content
	if update.Content != nil {
		content = *update.Content
	}
	name := current.Name
	if update.Name != nil {
		name = strings.TrimSpace(*update.Name)
	}
	if !strings.EqualFold(name, current.Name) {
		return web.RuleListDocument{}, &web.PublicError{Status: http.StatusConflict, Code: "rule_list_name_immutable", Message: "Create a new list to change its name so provider references stay valid"}
	}
	name = current.Name
	content = rulelist.AutoPrefixContent(current.Name, content)
	if name == current.Name {
		item, err := service.Store.Put(name, content, current.Revision)
		if err != nil {
			return web.RuleListDocument{}, mapRuleListError(err)
		}
		result := web.RuleListDocument{RuleList: webRuleList(item, item.Content), Content: item.Content}
		if service.Config != nil {
			document, configErr := service.Config.RawConfig(ctx)
			if configErr != nil {
				return web.RuleListDocument{}, configErr
			}
			binding, bindingErr := configpkg.InspectLocalRuleListBinding([]byte(document.Content), item.Name)
			if bindingErr != nil {
				return web.RuleListDocument{}, bindingErr
			}
			applyRuleListBinding(&result.RuleList, binding)
			if binding.InConfig && service.Config.OnReload != nil {
				if _, reloadErr := service.Config.OnReload(ctx); reloadErr != nil {
					return web.RuleListDocument{}, fmt.Errorf("rule list was saved but core reload failed: %w", reloadErr)
				}
			}
		}
		return result, nil
	}
	created, err := service.Store.Create(name, content)
	if err != nil {
		return web.RuleListDocument{}, mapRuleListError(err)
	}
	if err := service.Store.Delete(current.Name, current.Revision); err != nil {
		_ = service.Store.Delete(created.Name, created.Revision)
		return web.RuleListDocument{}, mapRuleListError(err)
	}
	return web.RuleListDocument{RuleList: webRuleList(created, created.Content), Content: created.Content}, nil
}

func (service RuleListService) DeleteRuleList(ctx context.Context, id, revision string) error {
	if isReservedRuleListName(id) {
		return reservedRuleListError()
	}
	current, err := service.Store.Get(id)
	if err != nil {
		return mapRuleListError(err)
	}
	if revision == "" || (revision != "*" && revision != current.Revision) {
		return web.ErrConflict
	}
	var original web.RawConfigDocument
	var saved web.ConfigSaveResult
	configChanged := false
	if service.Config != nil {
		original, err = service.Config.RawConfig(ctx)
		if err != nil {
			return err
		}
		updated, binding, mutationErr := configpkg.RemoveLocalRuleProvider([]byte(original.Content), current.Name)
		if mutationErr != nil {
			return mutationErr
		}
		if binding.InUse {
			return &web.PublicError{Status: http.StatusConflict, Code: "rule_list_in_use", Message: "Remove RULE-SET references from the active configuration before deleting this list"}
		}
		if !bytes.Equal(updated, []byte(original.Content)) {
			saved, err = service.Config.SaveRawConfig(ctx, web.RawConfigUpdate{Content: string(updated), Revision: original.Revision, Apply: configApplyReload})
			if err != nil {
				rollbackErr := rollbackRuleListConfig(ctx, service.Config, original, updated)
				return errors.Join(err, rollbackErr)
			}
			configChanged = true
		}
	}
	if err := service.Store.Delete(current.Name, current.Revision); err != nil {
		if configChanged {
			_, rollbackErr := service.Config.SaveRawConfig(context.Background(), web.RawConfigUpdate{Content: original.Content, Revision: saved.Revision, Apply: configApplyReload})
			return errors.Join(mapRuleListError(err), rollbackErr)
		}
		return mapRuleListError(err)
	}
	return nil
}

func (service RuleListService) AddRuleListToConfig(ctx context.Context, id string) (web.RuleListDocument, error) {
	if service.Config == nil {
		return web.RuleListDocument{}, &web.PublicError{Status: http.StatusNotImplemented, Code: "config_unavailable", Message: "Active configuration editing is unavailable"}
	}
	item, err := service.Store.Get(id)
	if err != nil {
		return web.RuleListDocument{}, mapRuleListError(err)
	}
	document, err := service.Config.RawConfig(ctx)
	if err != nil {
		return web.RuleListDocument{}, err
	}
	updated, binding, err := configpkg.InsertLocalRuleProvider([]byte(document.Content), item.Name)
	if err != nil {
		if errors.Is(err, configpkg.ErrLocalRuleProviderConflict) {
			return web.RuleListDocument{}, &web.PublicError{Status: http.StatusConflict, Code: "provider_name_taken", Message: "An unrelated rule-provider already uses this local provider name"}
		}
		if errors.Is(err, configpkg.ErrUnsupportedYAMLSurgery) {
			return web.RuleListDocument{}, &web.PublicError{Status: http.StatusConflict, Code: "config_layout_unsupported", Message: "This YAML layout cannot be edited surgically; add the provider in the configuration editor"}
		}
		return web.RuleListDocument{}, err
	}
	if !bytes.Equal(updated, []byte(document.Content)) {
		if _, err := service.Config.SaveRawConfig(ctx, web.RawConfigUpdate{Content: string(updated), Revision: document.Revision, Apply: configApplyReload}); err != nil {
			rollbackErr := rollbackRuleListConfig(ctx, service.Config, document, updated)
			return web.RuleListDocument{}, errors.Join(err, rollbackErr)
		}
	}
	result := web.RuleListDocument{RuleList: webRuleList(item, item.Content), Content: item.Content}
	applyRuleListBinding(&result.RuleList, binding)
	return result, nil
}

// rollbackRuleListConfig restores a config mutation that could not be applied
// to the running core. It only rolls back the exact content written by this
// operation, so a concurrent editor is never overwritten. SaveRawConfig writes
// before invoking OnReload, therefore this compensation is required even when
// the original save returned an error.
func rollbackRuleListConfig(ctx context.Context, service *ConfigService, original web.RawConfigDocument, expected []byte) error {
	if service == nil {
		return nil
	}
	rollbackContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	current, err := service.RawConfig(rollbackContext)
	if err != nil {
		return fmt.Errorf("inspect config for rule-list rollback: %w", err)
	}
	if current.Content == original.Content {
		return nil
	}
	expectedContent := strings.TrimRight(string(expected), "\r\n") + "\n"
	if current.Content != expectedContent {
		return errors.New("rule-list config rollback skipped because configuration changed concurrently")
	}
	if _, err := service.SaveRawConfig(rollbackContext, web.RawConfigUpdate{
		Content: original.Content, Revision: current.Revision, Apply: configApplyReload,
	}); err != nil {
		return fmt.Errorf("roll back rule-list config mutation: %w", err)
	}
	return nil
}

func applyRuleListBinding(item *web.RuleList, binding configpkg.LocalRuleListBinding) {
	item.ProviderName = binding.ProviderName
	item.InConfig = binding.InConfig
	item.ConfigNameTaken = binding.ConfigNameTaken
	item.InUse = binding.InUse
}

func isReservedRuleListName(name string) bool {
	normalized := strings.ToLower(strings.TrimSpace(name))
	return normalized == fakeIPWhitelistRuleListName || normalized == strings.ToLower(fakeip.FileName)
}

func reservedRuleListError() error {
	return &web.PublicError{
		Status:  http.StatusConflict,
		Code:    "reserved_rule_list",
		Message: "The fake-IP capture destination list is managed through its dedicated API",
	}
}

func webRuleList(item rulelist.Item, content string) web.RuleList {
	result := web.RuleList{
		ID: item.Name, Name: item.Name, Format: "text", Enabled: true,
		RuleCount: countRules(content), Revision: item.Revision,
	}
	if providerName, err := configpkg.LocalRuleProviderName(item.Name); err == nil {
		result.ProviderName = providerName
	}
	return result
}

func countRules(content string) int {
	count := 0
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			count++
		}
	}
	return count
}

func supportedRuleListFormat(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), "text")
}

func mapRuleListError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, rulelist.ErrNotFound):
		return web.ErrNotFound
	case errors.Is(err, rulelist.ErrConflict):
		return web.ErrConflict
	default:
		return err
	}
}

type BackupService struct {
	Manager          backup.Manager
	LockManagedState func(context.Context) (func() error, error)
	LockExport       func(context.Context) (func() error, error)
	LockImport       func(context.Context) (func() error, error)
	CanImport        func() bool
	WasRunning       func() bool
	StopCore         func(context.Context) error
	StartCore        func(context.Context) error
}

func (service BackupService) ExportBackup(ctx context.Context, options web.BackupExportOptions) (result web.BackupArchive, returnErr error) {
	if service.LockManagedState != nil {
		unlock, err := service.LockManagedState(ctx)
		if err != nil {
			return web.BackupArchive{}, err
		}
		if unlock == nil {
			return web.BackupArchive{}, errors.New("backup managed-state lock returned no release function")
		}
		defer func() { returnErr = errors.Join(returnErr, unlock()) }()
	}
	if service.LockExport != nil {
		unlock, err := service.LockExport(ctx)
		if err != nil {
			return web.BackupArchive{}, err
		}
		if unlock == nil {
			return web.BackupArchive{}, errors.New("backup export lock returned no release function")
		}
		defer func() { returnErr = errors.Join(returnErr, unlock()) }()
	}
	path, err := service.Manager.CreateWithOptions(ctx, backup.ExportOptions{
		IncludeAdminPassword:  options.IncludeAdminPassword,
		IncludeProviderCaches: options.IncludeProviderCaches,
		IncludeDashboardUI:    options.IncludeDashboardUI,
	})
	if err != nil {
		return web.BackupArchive{}, err
	}
	defer os.Remove(path)
	info, err := os.Lstat(path)
	if err != nil {
		return web.BackupArchive{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 64<<20 {
		return web.BackupArchive{}, errors.New("generated backup is not a bounded regular file")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return web.BackupArchive{}, err
	}
	return web.BackupArchive{Filename: filepath.Base(path), Data: content}, nil
}

func (service BackupService) ImportBackup(ctx context.Context, archive web.BackupImport) (result web.BackupImportResult, returnErr error) {
	if len(archive.Data) == 0 || len(archive.Data) > 64<<20 {
		return web.BackupImportResult{}, &web.PublicError{Status: http.StatusBadRequest, Code: "invalid_backup", Message: "Backup is empty or too large"}
	}
	root := service.Manager.Root
	if root == "" {
		return web.BackupImportResult{}, errors.New("backup root is not configured")
	}
	temporaryDir := filepath.Join(root, ".boxctl", "imports")
	if err := os.MkdirAll(temporaryDir, 0o700); err != nil {
		return web.BackupImportResult{}, err
	}
	temporary, err := os.CreateTemp(temporaryDir, ".restore-*.tar.gz")
	if err != nil {
		return web.BackupImportResult{}, err
	}
	path := temporary.Name()
	defer os.Remove(path)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return web.BackupImportResult{}, err
	}
	if _, err := temporary.Write(archive.Data); err != nil {
		_ = temporary.Close()
		return web.BackupImportResult{}, err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return web.BackupImportResult{}, err
	}
	if err := temporary.Close(); err != nil {
		return web.BackupImportResult{}, err
	}
	if _, err := service.Manager.Validate(ctx, path); err != nil {
		return web.BackupImportResult{}, &web.PublicError{Status: http.StatusBadRequest, Code: "invalid_backup", Message: "Backup integrity validation failed"}
	}
	// Scheduler refreshes and interactive profile/subscription mutations hold
	// these service locks across both metadata and cache writes. Keep them until
	// restore finalization (including an optional restart) is complete so no
	// writer can publish into the state tree while top-level paths are swapped.
	if service.LockManagedState != nil {
		unlock, err := service.LockManagedState(ctx)
		if err != nil {
			return web.BackupImportResult{}, err
		}
		if unlock == nil {
			return web.BackupImportResult{}, errors.New("backup managed-state lock returned no release function")
		}
		defer func() { returnErr = errors.Join(returnErr, unlock()) }()
	}

	wasRunning := service.WasRunning != nil && service.WasRunning()
	if wasRunning {
		if service.StopCore == nil || service.StartCore == nil {
			return web.BackupImportResult{}, errors.New("backup lifecycle callbacks are incomplete")
		}
		if err := service.StopCore(ctx); err != nil {
			return web.BackupImportResult{}, fmt.Errorf("stop selective routing for restore: %w", err)
		}
	}

	restored := false
	operationErr := func() (err error) {
		var unlock func() error
		if service.LockImport != nil {
			unlock, err = service.LockImport(ctx)
			if err != nil {
				return err
			}
			if unlock == nil {
				return errors.New("backup import lock returned no release function")
			}
			defer func() { err = errors.Join(err, unlock()) }()
		}
		if service.CanImport != nil && !service.CanImport() {
			return &web.PublicError{Status: http.StatusConflict, Code: "service_not_stopped", Message: "Selective routing could not be stopped safely for restore"}
		}
		if err := service.Manager.Restore(ctx, path); err != nil {
			return fmt.Errorf("restore backup: %w", err)
		}
		restored = true
		return nil
	}()

	var restartErr error
	if wasRunning {
		resumeContext, cancelResume := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		restartErr = service.StartCore(resumeContext)
		cancelResume()
	}
	if !restored {
		return web.BackupImportResult{}, errors.Join(operationErr, restartErr)
	}
	result = web.BackupImportResult{Imported: true, CoreRestarted: wasRunning && restartErr == nil}
	if operationErr != nil {
		result.Warnings = append(result.Warnings, "Backup restored, but finalization reported an error")
	}
	if restartErr != nil {
		result.RestartRequired = true
		result.Warnings = append(result.Warnings, "Backup restored, but selective routing could not be restarted")
	}
	return result, nil
}

func DefaultBackupManager(root string) backup.Manager {
	return backup.Manager{Root: root, BackupDir: filepath.Join(root, "backups"), MaxFiles: 10_000, MaxFileSize: 32 << 20, MaxExpandedSize: 128 << 20, MaxArchiveSize: 32 << 20}
}

var _ web.RuleListService = RuleListService{}
var _ web.BackupService = BackupService{}

// Ensure imported files never borrow special filesystem modes even when a
// future backup schema expands the include list.
var _ fs.FileMode = 0o600
