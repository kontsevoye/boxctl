package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontsevoye/boxctl/internal/backup"
	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/fakeip"
	"github.com/kontsevoye/boxctl/internal/rulelist"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

func TestRuleListServiceCRUDAndConflict(t *testing.T) {
	service := RuleListService{Store: &rulelist.Store{Directory: filepath.Join(t.TempDir(), "local-rules")}}
	created, err := service.CreateRuleList(context.Background(), web.RuleListDraft{Name: "Telegram", Format: "text", Content: "# note\n1.1.1.1/32\n"})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != "telegram" || created.RuleCount != 1 {
		t.Fatalf("created = %+v", created)
	}
	lists, err := service.RuleLists(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(lists) != 1 || lists[0].RuleCount != 1 {
		t.Fatalf("listed = %+v", lists)
	}
	if _, err := service.CreateRuleList(context.Background(), web.RuleListDraft{Name: "wrong-format", Format: "yaml", Content: "payload"}); err == nil {
		t.Fatal("non-text local rule list format was accepted")
	}
	if _, err := service.CreateRuleList(context.Background(), web.RuleListDraft{Name: "telegram", Format: "text", Content: "replace"}); !errors.Is(err, web.ErrConflict) {
		t.Fatalf("second create = %v", err)
	}
	content := "2.2.2.2/32\n"
	updated, err := service.UpdateRuleList(context.Background(), created.ID, web.RuleListUpdate{Content: &content, Revision: created.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Content != content || updated.Revision == created.Revision {
		t.Fatalf("updated = %+v", updated)
	}
	if err := service.DeleteRuleList(context.Background(), created.ID, created.Revision); !errors.Is(err, web.ErrConflict) {
		t.Fatalf("stale delete = %v", err)
	}
}

func TestRuleListServiceAutoPrefixesAndWiresActiveConfig(t *testing.T) {
	root := t.TempDir()
	for _, directory := range []string{"engines/mihomo", "configs"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "engines", "mihomo", "mihomo"), []byte("fake"), 0o700); err != nil {
		t.Fatal(err)
	}
	profiles, err := state.NewProfileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	profile := state.ActiveProfile{Name: "default", Engine: state.EngineMihomo}
	configuration := []byte("mode: rule\nrules:\n  - MATCH,DIRECT\n")
	if err := profiles.Create(context.Background(), profile, configuration); err != nil {
		t.Fatal(err)
	}
	if err := profiles.Activate(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	preparer, err := NewActiveMihomoPreparer(root, &recordingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	configService := &ConfigService{Preparer: preparer}
	service := RuleListService{
		Store:  &rulelist.Store{Directory: filepath.Join(root, "local-rules")},
		Config: configService,
	}
	created, err := service.CreateRuleList(context.Background(), web.RuleListDraft{Name: "telegram-ip", Format: "text", Content: "# Telegram\n149.154.160.0/20\nIP-CIDR,91.108.4.0/22\n"})
	if err != nil {
		t.Fatal(err)
	}
	if created.Content != "# Telegram\nIP-CIDR,149.154.160.0/20\nIP-CIDR,91.108.4.0/22\n" {
		t.Fatalf("auto-prefixed content = %q", created.Content)
	}
	attached, err := service.AddRuleListToConfig(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !attached.InConfig || attached.ProviderName != "local-telegram-ip" {
		t.Fatalf("attached = %+v", attached)
	}
	document, err := configService.RawConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(document.Content, "local-telegram-ip:\n") || !strings.Contains(document.Content, "path: ./local-rules/telegram-ip.txt\n") {
		t.Fatalf("active config was not wired:\n%s", document.Content)
	}
	lists, err := service.RuleLists(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(lists) != 1 || !lists[0].InConfig {
		t.Fatalf("lists = %+v", lists)
	}
	if err := service.DeleteRuleList(context.Background(), created.ID, created.Revision); err != nil {
		t.Fatal(err)
	}
	after, err := configService.RawConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(after.Content, "local-telegram-ip") {
		t.Fatalf("managed provider survived delete:\n%s", after.Content)
	}
}

func TestRuleListServiceUsesHotReloadForConfigMutations(t *testing.T) {
	service, configService := newRuleListServiceWithConfig(t, "mode: rule\nrules:\n  - MATCH,DIRECT\n")
	reloads := 0
	restarts := 0
	configService.OnReload = func(context.Context) (bool, error) {
		reloads++
		return true, nil
	}
	configService.OnChanged = func(context.Context) (bool, error) {
		restarts++
		return true, nil
	}

	created, err := service.CreateRuleList(context.Background(), web.RuleListDraft{
		Name: "video-domain", Format: "text", Content: "example.com\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.AddRuleListToConfig(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteRuleList(context.Background(), created.ID, created.Revision); err != nil {
		t.Fatal(err)
	}
	if reloads != 2 || restarts != 0 {
		t.Fatalf("reloads=%d restarts=%d, want reloads=2 restarts=0", reloads, restarts)
	}
}

func TestRuleListServiceReloadsAttachedContentAndIsSafeWhileStopped(t *testing.T) {
	service, configService := newRuleListServiceWithConfig(t, "mode: rule\nrules:\n  - MATCH,DIRECT\n")
	running := true
	reloads := 0
	configService.OnReload = func(context.Context) (bool, error) {
		reloads++
		return running, nil
	}
	configService.OnChanged = func(context.Context) (bool, error) {
		t.Fatal("attached rule-list update requested a core restart")
		return false, nil
	}

	created, err := service.CreateRuleList(context.Background(), web.RuleListDraft{
		Name: "video-domain", Format: "text", Content: "one.example\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.AddRuleListToConfig(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
	firstContent := "two.example\n"
	updated, err := service.UpdateRuleList(context.Background(), created.ID, web.RuleListUpdate{
		Content: &firstContent, Revision: created.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	if reloads != 2 {
		t.Fatalf("reloads after running update = %d, want 2", reloads)
	}

	running = false
	secondContent := "three.example\n"
	stoppedUpdate, err := service.UpdateRuleList(context.Background(), created.ID, web.RuleListUpdate{
		Content: &secondContent, Revision: updated.Revision,
	})
	if err != nil {
		t.Fatalf("stopped update failed: %v", err)
	}
	if reloads != 3 {
		t.Fatalf("reload callback calls = %d, want 3", reloads)
	}
	if stoppedUpdate.Content != "DOMAIN-SUFFIX,three.example\n" {
		t.Fatalf("stopped update content = %q", stoppedUpdate.Content)
	}
	stored, err := service.Store.Get(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Content != stoppedUpdate.Content {
		t.Fatalf("stored content = %q, response = %q", stored.Content, stoppedUpdate.Content)
	}
}

func TestRuleListServiceReloadErrorsPreserveUserData(t *testing.T) {
	reloadErr := errors.New("reload failed")

	t.Run("add rolls config back and keeps list", func(t *testing.T) {
		service, configService := newRuleListServiceWithConfig(t, "mode: rule\nrules:\n  - MATCH,DIRECT\n")
		calls := 0
		configService.OnReload = func(context.Context) (bool, error) {
			calls++
			return false, reloadErr
		}
		created, err := service.CreateRuleList(context.Background(), web.RuleListDraft{
			Name: "video-domain", Format: "text", Content: "example.com\n",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.AddRuleListToConfig(context.Background(), created.ID); !errors.Is(err, reloadErr) {
			t.Fatalf("add error = %v, want reload failure", err)
		}
		if calls != 2 {
			t.Fatalf("reload calls = %d, want failed apply plus rollback", calls)
		}
		document, err := configService.RawConfig(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(document.Content, "local-video-domain") {
			t.Fatalf("failed add left provider attached:\n%s", document.Content)
		}
		if _, err := service.Store.Get(created.ID); err != nil {
			t.Fatalf("failed add lost list: %v", err)
		}
	})

	t.Run("delete rolls config back and keeps list", func(t *testing.T) {
		service, configService := newRuleListServiceWithConfig(t, "mode: rule\nrules:\n  - MATCH,DIRECT\n")
		configService.OnReload = func(context.Context) (bool, error) { return true, nil }
		created, err := service.CreateRuleList(context.Background(), web.RuleListDraft{
			Name: "video-domain", Format: "text", Content: "example.com\n",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.AddRuleListToConfig(context.Background(), created.ID); err != nil {
			t.Fatal(err)
		}
		calls := 0
		configService.OnReload = func(context.Context) (bool, error) {
			calls++
			return false, reloadErr
		}
		if err := service.DeleteRuleList(context.Background(), created.ID, created.Revision); !errors.Is(err, reloadErr) {
			t.Fatalf("delete error = %v, want reload failure", err)
		}
		if calls != 2 {
			t.Fatalf("reload calls = %d, want failed apply plus rollback", calls)
		}
		document, err := configService.RawConfig(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(document.Content, "local-video-domain") {
			t.Fatalf("failed delete did not restore provider:\n%s", document.Content)
		}
		if _, err := service.Store.Get(created.ID); err != nil {
			t.Fatalf("failed delete lost list: %v", err)
		}
	})

	t.Run("content update remains saved for retry", func(t *testing.T) {
		service, configService := newRuleListServiceWithConfig(t, "mode: rule\nrules:\n  - MATCH,DIRECT\n")
		configService.OnReload = func(context.Context) (bool, error) { return true, nil }
		created, err := service.CreateRuleList(context.Background(), web.RuleListDraft{
			Name: "video-domain", Format: "text", Content: "old.example\n",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.AddRuleListToConfig(context.Background(), created.ID); err != nil {
			t.Fatal(err)
		}
		configService.OnReload = func(context.Context) (bool, error) { return false, reloadErr }
		content := "new.example\n"
		if _, err := service.UpdateRuleList(context.Background(), created.ID, web.RuleListUpdate{
			Content: &content, Revision: created.Revision,
		}); !errors.Is(err, reloadErr) || !strings.Contains(err.Error(), "saved") {
			t.Fatalf("update error = %v, want saved reload failure", err)
		}
		stored, err := service.Store.Get(created.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.Content != "DOMAIN-SUFFIX,new.example\n" {
			t.Fatalf("failed reload lost edited content: %q", stored.Content)
		}
	})
}

func TestRuleListServiceDeleteConflictRestoresConfigAndKeepsConcurrentEdit(t *testing.T) {
	service, configService := newRuleListServiceWithConfig(t, "mode: rule\nrules:\n  - MATCH,DIRECT\n")
	configService.OnReload = func(context.Context) (bool, error) { return true, nil }
	created, err := service.CreateRuleList(context.Background(), web.RuleListDraft{
		Name: "video-domain", Format: "text", Content: "old.example\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.AddRuleListToConfig(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}

	reloads := 0
	configService.OnReload = func(context.Context) (bool, error) {
		reloads++
		if reloads == 1 {
			if _, err := service.Store.Put(created.ID, "DOMAIN-SUFFIX,concurrent.example\n", created.Revision); err != nil {
				t.Fatalf("concurrent edit: %v", err)
			}
		}
		return true, nil
	}
	if err := service.DeleteRuleList(context.Background(), created.ID, created.Revision); !errors.Is(err, web.ErrConflict) {
		t.Fatalf("delete error = %v, want revision conflict", err)
	}
	if reloads != 2 {
		t.Fatalf("reloads = %d, want delete mutation plus config rollback", reloads)
	}
	stored, err := service.Store.Get(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Content != "DOMAIN-SUFFIX,concurrent.example\n" {
		t.Fatalf("concurrent content was lost: %q", stored.Content)
	}
	document, err := configService.RawConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(document.Content, "local-video-domain") {
		t.Fatalf("provider was not restored after delete conflict:\n%s", document.Content)
	}
}

func newRuleListServiceWithConfig(t *testing.T, configuration string) (RuleListService, *ConfigService) {
	t.Helper()
	root := t.TempDir()
	for _, directory := range []string{"engines/mihomo", "configs"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "engines", "mihomo", "mihomo"), []byte("fake"), 0o700); err != nil {
		t.Fatal(err)
	}
	profiles, err := state.NewProfileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	profile := state.ActiveProfile{Name: "default", Engine: state.EngineMihomo}
	if err := profiles.Create(context.Background(), profile, []byte(configuration)); err != nil {
		t.Fatal(err)
	}
	if err := profiles.Activate(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	preparer, err := NewActiveMihomoPreparer(root, &recordingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	configService := &ConfigService{Preparer: preparer}
	return RuleListService{
		Store:  &rulelist.Store{Directory: filepath.Join(root, "local-rules")},
		Config: configService,
	}, configService
}

func TestRuleListServiceProtectsListReferencedByRuleSet(t *testing.T) {
	root := t.TempDir()
	for _, directory := range []string{"engines/mihomo", "configs", "local-rules"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "engines", "mihomo", "mihomo"), []byte("fake"), 0o700); err != nil {
		t.Fatal(err)
	}
	profiles, err := state.NewProfileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	profile := state.ActiveProfile{Name: "default", Engine: state.EngineMihomo}
	configuration := []byte("rule-providers:\n  local-video-domain:\n    type: file\n    behavior: classical\n    format: text\n    path: ./local-rules/video-domain.txt\nrules:\n  - RULE-SET,local-video-domain,PROXY\n")
	if err := profiles.Create(context.Background(), profile, configuration); err != nil {
		t.Fatal(err)
	}
	if err := profiles.Activate(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	preparer, err := NewActiveMihomoPreparer(root, &recordingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	service := RuleListService{Store: &rulelist.Store{Directory: filepath.Join(root, "local-rules")}, Config: &ConfigService{Preparer: preparer}}
	created, err := service.CreateRuleList(context.Background(), web.RuleListDraft{Name: "video-domain", Format: "text", Content: "example.com\n"})
	if err != nil {
		t.Fatal(err)
	}
	err = service.DeleteRuleList(context.Background(), created.ID, created.Revision)
	var public *web.PublicError
	if !errors.As(err, &public) || public.Code != "rule_list_in_use" {
		t.Fatalf("delete error = %v", err)
	}
	if _, err := service.Store.Get(created.ID); err != nil {
		t.Fatalf("referenced list was deleted: %v", err)
	}
}

func TestRuleListServiceReservesFakeIPWhitelist(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "local-rules")
	fakeIPStore := &fakeip.Store{Directory: directory}
	empty, err := fakeIPStore.Read()
	if err != nil {
		t.Fatal(err)
	}
	original, err := fakeIPStore.SaveManual("# dedicated document\n198.51.100.0/24\n", empty.Revision)
	if err != nil {
		t.Fatal(err)
	}

	service := RuleListService{Store: &rulelist.Store{Directory: directory}}
	created, err := service.CreateRuleList(context.Background(), web.RuleListDraft{Name: "ordinary", Format: "text", Content: "203.0.113.0/24\n"})
	if err != nil {
		t.Fatal(err)
	}
	lists, err := service.RuleLists(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(lists) != 1 || lists[0].ID != created.ID {
		t.Fatalf("generic rule lists exposed reserved document: %+v", lists)
	}

	reservedName := strings.TrimSuffix(fakeip.FileName, filepath.Ext(fakeip.FileName))
	assertReservedRuleListError(t, func() error {
		_, getErr := service.RuleList(context.Background(), "  "+strings.ToUpper(reservedName)+"  ")
		return getErr
	}())
	assertReservedRuleListError(t, func() error {
		_, createErr := service.CreateRuleList(context.Background(), web.RuleListDraft{Name: fakeip.FileName, Format: "text", Content: "replace\n"})
		return createErr
	}())
	content := "replace\n"
	assertReservedRuleListError(t, func() error {
		_, updateErr := service.UpdateRuleList(context.Background(), reservedName, web.RuleListUpdate{Content: &content, Revision: original.Revision})
		return updateErr
	}())
	assertReservedRuleListError(t, service.DeleteRuleList(context.Background(), reservedName, original.Revision))
	rename := strings.ToUpper(reservedName)
	assertReservedRuleListError(t, func() error {
		_, updateErr := service.UpdateRuleList(context.Background(), created.ID, web.RuleListUpdate{Name: &rename, Revision: created.Revision})
		return updateErr
	}())

	after, err := fakeIPStore.Read()
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision != original.Revision || after.Content != original.Content {
		t.Fatalf("reserved document changed through generic CRUD: before=%+v after=%+v", original, after)
	}
}

func assertReservedRuleListError(t *testing.T, err error) {
	t.Helper()
	var public *web.PublicError
	if !errors.As(err, &public) {
		t.Fatalf("reserved rule list error = %v, want PublicError", err)
	}
	if public.Status != 409 || public.Code != "reserved_rule_list" || strings.Contains(public.Message, fakeip.FileName) {
		t.Fatalf("reserved rule list error = %+v", public)
	}
}

func TestBackupServiceRoundTripAndStoppedGuard(t *testing.T) {
	root := t.TempDir()
	locked := false
	service := BackupService{
		Manager: DefaultBackupManager(root),
		LockImport: func(context.Context) (func() error, error) {
			if locked {
				t.Fatal("backup import lock was acquired recursively")
			}
			locked = true
			return func() error { locked = false; return nil }, nil
		},
		CanImport: func() bool {
			if !locked {
				t.Fatal("backup state was checked before import lock")
			}
			return false
		},
	}
	archive, err := service.ExportBackup(context.Background(), web.BackupExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(archive.Data) == 0 {
		t.Fatal("empty backup")
	}
	if _, err := service.ImportBackup(context.Background(), web.BackupImport(archive)); err == nil {
		t.Fatal("running-service restore succeeded")
	}
	if locked {
		t.Fatal("backup import lock remained held after rejected restore")
	}
	service.CanImport = func() bool { return true }
	result, err := service.ImportBackup(context.Background(), web.BackupImport(archive))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Imported || result.RestartRequired {
		t.Fatalf("result = %+v", result)
	}
	if locked {
		t.Fatal("backup import lock remained held after successful restore")
	}
}

func TestDefaultBackupManagerValidatesRestoredActiveConfigWithExactSingBox(t *testing.T) {
	root := t.TempDir()
	profile := state.ActiveProfile{Name: "travel", Engine: state.EngineSingBox}
	for _, directory := range []string{
		filepath.Join(root, ".boxctl"), filepath.Join(root, "configs"),
		filepath.Join(root, "engines", state.EngineSingBox, "versions", "1.14.0"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	active, err := state.MarshalActiveProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".boxctl", "active-profile"), active, 0o600); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(root, "configs", state.ProfileConfigName(profile))
	invalid := []byte("{\"reject_candidate\":true,\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\"}],\"route\":{\"final\":\"direct\"}}\n")
	if err := os.WriteFile(profilePath, invalid, 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "engines", state.EngineSingBox, "versions", "1.14.0", state.EngineSingBox)
	script := "#!/bin/sh\ncase \"$1\" in\nversion) echo 'sing-box version 1.14.0' ;;\nmerge) cp \"$6\" \"$2\" ;;\ncheck) if grep -q reject_candidate \"$5\"; then exit 42; fi ;;\n*) exit 1 ;;\nesac\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(script))
	pointer := `{"schema":1,"engine":"sing-box","current":{"engine":"sing-box","version":"1.14.0","binary":"versions/1.14.0/sing-box","binarySHA256":"` + hex.EncodeToString(digest[:]) + `"}}` + "\n"
	if err := os.WriteFile(filepath.Join(root, "engines", state.EngineSingBox, "current.json"), []byte(pointer), 0o600); err != nil {
		t.Fatal(err)
	}

	manager := DefaultBackupManager(root)
	archive, err := manager.CreateWithOptions(context.Background(), backup.ExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	current := []byte("{\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\"}],\"route\":{\"final\":\"direct\"}}\n")
	if err := os.WriteFile(profilePath, current, 0o600); err != nil {
		t.Fatal(err)
	}

	err = manager.Restore(context.Background(), archive)
	if err == nil || !strings.Contains(err.Error(), "restore application preflight") || !strings.Contains(err.Error(), "validate restored sing-box config") {
		t.Fatalf("Restore() error = %v", err)
	}
	content, readErr := os.ReadFile(profilePath)
	if readErr != nil || string(content) != string(current) {
		t.Fatalf("failed preflight replaced current profile: %q, %v", content, readErr)
	}
	if _, secretErr := os.Lstat(filepath.Join(root, singBoxControllerStatePath)); !errors.Is(secretErr, os.ErrNotExist) {
		t.Fatalf("restore preflight wrote controller state: %v", secretErr)
	}
}

func TestRestorePreflightValidatesUnversionedMihomoBeforeStateSwap(t *testing.T) {
	root := t.TempDir()
	payload := t.TempDir()
	for _, directory := range []string{
		filepath.Join(root, "engines", state.EngineMihomo),
		filepath.Join(payload, ".boxctl"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(root, "engines", state.EngineMihomo, state.EngineMihomo)
	script := "#!/bin/sh\nif [ \"$1\" = -v ]; then echo 'Mihomo Meta v1.19.0'; exit 0; fi\ncase \"$*\" in *reject_candidate*) exit 42 ;; esac\nfor arg in \"$@\"; do [ \"$arg\" = -f ] && config_next=1 && continue; if [ \"${config_next:-0}\" = 1 ]; then grep -q reject_candidate \"$arg\" && exit 42; config_next=0; fi; done\nexit 0\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(payload, "config.yaml"), []byte("mode: rule\nreject_candidate: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := backup.Manifest{
		Schema:  backup.CurrentManifestSchema,
		Engines: []backup.EngineRequirement{{Engine: state.EngineMihomo}},
	}
	if err := validateRestoredActiveConfig(context.Background(), root, payload, manifest); err == nil || !strings.Contains(err.Error(), "validate restored Mihomo config") {
		t.Fatalf("unversioned Mihomo restore preflight = %v", err)
	}
}

func TestRestorePreflightUsesTheSameMihomoMirrorAsRuntimePreparation(t *testing.T) {
	root := t.TempDir()
	payload := t.TempDir()
	profile := state.ActiveProfile{Name: "selected", Engine: state.EngineMihomo}
	for _, directory := range []string{
		filepath.Join(root, "engines", state.EngineMihomo),
		filepath.Join(payload, ".boxctl"), filepath.Join(payload, "configs"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(root, "engines", state.EngineMihomo, state.EngineMihomo)
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n[ \"$1\" = -v ] && echo 'Mihomo Meta v1.19.0'\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	active, err := state.MarshalActiveProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(payload, ".boxctl", "active-profile"), active, 0o600); err != nil {
		t.Fatal(err)
	}
	// A completed activation makes config.yaml authoritative. Keep a malformed
	// stale profile beside it to prove preflight does not derive settings from a
	// different generation than the one PrepareActive will launch.
	if err := os.WriteFile(filepath.Join(payload, "config.yaml"), []byte("mode: rule\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(payload, "configs", state.ProfileConfigName(profile)), []byte("[invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := backup.Manifest{
		Schema:  backup.CurrentManifestSchema,
		Engines: []backup.EngineRequirement{{Engine: state.EngineMihomo}},
	}
	if err := validateRestoredActiveConfig(context.Background(), root, payload, manifest); err != nil {
		t.Fatalf("preflight rejected authoritative Mihomo mirror: %v", err)
	}
}

func TestRestorePreflightValidatesCustomSingBoxBeforeStateSwap(t *testing.T) {
	root := t.TempDir()
	payload := t.TempDir()
	profile := state.ActiveProfile{Name: "travel", Engine: state.EngineSingBox}
	for _, directory := range []string{
		filepath.Join(root, "engines", state.EngineSingBox),
		filepath.Join(payload, ".boxctl"), filepath.Join(payload, "configs"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(root, "engines", state.EngineSingBox, state.EngineSingBox)
	script := "#!/bin/sh\ncase \"$1\" in\nversion) echo 'sing-box version 1.14.0' ;;\nmerge) cp \"$6\" \"$2\" ;;\ncheck) grep -q reject_candidate \"$5\" && exit 42 ;;\n*) exit 1 ;;\nesac\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	active, err := state.MarshalActiveProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(payload, ".boxctl", "active-profile"), active, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(payload, "configs", state.ProfileConfigName(profile)), []byte("{\"reject_candidate\":true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := backup.Manifest{
		Schema:  backup.CurrentManifestSchema,
		Engines: []backup.EngineRequirement{{Engine: state.EngineSingBox}},
	}
	if err := validateRestoredActiveConfig(context.Background(), root, payload, manifest); err == nil || !strings.Contains(err.Error(), "validate restored sing-box config") {
		t.Fatalf("custom sing-box restore preflight = %v", err)
	}
}

func TestRestoreApplicationPreflightDoesNotInterpretLegacyEngineFields(t *testing.T) {
	err := validateRestoredActiveConfig(context.Background(), t.TempDir(), filepath.Join(t.TempDir(), "missing-payload"), backup.Manifest{
		Schema: 1,
		Engines: []backup.EngineRequirement{{
			Engine: state.EngineSingBox, Version: "1.14.0", Binary: "versions/1.14.0/sing-box",
			BinarySHA256: strings.Repeat("a", 64),
		}},
	})
	if err != nil {
		t.Fatalf("legacy preflight = %v", err)
	}
}

func TestBackupServiceStopsAndRestartsPreviouslyRunningCore(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte("mode: rule\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	installAcceptingMihomoFixture(t, root)
	base := BackupService{Manager: DefaultBackupManager(root)}
	archive, err := base.ExportBackup(context.Background(), web.BackupExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	running := true
	locked := false
	var calls []string
	service := BackupService{
		Manager:    DefaultBackupManager(root),
		WasRunning: func() bool { return running },
		StopCore: func(context.Context) error {
			calls = append(calls, "stop")
			running = false
			return nil
		},
		StartCore: func(context.Context) error {
			if locked {
				t.Fatal("core restart ran while restore lock was held")
			}
			calls = append(calls, "start")
			running = true
			return nil
		},
		LockImport: func(context.Context) (func() error, error) {
			if running {
				t.Fatal("restore lock acquired before core stop")
			}
			locked = true
			calls = append(calls, "lock")
			return func() error {
				calls = append(calls, "unlock")
				locked = false
				return nil
			}, nil
		},
		CanImport: func() bool { return !running && locked },
	}
	result, err := service.ImportBackup(context.Background(), web.BackupImport(archive))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Imported || !result.CoreRestarted || result.RestartRequired || !running {
		t.Fatalf("restore result=%+v running=%v", result, running)
	}
	if got := strings.Join(calls, ","); got != "stop,lock,unlock,start" {
		t.Fatalf("restore order = %s", got)
	}
}

func TestBackupServiceRollsBackStateWhenRestoredCoreCannotRestart(t *testing.T) {
	root := t.TempDir()
	backupConfig := []byte("mode: rule\ngeneration: backup\n")
	currentConfig := []byte("mode: direct\ngeneration: current\n")
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), backupConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	installAcceptingMihomoFixture(t, root)
	base := BackupService{Manager: DefaultBackupManager(root)}
	archive, err := base.ExportBackup(context.Background(), web.BackupExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), currentConfig, 0o600); err != nil {
		t.Fatal(err)
	}

	running := true
	locked := false
	startCalls := 0
	service := BackupService{
		Manager:    DefaultBackupManager(root),
		WasRunning: func() bool { return running },
		StopCore: func(context.Context) error {
			running = false
			return nil
		},
		StartCore: func(context.Context) error {
			startCalls++
			content, readErr := os.ReadFile(filepath.Join(root, "config.yaml"))
			if readErr != nil {
				return readErr
			}
			if bytes.Equal(content, backupConfig) {
				return errors.New("restored core did not become ready")
			}
			if !bytes.Equal(content, currentConfig) {
				t.Fatalf("unexpected config during restart: %q", content)
			}
			running = true
			return nil
		},
		LockImport: func(context.Context) (func() error, error) {
			if locked {
				t.Fatal("backup import lock was acquired recursively")
			}
			locked = true
			return func() error { locked = false; return nil }, nil
		},
		CanImport: func() bool { return locked && !running },
	}

	result, err := service.ImportBackup(context.Background(), web.BackupImport(archive))
	if err == nil || !strings.Contains(err.Error(), "failed readiness and was rolled back") {
		t.Fatalf("ImportBackup() result=%+v error=%v", result, err)
	}
	if result.Imported || startCalls != 2 || !running || locked {
		t.Fatalf("rollback result=%+v starts=%d running=%t locked=%t", result, startCalls, running, locked)
	}
	content, readErr := os.ReadFile(filepath.Join(root, "config.yaml"))
	if readErr != nil || !bytes.Equal(content, currentConfig) {
		t.Fatalf("previous config was not restored: %q, %v", content, readErr)
	}
}

func TestBackupServiceRetainsPreviousStateWhenFailedRuntimeCannotBeStopped(t *testing.T) {
	root := filepath.Join(t.TempDir(), "boxctl")
	backupConfig := []byte("mode: rule\ngeneration: backup\n")
	currentConfig := []byte("mode: direct\ngeneration: current\n")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), backupConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	installAcceptingMihomoFixture(t, root)
	base := BackupService{Manager: DefaultBackupManager(root)}
	archive, err := base.ExportBackup(context.Background(), web.BackupExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), currentConfig, 0o600); err != nil {
		t.Fatal(err)
	}

	running := true
	uncertain := false
	locked := false
	stopCalls := 0
	service := BackupService{
		Manager:    DefaultBackupManager(root),
		WasRunning: func() bool { return running },
		StopCore: func(context.Context) error {
			stopCalls++
			if uncertain {
				return errors.New("restored process ownership is uncertain")
			}
			running = false
			return nil
		},
		StartCore: func(context.Context) error {
			uncertain = true
			return errors.New("restored core did not become ready")
		},
		LockImport: func(context.Context) (func() error, error) {
			if locked {
				t.Fatal("backup import lock was acquired recursively")
			}
			locked = true
			return func() error { locked = false; return nil }, nil
		},
		CanImport: func() bool { return locked && !running && !uncertain },
	}

	result, err := service.ImportBackup(context.Background(), web.BackupImport(archive))
	if err != nil {
		t.Fatalf("ImportBackup() error = %v", err)
	}
	if !result.Imported || !result.RestartRequired || result.CoreRestarted || stopCalls != 2 || locked {
		t.Fatalf("restore result=%+v stops=%d locked=%t", result, stopCalls, locked)
	}
	if len(result.Warnings) < 2 || !strings.Contains(strings.Join(result.Warnings, " "), "previous state was retained") {
		t.Fatalf("restore warnings = %#v", result.Warnings)
	}
	content, readErr := os.ReadFile(filepath.Join(root, "config.yaml"))
	if readErr != nil || !bytes.Equal(content, backupConfig) {
		t.Fatalf("restored config is not active: %q, %v", content, readErr)
	}
	staging, globErr := filepath.Glob(filepath.Join(filepath.Dir(root), ".boxctl-restore-*"))
	if globErr != nil || len(staging) != 1 {
		t.Fatalf("retained restore staging = %#v, %v", staging, globErr)
	}
	t.Cleanup(func() { _ = os.RemoveAll(staging[0]) })
	retained, readErr := os.ReadFile(filepath.Join(staging[0], "rollback", "config.yaml"))
	if readErr != nil || !bytes.Equal(retained, currentConfig) {
		t.Fatalf("previous config was not retained: %q, %v", retained, readErr)
	}
}

func TestLockBackupManagedStateBlocksProfileAndSubscriptionMutations(t *testing.T) {
	profiles := &ProfilesService{}
	subscriptions := &ProxySubscriptionsService{}
	unlock, err := lockBackupManagedState(context.Background(), profiles, subscriptions)
	if err != nil {
		t.Fatal(err)
	}

	profileAcquired := make(chan struct{})
	go func() {
		profiles.mutationMu.Lock()
		close(profileAcquired)
		profiles.mutationMu.Unlock()
	}()
	subscriptionAcquired := make(chan struct{})
	go func() {
		subscriptions.mu.Lock()
		close(subscriptionAcquired)
		subscriptions.mu.Unlock()
	}()
	for name, acquired := range map[string]<-chan struct{}{
		"profile": profileAcquired, "subscription": subscriptionAcquired,
	} {
		select {
		case <-acquired:
			t.Fatalf("%s mutation entered during backup state lock", name)
		case <-time.After(25 * time.Millisecond):
		}
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	for name, acquired := range map[string]<-chan struct{}{
		"profile": profileAcquired, "subscription": subscriptionAcquired,
	} {
		select {
		case <-acquired:
		case <-time.After(time.Second):
			t.Fatalf("%s mutation remained blocked after backup state unlock", name)
		}
	}
}

func TestBackupServiceHoldsManagedStateAcrossRestoreRestart(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte("mode: rule\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	installAcceptingMihomoFixture(t, root)
	base := BackupService{Manager: DefaultBackupManager(root)}
	archive, err := base.ExportBackup(context.Background(), web.BackupExportOptions{})
	if err != nil {
		t.Fatal(err)
	}

	managedLocked := false
	running := true
	service := BackupService{
		Manager: DefaultBackupManager(root),
		LockManagedState: func(context.Context) (func() error, error) {
			managedLocked = true
			return func() error { managedLocked = false; return nil }, nil
		},
		WasRunning: func() bool {
			if !managedLocked {
				t.Fatal("running state inspected outside managed-state lock")
			}
			return running
		},
		StopCore: func(context.Context) error { running = false; return nil },
		StartCore: func(context.Context) error {
			if !managedLocked {
				t.Fatal("core restarted after managed-state lock was released")
			}
			running = true
			return nil
		},
		CanImport: func() bool { return !running },
	}
	result, err := service.ImportBackup(context.Background(), web.BackupImport(archive))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Imported || !result.CoreRestarted || !running || managedLocked {
		t.Fatalf("restore result=%+v running=%v managedLocked=%v", result, running, managedLocked)
	}
}

func installAcceptingMihomoFixture(t *testing.T, root string) {
	t.Helper()
	binary := filepath.Join(root, "engines", state.EngineMihomo, state.EngineMihomo)
	if err := os.MkdirAll(filepath.Dir(binary), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nif [ \"$1\" = -v ]; then echo 'Mihomo Meta v1.19.0'; fi\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestLockBackupImportSerializesLifecycleAndGatewayOwner(t *testing.T) {
	store, err := state.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	openWrtLocks, err := state.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lifecycle := &Lifecycle{}
	unlock, err := lockBackupImport(context.Background(), lifecycle, store, openWrtLocks)
	if err != nil {
		t.Fatal(err)
	}
	lifecycleContext, cancelLifecycle := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancelLifecycle()
	if err := lifecycle.lockOperation(lifecycleContext); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("concurrent lifecycle lock error = %v", err)
	}
	for _, target := range []struct {
		store state.Store
		name  string
	}{
		{store: openWrtLocks, name: "gateway-dns"},
		{store: store, name: "state"},
		{store: store, name: "credentials"},
	} {
		lockContext, cancelLock := context.WithTimeout(context.Background(), 30*time.Millisecond)
		lock, lockErr := target.store.Lock(lockContext, target.name)
		cancelLock()
		if lock != nil {
			_ = lock.Unlock()
		}
		if !errors.Is(lockErr, context.DeadlineExceeded) {
			t.Fatalf("concurrent %s lock error = %v", target.name, lockErr)
		}
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.lockOperation(context.Background()); err != nil {
		t.Fatal(err)
	}
	lifecycle.opMu.Unlock()
}

func TestLifecycleAllowsBackupImportOnlyWhenCoreIsKnownStopped(t *testing.T) {
	tests := []struct {
		name     string
		snapshot LifecycleSnapshot
		want     bool
	}{
		{name: "stopped", snapshot: LifecycleSnapshot{State: LifecycleStopped}, want: true},
		{name: "failed and not running", snapshot: LifecycleSnapshot{State: LifecycleFailed}, want: true},
		{name: "running", snapshot: LifecycleSnapshot{State: LifecycleRunning}},
		{name: "starting", snapshot: LifecycleSnapshot{State: LifecycleStarting}},
		{name: "stopping", snapshot: LifecycleSnapshot{State: LifecycleStopping}},
		{name: "cleanup failed", snapshot: LifecycleSnapshot{State: LifecycleCleanupFailed}},
		{name: "stopped state with live health", snapshot: LifecycleSnapshot{State: LifecycleStopped, Health: engine.HealthStatus{Running: true}}},
		{name: "failed state with prepared core", snapshot: LifecycleSnapshot{State: LifecycleFailed, Prepared: engine.PreparedCore{Engine: "mihomo", BinaryPath: "/core"}}},
		{name: "stopped state with prepared core", snapshot: LifecycleSnapshot{State: LifecycleStopped, Prepared: engine.PreparedCore{RuntimeConfigPath: "/runtime/config.yaml"}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := lifecycleAllowsBackupImport(test.snapshot); got != test.want {
				t.Fatalf("lifecycleAllowsBackupImport(%+v) = %v, want %v", test.snapshot, got, test.want)
			}
		})
	}
}
