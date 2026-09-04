package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

func TestProfilesServiceCRUDDefaultsToMihomo(t *testing.T) {
	service, err := NewProfilesService(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateProfile(context.Background(), web.ProfileDraft{
		Name: "default", Content: "external-controller: 127.0.0.1:9090\nsecret: private\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != "mihomo:default" || created.Engine != "mihomo" || created.HasSource || created.Fingerprint == "" {
		t.Fatalf("created = %+v", created)
	}
	activated, err := service.ActivateProfile(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !activated.Active {
		t.Fatalf("activated = %+v", activated)
	}
	profiles, err := service.Profiles(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 || profiles[0].Name != "default" {
		t.Fatalf("profiles = %+v", profiles)
	}
	if err := service.DeleteProfile(context.Background(), created.ID); err == nil {
		t.Fatal("active profile was deleted")
	}
}

func TestProfilesServiceRemoteRefreshUsesValidatorsAndHeaderInterval(t *testing.T) {
	var version atomic.Int32
	version.Store(1)
	var conditional atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("If-None-Match") == `"info"` {
			conditional.Store(true)
			if version.Load() == 1 {
				response.Header().Set("ETag", `"info"`)
				response.Header().Set("Profile-Update-Interval", "12")
				response.WriteHeader(http.StatusNotModified)
				return
			}
		}
		level := "info"
		if version.Load() == 2 {
			level = "debug"
		}
		response.Header().Set("ETag", `"`+level+`"`)
		response.Header().Set("Profile-Update-Interval", "6")
		_, _ = response.Write([]byte("mode: rule\nlog-level: " + level + "\n"))
	}))
	defer server.Close()

	service, err := NewProfilesService(t.TempDir(), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateProfile(context.Background(), web.ProfileDraft{Name: "remote", SourceURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !created.HasSource || !created.SourceEnabled || created.UpdateIntervalHours != 6 || created.NextUpdateAt.IsZero() {
		t.Fatalf("created = %+v", created)
	}
	unchanged, err := service.RefreshProfile(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !conditional.Load() || unchanged.LastCheckedAt.IsZero() || unchanged.UpdateIntervalHours != 12 {
		t.Fatalf("conditional=%v unchanged=%+v", conditional.Load(), unchanged)
	}
	version.Store(2)
	updated, err := service.RefreshProfile(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Fingerprint == created.Fingerprint || updated.LastError != "" || updated.UpdateIntervalHours != 6 {
		t.Fatalf("updated = %+v", updated)
	}
}

func TestProfilesServiceExplicitIntervalOverridesResponseHeader(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("ETag", `"same"`)
		response.Header().Set("Profile-Update-Interval", "12")
		if request.Header.Get("If-None-Match") == `"same"` {
			response.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = response.Write([]byte("mode: rule\n"))
	}))
	defer server.Close()
	service, err := NewProfilesService(t.TempDir(), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	interval := 1
	created, err := service.CreateProfile(context.Background(), web.ProfileDraft{
		Name: "explicit", SourceURL: server.URL, UpdateIntervalHours: &interval,
	})
	if err != nil {
		t.Fatal(err)
	}
	refreshed, err := service.RefreshProfile(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.UpdateIntervalHours != 1 {
		t.Fatalf("explicit interval changed: %+v", refreshed)
	}
	automatic := true
	reset, err := service.UpdateProfile(context.Background(), created.ID, web.ProfilePatch{UpdateIntervalAuto: &automatic})
	if err != nil {
		t.Fatal(err)
	}
	if !reset.UpdateIntervalAuto {
		t.Fatalf("automatic interval was not restored: %+v", reset)
	}
	refreshed, err = service.RefreshProfile(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.UpdateIntervalHours != 12 || !refreshed.UpdateIntervalAuto {
		t.Fatalf("response interval was not restored: %+v", refreshed)
	}
}

func TestProfilesServiceRemoteSourceCanPauseScheduleAndDetach(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = response.Write([]byte("mode: rule\n"))
	}))
	defer server.Close()
	service, err := NewProfilesService(t.TempDir(), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	interval := 1
	created, err := service.CreateProfile(context.Background(), web.ProfileDraft{
		Name: "scheduled", SourceURL: server.URL, UpdateIntervalHours: &interval,
	})
	if err != nil {
		t.Fatal(err)
	}
	enabled := false
	paused, err := service.UpdateProfile(context.Background(), created.ID, web.ProfilePatch{SourceEnabled: &enabled})
	if err != nil {
		t.Fatal(err)
	}
	if paused.SourceEnabled {
		t.Fatalf("paused = %+v", paused)
	}
	if err := service.RefreshDueProfiles(context.Background(), time.Now().Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatalf("paused scheduler requests = %d", requests.Load())
	}
	if _, err := service.RefreshProfile(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 {
		t.Fatalf("manual requests = %d", requests.Load())
	}
	local, err := service.DetachProfileSource(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if local.HasSource || local.SourceKind != "local" || local.UpdateIntervalHours != 0 {
		t.Fatalf("detached = %+v", local)
	}
}

func TestProfilesServiceRejectsRemoteIntervalOutsideOneTo168Hours(t *testing.T) {
	service, err := NewProfilesService(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	interval := 169
	_, err = service.CreateProfile(context.Background(), web.ProfileDraft{Name: "remote", SourceURL: "https://example.test/profile", UpdateIntervalHours: &interval})
	var public *web.PublicError
	if !errors.As(err, &public) || public.Code != "invalid_update_interval" {
		t.Fatalf("error = %v", err)
	}
}

func TestProfilesServiceActivatesSingBoxThroughProfileSwitcher(t *testing.T) {
	service, err := NewProfilesService(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte(`{"log":{"level":"info"}}`)
	var switched state.ActiveProfile
	var switchedRevision string
	service.SwitchProfile = func(ctx context.Context, target state.ActiveProfile, confirmed bool) error {
		if confirmed {
			t.Fatal("stopped profile activation unexpectedly required restart confirmation")
		}
		source, err := service.Store.Get(target)
		if err != nil {
			return err
		}
		switched = target
		switchedRevision = contentRevision(source)
		if err := service.Store.Activate(ctx, target); err != nil {
			return err
		}
		return service.Revisions.MarkAppliedRevision(ctx, target, switchedRevision)
	}
	created, err := service.CreateProfile(context.Background(), web.ProfileDraft{Name: "future", Engine: "sing-box", Content: string(content)})
	if err != nil {
		t.Fatal(err)
	}
	if created.Engine != "sing-box" {
		t.Fatalf("created = %+v", created)
	}
	wantTarget := state.ActiveProfile{Name: "future", Engine: state.EngineSingBox}
	storedContent, err := service.Store.Get(wantTarget)
	if err != nil {
		t.Fatal(err)
	}
	wantRevision := contentRevision(storedContent)
	activated, err := service.ActivateProfile(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if switched != wantTarget || switchedRevision != wantRevision {
		t.Fatalf("switch target = %+v at %q, want %+v at %q", switched, switchedRevision, wantTarget, wantRevision)
	}
	if !activated.Active {
		t.Fatalf("activated = %+v", activated)
	}
	revision, exists, err := service.Revisions.Snapshot(wantTarget)
	if err != nil {
		t.Fatal(err)
	}
	if !exists || revision.AppliedRevision != wantRevision || revision.PendingRevision != "" {
		t.Fatalf("revision snapshot = %+v, exists = %t", revision, exists)
	}
}

func TestProfilesServiceRollsBackActiveSingBoxWhenPendingRevisionCannotBeRecorded(t *testing.T) {
	service, err := NewProfilesService(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	original := "{\"log\":{\"level\":\"info\"}}\n"
	created, err := service.CreateProfile(context.Background(), web.ProfileDraft{
		Name: "sing", Engine: state.EngineSingBox, Content: original,
	})
	if err != nil {
		t.Fatal(err)
	}
	profile := state.ActiveProfile{Name: "sing", Engine: state.EngineSingBox}
	if err := service.Store.Activate(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	if err := service.Revisions.MarkAppliedRevision(context.Background(), profile, contentRevision([]byte(original))); err != nil {
		t.Fatal(err)
	}
	pendingErr := errors.New("pending registry unavailable")
	service.OnPending = func(context.Context, state.ActiveProfile, string) error { return pendingErr }
	replacement := "{\"log\":{\"level\":\"debug\"}}"
	if _, err := service.UpdateProfile(context.Background(), created.ID, web.ProfilePatch{Content: &replacement}); !errors.Is(err, pendingErr) {
		t.Fatalf("UpdateProfile() error = %v", err)
	}
	content, err := service.Store.Get(profile)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != original {
		t.Fatalf("profile content = %q, want rollback to %q", content, original)
	}
	mirror, err := os.ReadFile(service.Store.Layout.SingBoxConfig)
	if err != nil {
		t.Fatal(err)
	}
	if string(mirror) != original {
		t.Fatalf("active mirror = %q, want rollback to %q", mirror, original)
	}
	revision, pending, err := service.Revisions.Pending(profile)
	if err != nil {
		t.Fatal(err)
	}
	if pending || revision.AppliedRevision != contentRevision([]byte(original)) {
		t.Fatalf("revision state = %+v pending=%t", revision, pending)
	}
}

func TestProfilesServiceRefreshRollsBackActiveSingBoxWhenPendingRevisionCannotBeRecorded(t *testing.T) {
	var version atomic.Int32
	version.Store(1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("ETag", fmt.Sprintf(`"v%d"`, version.Load()))
		level := "info"
		if version.Load() == 2 {
			level = "debug"
		}
		_, _ = fmt.Fprintf(response, `{"log":{"level":%q}}`, level)
	}))
	defer server.Close()

	service, err := NewProfilesService(t.TempDir(), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateProfile(context.Background(), web.ProfileDraft{
		Name: "sing", Engine: state.EngineSingBox, SourceURL: server.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	profile := state.ActiveProfile{Name: "sing", Engine: state.EngineSingBox}
	if err := service.Store.Activate(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	original, err := service.Store.Get(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Revisions.MarkAppliedRevision(context.Background(), profile, contentRevision(original)); err != nil {
		t.Fatal(err)
	}
	originalSource, err := service.loadSource(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	pendingErr := errors.New("pending registry unavailable")
	service.OnPending = func(context.Context, state.ActiveProfile, string) error { return pendingErr }

	version.Store(2)
	if _, err := service.RefreshProfile(context.Background(), created.ID); !errors.Is(err, pendingErr) {
		t.Fatalf("RefreshProfile() error = %v", err)
	}
	content, err := service.Store.Get(profile)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != string(original) {
		t.Fatalf("profile content = %q, want rollback to %q", content, original)
	}
	mirror, err := os.ReadFile(service.Store.Layout.SingBoxConfig)
	if err != nil {
		t.Fatal(err)
	}
	if string(mirror) != string(original) {
		t.Fatalf("active mirror = %q, want rollback to %q", mirror, original)
	}
	refreshedSource, err := service.loadSource(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if refreshedSource.ETag != originalSource.ETag || refreshedSource.Fingerprint != originalSource.Fingerprint {
		t.Fatalf("source metadata = %+v, want rollback to %+v", refreshedSource, originalSource)
	}
	revision, pending, err := service.Revisions.Pending(profile)
	if err != nil {
		t.Fatal(err)
	}
	if pending || revision.AppliedRevision != contentRevision(original) {
		t.Fatalf("revision state = %+v pending=%t", revision, pending)
	}
}

func TestProfilesServiceRenameUsesAtomicCreateDeleteContract(t *testing.T) {
	service, err := NewProfilesService(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateProfile(context.Background(), web.ProfileDraft{Name: "old", Content: "external-controller: 127.0.0.1:9090\n"})
	if err != nil {
		t.Fatal(err)
	}
	name := "new"
	updated, err := service.UpdateProfile(context.Background(), created.ID, web.ProfilePatch{Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != "mihomo:new" {
		t.Fatalf("updated = %+v", updated)
	}
	if _, err := service.Profile(context.Background(), created.ID); !errors.Is(err, web.ErrNotFound) {
		t.Fatalf("old profile = %v", err)
	}
}

func TestProfilesServiceUpdateActiveContentPublishesAndRefreshesRuntime(t *testing.T) {
	service, err := NewProfilesService(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateProfile(context.Background(), web.ProfileDraft{
		Name: "active", Content: "mode: rule\nlog-level: info\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ActivateProfile(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}

	var refreshes atomic.Int32
	service.OnActivated = func(context.Context) error {
		refreshes.Add(1)
		return nil
	}
	content := "mode: rule\nlog-level: debug\n"
	updated, err := service.UpdateProfile(context.Background(), created.ID, web.ProfilePatch{Content: &content})
	if err != nil {
		t.Fatal(err)
	}
	if !updated.Active {
		t.Fatalf("updated profile is not active: %+v", updated)
	}
	if refreshes.Load() != 1 {
		t.Fatalf("runtime refreshes = %d, want 1", refreshes.Load())
	}
	activeProfile, err := service.Store.Current()
	if err != nil {
		t.Fatal(err)
	}
	stored, err := service.Store.Get(activeProfile)
	if err != nil {
		t.Fatal(err)
	}
	mirror, err := os.ReadFile(service.Store.Layout.MihomoConfig)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != content || string(mirror) != content {
		t.Fatalf("profile=%q mirror=%q, want %q", stored, mirror, content)
	}
}

func TestProfilesServiceUpdateInactiveContentDoesNotTouchActiveRuntime(t *testing.T) {
	service, err := NewProfilesService(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	activeContent := "mode: rule\nlog-level: info\n"
	active, err := service.CreateProfile(context.Background(), web.ProfileDraft{Name: "active", Content: activeContent})
	if err != nil {
		t.Fatal(err)
	}
	standby, err := service.CreateProfile(context.Background(), web.ProfileDraft{Name: "standby", Content: "mode: rule\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ActivateProfile(context.Background(), active.ID); err != nil {
		t.Fatal(err)
	}

	var refreshes atomic.Int32
	service.OnActivated = func(context.Context) error {
		refreshes.Add(1)
		return nil
	}
	standbyContent := "mode: rule\nlog-level: debug\n"
	if _, err := service.UpdateProfile(context.Background(), standby.ID, web.ProfilePatch{Content: &standbyContent}); err != nil {
		t.Fatal(err)
	}
	if refreshes.Load() != 0 {
		t.Fatalf("inactive update refreshed runtime %d times", refreshes.Load())
	}
	mirror, err := os.ReadFile(service.Store.Layout.MihomoConfig)
	if err != nil {
		t.Fatal(err)
	}
	if string(mirror) != activeContent {
		t.Fatalf("active mirror = %q, want %q", mirror, activeContent)
	}
}

func TestProfilesServiceUpdateActiveContentRollsBackWhenPublishFails(t *testing.T) {
	service, err := NewProfilesService(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	oldContent := "mode: rule\nlog-level: info\n"
	created, err := service.CreateProfile(context.Background(), web.ProfileDraft{Name: "active", Content: oldContent})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ActivateProfile(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
	activeProfile, err := service.Store.Current()
	if err != nil {
		t.Fatal(err)
	}

	service.ValidateMihomo = func(context.Context, []byte) error {
		if err := os.Remove(service.Store.Layout.ActiveProfile); err != nil {
			return err
		}
		return os.Mkdir(service.Store.Layout.ActiveProfile, 0o700)
	}
	var refreshes atomic.Int32
	service.OnActivated = func(context.Context) error {
		refreshes.Add(1)
		return nil
	}
	newContent := "mode: rule\nlog-level: debug\n"
	if _, err := service.UpdateProfile(context.Background(), created.ID, web.ProfilePatch{Content: &newContent}); err == nil {
		t.Fatal("active profile update succeeded with an unwritable active-profile marker")
	}
	if refreshes.Load() != 0 {
		t.Fatalf("failed publish refreshed runtime %d times", refreshes.Load())
	}
	stored, err := service.Store.Get(activeProfile)
	if err != nil {
		t.Fatal(err)
	}
	mirror, err := os.ReadFile(service.Store.Layout.MihomoConfig)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != oldContent || string(mirror) != oldContent {
		t.Fatalf("profile=%q mirror=%q after rollback, want %q", stored, mirror, oldContent)
	}
}
