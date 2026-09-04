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
	"path/filepath"
	"strings"
	"sync"
	"time"

	configpkg "github.com/kontsevoye/boxctl/internal/config"
	"github.com/kontsevoye/boxctl/internal/remote"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

type profileSource struct {
	URL                 string            `json:"url"`
	ETag                string            `json:"etag,omitempty"`
	LastModified        string            `json:"lastModified,omitempty"`
	Fingerprint         string            `json:"fingerprint,omitempty"`
	UpdateIntervalHours int               `json:"updateIntervalHours,omitempty"`
	IntervalExplicit    bool              `json:"intervalExplicit,omitempty"`
	Stopped             bool              `json:"stopped,omitempty"`
	LastCheckedAt       time.Time         `json:"lastCheckedAt,omitempty"`
	LastUpdatedAt       time.Time         `json:"lastUpdatedAt,omitempty"`
	LastError           string            `json:"lastError,omitempty"`
	Headers             map[string]string `json:"headers,omitempty"`
}

const defaultProfileUpdateIntervalHours = 24

// ProfilesService adapts native profile files to the secret-free web API.
// Source URLs live in private state and are never copied into Profile DTOs.
type ProfilesService struct {
	Store           state.ProfileStore
	State           state.Store
	Revisions       *ProfileRevisionStore
	Fetcher         remote.Fetcher
	ValidateMihomo  func(context.Context, []byte) error
	ValidateSingBox func(context.Context, []byte) error
	OnActivated     func(context.Context) error
	SwitchProfile   func(context.Context, state.ActiveProfile, bool) error
	OnPending       func(context.Context, state.ActiveProfile, string) error
	mutationMu      sync.Mutex
}

func NewProfilesService(root string, client *http.Client) (*ProfilesService, error) {
	profiles, err := state.NewProfileStore(root)
	if err != nil {
		return nil, err
	}
	store, err := state.NewStore(root)
	if err != nil {
		return nil, err
	}
	revisions, err := NewProfileRevisionStore(root)
	if err != nil {
		return nil, err
	}
	service := &ProfilesService{Store: profiles, State: store, Revisions: revisions}
	service.OnPending = revisions.MarkPending
	service.Fetcher = remote.Fetcher{Client: client, Validator: remote.ValidatorFunc(service.validateRemoteMihomo)}
	return service, nil
}

func (service *ProfilesService) ProfilesList(ctx context.Context) ([]web.Profile, error) {
	return service.ProfilesAPI(ctx)
}

// Profiles implements web.ProfileService.
func (service *ProfilesService) ProfilesAPI(_ context.Context) ([]web.Profile, error) {
	entries, err := service.Store.List()
	if err != nil {
		return nil, err
	}
	active, activeErr := service.Store.Current()
	result := make([]web.Profile, 0, len(entries))
	for _, entry := range entries {
		profile, err := service.webProfile(entry, active, activeErr)
		if err != nil {
			return nil, err
		}
		result = append(result, profile)
	}
	return result, nil
}

// Profiles has the exact interface name required by web.ProfileService.
func (service *ProfilesService) Profiles(ctx context.Context) ([]web.Profile, error) {
	return service.ProfilesAPI(ctx)
}

func (service *ProfilesService) Profile(_ context.Context, id string) (web.Profile, error) {
	entry, err := service.entry(id)
	if err != nil {
		return web.Profile{}, err
	}
	active, activeErr := service.Store.Current()
	return service.webProfile(entry, active, activeErr)
}

func (service *ProfilesService) CreateProfile(ctx context.Context, draft web.ProfileDraft) (web.Profile, error) {
	service.mutationMu.Lock()
	defer service.mutationMu.Unlock()

	engineName := normalizedEngine(draft.Engine)
	profile := state.ActiveProfile{Name: strings.TrimSpace(draft.Name), Engine: engineName}
	content, source, err := service.resolveDraft(ctx, engineName, draft.Content, draft.SourceURL, draft.UpdateIntervalHours)
	if err != nil {
		return web.Profile{}, err
	}
	if err := service.validateContent(ctx, engineName, content); err != nil {
		return web.Profile{}, publicInvalidProfile(err)
	}
	if err := service.Store.Create(ctx, profile, content); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return web.Profile{}, &web.PublicError{Status: http.StatusConflict, Code: "profile_exists", Message: "Profile already exists"}
		}
		return web.Profile{}, err
	}
	if source != nil {
		if err := service.saveSource(profileID(profile), *source); err != nil {
			_ = service.Store.Delete(ctx, profile)
			return web.Profile{}, err
		}
	}
	return service.Profile(ctx, profileID(profile))
}

func (service *ProfilesService) UpdateProfile(ctx context.Context, id string, patch web.ProfilePatch) (web.Profile, error) {
	service.mutationMu.Lock()
	defer service.mutationMu.Unlock()

	entry, err := service.entry(id)
	if err != nil {
		return web.Profile{}, err
	}
	oldProfile := entry.ActiveProfile
	newProfile := oldProfile
	if patch.Name != nil {
		newProfile.Name = strings.TrimSpace(*patch.Name)
	}
	if patch.Engine != nil {
		requestedEngine := normalizedEngine(*patch.Engine)
		if requestedEngine != oldProfile.Engine {
			return web.Profile{}, &web.PublicError{Status: http.StatusConflict, Code: "profile_engine_immutable", Message: "Profile engine cannot be changed; create a new profile instead"}
		}
	}
	active, activeErr := service.Store.Current()
	if activeErr != nil && !errors.Is(activeErr, fs.ErrNotExist) {
		return web.Profile{}, activeErr
	}
	isActive := activeErr == nil && active == oldProfile
	if newProfile != oldProfile && isActive {
		return web.Profile{}, &web.PublicError{Status: http.StatusConflict, Code: "active_profile_rename", Message: "Stop and switch away from the active profile before renaming it"}
	}
	oldContent, err := service.Store.Get(oldProfile)
	if err != nil {
		return web.Profile{}, err
	}
	content := oldContent
	oldSource, sourceErr := service.loadSource(id)
	if sourceErr != nil && !errors.Is(sourceErr, fs.ErrNotExist) {
		return web.Profile{}, sourceErr
	}
	oldSourceSnapshot := oldSource
	var source *profileSource
	if sourceErr == nil {
		source = &oldSource
	}
	if patch.Content != nil || patch.SourceURL != nil {
		contentValue := ""
		urlValue := ""
		if patch.Content != nil {
			contentValue = *patch.Content
		}
		if patch.SourceURL != nil {
			urlValue = *patch.SourceURL
		} else if source != nil && patch.Content == nil {
			urlValue = source.URL
		}
		content, source, err = service.resolveDraft(ctx, newProfile.Engine, contentValue, urlValue, patch.UpdateIntervalHours)
		if err != nil {
			return web.Profile{}, err
		}
		if source != nil && sourceErr == nil {
			if patch.UpdateIntervalHours == nil && oldSource.IntervalExplicit && (patch.UpdateIntervalAuto == nil || !*patch.UpdateIntervalAuto) {
				source.UpdateIntervalHours = oldSource.UpdateIntervalHours
				source.IntervalExplicit = true
			}
			source.Stopped = oldSource.Stopped
		}
	}
	if patch.UpdateIntervalHours != nil && source == nil {
		return web.Profile{}, &web.PublicError{Status: http.StatusConflict, Code: "local_profile", Message: "Local profiles do not have an update interval"}
	}
	if patch.UpdateIntervalHours != nil {
		if err := validateProfileInterval(*patch.UpdateIntervalHours); err != nil {
			return web.Profile{}, err
		}
		source.UpdateIntervalHours = *patch.UpdateIntervalHours
		source.IntervalExplicit = true
	}
	if patch.UpdateIntervalAuto != nil {
		if source == nil {
			return web.Profile{}, &web.PublicError{Status: http.StatusConflict, Code: "local_profile", Message: "Local profiles do not have an update interval"}
		}
		if *patch.UpdateIntervalAuto && patch.UpdateIntervalHours != nil {
			return web.Profile{}, &web.PublicError{Status: http.StatusBadRequest, Code: "ambiguous_update_interval", Message: "Choose an explicit interval or automatic response-header updates"}
		}
		if *patch.UpdateIntervalAuto {
			source.IntervalExplicit = false
		}
	}
	if patch.SourceEnabled != nil {
		if source == nil {
			return web.Profile{}, &web.PublicError{Status: http.StatusConflict, Code: "local_profile", Message: "Local profiles do not have a remote source"}
		}
		source.Stopped = !*patch.SourceEnabled
	}
	if err := service.validateContent(ctx, newProfile.Engine, content); err != nil {
		return web.Profile{}, publicInvalidProfile(err)
	}
	contentChanged := !bytes.Equal(oldContent, content)
	var revisionBefore profileRevision
	revisionExisted := false
	if isActive && contentChanged && newProfile.Engine == state.EngineSingBox && service.Revisions != nil {
		revisionBefore, revisionExisted, err = service.Revisions.Snapshot(oldProfile)
		if err != nil {
			return web.Profile{}, fmt.Errorf("snapshot profile revision state: %w", err)
		}
	}

	if newProfile == oldProfile {
		if err := service.Store.Update(ctx, oldProfile, content); err != nil {
			return web.Profile{}, err
		}
	} else {
		if err := service.Store.Create(ctx, newProfile, content); err != nil {
			return web.Profile{}, err
		}
		if err := service.Store.Delete(ctx, oldProfile); err != nil {
			_ = service.Store.Delete(ctx, newProfile)
			return web.Profile{}, err
		}
	}
	newID := profileID(newProfile)
	oldSourceExists := sourceErr == nil
	if err := service.persistSource(newID, source); err != nil {
		rollbackErr := service.rollbackProfileUpdate(oldProfile, newProfile, oldContent, id, oldSourceSnapshot, oldSourceExists, false)
		return web.Profile{}, fmt.Errorf("update profile source metadata: %w", errors.Join(err, rollbackErr))
	}
	if newID != id {
		if err := service.deleteSource(id); err != nil {
			rollbackErr := service.rollbackProfileUpdate(oldProfile, newProfile, oldContent, id, oldSourceSnapshot, oldSourceExists, false)
			return web.Profile{}, fmt.Errorf("remove previous profile source metadata: %w", errors.Join(err, rollbackErr))
		}
	}
	if isActive && contentChanged {
		if err := service.Store.Activate(ctx, newProfile); err != nil {
			rollbackErr := service.rollbackProfileUpdate(oldProfile, newProfile, oldContent, id, oldSourceSnapshot, oldSourceExists, true)
			return web.Profile{}, fmt.Errorf("publish active profile update: %w", errors.Join(err, rollbackErr))
		}
		if newProfile.Engine == state.EngineSingBox {
			if service.OnPending != nil {
				if err := service.OnPending(ctx, newProfile, contentRevision(oldContent)); err != nil {
					rollbackErr := service.rollbackProfileUpdate(oldProfile, newProfile, oldContent, id, oldSourceSnapshot, oldSourceExists, true)
					var revisionErr error
					if service.Revisions != nil {
						revisionErr = service.Revisions.Restore(context.WithoutCancel(ctx), oldProfile, revisionBefore, revisionExisted)
					}
					return web.Profile{}, errors.Join(fmt.Errorf("record pending sing-box profile: %w", err), rollbackErr, revisionErr)
				}
			}
		} else if service.OnActivated != nil {
			if err := service.OnActivated(ctx); err != nil {
				return web.Profile{}, fmt.Errorf("profile updated but runtime refresh failed: %w", err)
			}
		}
	}
	return service.Profile(ctx, newID)
}

func (service *ProfilesService) DeleteProfile(ctx context.Context, id string) error {
	service.mutationMu.Lock()
	defer service.mutationMu.Unlock()

	entry, err := service.entry(id)
	if err != nil {
		return err
	}
	if err := service.Store.Delete(ctx, entry.ActiveProfile); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return web.ErrNotFound
		}
		return err
	}
	var revisionErr error
	if service.Revisions != nil {
		revisionErr = service.Revisions.Remove(ctx, entry.ActiveProfile)
	}
	return errors.Join(service.deleteSource(id), revisionErr)
}

func (service *ProfilesService) ActivateProfile(ctx context.Context, id string) (web.Profile, error) {
	return service.ActivateProfileWithRequest(ctx, id, web.ProfileActivationRequest{})
}

func (service *ProfilesService) ActivateProfileWithRequest(ctx context.Context, id string, request web.ProfileActivationRequest) (web.Profile, error) {
	service.mutationMu.Lock()
	defer service.mutationMu.Unlock()

	entry, err := service.entry(id)
	if err != nil {
		return web.Profile{}, err
	}
	content, err := service.Store.Get(entry.ActiveProfile)
	if err != nil {
		return web.Profile{}, err
	}
	if err := service.validateContent(ctx, entry.Engine, content); err != nil {
		return web.Profile{}, publicInvalidProfile(err)
	}
	if active, activeErr := service.Store.Current(); activeErr == nil && active == entry.ActiveProfile {
		return service.Profile(ctx, id)
	} else if activeErr != nil && !errors.Is(activeErr, fs.ErrNotExist) {
		return web.Profile{}, activeErr
	}
	if service.SwitchProfile != nil {
		if err := service.SwitchProfile(ctx, entry.ActiveProfile, request.ConfirmRestart); err != nil {
			return web.Profile{}, err
		}
	} else {
		if err := service.Store.Activate(ctx, entry.ActiveProfile); err != nil {
			return web.Profile{}, err
		}
		if service.OnActivated != nil {
			if err := service.OnActivated(ctx); err != nil {
				return web.Profile{}, fmt.Errorf("profile activated but runtime refresh failed: %w", err)
			}
		}
	}
	return service.Profile(ctx, id)
}

// RefreshProfile conditionally updates one remote profile. Source credentials
// remain private, while ETag and Last-Modified prevent needless downloads.
func (service *ProfilesService) RefreshProfile(ctx context.Context, id string) (web.Profile, error) {
	service.mutationMu.Lock()
	defer service.mutationMu.Unlock()

	entry, err := service.entry(id)
	if err != nil {
		return web.Profile{}, err
	}
	source, err := service.loadSource(id)
	if errors.Is(err, fs.ErrNotExist) {
		return web.Profile{}, &web.PublicError{Status: http.StatusConflict, Code: "local_profile", Message: "This profile has no remote source"}
	}
	if err != nil {
		return web.Profile{}, err
	}
	sourceBefore := source
	now := time.Now().UTC()
	fetcher := service.Fetcher
	fetcher.Validator = remote.ValidatorFunc(func(validateContext context.Context, content []byte) error {
		return service.validateContent(validateContext, entry.Engine, content)
	})
	result, fetchErr := fetcher.Fetch(ctx, remote.Request{
		URL: source.URL, ETag: source.ETag, LastModified: source.LastModified,
		Headers: source.Headers, RemnawaveFallback: entry.Engine == state.EngineMihomo,
	})
	if fetchErr != nil && ctx.Err() != nil {
		return web.Profile{}, ctx.Err()
	}
	source.LastCheckedAt = now
	if fetchErr != nil {
		source.LastError = "Remote profile refresh failed"
		if saveErr := service.saveSource(id, source); saveErr != nil {
			return web.Profile{}, errors.Join(fetchErr, saveErr)
		}
		return web.Profile{}, &web.PublicError{Status: http.StatusBadGateway, Code: "profile_refresh_failed", Message: "The remote profile could not be refreshed"}
	}
	source.LastError = ""
	if result.SuggestedUpdate > 0 && !source.IntervalExplicit {
		source.UpdateIntervalHours = int(result.SuggestedUpdate / time.Hour)
	}
	if result.NotModified {
		if result.ETag != "" {
			source.ETag = result.ETag
		}
		if result.LastModified != "" {
			source.LastModified = result.LastModified
		}
	}
	var (
		oldContent       []byte
		contentChanged   bool
		active           bool
		revisionBefore   profileRevision
		revisionExisted  bool
		revisionSnapshot bool
	)
	if !result.NotModified {
		var readErr error
		oldContent, readErr = service.Store.Get(entry.ActiveProfile)
		if readErr != nil {
			return web.Profile{}, readErr
		}
		contentChanged = !bytes.Equal(oldContent, result.Content)
		if contentChanged {
			current, activeErr := service.Store.Current()
			if activeErr != nil && !errors.Is(activeErr, fs.ErrNotExist) {
				return web.Profile{}, fmt.Errorf("read active profile before refresh: %w", activeErr)
			}
			active = activeErr == nil && current == entry.ActiveProfile
			if active && entry.Engine == state.EngineSingBox && service.Revisions != nil {
				revisionBefore, revisionExisted, err = service.Revisions.Snapshot(entry.ActiveProfile)
				if err != nil {
					return web.Profile{}, fmt.Errorf("snapshot profile revision state: %w", err)
				}
				revisionSnapshot = true
			}
			if err := service.Store.Update(ctx, entry.ActiveProfile, result.Content); err != nil {
				return web.Profile{}, err
			}
			if active {
				if err := service.Store.Activate(ctx, entry.ActiveProfile); err != nil {
					rollbackErr := service.rollbackProfileRefresh(entry.ActiveProfile, oldContent, id, sourceBefore, true, revisionBefore, revisionExisted, revisionSnapshot)
					return web.Profile{}, errors.Join(err, rollbackErr)
				}
				if entry.Engine == state.EngineSingBox {
					if service.OnPending != nil {
						if err := service.OnPending(ctx, entry.ActiveProfile, contentRevision(oldContent)); err != nil {
							rollbackErr := service.rollbackProfileRefresh(entry.ActiveProfile, oldContent, id, sourceBefore, true, revisionBefore, revisionExisted, revisionSnapshot)
							return web.Profile{}, errors.Join(fmt.Errorf("record pending sing-box profile: %w", err), rollbackErr)
						}
					}
				} else if service.OnActivated != nil {
					if err := service.OnActivated(ctx); err != nil {
						return web.Profile{}, fmt.Errorf("profile refreshed but runtime refresh failed: %w", err)
					}
				}
			}
		}
		source.ETag = result.ETag
		source.LastModified = result.LastModified
		source.Fingerprint = result.Fingerprint
		source.LastUpdatedAt = now
	}
	if err := service.saveSource(id, source); err != nil {
		if contentChanged && (!active || entry.Engine == state.EngineSingBox) {
			rollbackErr := service.rollbackProfileRefresh(entry.ActiveProfile, oldContent, id, sourceBefore, active, revisionBefore, revisionExisted, revisionSnapshot)
			return web.Profile{}, errors.Join(err, rollbackErr)
		}
		return web.Profile{}, err
	}
	return service.Profile(ctx, id)
}

func (service *ProfilesService) rollbackProfileRefresh(
	profile state.ActiveProfile,
	oldContent []byte,
	id string,
	oldSource profileSource,
	restoreActive bool,
	revision profileRevision,
	revisionExisted bool,
	restoreRevision bool,
) error {
	rollbackErr := service.rollbackProfileUpdate(profile, profile, oldContent, id, oldSource, true, restoreActive)
	if restoreRevision && service.Revisions != nil {
		revisionErr := service.Revisions.Restore(context.Background(), profile, revision, revisionExisted)
		rollbackErr = errors.Join(rollbackErr, revisionErr)
	}
	return rollbackErr
}

// DetachProfileSource keeps the last validated native profile and permanently
// removes its remote URL and validators.
func (service *ProfilesService) DetachProfileSource(ctx context.Context, id string) (web.Profile, error) {
	service.mutationMu.Lock()
	defer service.mutationMu.Unlock()

	if _, err := service.entry(id); err != nil {
		return web.Profile{}, err
	}
	if _, err := service.loadSource(id); errors.Is(err, fs.ErrNotExist) {
		return web.Profile{}, &web.PublicError{Status: http.StatusConflict, Code: "local_profile", Message: "This profile has no remote source"}
	} else if err != nil {
		return web.Profile{}, err
	}
	if err := service.deleteSource(id); err != nil {
		return web.Profile{}, err
	}
	return service.Profile(ctx, id)
}

// RefreshDueProfiles performs one scheduler pass. A failure is recorded on the
// affected profile and does not prevent other sources from being considered.
func (service *ProfilesService) RefreshDueProfiles(ctx context.Context, now time.Time) error {
	profiles, err := service.Profiles(ctx)
	if err != nil {
		return err
	}
	var failures []error
	for _, profile := range profiles {
		if !profile.HasSource || !profile.SourceEnabled || profile.UpdateIntervalHours == 0 || now.Before(profile.NextUpdateAt) {
			continue
		}
		if _, err := service.RefreshProfile(ctx, profile.ID); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// StartScheduler starts a bounded one-minute due-source scan and returns a
// synchronous stop function for daemon shutdown.
func (service *ProfilesService) StartScheduler(parent context.Context) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		_ = service.RefreshDueProfiles(ctx, time.Now().UTC())
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				_ = service.RefreshDueProfiles(ctx, now.UTC())
			}
		}
	}()
	return func() { cancel(); <-done }
}

// RemoteSourceURLs returns private endpoint inputs for the OpenWrt bypass
// resolver. Callers must never log or serialize the returned URLs.
func (service *ProfilesService) RemoteSourceURLs() ([]string, error) {
	entries, err := service.Store.List()
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		source, err := service.loadSource(profileID(entry.ActiveProfile))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if source.URL != "" {
			result = append(result, source.URL)
		}
	}
	return result, nil
}

func (service *ProfilesService) entry(id string) (state.ProfileEntry, error) {
	profile, err := parseProfileID(id)
	if err != nil {
		return state.ProfileEntry{}, web.ErrNotFound
	}
	entries, err := service.Store.List()
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

func (service *ProfilesService) webProfile(entry state.ProfileEntry, active state.ActiveProfile, activeErr error) (web.Profile, error) {
	content, err := service.Store.Get(entry.ActiveProfile)
	if err != nil {
		return web.Profile{}, err
	}
	digest := sha256.Sum256(content)
	result := web.Profile{
		ID: profileID(entry.ActiveProfile), Name: entry.Name, Engine: entry.Engine,
		SourceKind: "local", Active: activeErr == nil && active == entry.ActiveProfile,
		Fingerprint: hex.EncodeToString(digest[:]),
	}
	if info, err := os.Stat(entry.Path); err == nil {
		result.UpdatedAt = info.ModTime().UTC()
	}
	if service.Revisions != nil {
		if revision, pending, err := service.Revisions.Pending(entry.ActiveProfile); err == nil {
			if revision.AppliedRevision != "" && revision.AppliedRevision != result.Fingerprint {
				pending = true
				if revision.PendingRevision == "" {
					revision.PendingRevision = result.Fingerprint
				}
			}
			result.AppliedRevision = revision.AppliedRevision
			result.PendingRevision = revision.PendingRevision
			result.PendingAt = revision.PendingAt
			result.RestartRequired = result.Active && pending
		} else if err != nil {
			return web.Profile{}, err
		}
	}
	if source, err := service.loadSource(result.ID); err == nil {
		result.SourceKind = "remote"
		result.HasSource = source.URL != ""
		result.SourceEnabled = source.URL != "" && !source.Stopped
		result.UpdateIntervalHours = source.UpdateIntervalHours
		result.UpdateIntervalAuto = !source.IntervalExplicit
		result.LastCheckedAt = source.LastCheckedAt
		result.LastError = source.LastError
		if result.UpdatedAt.IsZero() && !source.LastUpdatedAt.IsZero() {
			result.UpdatedAt = source.LastUpdatedAt
		}
		if source.UpdateIntervalHours > 0 {
			anchor := source.LastCheckedAt
			if anchor.IsZero() {
				anchor = result.UpdatedAt
			}
			if !anchor.IsZero() {
				result.NextUpdateAt = anchor.Add(time.Duration(source.UpdateIntervalHours) * time.Hour)
			}
		}
		if source.Fingerprint != "" {
			result.Fingerprint = source.Fingerprint
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return web.Profile{}, err
	}
	return result, nil
}

func (service *ProfilesService) resolveDraft(ctx context.Context, engineName, content, sourceURL string, requestedInterval *int) ([]byte, *profileSource, error) {
	content = strings.TrimSpace(content)
	sourceURL = strings.TrimSpace(sourceURL)
	if content != "" && sourceURL != "" {
		return nil, nil, &web.PublicError{Status: http.StatusBadRequest, Code: "ambiguous_profile", Message: "Provide either native content or a source URL"}
	}
	if content != "" {
		return []byte(content + "\n"), nil, nil
	}
	if sourceURL == "" {
		return nil, nil, &web.PublicError{Status: http.StatusBadRequest, Code: "profile_source_required", Message: "Native profile content or an HTTPS source URL is required"}
	}
	if requestedInterval != nil {
		if err := validateProfileInterval(*requestedInterval); err != nil {
			return nil, nil, err
		}
	}
	fetcher := service.Fetcher
	fetcher.Validator = remote.ValidatorFunc(func(validateContext context.Context, candidate []byte) error {
		return service.validateContent(validateContext, engineName, candidate)
	})
	result, err := fetcher.Fetch(ctx, remote.Request{URL: sourceURL, RemnawaveFallback: engineName == state.EngineMihomo})
	if err != nil {
		return nil, nil, &web.PublicError{Status: http.StatusBadGateway, Code: "profile_fetch_failed", Message: "The remote native profile could not be downloaded and validated"}
	}
	interval := defaultProfileUpdateIntervalHours
	if result.SuggestedUpdate > 0 {
		interval = int(result.SuggestedUpdate / time.Hour)
	}
	if requestedInterval != nil {
		interval = *requestedInterval
	}
	now := time.Now().UTC()
	return result.Content, &profileSource{
		URL: sourceURL, ETag: result.ETag, LastModified: result.LastModified,
		Fingerprint: result.Fingerprint, UpdateIntervalHours: interval,
		IntervalExplicit: requestedInterval != nil, LastCheckedAt: now, LastUpdatedAt: now,
	}, nil
}

func validateProfileInterval(hours int) error {
	if hours < 1 || hours > 168 {
		return &web.PublicError{Status: http.StatusBadRequest, Code: "invalid_update_interval", Message: "Update interval must be between 1 and 168 hours"}
	}
	return nil
}

func (service *ProfilesService) validateRemoteMihomo(ctx context.Context, content []byte) error {
	return service.validateContent(ctx, state.EngineMihomo, content)
}

func (service *ProfilesService) validateContent(ctx context.Context, engineName string, content []byte) error {
	if len(bytes.TrimSpace(content)) == 0 {
		return errors.New("profile is empty")
	}
	switch engineName {
	case state.EngineMihomo:
		if _, err := configpkg.InspectMihomo(content); err != nil {
			return err
		}
		if service.ValidateMihomo != nil {
			return service.ValidateMihomo(ctx, content)
		}
		return nil
	case state.EngineSingBox:
		if service.ValidateSingBox != nil {
			return service.ValidateSingBox(ctx, content)
		}
		decoder := json.NewDecoder(bytes.NewReader(content))
		var document map[string]any
		if err := decoder.Decode(&document); err != nil || document == nil {
			return errors.New("sing-box profile is not a JSON object")
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return errors.New("sing-box profile contains trailing JSON")
		}
		return nil
	default:
		return errors.New("unsupported profile engine")
	}
}

func (service *ProfilesService) saveSource(id string, source profileSource) error {
	return service.State.WriteJSON(profileSourcePath(id), source, 0o600)
}

func (service *ProfilesService) persistSource(id string, source *profileSource) error {
	if source != nil {
		return service.saveSource(id, *source)
	}
	return service.deleteSource(id)
}

func (service *ProfilesService) rollbackProfileUpdate(
	oldProfile, newProfile state.ActiveProfile,
	oldContent []byte,
	oldID string,
	oldSource profileSource,
	oldSourceExists bool,
	restoreActive bool,
) error {
	rollbackCtx := context.Background()
	var profileErr error
	if oldProfile == newProfile {
		profileErr = service.Store.Update(rollbackCtx, oldProfile, oldContent)
	} else {
		profileErr = service.Store.Create(rollbackCtx, oldProfile, oldContent)
		if profileErr == nil {
			profileErr = service.Store.Delete(rollbackCtx, newProfile)
		}
	}
	if profileErr != nil {
		profileErr = fmt.Errorf("restore previous profile: %w", profileErr)
	}

	var sourceErr error
	if oldSourceExists {
		sourceErr = service.saveSource(oldID, oldSource)
	} else {
		sourceErr = service.deleteSource(oldID)
	}
	if sourceErr == nil && oldProfile != newProfile {
		sourceErr = service.deleteSource(profileID(newProfile))
	}
	if sourceErr != nil {
		sourceErr = fmt.Errorf("restore previous profile source metadata: %w", sourceErr)
	}

	var activeErr error
	if restoreActive && profileErr == nil {
		activeErr = service.Store.Activate(rollbackCtx, oldProfile)
		if activeErr != nil {
			activeErr = fmt.Errorf("restore active profile mirror: %w", activeErr)
		}
	}
	return errors.Join(profileErr, sourceErr, activeErr)
}

func (service *ProfilesService) loadSource(id string) (profileSource, error) {
	content, err := service.State.Read(profileSourcePath(id))
	if err != nil {
		return profileSource{}, err
	}
	var source profileSource
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&source); err != nil {
		return profileSource{}, err
	}
	if source.URL != "" && source.UpdateIntervalHours == 0 {
		source.UpdateIntervalHours = defaultProfileUpdateIntervalHours
	}
	return source, nil
}

func (service *ProfilesService) deleteSource(id string) error {
	path := filepath.Join(service.State.Root, filepath.FromSlash(profileSourcePath(id)))
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("profile source metadata is not a regular file")
	}
	return os.Remove(path)
}

func profileSourcePath(id string) string {
	digest := sha256.Sum256([]byte(id))
	return filepath.ToSlash(filepath.Join(".boxctl", "profile-sources", hex.EncodeToString(digest[:])+".json"))
}

func normalizedEngine(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return state.EngineMihomo
	}
	return value
}

func profileID(profile state.ActiveProfile) string { return profile.Engine + ":" + profile.Name }

func parseProfileID(id string) (state.ActiveProfile, error) {
	engineName, name, found := strings.Cut(strings.TrimSpace(id), ":")
	if !found {
		engineName, name = state.EngineMihomo, strings.TrimSpace(id)
	}
	profile := state.ActiveProfile{Name: name, Engine: normalizedEngine(engineName)}
	// Marshal performs the state package's strict name/engine validation.
	if _, err := state.MarshalActiveProfile(profile); err != nil {
		return state.ActiveProfile{}, err
	}
	return profile, nil
}

func publicInvalidProfile(_ error) error {
	return &web.PublicError{Status: http.StatusBadRequest, Code: "invalid_profile", Message: "The native profile failed validation"}
}

var _ web.ProfileService = (*ProfilesService)(nil)
