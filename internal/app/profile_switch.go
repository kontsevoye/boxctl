package app

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

const profileTransitionPath = ".boxctl/profile-transition.v1.json"

const (
	maxProfileTransitionMirrorSize = 32 << 20
	profileTransitionRecoveryTime  = 15 * time.Second
)

type profileMirrorSnapshot struct {
	Captured bool   `json:"captured"`
	Existed  bool   `json:"existed"`
	Revision string `json:"revision,omitempty"`
	Content  []byte `json:"content,omitempty"`
}

type profileTransition struct {
	Version                        int                   `json:"version"`
	Old                            *state.ActiveProfile  `json:"old,omitempty"`
	New                            state.ActiveProfile   `json:"new"`
	OldRevision                    string                `json:"oldRevision,omitempty"`
	NewRevision                    string                `json:"newRevision"`
	PreviousMirror                 profileMirrorSnapshot `json:"previousMirror"`
	PreviousTargetRevisionCaptured bool                  `json:"previousTargetRevisionCaptured,omitempty"`
	PreviousTargetRevisionExisted  bool                  `json:"previousTargetRevisionExisted,omitempty"`
	PreviousTargetRevision         profileRevision       `json:"previousTargetRevision,omitempty"`
	WasRunning                     bool                  `json:"wasRunning"`
	Phase                          string                `json:"phase"`
	UpdatedAt                      time.Time             `json:"updatedAt"`
}

type profileRevisionApplier interface {
	MarkAppliedRevision(context.Context, state.ActiveProfile, string) error
}

type profileRevisionTransaction interface {
	profileRevisionApplier
	Snapshot(state.ActiveProfile) (profileRevision, bool, error)
	Restore(context.Context, state.ActiveProfile, profileRevision, bool) error
}

type ProfileSwitcher struct {
	State     state.Store
	Profiles  state.ProfileStore
	Preparer  *EnginePreparer
	Lifecycle *Lifecycle
	Revisions profileRevisionApplier
	Now       func() time.Time
}

func (switcher *ProfileSwitcher) Switch(ctx context.Context, target state.ActiveProfile, confirmed bool) error {
	if switcher == nil || switcher.Preparer == nil || switcher.Lifecycle == nil {
		return errors.New("profile switcher is not initialized")
	}
	var old *state.ActiveProfile
	current, currentErr := switcher.Profiles.Current()
	if currentErr == nil {
		old = &current
		if current == target {
			return switcher.finalizeCommittedState(ctx, target)
		}
	} else if !errors.Is(currentErr, fs.ErrNotExist) {
		return currentErr
	}
	lifecycleSnapshot := switcher.Lifecycle.Snapshot()
	wasRunning := lifecycleSnapshot.State == LifecycleRunning
	if wasRunning && !confirmed {
		return errors.Join(web.ErrConflict, &web.PublicError{
			Status: http.StatusConflict, Code: "restart_confirmation_required",
			Message: "Activating another profile will restart the running core; explicit confirmation is required",
		})
	}
	prepared, err := switcher.Preparer.PrepareProfile(ctx, target)
	if err != nil {
		return fmt.Errorf("preflight target profile: %w", err)
	}
	if !validProfileRevision(prepared.SourceRevision) {
		engine.CleanupPreparedRuntime(prepared)
		return errors.New("preflight target profile did not report a valid source revision")
	}
	previousMirror, err := switcher.captureTargetMirror(target)
	if err != nil {
		engine.CleanupPreparedRuntime(prepared)
		return fmt.Errorf("capture active config mirror before profile switch: %w", err)
	}
	transition := profileTransition{
		Version: 1, Old: old, New: target, WasRunning: wasRunning,
		NewRevision: prepared.SourceRevision, PreviousMirror: previousMirror,
		Phase: "prepared", UpdatedAt: switcher.now().UTC(),
	}
	if revisions, ok := switcher.Revisions.(profileRevisionTransaction); ok {
		previous, existed, snapshotErr := revisions.Snapshot(target)
		if snapshotErr != nil {
			engine.CleanupPreparedRuntime(prepared)
			return fmt.Errorf("capture target revision before profile switch: %w", snapshotErr)
		}
		transition.PreviousTargetRevisionCaptured = true
		transition.PreviousTargetRevisionExisted = existed
		transition.PreviousTargetRevision = previous
	}
	if old != nil {
		if wasRunning && preparedMatchesProfile(switcher.Profiles.Layout, lifecycleSnapshot.Prepared, *old) && validProfileRevision(lifecycleSnapshot.Prepared.SourceRevision) {
			transition.OldRevision = lifecycleSnapshot.Prepared.SourceRevision
		} else {
			content, readErr := switcher.Profiles.Get(*old)
			if readErr != nil {
				engine.CleanupPreparedRuntime(prepared)
				return fmt.Errorf("read previous profile revision: %w", readErr)
			}
			transition.OldRevision = contentRevision(content)
		}
	}
	if err := switcher.save(transition); err != nil {
		engine.CleanupPreparedRuntime(prepared)
		return err
	}
	commit := func() error {
		content, readErr := switcher.Profiles.Get(target)
		if readErr != nil {
			return fmt.Errorf("recheck target profile before activation: %w", readErr)
		}
		if contentRevision(content) != transition.NewRevision {
			return errors.Join(web.ErrConflict, &web.PublicError{
				Status: http.StatusConflict, Code: "profile_changed_during_switch",
				Message: "The target profile changed after preflight; retry the switch",
			})
		}
		if err := switcher.Profiles.Activate(ctx, target); err != nil {
			return errors.Join(err, switcher.restoreTransition(transition))
		}
		if switcher.Revisions != nil {
			if err := switcher.Revisions.MarkAppliedRevision(ctx, target, transition.NewRevision); err != nil {
				return errors.Join(err, switcher.restoreTransition(transition))
			}
		}
		transition.Phase = "committed"
		transition.UpdatedAt = switcher.now().UTC()
		if err := switcher.save(transition); err != nil {
			return errors.Join(err, switcher.restoreTransition(transition))
		}
		return nil
	}
	_, switchErr := switcher.Lifecycle.SwitchPrepared(ctx, prepared, commit)
	if switchErr != nil {
		return switchErr
	}
	if err := switcher.Preparer.PublishProfileState(ctx, target, transition.NewRevision); err != nil {
		// Selection and runtime are already committed. Keep the committed journal
		// so startup recovery (or a retry after the persistence fault is fixed)
		// still identifies the new profile as authoritative.
		return fmt.Errorf("profile selection committed but shared state publication failed: %w", err)
	}
	return switcher.remove()
}

func (switcher *ProfileSwitcher) finalizeCommittedState(ctx context.Context, target state.ActiveProfile) error {
	transition, err := switcher.load()
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if transition.Phase != "committed" || transition.New != target {
		return nil
	}
	if err := switcher.Preparer.PublishProfileState(ctx, target, transition.NewRevision); err != nil {
		return fmt.Errorf("publish committed profile shared state: %w", err)
	}
	return switcher.remove()
}

// RecoverSelection resolves the durable metadata side of an interrupted
// switch. The journal intentionally remains until startup has inspected and,
// if necessary, stopped an adopted process from the opposite side.
func (switcher *ProfileSwitcher) RecoverSelection() error {
	transition, err := switcher.load()
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var restoreErr error
	if transition.Phase == "committed" {
		recoveryContext, cancelRecovery := switcher.recoveryContext()
		restoreErr = switcher.Profiles.Activate(recoveryContext, transition.New)
		cancelRecovery()
	} else {
		restoreErr = switcher.restoreTransition(transition)
	}
	if restoreErr != nil {
		return restoreErr
	}
	return nil
}

func (switcher *ProfileSwitcher) RecoveryProfile() (*state.ActiveProfile, string, bool, error) {
	transition, err := switcher.load()
	if errors.Is(err, fs.ErrNotExist) {
		return nil, "", false, nil
	}
	if err != nil {
		return nil, "", false, err
	}
	if transition.Phase == "committed" {
		target := transition.New
		return &target, transition.NewRevision, true, nil
	}
	return transition.Old, transition.OldRevision, true, nil
}

// CompleteRecovery publishes any companion state which may have been skipped
// by a crash after the durable profile commit, then removes the transition
// journal. Prepared transitions restore the old selection and have no target
// state to publish.
func (switcher *ProfileSwitcher) CompleteRecovery(ctx context.Context) error {
	transition, err := switcher.load()
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if transition.Phase == "committed" {
		if err := switcher.Preparer.PublishProfileState(ctx, transition.New, transition.NewRevision); err != nil {
			return fmt.Errorf("publish recovered profile shared state: %w", err)
		}
	}
	return switcher.remove()
}

func (switcher *ProfileSwitcher) CurrentPhase() string {
	transition, err := switcher.load()
	if err != nil {
		return ""
	}
	return transition.Phase
}

func (switcher *ProfileSwitcher) restoreTransition(transition profileTransition) error {
	ctx, cancel := switcher.recoveryContext()
	defer cancel()
	revisionErr := switcher.restoreTargetRevision(ctx, transition)
	if transition.Old == nil {
		mirrorErr := switcher.restoreTargetMirror(transition.New, transition.PreviousMirror)
		metadataPath, pathErr := switcher.relativeStatePath(switcher.Profiles.Layout.ActiveProfile)
		if pathErr != nil {
			return errors.Join(mirrorErr, pathErr, revisionErr)
		}
		return errors.Join(mirrorErr, switcher.State.RemoveRegular(metadataPath), revisionErr)
	}
	selectionErr := switcher.Profiles.Activate(ctx, *transition.Old)
	return errors.Join(selectionErr, switcher.restoreTargetMirror(transition.New, transition.PreviousMirror), revisionErr)
}

func (switcher *ProfileSwitcher) restoreTargetRevision(ctx context.Context, transition profileTransition) error {
	if !transition.PreviousTargetRevisionCaptured {
		return nil
	}
	revisions, ok := switcher.Revisions.(profileRevisionTransaction)
	if !ok {
		return errors.New("profile revision transaction is unavailable during switch recovery")
	}
	return revisions.Restore(ctx, transition.New, transition.PreviousTargetRevision, transition.PreviousTargetRevisionExisted)
}

func (switcher *ProfileSwitcher) captureTargetMirror(target state.ActiveProfile) (profileMirrorSnapshot, error) {
	relative, err := switcher.targetMirrorRelativePath(target)
	if err != nil {
		return profileMirrorSnapshot{}, err
	}
	content, err := switcher.State.Read(relative)
	if errors.Is(err, fs.ErrNotExist) {
		return profileMirrorSnapshot{Captured: true}, nil
	}
	if err != nil {
		return profileMirrorSnapshot{}, err
	}
	if len(content) > maxProfileTransitionMirrorSize {
		return profileMirrorSnapshot{}, errors.New("active config mirror exceeds transition snapshot limit")
	}
	return profileMirrorSnapshot{
		Captured: true, Existed: true, Revision: contentRevision(content), Content: append([]byte(nil), content...),
	}, nil
}

func (switcher *ProfileSwitcher) restoreTargetMirror(target state.ActiveProfile, snapshot profileMirrorSnapshot) error {
	if err := validateProfileMirrorSnapshot(snapshot); err != nil {
		return err
	}
	relative, err := switcher.targetMirrorRelativePath(target)
	if err != nil {
		return err
	}
	if !snapshot.Existed {
		return switcher.State.RemoveRegular(relative)
	}
	return switcher.State.Write(relative, snapshot.Content, 0o600)
}

func (switcher *ProfileSwitcher) targetMirrorRelativePath(profile state.ActiveProfile) (string, error) {
	target := switcher.Profiles.Layout.MihomoConfig
	if profile.Engine == state.EngineSingBox {
		target = switcher.Profiles.Layout.SingBoxConfig
	} else if profile.Engine != "" && profile.Engine != state.EngineMihomo {
		return "", fmt.Errorf("unsupported profile engine %q", profile.Engine)
	}
	return switcher.relativeStatePath(target)
}

func (switcher *ProfileSwitcher) relativeStatePath(path string) (string, error) {
	relative, err := filepath.Rel(switcher.State.Root, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("profile transition path escapes the state root")
	}
	return filepath.ToSlash(relative), nil
}

func (switcher *ProfileSwitcher) save(transition profileTransition) error {
	return switcher.State.WriteJSON(profileTransitionPath, transition, 0o600)
}

func (switcher *ProfileSwitcher) load() (profileTransition, error) {
	content, err := switcher.State.Read(profileTransitionPath)
	if err != nil {
		return profileTransition{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var transition profileTransition
	if err := decoder.Decode(&transition); err != nil {
		return profileTransition{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return profileTransition{}, errors.New("profile transition journal contains trailing data")
	}
	if transition.Version != 1 || transition.New.Name == "" || !validProfileRevision(transition.NewRevision) ||
		(transition.OldRevision != "" && !validProfileRevision(transition.OldRevision)) ||
		(transition.Phase != "prepared" && transition.Phase != "committed") || validateProfileMirrorSnapshot(transition.PreviousMirror) != nil ||
		validateTransitionRevisionSnapshot(transition) != nil {
		return profileTransition{}, errors.New("profile transition journal is invalid")
	}
	return transition, nil
}

func validateTransitionRevisionSnapshot(transition profileTransition) error {
	value := transition.PreviousTargetRevision
	if !transition.PreviousTargetRevisionCaptured {
		if transition.PreviousTargetRevisionExisted || value.AppliedRevision != "" || value.PendingRevision != "" || !value.PendingAt.IsZero() {
			return errors.New("uncaptured profile revision snapshot contains data")
		}
		return nil
	}
	if !transition.PreviousTargetRevisionExisted {
		if value.AppliedRevision != "" || value.PendingRevision != "" || !value.PendingAt.IsZero() {
			return errors.New("absent profile revision snapshot contains data")
		}
		return nil
	}
	if value.AppliedRevision != "" && !validProfileRevision(value.AppliedRevision) {
		return errors.New("profile revision snapshot has an invalid applied revision")
	}
	if value.PendingRevision != "" && !validProfileRevision(value.PendingRevision) {
		return errors.New("profile revision snapshot has an invalid pending revision")
	}
	return nil
}

func (switcher *ProfileSwitcher) remove() error {
	return switcher.State.RemoveRegular(profileTransitionPath)
}

func validateProfileMirrorSnapshot(snapshot profileMirrorSnapshot) error {
	if !snapshot.Captured {
		return errors.New("profile transition mirror snapshot is missing")
	}
	if !snapshot.Existed {
		if snapshot.Revision != "" || len(snapshot.Content) != 0 {
			return errors.New("absent profile transition mirror contains data")
		}
		return nil
	}
	if len(snapshot.Content) > maxProfileTransitionMirrorSize || !validProfileRevision(snapshot.Revision) || contentRevision(snapshot.Content) != snapshot.Revision {
		return errors.New("profile transition mirror snapshot is invalid")
	}
	return nil
}

func validProfileRevision(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func (switcher *ProfileSwitcher) recoveryContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), profileTransitionRecoveryTime)
}

func (switcher *ProfileSwitcher) now() time.Time {
	if switcher.Now != nil {
		return switcher.Now()
	}
	return time.Now()
}
