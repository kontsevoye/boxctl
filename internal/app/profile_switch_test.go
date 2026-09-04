package app

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"testing"
	"time"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

type profileSwitchPrepareFunc func(context.Context, state.ActiveProfile) (engine.PreparedCore, error)

func (prepare profileSwitchPrepareFunc) PrepareProfile(ctx context.Context, profile state.ActiveProfile) (engine.PreparedCore, error) {
	return prepare(ctx, profile)
}

type profileSwitchPublishingPreparer struct {
	prepare   profileSwitchPrepareFunc
	published []state.ActiveProfile
	revisions []string
	err       error
}

func (preparer *profileSwitchPublishingPreparer) PrepareProfile(ctx context.Context, profile state.ActiveProfile) (engine.PreparedCore, error) {
	return preparer.prepare(ctx, profile)
}

func (preparer *profileSwitchPublishingPreparer) PublishProfileState(_ context.Context, profile state.ActiveProfile, revision string) error {
	preparer.published = append(preparer.published, profile)
	preparer.revisions = append(preparer.revisions, revision)
	return preparer.err
}

type profileSwitchCore struct{}

func (profileSwitchCore) Start(context.Context, engine.PreparedCore) error { return nil }
func (profileSwitchCore) Stop(context.Context) error                       { return nil }
func (profileSwitchCore) Health(context.Context) (engine.HealthStatus, error) {
	return engine.HealthStatus{}, nil
}

type profileSwitchActivation struct{}

func (profileSwitchActivation) Activate(context.Context, engine.PreparedCore) error   { return nil }
func (profileSwitchActivation) Deactivate(context.Context, engine.PreparedCore) error { return nil }

type recordingProfileRevisionApplier struct {
	profile  state.ActiveProfile
	revision string
	err      error
}

func (applier *recordingProfileRevisionApplier) MarkAppliedRevision(_ context.Context, profile state.ActiveProfile, revision string) error {
	applier.profile = profile
	applier.revision = revision
	return applier.err
}

func TestProfileSwitcherCommitsExactPreparedRevision(t *testing.T) {
	ctx := context.Background()
	target := state.ActiveProfile{Name: "target", Engine: state.EngineSingBox}
	targetContent := []byte(`{"log":{"level":"info"}}`)
	var profiles state.ProfileStore
	switcher, profiles := newStoppedProfileSwitcher(t, profileSwitchPrepareFunc(func(_ context.Context, profile state.ActiveProfile) (engine.PreparedCore, error) {
		content, err := profiles.Get(profile)
		if err != nil {
			return engine.PreparedCore{}, err
		}
		return engine.PreparedCore{Engine: profile.Engine, SourceRevision: contentRevision(content)}, nil
	}))
	if err := profiles.Create(ctx, target, targetContent); err != nil {
		t.Fatal(err)
	}
	revisions := &recordingProfileRevisionApplier{}
	switcher.Revisions = revisions

	if err := switcher.Switch(ctx, target, true); err != nil {
		t.Fatal(err)
	}
	wantRevision := contentRevision(targetContent)
	if revisions.profile != target || revisions.revision != wantRevision {
		t.Fatalf("applied revision = (%+v, %q), want (%+v, %q)", revisions.profile, revisions.revision, target, wantRevision)
	}
	active, err := profiles.Current()
	if err != nil {
		t.Fatal(err)
	}
	if active != target {
		t.Fatalf("active profile = %+v, want %+v", active, target)
	}
	if _, err := switcher.State.Read(profileTransitionPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("transition journal remained after commit: %v", err)
	}
}

func TestProfileSwitcherRejectsTargetChangedAfterPreflight(t *testing.T) {
	ctx := context.Background()
	old := state.ActiveProfile{Name: "old", Engine: state.EngineMihomo}
	target := state.ActiveProfile{Name: "target", Engine: state.EngineMihomo}
	initial := []byte("mode: rule\n")
	changed := []byte("mode: global\n")
	var profiles state.ProfileStore
	switcher, profiles := newStoppedProfileSwitcher(t, profileSwitchPrepareFunc(func(ctx context.Context, profile state.ActiveProfile) (engine.PreparedCore, error) {
		content, err := profiles.Get(profile)
		if err != nil {
			return engine.PreparedCore{}, err
		}
		prepared := engine.PreparedCore{Engine: profile.Engine, SourceRevision: contentRevision(content)}
		if err := profiles.Update(ctx, profile, changed); err != nil {
			return engine.PreparedCore{}, err
		}
		return prepared, nil
	}))
	if err := profiles.Create(ctx, old, []byte("mode: direct\n")); err != nil {
		t.Fatal(err)
	}
	if err := profiles.Create(ctx, target, initial); err != nil {
		t.Fatal(err)
	}
	if err := profiles.Activate(ctx, old); err != nil {
		t.Fatal(err)
	}
	revisions := &recordingProfileRevisionApplier{}
	switcher.Revisions = revisions

	err := switcher.Switch(ctx, target, true)
	var public *web.PublicError
	if !errors.As(err, &public) || public.Code != "profile_changed_during_switch" {
		t.Fatalf("switch error = %v", err)
	}
	active, currentErr := profiles.Current()
	if currentErr != nil {
		t.Fatal(currentErr)
	}
	if active != old {
		t.Fatalf("active profile = %+v, want previous %+v", active, old)
	}
	if revisions.revision != "" {
		t.Fatalf("revision was marked despite failed recheck: %q", revisions.revision)
	}
}

func TestProfileSwitcherRestoresLegacyMirrorWhenCommitFails(t *testing.T) {
	ctx := context.Background()
	target := state.ActiveProfile{Name: "target", Engine: state.EngineMihomo}
	legacy := []byte("mode: direct\nlegacy: true\n")
	targetContent := []byte("mode: rule\n")
	var profiles state.ProfileStore
	switcher, profiles := newStoppedProfileSwitcher(t, profileSwitchPrepareFunc(func(_ context.Context, profile state.ActiveProfile) (engine.PreparedCore, error) {
		content, err := profiles.Get(profile)
		if err != nil {
			return engine.PreparedCore{}, err
		}
		return engine.PreparedCore{Engine: profile.Engine, SourceRevision: contentRevision(content)}, nil
	}))
	if err := profiles.Create(ctx, target, targetContent); err != nil {
		t.Fatal(err)
	}
	if err := switcher.State.Write("config.yaml", legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	switcher.Revisions = &recordingProfileRevisionApplier{err: errors.New("revision registry unavailable")}

	if err := switcher.Switch(ctx, target, true); err == nil {
		t.Fatal("switch unexpectedly succeeded")
	}
	assertLegacySelectionRestored(t, switcher, profiles, legacy)
}

func TestProfileSwitcherRestoresExactSameEngineMirrorWhenCommitFails(t *testing.T) {
	ctx := context.Background()
	old := state.ActiveProfile{Name: "old", Engine: state.EngineMihomo}
	target := state.ActiveProfile{Name: "target", Engine: state.EngineMihomo}
	appliedOldContent := []byte("mode: direct\ngeneration: applied\n")
	pendingOldContent := []byte("mode: direct\ngeneration: pending\n")
	targetContent := []byte("mode: rule\n")
	var profiles state.ProfileStore
	switcher, profiles := newStoppedProfileSwitcher(t, profileSwitchPrepareFunc(func(_ context.Context, profile state.ActiveProfile) (engine.PreparedCore, error) {
		content, err := profiles.Get(profile)
		if err != nil {
			return engine.PreparedCore{}, err
		}
		return engine.PreparedCore{Engine: profile.Engine, SourceRevision: contentRevision(content)}, nil
	}))
	if err := profiles.Create(ctx, old, appliedOldContent); err != nil {
		t.Fatal(err)
	}
	if err := profiles.Create(ctx, target, targetContent); err != nil {
		t.Fatal(err)
	}
	if err := profiles.Activate(ctx, old); err != nil {
		t.Fatal(err)
	}
	if err := profiles.Update(ctx, old, pendingOldContent); err != nil {
		t.Fatal(err)
	}
	switcher.Revisions = &recordingProfileRevisionApplier{err: errors.New("revision registry unavailable")}

	if err := switcher.Switch(ctx, target, true); err == nil {
		t.Fatal("switch unexpectedly succeeded")
	}
	active, err := profiles.Current()
	if err != nil {
		t.Fatal(err)
	}
	if active != old {
		t.Fatalf("active profile = %+v, want %+v", active, old)
	}
	mirror, err := switcher.State.Read("config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mirror, appliedOldContent) {
		t.Fatalf("restored mirror = %q, want exact applied bytes %q", mirror, appliedOldContent)
	}
}

func TestProfileSwitcherRecoversPreparedLegacyTransition(t *testing.T) {
	ctx := context.Background()
	target := state.ActiveProfile{Name: "target", Engine: state.EngineMihomo}
	legacy := []byte("mode: direct\nlegacy: true\n")
	targetContent := []byte("mode: rule\n")
	switcher, profiles := newStoppedProfileSwitcher(t, profileSwitchPrepareFunc(func(context.Context, state.ActiveProfile) (engine.PreparedCore, error) {
		return engine.PreparedCore{}, errors.New("not used")
	}))
	if err := profiles.Create(ctx, target, targetContent); err != nil {
		t.Fatal(err)
	}
	if err := switcher.State.Write("config.yaml", legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := switcher.captureTargetMirror(target)
	if err != nil {
		t.Fatal(err)
	}
	transition := profileTransition{
		Version: 1, New: target, NewRevision: contentRevision(targetContent), PreviousMirror: snapshot,
		Phase: "prepared", UpdatedAt: time.Now().UTC(),
	}
	if err := switcher.save(transition); err != nil {
		t.Fatal(err)
	}
	if err := profiles.Activate(ctx, target); err != nil {
		t.Fatal(err)
	}

	if err := switcher.RecoverSelection(); err != nil {
		t.Fatal(err)
	}
	assertLegacySelectionRestored(t, switcher, profiles, legacy)
	if err := switcher.CompleteRecovery(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := switcher.State.Read(profileTransitionPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("transition journal remained after recovery completion: %v", err)
	}
}

func TestProfileSwitcherCompleteRecoveryPublishesCommittedStateBeforeRemovingJournal(t *testing.T) {
	ctx := context.Background()
	target := state.ActiveProfile{Name: "target", Engine: state.EngineMihomo}
	targetContent := []byte("mode: rule\n")
	switcher, profiles := newStoppedProfileSwitcher(t, profileSwitchPrepareFunc(func(context.Context, state.ActiveProfile) (engine.PreparedCore, error) {
		return engine.PreparedCore{}, errors.New("not used")
	}))
	if err := profiles.Create(ctx, target, targetContent); err != nil {
		t.Fatal(err)
	}
	if err := profiles.Activate(ctx, target); err != nil {
		t.Fatal(err)
	}
	revision := contentRevision(targetContent)
	transition := profileTransition{
		Version: 1, New: target, NewRevision: revision,
		PreviousMirror: profileMirrorSnapshot{Captured: true},
		Phase:          "committed", UpdatedAt: time.Now().UTC(),
	}
	if err := switcher.save(transition); err != nil {
		t.Fatal(err)
	}
	publisher := &profileSwitchPublishingPreparer{
		prepare: func(context.Context, state.ActiveProfile) (engine.PreparedCore, error) {
			return engine.PreparedCore{}, errors.New("not used")
		},
		err: errors.New("shared state unavailable"),
	}
	switcher.Preparer.Preparers[state.EngineMihomo] = publisher

	if err := switcher.CompleteRecovery(ctx); err == nil {
		t.Fatal("failed recovered publication was accepted")
	}
	if _, err := switcher.State.Read(profileTransitionPath); err != nil {
		t.Fatalf("committed journal was removed after publication failure: %v", err)
	}
	publisher.err = nil
	if err := switcher.CompleteRecovery(ctx); err != nil {
		t.Fatal(err)
	}
	if len(publisher.published) != 2 || publisher.published[0] != target || publisher.published[1] != target ||
		len(publisher.revisions) != 2 || publisher.revisions[0] != revision || publisher.revisions[1] != revision {
		t.Fatalf("published state = (%+v, %v), want two attempts for (%+v, %s)", publisher.published, publisher.revisions, target, revision)
	}
	if _, err := switcher.State.Read(profileTransitionPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("transition journal remained after recovered publication: %v", err)
	}
}

func TestProfileSwitcherRecoveryRestoresExactTargetRevisionRecord(t *testing.T) {
	ctx := context.Background()
	target := state.ActiveProfile{Name: "target", Engine: state.EngineSingBox}
	legacy := []byte("mode: direct\nlegacy: true\n")
	targetContent := []byte(`{"log":{"level":"info"}}`)
	switcher, profiles := newStoppedProfileSwitcher(t, profileSwitchPrepareFunc(func(context.Context, state.ActiveProfile) (engine.PreparedCore, error) {
		return engine.PreparedCore{}, errors.New("not used")
	}))
	if err := profiles.Create(ctx, target, targetContent); err != nil {
		t.Fatal(err)
	}
	if err := switcher.State.Write("config.json", legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	revisions := &ProfileRevisionStore{State: switcher.State, Profiles: profiles, Now: time.Now}
	previous := profileRevision{
		AppliedRevision: contentRevision([]byte("previous applied")),
		PendingRevision: contentRevision(targetContent),
		PendingAt:       time.Now().UTC().Add(-time.Minute),
	}
	if err := revisions.Restore(ctx, target, previous, true); err != nil {
		t.Fatal(err)
	}
	switcher.Revisions = revisions
	mirror, err := switcher.captureTargetMirror(target)
	if err != nil {
		t.Fatal(err)
	}
	transition := profileTransition{
		Version: 1, New: target, NewRevision: contentRevision(targetContent), PreviousMirror: mirror,
		PreviousTargetRevisionCaptured: true, PreviousTargetRevisionExisted: true, PreviousTargetRevision: previous,
		Phase: "prepared", UpdatedAt: time.Now().UTC(),
	}
	if err := switcher.save(transition); err != nil {
		t.Fatal(err)
	}
	if err := profiles.Activate(ctx, target); err != nil {
		t.Fatal(err)
	}
	if err := revisions.MarkAppliedRevision(ctx, target, transition.NewRevision); err != nil {
		t.Fatal(err)
	}

	if err := switcher.RecoverSelection(); err != nil {
		t.Fatal(err)
	}
	got, existed, err := revisions.Snapshot(target)
	if err != nil {
		t.Fatal(err)
	}
	if !existed || got != previous {
		t.Fatalf("restored target revision = (%+v, %t), want (%+v, true)", got, existed, previous)
	}
}

func newStoppedProfileSwitcher(t *testing.T, native profileSwitchPrepareFunc) (*ProfileSwitcher, state.ProfileStore) {
	t.Helper()
	root := t.TempDir()
	profiles, err := state.NewProfileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	preparer := &EnginePreparer{Profiles: profiles, Preparers: map[string]ExplicitProfilePreparer{
		state.EngineMihomo:  native,
		state.EngineSingBox: native,
	}}
	lifecycle := &Lifecycle{
		Preparer: preparer, Core: profileSwitchCore{}, Activation: profileSwitchActivation{},
		snap: LifecycleSnapshot{State: LifecycleStopped},
	}
	return &ProfileSwitcher{State: store, Profiles: profiles, Preparer: preparer, Lifecycle: lifecycle}, profiles
}

func assertLegacySelectionRestored(t *testing.T, switcher *ProfileSwitcher, profiles state.ProfileStore, want []byte) {
	t.Helper()
	active, err := profiles.Current()
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("active profile = %+v, error = %v; want no profile metadata", active, err)
	}
	content, err := switcher.State.Read("config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, want) {
		t.Fatalf("legacy mirror = %q, want %q", content, want)
	}
}
