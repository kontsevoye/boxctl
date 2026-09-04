package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"time"

	"github.com/kontsevoye/boxctl/internal/state"
)

const profileRevisionsPath = ".boxctl/profile-revisions.v1.json"

type profileRevision struct {
	AppliedRevision string    `json:"appliedRevision,omitempty"`
	PendingRevision string    `json:"pendingRevision,omitempty"`
	PendingAt       time.Time `json:"pendingAt,omitempty"`
}

type profileRevisionRegistry struct {
	Version int                        `json:"version"`
	Items   map[string]profileRevision `json:"items"`
}

type ProfileRevisionStore struct {
	State    state.Store
	Profiles state.ProfileStore
	Now      func() time.Time
}

func NewProfileRevisionStore(root string) (*ProfileRevisionStore, error) {
	store, err := state.NewStore(root)
	if err != nil {
		return nil, err
	}
	profiles, err := state.NewProfileStore(root)
	if err != nil {
		return nil, err
	}
	return &ProfileRevisionStore{State: store, Profiles: profiles, Now: time.Now}, nil
}

func (store *ProfileRevisionStore) Get(profile state.ActiveProfile) (profileRevision, error) {
	registry, err := store.load()
	if err != nil {
		return profileRevision{}, err
	}
	return registry.Items[profileID(profile)], nil
}

func (store *ProfileRevisionStore) Snapshot(profile state.ActiveProfile) (profileRevision, bool, error) {
	registry, err := store.load()
	if err != nil {
		return profileRevision{}, false, err
	}
	value, exists := registry.Items[profileID(profile)]
	return value, exists, nil
}

// Restore reinstates the exact revision record captured before a compensated
// profile mutation. It is deliberately private to application transactions;
// normal callers should use MarkPending/MarkAppliedRevision instead.
func (store *ProfileRevisionStore) Restore(ctx context.Context, profile state.ActiveProfile, value profileRevision, existed bool) error {
	return store.update(ctx, func(registry *profileRevisionRegistry) {
		if !existed {
			delete(registry.Items, profileID(profile))
			return
		}
		registry.Items[profileID(profile)] = value
	})
}

func (store *ProfileRevisionStore) MarkPending(ctx context.Context, profile state.ActiveProfile, previous string) error {
	content, err := store.Profiles.Get(profile)
	if err != nil {
		return err
	}
	pending := contentRevision(content)
	return store.update(ctx, func(registry *profileRevisionRegistry) {
		item := registry.Items[profileID(profile)]
		if item.AppliedRevision == "" {
			item.AppliedRevision = previous
		}
		if item.AppliedRevision == pending {
			item.PendingRevision = ""
			item.PendingAt = time.Time{}
		} else {
			item.PendingRevision = pending
			item.PendingAt = store.now().UTC()
		}
		registry.Items[profileID(profile)] = item
	})
}

func (store *ProfileRevisionStore) MarkApplied(ctx context.Context, profile state.ActiveProfile) error {
	content, err := store.Profiles.Get(profile)
	if err != nil {
		return err
	}
	return store.MarkAppliedRevision(ctx, profile, contentRevision(content))
}

func (store *ProfileRevisionStore) MarkAppliedRevision(ctx context.Context, profile state.ActiveProfile, revision string) error {
	if revision == "" {
		return errors.New("applied profile revision is empty")
	}
	return store.update(ctx, func(registry *profileRevisionRegistry) {
		item := registry.Items[profileID(profile)]
		item.AppliedRevision = revision
		if item.PendingRevision == revision {
			item.PendingRevision = ""
			item.PendingAt = time.Time{}
		}
		registry.Items[profileID(profile)] = item
	})
}

func (store *ProfileRevisionStore) Remove(ctx context.Context, profile state.ActiveProfile) error {
	return store.update(ctx, func(registry *profileRevisionRegistry) {
		delete(registry.Items, profileID(profile))
	})
}

func (store *ProfileRevisionStore) Pending(profile state.ActiveProfile) (profileRevision, bool, error) {
	item, err := store.Get(profile)
	if err != nil {
		return profileRevision{}, false, err
	}
	return item, item.PendingRevision != "" && item.PendingRevision != item.AppliedRevision, nil
}

func (store *ProfileRevisionStore) update(ctx context.Context, mutate func(*profileRevisionRegistry)) error {
	return store.State.WithLock(ctx, "profile-revisions", func() error {
		registry, err := store.load()
		if err != nil {
			return err
		}
		mutate(&registry)
		return store.State.WriteJSON(profileRevisionsPath, registry, 0o600)
	})
}

func (store *ProfileRevisionStore) load() (profileRevisionRegistry, error) {
	content, err := store.State.Read(profileRevisionsPath)
	if errors.Is(err, fs.ErrNotExist) {
		return profileRevisionRegistry{Version: 1, Items: make(map[string]profileRevision)}, nil
	}
	if err != nil {
		return profileRevisionRegistry{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var registry profileRevisionRegistry
	if err := decoder.Decode(&registry); err != nil {
		return profileRevisionRegistry{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return profileRevisionRegistry{}, errors.New("profile revision registry contains trailing data")
	}
	if registry.Version != 1 {
		return profileRevisionRegistry{}, errors.New("unsupported profile revision registry version")
	}
	if registry.Items == nil {
		registry.Items = make(map[string]profileRevision)
	}
	return registry, nil
}

func (store *ProfileRevisionStore) now() time.Time {
	if store.Now != nil {
		return store.Now()
	}
	return time.Now()
}
