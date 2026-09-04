package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/kontsevoye/boxctl/internal/state"
)

const (
	openWrtOwnerStatePath    = "openwrt-owner.json"
	openWrtOwnerStateVersion = 1
)

type openWrtOwnerState struct {
	Version int    `json:"version"`
	Root    string `json:"root"`
}

// claimOpenWrtOwnerState publishes the canonical data-root identity while the
// caller holds the lifetime owner lock. The gateway lock makes publication
// atomic with one-shot authorization checks.
func claimOpenWrtOwnerState(ctx context.Context, locks state.Store, root string) error {
	return locks.WithLock(ctx, "gateway-dns", func() error {
		return authorizeOpenWrtRootLocked(locks, root, true)
	})
}

func clearOpenWrtOwnerState(ctx context.Context, locks state.Store, root string) error {
	return locks.WithLock(ctx, "gateway-dns", func() error {
		owner, err := loadOpenWrtOwnerState(locks)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		canonical, err := canonicalOwnerRoot(root)
		if err != nil {
			return err
		}
		if owner.Root != canonical {
			return foreignOpenWrtOwnerError(owner.Root)
		}
		return locks.RemoveRegular(openWrtOwnerStatePath)
	})
}

// authorizeOpenWrtRootLocked must run while gateway-dns is held. Missing state
// can be claimed only by activation/reconcile; read-only diagnosis and
// ownership-only cleanup may proceed without recreating a marker after a clean
// daemon shutdown. Existing state is never reassigned across data roots.
func authorizeOpenWrtRootLocked(locks state.Store, root string, claimMissing bool) error {
	canonical, err := canonicalOwnerRoot(root)
	if err != nil {
		return err
	}
	owner, err := loadOpenWrtOwnerState(locks)
	if errors.Is(err, fs.ErrNotExist) {
		if !claimMissing {
			return nil
		}
		return locks.WriteJSON(openWrtOwnerStatePath, openWrtOwnerState{
			Version: openWrtOwnerStateVersion,
			Root:    canonical,
		}, 0o600)
	}
	if err != nil {
		return err
	}
	if owner.Root != canonical {
		return foreignOpenWrtOwnerError(owner.Root)
	}
	return nil
}

func loadOpenWrtOwnerState(locks state.Store) (openWrtOwnerState, error) {
	content, err := locks.Read(openWrtOwnerStatePath)
	if err != nil {
		return openWrtOwnerState{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var owner openWrtOwnerState
	if err := decoder.Decode(&owner); err != nil {
		return openWrtOwnerState{}, fmt.Errorf("decode OpenWrt owner state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return openWrtOwnerState{}, errors.New("decode OpenWrt owner state: trailing data")
	}
	if owner.Version != openWrtOwnerStateVersion {
		return openWrtOwnerState{}, fmt.Errorf("unsupported OpenWrt owner state version %d", owner.Version)
	}
	canonical, err := canonicalOwnerRoot(owner.Root)
	if err != nil || canonical != owner.Root {
		return openWrtOwnerState{}, errors.New("OpenWrt owner state contains a non-canonical root")
	}
	return owner, nil
}

func canonicalOwnerRoot(root string) (string, error) {
	store, err := state.NewStore(root)
	if err != nil {
		return "", err
	}
	return store.Root, nil
}

func foreignOpenWrtOwnerError(root string) error {
	return fmt.Errorf("OpenWrt gateway is owned by another boxctl data root %q", root)
}
