package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/kontsevoye/boxctl/internal/state"
)

const (
	managerHandoffPath    = ".boxctl/manager-handoff.json"
	managerHandoffVersion = 1
	managerHandoffTTL     = 2 * time.Minute
)

type managerHandoff struct {
	Version       int       `json:"version"`
	TargetVersion string    `json:"targetVersion"`
	ExpiresAt     time.Time `json:"expiresAt"`
}

func writeManagerHandoff(layout state.Layout, targetVersion string) error {
	store, err := state.NewStore(layout.Root)
	if err != nil {
		return err
	}
	return store.WriteJSON(managerHandoffPath, managerHandoff{
		Version: managerHandoffVersion, TargetVersion: targetVersion,
		ExpiresAt: time.Now().UTC().Add(managerHandoffTTL),
	}, 0o600)
}

func validManagerHandoff(root, targetVersion string) (bool, error) {
	store, err := state.NewStore(root)
	if err != nil {
		return false, err
	}
	content, err := store.Read(managerHandoffPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var handoff managerHandoff
	if err := decoder.Decode(&handoff); err != nil {
		return false, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return false, errors.New("manager handoff contains trailing data")
	}
	if handoff.Version != managerHandoffVersion || handoff.TargetVersion == "" || !handoff.ExpiresAt.After(time.Now().UTC()) {
		return false, nil
	}
	return targetVersion == "" || handoff.TargetVersion == targetVersion, nil
}

func removeManagerHandoff(layout state.Layout) error {
	store, err := state.NewStore(layout.Root)
	if err != nil {
		return err
	}
	return store.RemoveRegular(managerHandoffPath)
}

func managerHandoffPresent(layout state.Layout) (bool, error) {
	store, err := state.NewStore(layout.Root)
	if err != nil {
		return false, err
	}
	_, err = store.Read(managerHandoffPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
