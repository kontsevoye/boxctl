package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"

	"github.com/kontsevoye/boxctl/internal/web"
)

const passkeyStatePath = ".boxctl/passkeys.v1.json" // #nosec G101 -- Private state filename, not a credential.

func (store CredentialStore) LoadPasskeys(_ context.Context) (web.PasskeyState, error) {
	content, err := store.State.Read(passkeyStatePath)
	if errors.Is(err, fs.ErrNotExist) {
		return web.PasskeyState{}, nil
	}
	if err != nil {
		return web.PasskeyState{}, fmt.Errorf("read passkeys: %w", err)
	}
	var result web.PasskeyState
	if err := json.Unmarshal(content, &result); err != nil {
		return web.PasskeyState{}, fmt.Errorf("decode passkeys: %w", err)
	}
	if len(result.UserHandle) != 32 {
		return web.PasskeyState{}, errors.New("invalid passkey user handle")
	}
	return result, nil
}

// UpdatePasskeys keeps credential lookup, verification and the atomic write
// under the credential lock, including concurrent CLI password changes.
func (store CredentialStore) UpdatePasskeys(ctx context.Context, update func(*web.PasskeyState, web.Credential) error) error {
	return store.State.WithLock(ctx, "credentials", func() error {
		credential, err := store.Credential(ctx)
		if err != nil {
			return err
		}
		current, err := store.LoadPasskeys(ctx)
		if err != nil {
			return err
		}
		if err := update(&current, credential); err != nil {
			return err
		}
		return store.State.WriteJSON(passkeyStatePath, current, 0o600)
	})
}
