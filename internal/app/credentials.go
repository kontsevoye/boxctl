package app

import (
	"bufio"
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"

	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

const (
	passwordPath     = ".boxctl/password"
	sessionStatePath = ".boxctl/session-secrets.v1.json"
	adminUserID      = "administrator"
	passwordRounds   = 100_000
	passwordSaltSize = 16
)

// CredentialStore adapts private on-disk state to password-only authentication.
type CredentialStore struct {
	State state.Store
}

func NewCredentialStore(root string) (CredentialStore, error) {
	store, err := state.NewStore(root)
	if err != nil {
		return CredentialStore{}, err
	}
	return CredentialStore{State: store}, nil
}

func (store CredentialStore) Credential(_ context.Context) (web.Credential, error) {
	record, err := store.State.Read(passwordPath)
	if errors.Is(err, fs.ErrNotExist) {
		return web.Credential{}, web.ErrNotFound
	}
	if err != nil {
		return web.Credential{}, fmt.Errorf("read administrator credential: %w", err)
	}
	trimmed := strings.TrimSpace(string(record))
	if _, err := state.ParsePasswordRecord(record); err != nil {
		return web.Credential{}, fmt.Errorf("read administrator credential: %w", err)
	}
	return web.Credential{UserID: adminUserID, DisplayName: "Administrator", PasswordRecord: trimmed}, nil
}

func (store CredentialStore) AdminSetupStatus(_ context.Context) (web.AdminSetupStatus, error) {
	_, err := store.State.Read(passwordPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return web.AdminSetupStatus{Required: true}, nil
	case err != nil:
		return web.AdminSetupStatus{}, fmt.Errorf("inspect administrator credential: %w", err)
	default:
		return web.AdminSetupStatus{Required: false}, nil
	}
}

// InitializeAdmin publishes the first canonical password exactly once. The
// inter-process credential lock closes the status/write race between multiple
// browser requests or concurrently started management processes.
func (store CredentialStore) InitializeAdmin(ctx context.Context, password string) error {
	return store.State.WithLock(ctx, "credentials", func() error {
		_, readErr := store.State.Read(passwordPath)
		switch {
		case readErr == nil:
			return &web.PublicError{Status: http.StatusConflict, Code: "setup_complete", Message: "Administrator setup is already complete"}
		case !errors.Is(readErr, fs.ErrNotExist):
			return fmt.Errorf("inspect administrator credential: %w", readErr)
		}
		// Do the deliberately expensive PBKDF2 work only after the one-time
		// state check. Once setup is complete, this unauthenticated endpoint must
		// remain a cheap conflict response rather than a CPU-amplification path.
		record, err := createPasswordRecord(password)
		if err != nil {
			return &web.PublicError{Status: http.StatusBadRequest, Code: "invalid_password", Message: err.Error()}
		}
		// There cannot be a legitimate authenticated browser session before the
		// first password exists. Remove any stale persisted signing state before
		// making the credential visible.
		if err := store.State.RemoveRegular(sessionStatePath); err != nil {
			return fmt.Errorf("revoke stale persisted sessions: %w", err)
		}
		return store.State.WritePasswordRecordOpaque(passwordPath, record)
	})
}

func (store CredentialStore) LoadSessionSecrets(_ context.Context) (web.SessionSecretSet, error) {
	content, err := store.State.Read(sessionStatePath)
	if errors.Is(err, fs.ErrNotExist) {
		return web.SessionSecretSet{}, nil
	}
	if err != nil {
		return web.SessionSecretSet{}, fmt.Errorf("load session signing state: %w", err)
	}
	var secrets web.SessionSecretSet
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&secrets); err != nil {
		return web.SessionSecretSet{}, fmt.Errorf("decode session signing state: %w", err)
	}
	return secrets, nil
}

func (store CredentialStore) SaveSessionSecrets(ctx context.Context, secrets web.SessionSecretSet) error {
	return store.State.WithLock(ctx, "credentials", func() error {
		return store.State.WriteJSON(sessionStatePath, secrets, 0o600)
	})
}

// SetPassword writes the compatible PBKDF2-HMAC-SHA256 record atomically and
// revokes persisted session keys under the same inter-process lock.
func (store CredentialStore) SetPassword(password string) error {
	record, err := createPasswordRecord(password)
	if err != nil {
		return err
	}
	return store.State.WithLock(context.Background(), "credentials", func() error {
		// Revoke persisted signing keys before publishing the new password. If the
		// password write fails, sessions may be revoked unnecessarily, but a
		// successful password change can never retain the old persisted keys.
		if err := store.State.RemoveRegular(sessionStatePath); err != nil {
			return fmt.Errorf("revoke persisted sessions: %w", err)
		}
		return store.State.WritePasswordRecordOpaque(passwordPath, record)
	})
}

func createPasswordRecord(password string) ([]byte, error) {
	if len(password) < 8 {
		return nil, errors.New("password must contain at least 8 characters")
	}
	if len(password) > 1024 || strings.ContainsRune(password, 0) || strings.ContainsAny(password, "\r\n") {
		return nil, errors.New("password is too long or contains an invalid character")
	}
	salt := make([]byte, passwordSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate password salt: %w", err)
	}
	derived, err := pbkdf2.Key(sha256.New, password, salt, passwordRounds, sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("derive password hash: %w", err)
	}
	record := fmt.Sprintf("pbkdf2$%d$%s$%s\n", passwordRounds, hex.EncodeToString(salt), hex.EncodeToString(derived))
	return []byte(record), nil
}

// ReadAndSetPassword implements the non-echo-neutral part of the CLI contract.
// The caller may provide a terminal reader that disables echo or a protected
// pipe. Passwords are never accepted as command-line arguments.
func (store CredentialStore) ReadAndSetPassword(input io.Reader, output io.Writer) error {
	reader := bufio.NewReader(io.LimitReader(input, 4096))
	if _, err := io.WriteString(output, "New administrator password: "); err != nil {
		return err
	}
	first, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read password: %w", err)
	}
	first = strings.TrimSuffix(strings.TrimSuffix(first, "\n"), "\r")
	if _, err := io.WriteString(output, "Confirm password: "); err != nil {
		return err
	}
	second, secondErr := reader.ReadString('\n')
	if secondErr != nil && !errors.Is(secondErr, io.EOF) {
		return fmt.Errorf("read password confirmation: %w", secondErr)
	}
	second = strings.TrimSuffix(strings.TrimSuffix(second, "\n"), "\r")
	if first != second {
		return errors.New("password confirmation does not match")
	}
	if err := store.SetPassword(first); err != nil {
		return err
	}
	_, err = io.WriteString(output, "Password updated; persisted sessions were revoked. Restart the management service to discard signing keys already held in memory.\n")
	return err
}
