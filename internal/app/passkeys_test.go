package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/kontsevoye/boxctl/internal/web"
)

func TestPasskeyStorePersistenceAndAtomicMutations(t *testing.T) {
	store, err := NewCredentialStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetPassword("correct horse"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := store.State.Write(".boxctl/settings.json", []byte(`{"unrelated":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := store.UpdatePasskeys(ctx, func(current *web.PasskeyState, credential web.Credential) error {
				if ok, _ := web.VerifyPBKDF2Record(credential.PasswordRecord, "correct horse"); !ok {
					return errors.New("missing current administrator credential")
				}
				if len(current.UserHandle) == 0 {
					current.UserHandle = bytes.Repeat([]byte{1}, 32)
				}
				current.Passkeys = append(current.Passkeys, web.StoredPasskey{Credential: webauthn.Credential{ID: []byte{byte(len(current.Passkeys))}, PublicKey: []byte("public key")}, Name: "device", RPID: "router.example"})
				return nil
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	reopened, err := NewCredentialStore(store.State.Root)
	if err != nil {
		t.Fatal(err)
	}
	current, err := reopened.LoadPasskeys(ctx)
	if err != nil || len(current.Passkeys) != 8 {
		t.Fatalf("reloaded passkeys = %d, %v", len(current.Passkeys), err)
	}
	before, err := store.State.Read(passkeyStatePath)
	if err != nil {
		t.Fatal(err)
	}
	err = store.UpdatePasskeys(ctx, func(current *web.PasskeyState, _ web.Credential) error {
		current.Passkeys = nil
		return errors.New("reject mutation")
	})
	if err == nil {
		t.Fatal("accepted failed update")
	}
	after, _ := store.State.Read(passkeyStatePath)
	if !bytes.Equal(before, after) {
		t.Fatal("failed callback changed state")
	}
	info, err := os.Stat(filepath.Join(store.State.Root, passkeyStatePath))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v %v", info, err)
	}
	settings, _ := store.State.Read(".boxctl/settings.json")
	if string(settings) != `{"unrelated":true}` {
		t.Fatal("changed unrelated settings")
	}
	if err := store.SetPassword("replacement password"); err != nil {
		t.Fatal(err)
	}
	current, err = store.LoadPasskeys(ctx)
	if err != nil || len(current.Passkeys) != 8 {
		t.Fatal("password rotation removed passkeys")
	}
}

func TestPasskeyStoreRejectsUnsafeFilesAndFirstSetupRevokesStaleKeys(t *testing.T) {
	store, err := NewCredentialStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.State.Write(passkeyStatePath, []byte(`{"userHandle":"malformed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadPasskeys(context.Background()); err == nil {
		t.Fatal("accepted malformed state")
	}
	if err := store.InitializeAdmin(context.Background(), "new administrator"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(store.State.Root, passkeyStatePath)); !os.IsNotExist(err) {
		t.Fatal("first setup retained stale passkeys")
	}
	outside := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(outside, []byte("do not touch"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(store.State.Root, passkeyStatePath)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadPasskeys(context.Background()); err == nil {
		t.Fatal("followed credential symlink")
	}
	if err := store.UpdatePasskeys(context.Background(), func(*web.PasskeyState, web.Credential) error { return nil }); err == nil {
		t.Fatal("wrote credential symlink")
	}
	content, _ := os.ReadFile(outside)
	if string(content) != "do not touch" {
		t.Fatal("changed symlink target")
	}
}
